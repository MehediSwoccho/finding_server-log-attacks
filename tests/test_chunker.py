import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from app import analyzer, db
from app.analyzer import chunk_entries, parse_log_line, prepare_job


class ChunkEntriesTests(unittest.TestCase):
    def test_public_count_tokens_uses_loaded_model_tokenizer(self):
        class FakeModel:
            @staticmethod
            def tokenize(value, **_kwargs):
                return list(value)

        with patch.object(analyzer, "_MODEL", FakeModel()):
            self.assertEqual(analyzer.count_tokens("local"), 5)

    def test_packs_whole_entries_and_preserves_line_numbers(self):
        entries = [(1, '{"line":1}'), (2, '{"line":2}'), (3, '{"line":3}')]
        chunks = list(chunk_entries(entries, lambda value: len(value), max_tokens=22))
        self.assertEqual(len(chunks), 2)
        self.assertEqual(chunks[0][0], '{"line":1}\n{"line":2}')
        self.assertEqual(chunks[1][0], '{"line":3}')
        self.assertTrue(all(tokens <= 22 for _, tokens in chunks))

    def test_never_splits_an_oversized_entry(self):
        with self.assertRaisesRegex(ValueError, "line 7"):
            list(chunk_entries([(7, "x" * 11)], len, max_tokens=10))

    def test_empty_input_has_no_chunks(self):
        self.assertEqual(list(chunk_entries([], len, max_tokens=10)), [])


class LogParsingTests(unittest.TestCase):
    def test_malformed_json_falls_back_to_raw_text_and_keeps_source_line(self):
        raw_line = '{"message": not valid json'
        fields, rendered = parse_log_line(raw_line, 17)

        self.assertEqual(fields, {"message": raw_line})
        decoded = json.loads(rendered)
        self.assertEqual(decoded["line"], 17)
        self.assertEqual(decoded["data"]["message"], raw_line)

    def test_compact_json_drops_noise_and_only_browser_user_agent(self):
        raw_line = json.dumps({
            "time": "2026-11-07T10:00:00Z",
            "ip": "192.0.2.5",
            "method": "GET",
            "path": "/admin",
            "status": 403,
            "username": "alice",
            "auth_result": "denied",
            "message": "blocked",
            "security_rule": "access_denied",
            "user_agent": "curl/8.7.1",
            "host": "noisy.example",
            "response_bytes": 8192,
        })
        fields, rendered = parse_log_line(raw_line, 9)

        self.assertEqual(fields["client_ip"], "192.0.2.5")
        self.assertEqual(fields["user_agent"], "curl/8.7.1")
        self.assertNotIn("host", fields)
        self.assertNotIn("response_bytes", fields)
        self.assertIn('"line":9', rendered)

        event_fields, event_rendering = parse_log_line(
            '{"event_id":"event-duplicate","message":"request"}', 11
        )
        self.assertEqual(event_fields["event_id"], "event-duplicate")
        self.assertNotIn("event-duplicate", event_rendering)

        browser_fields, _ = parse_log_line(
            '{"user_agent":"Mozilla/5.0 Chrome/130.0.0.0","message":"ok"}', 10
        )
        self.assertNotIn("user_agent", browser_fields)


class PrepareJobChunkingTests(unittest.TestCase):
    def _create_job(self, root: Path, contents: str) -> tuple[str, Path, Path]:
        job_id = "test-job"
        log_path = root / "input.log"
        log_path.write_text(contents, encoding="utf-8")
        return job_id, log_path, root / "checkpoints.sqlite3"

    def test_production_chunking_keeps_entries_whole_and_line_numbered(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            contents = (
                json.dumps({"message": "a" * 450}) + "\n" +
                json.dumps({"message": "b" * 450}) + "\n"
            )
            job_id, log_path, database_path = self._create_job(root, contents)

            with patch.object(db, "DB_PATH", database_path):
                db.initialize_database()
                db.create_job(job_id, log_path.name, str(log_path))
                self.assertEqual(prepare_job(job_id, len), 2)
                with db.connect() as connection:
                    chunks = connection.execute(
                        "SELECT log_text, token_count FROM chunks WHERE job_id = ? ORDER BY chunk_index",
                        (job_id,),
                    ).fetchall()

            self.assertIn('"line":1', chunks[0]["log_text"])
            self.assertNotIn('"line":2', chunks[0]["log_text"])
            self.assertIn('"line":2', chunks[1]["log_text"])
            self.assertTrue(all(chunk["token_count"] <= 900 for chunk in chunks))

    def test_production_rejects_oversized_single_source_line(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            job_id, log_path, database_path = self._create_job(root, "x" * 1000 + "\n")

            with patch.object(db, "DB_PATH", database_path):
                db.initialize_database()
                db.create_job(job_id, log_path.name, str(log_path))
                with self.assertRaisesRegex(ValueError, "line 1"):
                    prepare_job(job_id, len)
                with db.connect() as connection:
                    chunk_count = connection.execute(
                        "SELECT COUNT(*) FROM chunks WHERE job_id = ?", (job_id,)
                    ).fetchone()[0]

            self.assertEqual(chunk_count, 0)

    def test_persistent_ip_and_username_ledger_feeds_later_chunk(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            events = [
                {
                    "client_ip": "192.0.2.44",
                    "username": "alice",
                    "auth_result": "failed",
                    "path": "/api/login",
                    "status": 401,
                    "message": "a" * 360,
                },
                {
                    "client_ip": "192.0.2.44",
                    "username": "alice",
                    "auth_result": "success",
                    "path": "/reports",
                    "status": 200,
                    "message": "b" * 360,
                },
            ]
            contents = "\n".join(json.dumps(event) for event in events) + "\n"
            job_id, log_path, database_path = self._create_job(root, contents)

            with patch.object(db, "DB_PATH", database_path):
                db.initialize_database()
                db.create_job(job_id, log_path.name, str(log_path))
                self.assertEqual(prepare_job(job_id, len), 2)

                # Read from fresh SQLite connections to verify persisted state.
                with db.connect() as connection:
                    chunks = connection.execute(
                        "SELECT ledger_text FROM chunks WHERE job_id = ? ORDER BY chunk_index",
                        (job_id,),
                    ).fetchall()
                    entities = connection.execute(
                        "SELECT * FROM entity_ledger_items WHERE job_id = ? ORDER BY entity_type",
                        (job_id,),
                    ).fetchall()

            self.assertEqual(chunks[0]["ledger_text"], "No prior entity facts.")
            self.assertLessEqual(len(chunks[1]["ledger_text"]), 250)
            self.assertIn("f=1", chunks[1]["ledger_text"])
            self.assertIn("/api/login", chunks[1]["ledger_text"])
            self.assertIn("username=alice", chunks[1]["ledger_text"])

            self.assertEqual({row["entity_type"] for row in entities}, {"client_ip", "username"})
            for row in entities:
                self.assertEqual(row["failed_login_count"], 1)
                self.assertEqual(row["successful_login_count"], 1)
                self.assertEqual(row["first_line"], 1)
                self.assertEqual(row["last_line"], 2)
                self.assertEqual(row["sensitive_path_hits"], 1)
                self.assertEqual(
                    json.loads(row["distinct_paths_json"]), ["/api/login", "/reports"]
                )
                self.assertEqual(json.loads(row["status_counts_json"]), {"401": 1, "200": 1})

    def test_event_ids_are_persisted_with_original_source_lines(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            contents = (
                '{"event_id":"evt-1","client_ip":"192.0.2.31","auth_result":"failed","path":"/login","status":401,"message":"first"}\n'
                '{"event_id":"evt-1","client_ip":"192.0.2.31","auth_result":"failed","path":"/login","status":401,"message":"duplicate"}\n'
            )
            job_id, log_path, database_path = self._create_job(root, contents)

            with patch.object(db, "DB_PATH", database_path):
                db.initialize_database()
                db.create_job(job_id, log_path.name, str(log_path))
                prepare_job(job_id, len)
                with db.connect() as connection:
                    rows = connection.execute(
                        "SELECT event_id, line_number FROM event_id_lines WHERE job_id = ? ORDER BY line_number",
                        (job_id,),
                    ).fetchall()
                    ledger = connection.execute(
                        "SELECT * FROM entity_ledger_items WHERE job_id = ? AND entity_type = 'client_ip'",
                        (job_id,),
                    ).fetchone()

            self.assertEqual([(row["event_id"], row["line_number"]) for row in rows], [("evt-1", 1), ("evt-1", 2)])
            self.assertEqual(ledger["failed_login_count"], 1)
            self.assertEqual(ledger["last_line"], 1)
            self.assertEqual(json.loads(ledger["status_counts_json"]), {"401": 1})

    def test_ip_ledger_records_success_line_after_repeated_failures(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            events = [
                {"client_ip": "192.0.2.77", "auth_result": "failed", "path": "/login", "status": 401},
                {"client_ip": "192.0.2.77", "auth_result": "failed", "path": "/login", "status": 401},
                {"client_ip": "192.0.2.77", "auth_result": "failed", "path": "/login", "status": 401},
                {"client_ip": "192.0.2.77", "auth_result": "success", "path": "/login", "status": 200},
            ]
            contents = "\n".join(json.dumps(event) for event in events) + "\n"
            job_id, log_path, database_path = self._create_job(root, contents)

            with patch.object(db, "DB_PATH", database_path):
                db.initialize_database()
                db.create_job(job_id, log_path.name, str(log_path))
                prepare_job(job_id, len)
                with db.connect() as connection:
                    ledger = connection.execute(
                        "SELECT * FROM entity_ledger_items WHERE job_id = ? AND entity_type = 'client_ip'",
                        (job_id,),
                    ).fetchone()

            self.assertEqual(ledger["failed_login_count"], 3)
            self.assertEqual(ledger["successful_login_count"], 1)
            self.assertEqual(ledger["success_after_repeated_failures_line"], 4)


if __name__ == "__main__":
    unittest.main()
