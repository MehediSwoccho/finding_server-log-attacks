import asyncio
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from app import analyzer, db


class FakeModel:
    @staticmethod
    def tokenize(value, **_kwargs):
        return list(value)


class JobRunnerTests(unittest.TestCase):
    def test_failed_chunk_is_recorded_others_continue_and_resume_retries_only_failure(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            database_path = Path(temporary_directory) / "jobs.sqlite3"
            log_path = Path(temporary_directory) / "log.txt"
            log_path.write_text("placeholder", encoding="utf-8")
            job_id = "runner-test"
            attempts: dict[str, int] = {}
            fail_first_chunk = True

            def fake_call(_model, log_text, _ledger_text):
                nonlocal fail_first_chunk
                attempts[log_text] = attempts.get(log_text, 0) + 1
                if log_text == "chunk-1" and fail_first_chunk:
                    raise RuntimeError("simulated model failure")
                return {"findings": []}

            with patch.object(db, "DB_PATH", database_path):
                db.initialize_database()
                db.create_job(job_id, log_path.name, str(log_path))
                db.set_job(job_id, prepared=1, total_chunks=3)
                with db.connect() as connection:
                    for index in range(3):
                        connection.execute(
                            """INSERT INTO chunks
                            (job_id, chunk_index, log_text, ledger_text, token_count, status)
                            VALUES (?, ?, ?, ?, ?, 'pending')""",
                            (job_id, index, f"chunk-{index + 1}", "facts", 7),
                        )

                with (
                    patch.object(analyzer, "_load_model", return_value=FakeModel()),
                    patch.object(analyzer, "_call_model", side_effect=fake_call),
                    patch.object(analyzer, "RETRY_BASE_SECONDS", 0),
                ):
                    asyncio.run(analyzer.start_analysis(job_id))

                job = db.get_job(job_id)
                self.assertEqual(job["status"], "completed_with_errors")
                self.assertTrue(job["report_json"])
                with db.connect() as connection:
                    rows = connection.execute(
                        "SELECT status, error, result_json, duration_ms, call_started_at FROM chunks WHERE job_id = ? ORDER BY chunk_index",
                        (job_id,),
                    ).fetchall()

                self.assertEqual([row["status"] for row in rows], ["failed", "completed", "completed"])
                self.assertIn("simulated model failure", rows[0]["error"])
                self.assertEqual(rows[0]["result_json"], None)
                self.assertIsNotNone(rows[0]["duration_ms"])
                self.assertIsNone(rows[0]["call_started_at"])
                progress = db.progress(job_id)
                self.assertEqual(progress["current_chunk"], 3)
                self.assertEqual(progress["completed_chunks"], 2)
                self.assertEqual(progress["failed_chunks"], 1)
                self.assertIsNotNone(progress["elapsed_seconds"])
                self.assertIsNotNone(progress["call_duration_ms"])
                self.assertEqual(attempts, {"chunk-1": 3, "chunk-2": 1, "chunk-3": 1})

                fail_first_chunk = False
                with (
                    patch.object(analyzer, "_load_model", return_value=FakeModel()),
                    patch.object(analyzer, "_call_model", side_effect=fake_call),
                    patch.object(analyzer, "RETRY_BASE_SECONDS", 0),
                ):
                    asyncio.run(analyzer.start_analysis(job_id))

                job = db.get_job(job_id)
                self.assertEqual(job["status"], "completed")
                self.assertEqual(attempts["chunk-1"], 4)
                self.assertEqual(attempts["chunk-2"], 1)
                self.assertEqual(attempts["chunk-3"], 1)


if __name__ == "__main__":
    unittest.main()
