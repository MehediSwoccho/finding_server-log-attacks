import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from app import analyzer, db


class ReportMergeTests(unittest.TestCase):
    def test_merges_and_deduplicates_evidence_then_upgrades_compromise(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            database_path = Path(temporary_directory) / "report.sqlite3"
            log_path = Path(temporary_directory) / "log.txt"
            log_path.write_text("placeholder", encoding="utf-8")
            job_id = "merge-test"
            brute_a = {
                "attack_type": "brute_force",
                "severity": "Medium",
                "entity": "192.0.2.9",
                "evidence_lines": [2],
                "reason": "Repeated login failures.",
                "action": "Review the account.",
            }
            brute_b = {
                **brute_a,
                "severity": "High",
                "evidence_lines": [3],
                "reason": "The same request was logged twice.",
            }
            ordinary_error = {
                "attack_type": "server_error",
                "severity": "Critical",
                "entity": "192.0.2.99",
                "evidence_lines": [9],
                "reason": "Routine application failure.",
                "action": "Review application health.",
            }

            with patch.object(db, "DB_PATH", database_path):
                db.initialize_database()
                db.create_job(job_id, log_path.name, str(log_path))
                with db.connect() as connection:
                    connection.execute(
                        """INSERT INTO entity_ledger_items
                        (job_id, entity_type, entity_value, failed_login_count, successful_login_count,
                         first_line, last_line, distinct_paths_json, status_counts_json,
                         sensitive_path_hits, success_after_repeated_failures_line)
                        VALUES (?, 'client_ip', ?, 3, 1, 1, 4, '[]', '{}', 0, 4)""",
                        (job_id, "192.0.2.9"),
                    )
                    connection.executemany(
                        "INSERT INTO event_id_lines(job_id, event_id, line_number) VALUES (?, ?, ?)",
                        [(job_id, "duplicate-event", 2), (job_id, "duplicate-event", 3)],
                    )
                    connection.execute(
                        "INSERT INTO benign_lines(job_id, line_number, reason) VALUES (?, 9, ?)",
                        (job_id, "ordinary application error"),
                    )
                    findings = {"findings": [brute_a, brute_b, ordinary_error]}
                    connection.execute(
                        """INSERT INTO chunks
                        (job_id, chunk_index, log_text, ledger_text, token_count, status, result_json)
                        VALUES (?, 0, '', '', 0, 'completed', ?)""",
                        (job_id, json.dumps(findings)),
                    )

                report = analyzer._merge_report(job_id)

            self.assertEqual(len(report["findings"]), 1)
            finding = report["findings"][0]
            self.assertEqual(finding["attack_type"], "account_compromise")
            self.assertEqual(finding["severity"], "high")
            self.assertEqual(finding["entity"], "192.0.2.9")
            self.assertEqual(finding["evidence_lines"], [2, 4])
            self.assertIn("successfully after at least three failures", finding["reason"])
            self.assertTrue(finding["action"])
            self.assertEqual(
                set(finding), {"attack_type", "severity", "entity", "evidence_lines", "reason", "action"}
            )


if __name__ == "__main__":
    unittest.main()
