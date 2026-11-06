from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from typing import Any

from .config import DB_PATH


class _ClosingConnection(sqlite3.Connection):
    def __exit__(self, exc_type: Any, exc_value: Any, traceback: Any) -> bool:
        try:
            return bool(super().__exit__(exc_type, exc_value, traceback))
        finally:
            self.close()


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def connect() -> sqlite3.Connection:
    connection = sqlite3.connect(DB_PATH, timeout=30, factory=_ClosingConnection)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


def initialize_database() -> None:
    with connect() as connection:
        connection.execute("PRAGMA journal_mode = WAL")
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS jobs (
                id TEXT PRIMARY KEY,
                filename TEXT NOT NULL,
                file_path TEXT NOT NULL,
                status TEXT NOT NULL,
                prepared INTEGER NOT NULL DEFAULT 0,
                total_chunks INTEGER NOT NULL DEFAULT 0,
                error TEXT,
                report_json TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS chunks (
                job_id TEXT NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
                chunk_index INTEGER NOT NULL,
                log_text TEXT NOT NULL,
                ledger_text TEXT NOT NULL,
                token_count INTEGER NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending',
                result_json TEXT,
                duration_ms REAL,
                error TEXT,
                PRIMARY KEY (job_id, chunk_index)
            );
            CREATE TABLE IF NOT EXISTS entity_ledger (
                job_id TEXT NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
                client_ip TEXT NOT NULL,
                failed_count INTEGER NOT NULL DEFAULT 0,
                successful_count INTEGER NOT NULL DEFAULT 0,
                first_line INTEGER NOT NULL,
                last_line INTEGER NOT NULL,
                sensitive_paths_json TEXT NOT NULL DEFAULT '[]',
                status_counts_json TEXT NOT NULL DEFAULT '{}',
                compromise_after_fail INTEGER NOT NULL DEFAULT 0,
                success_line INTEGER,
                PRIMARY KEY (job_id, client_ip)
            );
            CREATE TABLE IF NOT EXISTS rule_findings (
                job_id TEXT NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
                attack_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                entity TEXT NOT NULL,
                evidence_line INTEGER NOT NULL,
                reason TEXT NOT NULL,
                action TEXT NOT NULL,
                PRIMARY KEY (job_id, attack_type, entity, evidence_line)
            );
            CREATE TABLE IF NOT EXISTS benign_lines (
                job_id TEXT NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
                line_number INTEGER NOT NULL,
                reason TEXT NOT NULL,
                PRIMARY KEY (job_id, line_number)
            );
            """
        )
        connection.execute(
            "UPDATE jobs SET status = 'paused', updated_at = ? WHERE status = 'running'",
            (now_iso(),),
        )


def create_job(job_id: str, filename: str, file_path: str) -> None:
    with connect() as connection:
        connection.execute(
            "INSERT INTO jobs(id, filename, file_path, status, created_at, updated_at) VALUES (?, ?, ?, 'uploaded', ?, ?)",
            (job_id, filename, file_path, now_iso(), now_iso()),
        )


def get_job(job_id: str) -> sqlite3.Row | None:
    with connect() as connection:
        return connection.execute("SELECT * FROM jobs WHERE id = ?", (job_id,)).fetchone()


def set_job(job_id: str, **values: Any) -> None:
    if not values:
        return
    allowed = {"status", "prepared", "total_chunks", "error", "report_json"}
    if not set(values).issubset(allowed):
        raise ValueError("Unsupported job field")
    values["updated_at"] = now_iso()
    assignments = ", ".join(f"{key} = ?" for key in values)
    with connect() as connection:
        connection.execute(
            f"UPDATE jobs SET {assignments} WHERE id = ?",
            (*values.values(), job_id),
        )


def progress(job_id: str) -> dict[str, Any] | None:
    with connect() as connection:
        job = connection.execute("SELECT * FROM jobs WHERE id = ?", (job_id,)).fetchone()
        if job is None:
            return None
        row = connection.execute(
            "SELECT COUNT(*) AS done FROM chunks WHERE job_id = ? AND status = 'completed'",
            (job_id,),
        ).fetchone()
        active = connection.execute(
            "SELECT chunk_index, duration_ms, status FROM chunks WHERE job_id = ? AND status IN ('running', 'completed') ORDER BY chunk_index DESC LIMIT 1",
            (job_id,),
        ).fetchone()
        return {
            "job_id": job_id,
            "filename": job["filename"],
            "status": job["status"],
            "total_chunks": job["total_chunks"],
            "completed_chunks": row["done"],
            "current_chunk": (active["chunk_index"] + 1) if active else None,
            "call_duration_ms": active["duration_ms"] if active else None,
            "error": job["error"],
            "report_available": bool(job["report_json"]),
        }


def decode_json(value: str, default: Any) -> Any:
    try:
        return json.loads(value)
    except (TypeError, json.JSONDecodeError):
        return default
