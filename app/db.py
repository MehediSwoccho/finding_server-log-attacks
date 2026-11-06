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
                started_at TEXT,
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
                call_started_at TEXT,
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
            CREATE TABLE IF NOT EXISTS entity_ledger_items (
                job_id TEXT NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
                entity_type TEXT NOT NULL CHECK (entity_type IN ('client_ip', 'username')),
                entity_value TEXT NOT NULL,
                failed_login_count INTEGER NOT NULL DEFAULT 0,
                successful_login_count INTEGER NOT NULL DEFAULT 0,
                first_line INTEGER NOT NULL,
                last_line INTEGER NOT NULL,
                distinct_paths_json TEXT NOT NULL DEFAULT '[]',
                status_counts_json TEXT NOT NULL DEFAULT '{}',
                sensitive_path_hits INTEGER NOT NULL DEFAULT 0,
                success_after_repeated_failures_line INTEGER,
                PRIMARY KEY (job_id, entity_type, entity_value)
            );
            CREATE TABLE IF NOT EXISTS event_id_lines (
                job_id TEXT NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
                event_id TEXT NOT NULL,
                line_number INTEGER NOT NULL,
                PRIMARY KEY (job_id, event_id, line_number)
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
        _ensure_column(connection, "jobs", "started_at", "TEXT")
        _ensure_column(connection, "chunks", "call_started_at", "TEXT")
        _ensure_column(
            connection,
            "entity_ledger_items",
            "success_after_repeated_failures_line",
            "INTEGER",
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


def _ensure_column(connection: sqlite3.Connection, table: str, column: str, declaration: str) -> None:
    columns = {row["name"] for row in connection.execute(f"PRAGMA table_info({table})")}
    if column not in columns:
        connection.execute(f"ALTER TABLE {table} ADD COLUMN {column} {declaration}")


def get_job(job_id: str) -> sqlite3.Row | None:
    with connect() as connection:
        return connection.execute("SELECT * FROM jobs WHERE id = ?", (job_id,)).fetchone()


def set_job(job_id: str, **values: Any) -> None:
    if not values:
        return
    allowed = {"status", "prepared", "total_chunks", "error", "report_json", "started_at"}
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
            """SELECT SUM(CASE WHEN status = 'completed' THEN 1 ELSE 0 END) AS done,
                      SUM(CASE WHEN status = 'failed' THEN 1 ELSE 0 END) AS failed
               FROM chunks WHERE job_id = ?""",
            (job_id,),
        ).fetchone()
        active = connection.execute(
            """SELECT chunk_index, duration_ms, call_started_at, error, status
               FROM chunks WHERE job_id = ? AND status = 'running'
               ORDER BY chunk_index DESC LIMIT 1""",
            (job_id,),
        ).fetchone()
        if active is None:
            active = connection.execute(
                """SELECT chunk_index, duration_ms, call_started_at, error, status
                   FROM chunks WHERE job_id = ? AND status IN ('completed', 'failed')
                   ORDER BY chunk_index DESC LIMIT 1""",
                (job_id,),
            ).fetchone()
        now = datetime.now(timezone.utc)
        elapsed_seconds = _elapsed_seconds(job["started_at"], now)
        call_elapsed_seconds = _elapsed_seconds(active["call_started_at"], now) if active else None
        return {
            "job_id": job_id,
            "filename": job["filename"],
            "status": job["status"],
            "total_chunks": job["total_chunks"],
            "completed_chunks": row["done"] or 0,
            "failed_chunks": row["failed"] or 0,
            "current_chunk": (active["chunk_index"] + 1) if active else None,
            "call_duration_ms": active["duration_ms"] if active else None,
            "call_elapsed_seconds": call_elapsed_seconds,
            "elapsed_seconds": elapsed_seconds,
            "call_error": active["error"] if active else None,
            "error": job["error"],
            "report_available": bool(job["report_json"]),
        }


def _elapsed_seconds(started_at: str | None, now: datetime) -> float | None:
    if not started_at:
        return None
    try:
        started = datetime.fromisoformat(started_at)
        if started.tzinfo is None:
            started = started.replace(tzinfo=timezone.utc)
        return max(0.0, round((now - started).total_seconds(), 1))
    except (TypeError, ValueError):
        return None


def decode_json(value: str, default: Any) -> Any:
    try:
        return json.loads(value)
    except (TypeError, json.JSONDecodeError):
        return default
