"""Persistance SQLite des analyses INPA, sans conservation des paquets."""

import json
import os
import sqlite3
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path


def utc_now():
    return datetime.now(timezone.utc).isoformat()


class AnalysisHistory:
    """Enregistre les sessions de capture et leurs résultats agrégés."""

    def __init__(self, database_path: Path | str):
        self.database_path = Path(database_path)

    def _connect(self):
        self.database_path.parent.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(self.database_path, timeout=10)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA busy_timeout = 10000")
        return connection

    @contextmanager
    def _connection(self):
        connection = self._connect()
        try:
            yield connection
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def initialize(self):
        with self._connection() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS analyses (
                    id TEXT PRIMARY KEY,
                    owner_id TEXT,
                    started_at TEXT NOT NULL,
                    ended_at TEXT,
                    interface TEXT,
                    status TEXT NOT NULL CHECK(status IN ('in_progress', 'completed', 'interrupted')),
                    packet_count INTEGER NOT NULL DEFAULT 0,
                    duration_seconds REAL,
                    result_json TEXT
                )
                """
            )
            columns = {row["name"] for row in connection.execute("PRAGMA table_info(analyses)")}
            if "owner_id" not in columns:
                connection.execute("ALTER TABLE analyses ADD COLUMN owner_id TEXT")
            connection.execute(
                "CREATE INDEX IF NOT EXISTS analyses_started_at_idx ON analyses(started_at DESC)"
            )
            connection.execute("CREATE INDEX IF NOT EXISTS analyses_owner_started_idx ON analyses(owner_id, started_at DESC)")

    def mark_interrupted_sessions(self):
        with self._connection() as connection:
            connection.execute(
                """UPDATE analyses SET status = 'interrupted', ended_at = ?
                   WHERE status = 'in_progress'""",
                (utc_now(),),
            )

    def start(self, interface: str | None, owner_id: str | None = None) -> str:
        analysis_id = uuid.uuid4().hex
        with self._connection() as connection:
            connection.execute(
                """INSERT INTO analyses (id, owner_id, started_at, interface, status)
                   VALUES (?, ?, ?, ?, 'in_progress')""",
                (analysis_id, owner_id, utc_now(), interface),
            )
        return analysis_id

    def finish(self, analysis_id: str, report: dict) -> bool:
        summary = report.get("summary", {})
        packet_count = int(summary.get("captured_packet_count", summary.get("packet_count", 0)))
        if packet_count <= 0:
            self.delete(analysis_id)
            return False

        metadata = report.get("capture", {})
        ended_at = metadata.get("ended_at") or utc_now()
        duration = metadata.get("duration_seconds")
        result_json = json.dumps(report, ensure_ascii=False, separators=(",", ":"))
        with self._connection() as connection:
            cursor = connection.execute(
                """UPDATE analyses
                   SET ended_at = ?, status = 'completed', packet_count = ?,
                       duration_seconds = ?, result_json = ?
                   WHERE id = ? AND status = 'in_progress'""",
                (ended_at, packet_count, duration, result_json, analysis_id),
            )
        return cursor.rowcount == 1

    def update_progress(self, analysis_id: str, packet_count: int, duration_seconds: float | None):
        with self._connection() as connection:
            connection.execute(
                """UPDATE analyses SET packet_count = ?, duration_seconds = ?
                   WHERE id = ? AND status = 'in_progress'""",
                (max(0, int(packet_count)), duration_seconds, analysis_id),
            )

    def delete(self, analysis_id: str):
        with self._connection() as connection:
            connection.execute("DELETE FROM analyses WHERE id = ?", (analysis_id,))

    def list(self, limit: int = 50, owner_id: str | None = None) -> list[dict]:
        with self._connection() as connection:
            if owner_id is None:
                query = """SELECT id, started_at, ended_at, interface, status,
                          packet_count, duration_seconds, result_json
                   FROM analyses WHERE owner_id IS NULL ORDER BY started_at DESC LIMIT ?"""
                params = (max(1, min(int(limit), 200)),)
            else:
                query = """SELECT id, started_at, ended_at, interface, status,
                          packet_count, duration_seconds, result_json
                   FROM analyses WHERE owner_id = ? ORDER BY started_at DESC LIMIT ?"""
                params = (owner_id, max(1, min(int(limit), 200)))
            rows = connection.execute(
                query, params,
            ).fetchall()
        return [self._row_to_dict(row, include_result=False) for row in rows]

    def get(self, analysis_id: str, owner_id: str | None = None) -> dict | None:
        with self._connection() as connection:
            if owner_id is None:
                query = """SELECT id, started_at, ended_at, interface, status,
                          packet_count, duration_seconds, result_json
                   FROM analyses WHERE id = ? AND owner_id IS NULL"""
                params = (analysis_id,)
            else:
                query = """SELECT id, started_at, ended_at, interface, status,
                          packet_count, duration_seconds, result_json
                   FROM analyses WHERE id = ? AND owner_id = ?"""
                params = (analysis_id, owner_id)
            row = connection.execute(query, params).fetchone()
        return self._row_to_dict(row, include_result=True) if row else None

    @staticmethod
    def _row_to_dict(row, include_result: bool) -> dict:
        result = {
            "id": row["id"],
            "started_at": row["started_at"],
            "ended_at": row["ended_at"],
            "interface": row["interface"],
            "status": row["status"],
            "packet_count": row["packet_count"],
            "duration_seconds": row["duration_seconds"],
        }
        report = json.loads(row["result_json"]) if row["result_json"] else None
        if report:
            observations = report.get("observations", [])
            if observations:
                result["main_observation"] = {
                    "title": observations[0].get("title"),
                    "observed_fact": observations[0].get("observed_fact"),
                }
        if include_result and report:
            result["report"] = report
        return result


def default_history_path(project_root: Path) -> Path:
    configured = os.getenv("INPA_HISTORY_DB")
    if not configured:
        return project_root / "data" / "inpa_history.sqlite3"
    path = Path(configured)
    return path if path.is_absolute() else project_root / path
