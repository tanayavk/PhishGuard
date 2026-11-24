"""Persistent SQLite audit logging for PhishGuard."""

import json
import math
import sqlite3

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from src.ingestion.processed_registry import _connect


PROJECT_ROOT = Path(__file__).resolve().parents[2]
AUDIT_DB_PATH = PROJECT_ROOT / "data" / "cache.db"

MAX_AUDIT_EVENTS = 100
MAX_EVENT_LENGTH = 500


def _get_connection() -> sqlite3.Connection:
    """Create a connection to the existing project database."""

    AUDIT_DB_PATH.parent.mkdir(parents=True, exist_ok=True)

    conn = sqlite3.connect(
        AUDIT_DB_PATH,
        timeout=10,
    )

    conn.row_factory = sqlite3.Row

    return conn


def initialize_audit_db() -> None:
    """Create the audit table and index if they do not exist."""

    with _get_connection() as conn:

        conn.execute("""
            CREATE TABLE IF NOT EXISTS audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                message_id TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                risk_score REAL NOT NULL,
                verdict TEXT NOT NULL,
                action TEXT NOT NULL,
                audit_events TEXT NOT NULL
            )
        """)

        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_audit_message_id
            ON audit_logs(message_id)
        """)

        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_audit_timestamp
            ON audit_logs(timestamp)
        """)


def _validate_report(report: Any) -> None:
    """Validate report fields before persistence."""

    if not isinstance(report.message_id, str) or not report.message_id.strip():
        raise ValueError("Invalid message ID")

    score = report.composite_risk_score

    if (
        not isinstance(score, (int, float))
        or isinstance(score, bool)
        or not math.isfinite(score)
        or not 0 <= score <= 100
    ):
        raise ValueError("Invalid risk score")

    if report.verdict not in {
        "safe",
        "suspicious",
        "malicious",
        "inconclusive",
    }:
        raise ValueError("Invalid verdict")

    if report.action not in {
        "allow",
        "warn",
        "block",
        "quarantine",
    }:
        raise ValueError("Invalid action")


def _prepare_events(events: list[str]) -> list[str]:
    """Sanitize audit events before storage."""

    if not isinstance(events, list):
        raise ValueError("Audit events must be a list")

    sanitized = []

    for event in events[:MAX_AUDIT_EVENTS]:

        if not isinstance(event, str):
            continue

        event = " ".join(event.split())
        event = event[:MAX_EVENT_LENGTH]

        if event and event not in sanitized:
            sanitized.append(event)

    return sanitized


def log_analysis(report: Any) -> int:
    """Persist one completed email analysis.

    Each analysis creates a separate record, preserving history
    when the same email is analyzed multiple times.
    """

    _validate_report(report)

    events = _prepare_events(
        report.analysis_audit
    )

    timestamp = datetime.now(timezone.utc).isoformat()

    initialize_audit_db()

    with _get_connection() as conn:

        cursor = conn.execute(
            """
            INSERT INTO audit_logs (
                message_id,
                timestamp,
                risk_score,
                verdict,
                action,
                audit_events
            )
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                report.message_id,
                timestamp,
                float(report.composite_risk_score),
                report.verdict.value,
                report.action.value,
                json.dumps(events),
            ),
        )

        return cursor.lastrowid


def get_audit_history(
    message_id: str,
    limit: int = 50,
) -> list[dict[str, Any]]:
    """Retrieve previous audit records for an email."""

    if not isinstance(message_id, str) or not message_id.strip():
        raise ValueError("A valid message ID is required")

    if (
        not isinstance(limit, int)
        or isinstance(limit, bool)
        or not 1 <= limit <= 500
    ):
        raise ValueError("Limit must be between 1 and 500")

    initialize_audit_db()

    with _get_connection() as conn:

        rows = conn.execute(
            """
            SELECT
                id,
                message_id,
                timestamp,
                risk_score,
                verdict,
                action,
                audit_events
            FROM audit_logs
            WHERE message_id = ?
            ORDER BY id DESC
            LIMIT ?
            """,
            (message_id, limit),
        ).fetchall()

    history = []

    for row in rows:

        record = dict(row)

        try:
            record["audit_events"] = json.loads(
                record["audit_events"]
            )
        except (json.JSONDecodeError, TypeError):
            record["audit_events"] = []

        history.append(record)

    return history

def list_audit_history(
    limit: int = 100,
    offset: int = 0,
    message_id: str | None = None
):
    """Retrieve audit records with optional message filtering."""

    if not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= 500:
        raise ValueError("limit must be between 1 and 500")

    if not isinstance(offset, int) or isinstance(offset, bool) or offset < 0:
        raise ValueError("offset must be non-negative")

    if message_id is not None:
        if not isinstance(message_id, str) or not message_id.strip():
            raise ValueError("message_id must be a non-empty string")

    with _connect() as connection:

        connection.execute("""
            CREATE TABLE IF NOT EXISTS audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                message_id TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                risk_score REAL NOT NULL,
                verdict TEXT NOT NULL,
                action TEXT NOT NULL,
                audit_events TEXT NOT NULL
            )
        """)

        if message_id:
            total = connection.execute(
                "SELECT COUNT(*) FROM audit_logs WHERE message_id = ?",
                (message_id,)
            ).fetchone()[0]

            rows = connection.execute(
                """
                SELECT id, message_id, timestamp, risk_score,
                       verdict, action, audit_events
                FROM audit_logs
                WHERE message_id = ?
                ORDER BY timestamp DESC
                LIMIT ? OFFSET ?
                """,
                (message_id, limit, offset)
            ).fetchall()

        else:
            total = connection.execute(
                "SELECT COUNT(*) FROM audit_logs"
            ).fetchone()[0]

            rows = connection.execute(
                """
                SELECT id, message_id, timestamp, risk_score,
                       verdict, action, audit_events
                FROM audit_logs
                ORDER BY timestamp DESC
                LIMIT ? OFFSET ?
                """,
                (limit, offset)
            ).fetchall()

    records = []

    for row in rows:
        record = dict(row)

        try:
            record["audit_events"] = json.loads(record["audit_events"])
        except (TypeError, json.JSONDecodeError):
            record["audit_events"] = []

        records.append(record)

    return {
        "total": total,
        "limit": limit,
        "offset": offset,
        "message_id": message_id,
        "audit_logs": records,
    }