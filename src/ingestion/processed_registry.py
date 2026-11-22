"""SQLite registry for tracking processed Gmail messages."""

import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DB_PATH = PROJECT_ROOT / "data" / "cache.db"

PROCESSING_TIMEOUT_MINUTES = 15


def _connect():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)

    connection = sqlite3.connect(str(DB_PATH), timeout=10)
    connection.row_factory = sqlite3.Row
    return connection


def initialize_registry():
    """Create the processed-message table if it does not exist."""

    with _connect() as connection:
        connection.execute("""
            CREATE TABLE IF NOT EXISTS processed_messages (
                message_id TEXT PRIMARY KEY,
                status TEXT NOT NULL,
                claimed_at TEXT,
                processed_at TEXT,
                verdict TEXT,
                action TEXT,
                risk_score REAL
            )
        """)


def claim_message(message_id: str) -> bool:
    """
    Atomically claim an email for analysis.

    Returns False if it is already completed or currently being
    processed by another runner.
    """

    if not isinstance(message_id, str) or not message_id.strip():
        raise ValueError("message_id must be a non-empty string")

    initialize_registry()

    now = datetime.now(timezone.utc)
    now_text = now.isoformat()
    timeout = now - timedelta(minutes=PROCESSING_TIMEOUT_MINUTES)

    with _connect() as connection:
        connection.execute("BEGIN IMMEDIATE")

        row = connection.execute(
            "SELECT status, claimed_at FROM processed_messages "
            "WHERE message_id = ?",
            (message_id,),
        ).fetchone()

        if row is None:
            connection.execute(
                """
                INSERT INTO processed_messages
                (message_id, status, claimed_at)
                VALUES (?, 'processing', ?)
                """,
                (message_id, now_text),
            )
            return True

        if row["status"] == "completed":
            return False

        if row["status"] == "processing" and row["claimed_at"]:
            claimed_at = datetime.fromisoformat(row["claimed_at"])

            if claimed_at > timeout:
                return False

        connection.execute(
            """
            UPDATE processed_messages
            SET status = 'processing',
                claimed_at = ?,
                processed_at = NULL,
                verdict = NULL,
                action = NULL,
                risk_score = NULL
            WHERE message_id = ?
            """,
            (now_text, message_id),
        )

        return True


def mark_completed(message_id: str, report):
    """Mark an email as successfully analyzed."""

    if not isinstance(message_id, str) or not message_id.strip():
        raise ValueError("message_id must be a non-empty string")

    score = float(report.composite_risk_score)

    if not 0 <= score <= 100:
        raise ValueError("Invalid risk score")

    initialize_registry()

    with _connect() as connection:
        connection.execute(
            """
            UPDATE processed_messages
            SET status = 'completed',
                processed_at = ?,
                verdict = ?,
                action = ?,
                risk_score = ?
            WHERE message_id = ?
            """,
            (
                datetime.now(timezone.utc).isoformat(),
                report.verdict.value,
                report.action.value,
                score,
                message_id,
            ),
        )


def mark_failed(message_id: str):
    """Mark a failed analysis so it can be retried later."""

    initialize_registry()

    with _connect() as connection:
        connection.execute(
            """
            UPDATE processed_messages
            SET status = 'failed',
                claimed_at = NULL
            WHERE message_id = ?
            """,
            (message_id,),
        )


def is_processed(message_id: str) -> bool:
    """Check whether an email has already been successfully analyzed."""

    initialize_registry()

    with _connect() as connection:
        row = connection.execute(
            """
            SELECT status FROM processed_messages
            WHERE message_id = ?
            """,
            (message_id,),
        ).fetchone()

    return row is not None and row["status"] == "completed"