"""Persistent storage for PhishGuard security reports."""

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DB_PATH = PROJECT_ROOT / "data" / "cache.db"


def _connect():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)

    connection = sqlite3.connect(str(DB_PATH), timeout=10)
    connection.row_factory = sqlite3.Row
    return connection


def initialize_report_store():
    """Initialize the security reports table."""

    with _connect() as connection:
        connection.execute("""
            CREATE TABLE IF NOT EXISTS security_reports (
                message_id TEXT PRIMARY KEY,
                analyzed_at TEXT NOT NULL,
                sender TEXT NOT NULL,
                subject TEXT NOT NULL,
                verdict TEXT NOT NULL,
                action TEXT NOT NULL,
                risk_score REAL NOT NULL,
                report_json TEXT NOT NULL
            )
        """)

        connection.execute("""
            CREATE INDEX IF NOT EXISTS idx_reports_verdict
            ON security_reports(verdict)
        """)

        connection.execute("""
            CREATE INDEX IF NOT EXISTS idx_reports_analyzed_at
            ON security_reports(analyzed_at)
        """)


def save_report(report):
    """
    Save or update a security report.

    Each Gmail message has one latest report.
    Reanalysis updates the existing record instead of
    creating duplicate dashboard entries.
    """

    if not report.message_id or not report.message_id.strip():
        raise ValueError("Report must have a valid message ID")

    score = float(report.composite_risk_score)

    if not 0 <= score <= 100:
        raise ValueError("Invalid risk score")

    report_data = report.model_dump(mode="json")

    analyzed_at = datetime.now(timezone.utc).isoformat()

    initialize_report_store()

    with _connect() as connection:
        connection.execute(
            """
            INSERT INTO security_reports (
                message_id,
                analyzed_at,
                sender,
                subject,
                verdict,
                action,
                risk_score,
                report_json
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)

            ON CONFLICT(message_id) DO UPDATE SET
                analyzed_at = excluded.analyzed_at,
                sender = excluded.sender,
                subject = excluded.subject,
                verdict = excluded.verdict,
                action = excluded.action,
                risk_score = excluded.risk_score,
                report_json = excluded.report_json
            """,
            (
                report.message_id,
                analyzed_at,
                report.sender,
                report.subject,
                report.verdict.value,
                report.action.value,
                score,
                json.dumps(report_data),
            ),
        )

    return report.message_id


def get_report(message_id: str):
    """Retrieve a security report by Gmail message ID."""

    if not isinstance(message_id, str) or not message_id.strip():
        raise ValueError("message_id must be a non-empty string")

    initialize_report_store()

    with _connect() as connection:
        row = connection.execute(
            """
            SELECT report_json
            FROM security_reports
            WHERE message_id = ?
            """,
            (message_id,),
        ).fetchone()

    if row is None:
        return None

    return json.loads(row["report_json"])


def list_reports(
    limit: int = 50,
    offset: int = 0,
    verdict: str | None = None,
):
    """Retrieve paginated security reports."""

    if (
        not isinstance(limit, int)
        or isinstance(limit, bool)
        or not 1 <= limit <= 500
    ):
        raise ValueError("limit must be between 1 and 500")

    if (
        not isinstance(offset, int)
        or isinstance(offset, bool)
        or offset < 0
    ):
        raise ValueError("offset must be a non-negative integer")

    valid_verdicts = {
        "safe",
        "suspicious",
        "malicious",
        "inconclusive",
    }

    if verdict is not None and verdict not in valid_verdicts:
        raise ValueError("Invalid verdict filter")

    initialize_report_store()

    query = """
        SELECT message_id, analyzed_at, sender, subject,
               verdict, action, risk_score
        FROM security_reports
    """

    parameters = []

    if verdict is not None:
        query += " WHERE verdict = ?"
        parameters.append(verdict)

    query += " ORDER BY analyzed_at DESC LIMIT ? OFFSET ?"

    parameters.extend([limit, offset])

    with _connect() as connection:
        rows = connection.execute(
            query,
            parameters,
        ).fetchall()

    return [dict(row) for row in rows]


def count_reports():
    """Return the total number of stored reports."""

    initialize_report_store()

    with _connect() as connection:
        row = connection.execute(
            "SELECT COUNT(*) AS total FROM security_reports"
        ).fetchone()

    return row["total"]

def get_dashboard_stats():
    """Generate statistics for the PhishGuard dashboard."""

    initialize_report_store()

    with _connect() as connection:

        # Count reports by verdict.
        rows = connection.execute("""
            SELECT verdict, COUNT(*) AS total
            FROM security_reports
            GROUP BY verdict
        """).fetchall()

        counts = {
            "safe": 0,
            "suspicious": 0,
            "malicious": 0,
            "inconclusive": 0,
        }

        for row in rows:
            if row["verdict"] in counts:
                counts[row["verdict"]] = row["total"]

        total = sum(counts.values())

        # Retrieve the five most recent analyses.
        recent_rows = connection.execute("""
            SELECT message_id, sender, subject,
                   verdict, action, risk_score, analyzed_at
            FROM security_reports
            ORDER BY analyzed_at DESC
            LIMIT 5
        """).fetchall()

    malicious = counts["malicious"]
    suspicious = counts["suspicious"]

    threat_percentage = (
        ((malicious + suspicious) / total) * 100
        if total > 0
        else 0.0
    )

    return {
        "total_scanned": total,
        "safe": counts["safe"],
        "suspicious": suspicious,
        "malicious": malicious,
        "inconclusive": counts["inconclusive"],
        "threats_detected": malicious + suspicious,
        "threat_percentage": round(threat_percentage, 2),
        "recent_activity": [
            dict(row) for row in recent_rows
        ],
    }