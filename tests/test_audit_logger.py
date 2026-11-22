"""Tests for PhishGuard persistent audit logging."""

from types import SimpleNamespace

import pytest

from src.schemas import ActionEnum, VerdictEnum
from src.reporting import audit_logger


@pytest.fixture
def audit_database(tmp_path, monkeypatch):
    """Use an isolated temporary SQLite database."""

    monkeypatch.setattr(
        audit_logger,
        "AUDIT_DB_PATH",
        tmp_path / "test_audit.db",
    )

    audit_logger.initialize_audit_db()

    return tmp_path / "test_audit.db"


@pytest.fixture
def sample_report():
    """Create a valid report for audit testing."""

    return SimpleNamespace(
        message_id="test-message-001",
        composite_risk_score=75.0,
        verdict=VerdictEnum.MALICIOUS,
        action=ActionEnum.QUARANTINE,
        analysis_audit=[
            "Email analysis started",
            "URL analysis completed",
            "Deterministic risk scoring completed",
            "Email analysis completed",
        ],
    )


def test_audit_database_initializes(audit_database):
    """Audit table should be created successfully."""

    import sqlite3

    with sqlite3.connect(audit_database) as conn:
        result = conn.execute(
            """
            SELECT name FROM sqlite_master
            WHERE type='table' AND name='audit_logs'
            """
        ).fetchone()

    assert result is not None


def test_log_analysis_saves_record(
    audit_database,
    sample_report,
):
    """A completed analysis should be persisted."""

    record_id = audit_logger.log_analysis(sample_report)

    assert isinstance(record_id, int)
    assert record_id > 0

    history = audit_logger.get_audit_history(
        "test-message-001"
    )

    assert len(history) == 1
    assert history[0]["risk_score"] == 75.0
    assert history[0]["verdict"] == "malicious"
    assert history[0]["action"] == "quarantine"


def test_audit_history_preserves_repeated_analyses(
    audit_database,
    sample_report,
):
    """Repeated analyses should create separate records."""

    first_id = audit_logger.log_analysis(sample_report)

    sample_report.composite_risk_score = 85.0

    second_id = audit_logger.log_analysis(sample_report)

    history = audit_logger.get_audit_history(
        "test-message-001"
    )

    assert first_id != second_id
    assert len(history) == 2

    assert history[0]["risk_score"] == 85.0
    assert history[1]["risk_score"] == 75.0


def test_audit_history_returns_correct_message(
    audit_database,
    sample_report,
):
    """History should only contain the requested message."""

    audit_logger.log_analysis(sample_report)

    history = audit_logger.get_audit_history(
        "different-message"
    )

    assert history == []


def test_audit_events_are_stored_as_list(
    audit_database,
    sample_report,
):
    """Stored JSON events should be decoded during retrieval."""

    audit_logger.log_analysis(sample_report)

    history = audit_logger.get_audit_history(
        "test-message-001"
    )

    events = history[0]["audit_events"]

    assert isinstance(events, list)
    assert "Email analysis started" in events
    assert "Email analysis completed" in events


def test_invalid_message_id_is_rejected(
    audit_database,
    sample_report,
):
    sample_report.message_id = ""

    with pytest.raises(ValueError):
        audit_logger.log_analysis(sample_report)


def test_invalid_risk_score_is_rejected(
    audit_database,
    sample_report,
):
    sample_report.composite_risk_score = 150

    with pytest.raises(ValueError):
        audit_logger.log_analysis(sample_report)


def test_invalid_verdict_is_rejected(
    audit_database,
    sample_report,
):
    sample_report.verdict = "unknown"

    with pytest.raises(ValueError):
        audit_logger.log_analysis(sample_report)


def test_invalid_action_is_rejected(
    audit_database,
    sample_report,
):
    sample_report.action = "execute"

    with pytest.raises(ValueError):
        audit_logger.log_analysis(sample_report)


def test_invalid_history_limit_is_rejected(
    audit_database,
):
    with pytest.raises(ValueError):
        audit_logger.get_audit_history(
            "test-message-001",
            limit=1000,
        )


def test_empty_message_id_history_is_rejected(
    audit_database,
):
    with pytest.raises(ValueError):
        audit_logger.get_audit_history("")


def test_audit_events_are_limited(
    audit_database,
    sample_report,
):
    sample_report.analysis_audit = [
        f"Event {i}" for i in range(150)
    ]

    audit_logger.log_analysis(sample_report)

    history = audit_logger.get_audit_history(
        "test-message-001"
    )

    assert len(history[0]["audit_events"]) == 100


def test_non_string_audit_events_are_ignored(
    audit_database,
    sample_report,
):
    sample_report.analysis_audit = [
        "Email analysis started",
        None,
        123,
        "Email analysis completed",
    ]

    audit_logger.log_analysis(sample_report)

    history = audit_logger.get_audit_history(
        "test-message-001"
    )

    assert history[0]["audit_events"] == [
        "Email analysis started",
        "Email analysis completed",
    ]