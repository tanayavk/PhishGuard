import pytest
from types import SimpleNamespace

from src.schemas import VerdictEnum, ActionEnum
from src.reporting import report_store


@pytest.fixture
def temporary_database(tmp_path, monkeypatch):
    monkeypatch.setattr(
        report_store,
        "DB_PATH",
        tmp_path / "test_reports.db",
    )

    report_store.initialize_report_store()


@pytest.fixture
def sample_report():
    return SimpleNamespace(
        message_id="email-001",
        sender="sender@example.com",
        subject="Test email",
        verdict=VerdictEnum.MALICIOUS,
        action=ActionEnum.QUARANTINE,
        composite_risk_score=85.0,
        model_dump=lambda mode: {
            "message_id": "email-001",
            "sender": "sender@example.com",
            "subject": "Test email",
            "verdict": "malicious",
            "action": "quarantine",
            "composite_risk_score": 85.0,
            "evidence": ["Suspicious URL detected"],
        },
    )


def test_initialize_report_store(temporary_database):
    assert report_store.count_reports() == 0


def test_save_report(temporary_database, sample_report):
    result = report_store.save_report(sample_report)

    assert result == "email-001"
    assert report_store.count_reports() == 1


def test_get_report(temporary_database, sample_report):
    report_store.save_report(sample_report)

    result = report_store.get_report("email-001")

    assert result["verdict"] == "malicious"
    assert result["action"] == "quarantine"


def test_get_missing_report(temporary_database):
    assert report_store.get_report("unknown") is None


def test_list_reports(temporary_database, sample_report):
    report_store.save_report(sample_report)

    results = report_store.list_reports()

    assert len(results) == 1
    assert results[0]["message_id"] == "email-001"


def test_filter_reports_by_verdict(
    temporary_database,
    sample_report,
):
    report_store.save_report(sample_report)

    results = report_store.list_reports(
        verdict="malicious"
    )

    assert len(results) == 1


def test_invalid_verdict_filter(temporary_database):
    with pytest.raises(ValueError):
        report_store.list_reports(verdict="unknown")


def test_invalid_limit(temporary_database):
    with pytest.raises(ValueError):
        report_store.list_reports(limit=1000)


def test_invalid_offset(temporary_database):
    with pytest.raises(ValueError):
        report_store.list_reports(offset=-1)


def test_duplicate_message_updates_existing_report(
    temporary_database,
    sample_report,
):
    report_store.save_report(sample_report)
    report_store.save_report(sample_report)

    assert report_store.count_reports() == 1


def test_invalid_message_id(temporary_database):
    report = SimpleNamespace(message_id="")

    with pytest.raises(ValueError):
        report_store.save_report(report)

def test_dashboard_stats_empty_database(temporary_database):
    stats = report_store.get_dashboard_stats()

    assert stats["total_scanned"] == 0
    assert stats["safe"] == 0
    assert stats["malicious"] == 0
    assert stats["suspicious"] == 0
    assert stats["inconclusive"] == 0
    assert stats["threat_percentage"] == 0.0
    assert stats["recent_activity"] == []


def test_dashboard_stats_with_reports(
    temporary_database,
    sample_report,
):
    report_store.save_report(sample_report)

    stats = report_store.get_dashboard_stats()

    assert stats["total_scanned"] == 1
    assert stats["malicious"] == 1
    assert stats["threats_detected"] == 1
    assert stats["threat_percentage"] == 100.0


def test_dashboard_stats_safe_email(
    temporary_database,
    sample_report,
):
    sample_report.verdict = VerdictEnum.SAFE
    sample_report.action = ActionEnum.ALLOW
    sample_report.composite_risk_score = 5.0

    report_store.save_report(sample_report)

    stats = report_store.get_dashboard_stats()

    assert stats["safe"] == 1
    assert stats["malicious"] == 0
    assert stats["threat_percentage"] == 0.0