from unittest.mock import patch

from fastapi.testclient import TestClient

from src.api.main import app

import pytest


@pytest.fixture(autouse=True)
def reset_api_security_environment(monkeypatch):
    monkeypatch.delenv("PHISHGUARD_API_KEY", raising=False)
    monkeypatch.setenv("PHISHGUARD_ENV", "development")

client = TestClient(app)


def test_root_endpoint():
    response = client.get("/")

    assert response.status_code == 200
    assert response.json()["name"] == "PhishGuard API"


def test_health_endpoint():
    response = client.get("/api/v1/health")

    assert response.status_code == 200
    assert response.json()["status"] == "healthy"


@patch("src.api.main.run_gmail_analysis")
def test_gmail_scan_success(mock_runner):
    mock_runner.return_value = {
        "total_fetched": 0,
        "successful": 0,
        "failed": 0,
        "skipped": 0,
        "labeling_failed": 0,
        "results": [],
    }

    response = client.post("/api/v1/gmail/scan")

    assert response.status_code == 200
    assert response.json()["total_fetched"] == 0

    mock_runner.assert_called_once_with(max_results=5)


@patch("src.api.main.run_gmail_analysis")
def test_gmail_scan_custom_limit(mock_runner):
    mock_runner.return_value = {
        "total_fetched": 0,
        "successful": 0,
        "failed": 0,
        "skipped": 0,
        "labeling_failed": 0,
        "results": [],
    }

    response = client.post(
        "/api/v1/gmail/scan?max_results=10"
    )

    assert response.status_code == 200

    mock_runner.assert_called_once_with(max_results=10)


def test_gmail_scan_rejects_invalid_limit():
    response = client.post(
        "/api/v1/gmail/scan?max_results=100"
    )

    assert response.status_code == 422


@patch("src.api.main.run_gmail_analysis")
def test_gmail_connection_failure(mock_runner):
    from src.ingestion.gmail_runner import GmailRunnerError

    mock_runner.side_effect = GmailRunnerError(
        "Unable to fetch unread Gmail messages."
    )

    response = client.post("/api/v1/gmail/scan")

    assert response.status_code == 502


@patch("src.api.main.report_store.list_reports")
@patch("src.api.main.report_store.count_reports")
def test_get_email_history(mock_count, mock_list):
    mock_count.return_value = 10
    mock_list.return_value = [
        {
            "message_id": "email-001",
            "sender": "test@example.com",
            "subject": "Test email",
            "verdict": "malicious",
            "action": "quarantine",
            "risk_score": 85.0,
            "analyzed_at": "2026-11-22T10:00:00Z",
        }
    ]

    response = client.get("/api/v1/emails")

    assert response.status_code == 200
    assert response.json()["total"] == 10
    assert len(response.json()["emails"]) == 1


@patch("src.api.main.report_store.list_reports")
@patch("src.api.main.report_store.count_reports")
def test_filter_emails_by_verdict(mock_count, mock_list):
    mock_count.return_value = 5
    mock_list.return_value = []

    response = client.get(
        "/api/v1/emails?verdict=malicious"
    )

    assert response.status_code == 200

    mock_list.assert_called_once_with(
        limit=50,
        offset=0,
        verdict="malicious",
    )


@patch("src.api.main.report_store.list_reports")
@patch("src.api.main.report_store.count_reports")
def test_email_history_pagination(mock_count, mock_list):
    mock_count.return_value = 100
    mock_list.return_value = []

    response = client.get(
        "/api/v1/emails?limit=10&offset=20"
    )

    assert response.status_code == 200

    mock_list.assert_called_once_with(
        limit=10,
        offset=20,
        verdict=None,
    )


def test_email_history_rejects_invalid_verdict():
    response = client.get(
        "/api/v1/emails?verdict=unknown"
    )

    assert response.status_code == 422


def test_email_history_rejects_invalid_limit():
    response = client.get(
        "/api/v1/emails?limit=1000"
    )

    assert response.status_code == 422


@patch("src.api.main.report_store.get_report")
def test_get_email_details(mock_get):
    mock_get.return_value = {
        "message_id": "email-001",
        "sender": "test@example.com",
        "subject": "Test email",
        "verdict": "malicious",
        "action": "quarantine",
        "composite_risk_score": 85.0,
        "evidence": ["Suspicious URL detected"],
    }

    response = client.get(
        "/api/v1/emails/email-001"
    )

    assert response.status_code == 200
    assert response.json()["verdict"] == "malicious"


@patch("src.api.main.report_store.get_report")
def test_get_missing_email_details(mock_get):
    mock_get.return_value = None

    response = client.get(
        "/api/v1/emails/unknown-email"
    )

    assert response.status_code == 404

@patch("src.api.main.report_store.get_dashboard_stats")
def test_dashboard_stats_endpoint(mock_stats):

    mock_stats.return_value = {
        "total_scanned": 10,
        "safe": 5,
        "suspicious": 2,
        "malicious": 2,
        "inconclusive": 1,
        "threats_detected": 4,
        "threat_percentage": 40.0,
        "recent_activity": [],
    }

    response = client.get("/api/v1/dashboard/stats")

    assert response.status_code == 200
    assert response.json()["total_scanned"] == 10
    assert response.json()["malicious"] == 2
    assert response.json()["threat_percentage"] == 40.0

@patch("src.api.main.audit_logger.list_audit_history")
def test_get_audit_logs(mock_audit):
    mock_audit.return_value = {
        "total": 1,
        "limit": 100,
        "offset": 0,
        "message_id": None,
        "audit_logs": [
            {
                "id": 1,
                "message_id": "test-message",
                "verdict": "malicious",
                "action": "quarantine",
                "risk_score": 85.0,
                "audit_events": [],
            }
        ],
    }

    response = client.get("/api/v1/audit")

    assert response.status_code == 200
    assert response.json()["total"] == 1
    assert response.json()["audit_logs"][0]["verdict"] == "malicious"


@patch("src.api.main.audit_logger.get_audit_history")
def test_get_email_audit_logs(mock_audit):
    mock_audit.return_value = [
        {"event": "analysis_completed", "verdict": "safe"}
    ]

    response = client.get("/api/v1/audit/test-message")

    assert response.status_code == 200
    assert response.json()["message_id"] == "test-message"
    assert response.json()["total"] == 1


def test_get_audit_logs_invalid_limit():
    response = client.get("/api/v1/audit?limit=0")
    assert response.status_code == 422

def test_api_key_not_required_in_development(monkeypatch):
    monkeypatch.setenv("PHISHGUARD_ENV", "development")
    monkeypatch.delenv("PHISHGUARD_API_KEY", raising=False)

    response = client.get("/api/v1/health")

    assert response.status_code == 200


def test_api_key_rejects_missing_key(monkeypatch):
    monkeypatch.setenv("PHISHGUARD_API_KEY", "test-secret")

    response = client.get("/api/v1/emails")

    assert response.status_code == 401


def test_api_key_accepts_valid_key(monkeypatch):
    monkeypatch.setenv("PHISHGUARD_API_KEY", "test-secret")

    response = client.get(
        "/api/v1/emails",
        headers={"X-API-Key": "test-secret"}
    )

    assert response.status_code == 200


def test_api_key_rejects_invalid_key(monkeypatch):
    monkeypatch.setenv("PHISHGUARD_API_KEY", "test-secret")

    response = client.get(
        "/api/v1/emails",
        headers={"X-API-Key": "wrong-secret"}
    )

    assert response.status_code == 401


def test_health_endpoint_remains_public(monkeypatch):
    monkeypatch.setenv("PHISHGUARD_API_KEY", "test-secret")

    response = client.get("/api/v1/health")

    assert response.status_code == 200


def test_production_requires_api_key_configuration(monkeypatch):
    monkeypatch.setenv("PHISHGUARD_ENV", "production")
    monkeypatch.delenv("PHISHGUARD_API_KEY", raising=False)

    response = client.get("/api/v1/emails")

    assert response.status_code == 503