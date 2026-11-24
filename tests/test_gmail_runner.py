import pytest
from unittest.mock import MagicMock, patch

from src.ingestion import processed_registry
from src.ingestion.gmail_runner import (
    run_gmail_analysis,
    GmailRunnerError,
    get_security_label,
)


@pytest.fixture(autouse=True)
def isolated_registry(tmp_path, monkeypatch):
    """Use a separate SQLite database for every test."""
    monkeypatch.setattr(
        processed_registry,
        "DB_PATH",
        tmp_path / "test_registry.db",
    )
    processed_registry.initialize_registry()


def create_artifact(message_id):
    artifact = MagicMock()
    artifact.message_id = message_id
    return artifact


def create_report(verdict="safe", action="allow", score=5.0):
    report = MagicMock()
    report.verdict.value = verdict
    report.action.value = action
    report.composite_risk_score = score
    report.message_id = "test-message"
    return report


@patch("src.ingestion.gmail_runner.save_report")
@patch("src.ingestion.gmail_runner.apply_label", return_value=True)
@patch("src.ingestion.gmail_runner.analyze_artifacts")
@patch("src.ingestion.gmail_runner.fetch_unread_emails")
def test_successful_gmail_analysis(
    mock_fetch, mock_analyze, mock_label, mock_save
):
    mock_fetch.return_value = [create_artifact("email-1")]
    mock_analyze.return_value = create_report()

    result = run_gmail_analysis()

    assert result["total_fetched"] == 1
    assert result["successful"] == 1
    assert result["failed"] == 0
    assert result["skipped"] == 0
    assert result["labeling_failed"] == 0

    assert result["results"][0]["label"] == "PhishGuard/Safe"
    assert result["results"][0]["label_applied"] is True

    mock_save.assert_called_once()
    mock_label.assert_called_once_with(
        message_id="email-1",
        label_name="PhishGuard/Safe",
    )


@patch("src.ingestion.gmail_runner.save_report")
@patch("src.ingestion.gmail_runner.apply_label", return_value=True)
@patch("src.ingestion.gmail_runner.analyze_artifacts")
@patch("src.ingestion.gmail_runner.fetch_unread_emails")
def test_analysis_failure_does_not_stop_batch(
    mock_fetch, mock_analyze, mock_label, mock_save
):
    mock_fetch.return_value = [
        create_artifact("email-1"),
        create_artifact("email-2"),
    ]

    mock_analyze.side_effect = [
        Exception("Analysis error"),
        create_report(),
    ]

    result = run_gmail_analysis()

    assert result["total_fetched"] == 2
    assert result["successful"] == 1
    assert result["failed"] == 1
    assert result["skipped"] == 0

    mock_save.assert_called_once()
    mock_label.assert_called_once()


@patch("src.ingestion.gmail_runner.fetch_unread_emails")
def test_gmail_fetch_failure(mock_fetch):
    mock_fetch.side_effect = Exception("Gmail unavailable")

    with pytest.raises(GmailRunnerError):
        run_gmail_analysis()


@pytest.mark.parametrize(
    "value",
    [0, -1, "5", None, True],
)
def test_invalid_max_results(value):
    with pytest.raises(ValueError):
        run_gmail_analysis(max_results=value)


@patch("src.ingestion.gmail_runner.analyze_artifacts")
@patch("src.ingestion.gmail_runner.fetch_unread_emails")
def test_empty_inbox(mock_fetch, mock_analyze):
    mock_fetch.return_value = []

    result = run_gmail_analysis()

    assert result["total_fetched"] == 0
    assert result["successful"] == 0
    assert result["failed"] == 0
    assert result["skipped"] == 0

    mock_analyze.assert_not_called()


@patch("src.ingestion.gmail_runner.save_report")
@patch("src.ingestion.gmail_runner.apply_label", return_value=True)
@patch("src.ingestion.gmail_runner.analyze_artifacts")
@patch("src.ingestion.gmail_runner.fetch_unread_emails")
def test_duplicate_email_is_skipped(
    mock_fetch, mock_analyze, mock_label, mock_save
):
    mock_fetch.return_value = [
        create_artifact("email-1"),
    ]

    mock_analyze.return_value = create_report()

    first_result = run_gmail_analysis()
    second_result = run_gmail_analysis()

    assert first_result["successful"] == 1
    assert second_result["skipped"] == 1

    assert mock_analyze.call_count == 1
    assert mock_label.call_count == 1
    assert mock_save.call_count == 1


@pytest.mark.parametrize(
    "verdict, expected_label",
    [
        ("safe", "PhishGuard/Safe"),
        ("suspicious", "PhishGuard/Suspicious"),
        ("malicious", "PhishGuard/Malicious"),
        ("inconclusive", "PhishGuard/Needs Review"),
    ],
)
def test_security_label_mapping(verdict, expected_label):
    assert get_security_label(verdict) == expected_label


def test_invalid_verdict_rejected():
    with pytest.raises(ValueError):
        get_security_label("unknown")


@patch("src.ingestion.gmail_runner.save_report")
@patch("src.ingestion.gmail_runner.apply_label")
@patch("src.ingestion.gmail_runner.analyze_artifacts")
@patch("src.ingestion.gmail_runner.fetch_unread_emails")
def test_label_failure_does_not_invalidate_analysis(
    mock_fetch, mock_analyze, mock_label, mock_save
):
    mock_fetch.return_value = [create_artifact("email-1")]
    mock_analyze.return_value = create_report()

    mock_label.side_effect = Exception("Gmail API unavailable")

    result = run_gmail_analysis()

    assert result["successful"] == 1
    assert result["failed"] == 0
    assert result["labeling_failed"] == 1
    assert result["results"][0]["label_applied"] is False

    mock_save.assert_called_once()


@patch("src.ingestion.gmail_runner.save_report")
@patch("src.ingestion.gmail_runner.apply_label", return_value=True)
@patch("src.ingestion.gmail_runner.analyze_artifacts")
@patch("src.ingestion.gmail_runner.fetch_unread_emails")
def test_malicious_email_receives_correct_label(
    mock_fetch, mock_analyze, mock_label, mock_save
):
    mock_fetch.return_value = [create_artifact("email-2")]

    mock_analyze.return_value = create_report(
        verdict="malicious",
        action="quarantine",
        score=85.0,
    )

    result = run_gmail_analysis()

    assert result["successful"] == 1
    assert result["results"][0]["label"] == "PhishGuard/Malicious"

    mock_label.assert_called_once_with(
        message_id="email-2",
        label_name="PhishGuard/Malicious",
    )