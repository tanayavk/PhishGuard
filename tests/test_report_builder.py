
"""Offline tests for the PhishGuard final report builder."""

from src.schemas import (
    ActionEnum,
    ExtractedArtifacts,
    FinalSecurityReport,
    VerdictEnum,
)
from src.reporting.report_builder import build_report


def test_build_report_returns_valid_schema():
    artifacts = ExtractedArtifacts(
        message_id="test-001",
        sender="sender@example.com",
        subject="Security test",
        urls=["https://example.com"],
    )

    report = build_report(
        artifacts,
        {
            "score": 0,
            "verdict": VerdictEnum.SAFE,
            "action": ActionEnum.ALLOW,
            "evidence": ["No risk indicators were supplied"],
        },
    )

    assert isinstance(report, FinalSecurityReport)
    assert report.message_id == "test-001"
    assert report.sender == "sender@example.com"
    assert report.subject == "Security test"
    assert report.composite_risk_score == 0


def test_build_report_preserves_verdict_action_and_evidence():
    artifacts = ExtractedArtifacts(
        message_id="test-002",
        sender="alerts@example.com",
        subject="Suspicious attachment",
    )
    evidence = ["Potentially risky executable extension: .exe"]

    report = build_report(
        artifacts,
        {
            "score": 75,
            "verdict": VerdictEnum.MALICIOUS,
            "action": ActionEnum.QUARANTINE,
            "evidence": evidence,
        },
    )

    assert report.verdict == VerdictEnum.MALICIOUS
    assert report.action == ActionEnum.QUARANTINE
    assert report.evidence == evidence


def test_build_report_rejects_out_of_range_score():
    artifacts = ExtractedArtifacts(
        message_id="test-003",
        sender="sender@example.com",
        subject="Invalid score",
    )

    try:
        build_report(
            artifacts,
            {
                "score": 120,
                "verdict": VerdictEnum.MALICIOUS,
                "action": ActionEnum.QUARANTINE,
                "evidence": ["Test"],
            },
        )
    except ValueError:
        pass
    else:
        raise AssertionError("Expected an out-of-range score to be rejected")
