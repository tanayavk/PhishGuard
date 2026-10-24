
"""Offline integration tests for the PhishGuard analysis pipeline."""

from src.schemas import (
    ActionEnum,
    ExtractedArtifacts,
    FinalSecurityReport,
    VerdictEnum,
)
from src.orchestrator.pipeline import analyze_artifacts


def test_pipeline_returns_valid_report_for_clean_artifacts(monkeypatch):
    # Keep the integration test completely offline.
    monkeypatch.setattr(
        "src.orchestrator.pipeline.analyze_url_reputation",
        lambda url: {
            "status": "unknown",
            "malicious": 0,
            "suspicious": 0,
            "harmless": 0,
            "undetected": 0,
            "reason": "Mocked test: no reputation lookup",
        },
    )

    artifacts = ExtractedArtifacts(
        message_id="pipeline-001",
        sender="sender@example.com",
        subject="Hello",
        urls=["https://example.com"],
        qr_urls=["https://example.com"],
        attachment_hashes=[],
    )

    report = analyze_artifacts(artifacts)

    assert isinstance(report, FinalSecurityReport)
    assert report.message_id == "pipeline-001"
    assert report.composite_risk_score == 0
    # assert report.verdict == VerdictEnum.SAFE
    # assert report.action == ActionEnum.ALLOW
    assert report.verdict == VerdictEnum.INCONCLUSIVE
    assert report.action == ActionEnum.WARN
    assert any(
        "incomplete" in item.lower()
        for item in report.evidence
    )


def test_pipeline_flags_executable_attachment(monkeypatch):
    monkeypatch.setattr(
        "src.orchestrator.pipeline.analyze_url_reputation",
        lambda url: {
            "status": "unknown",
            "malicious": 0,
            "suspicious": 0,
            "harmless": 0,
            "undetected": 0,
            "reason": "Mocked test: no reputation lookup",
        },
    )

    artifacts = ExtractedArtifacts(
        message_id="pipeline-002",
        sender="sender@example.com",
        subject="Invoice",
        attachment_hashes=[
            {
                "filename": "invoice.exe",
                "sha256": "a" * 64,
                "mime": "application/octet-stream",
            }
        ],
    )

    report = analyze_artifacts(artifacts)

    assert report.composite_risk_score > 0
    assert any("executable" in item.lower() for item in report.evidence)


def test_pipeline_reports_unknown_reputation_without_calling_it_safe_evidence(
    monkeypatch,
):
    monkeypatch.setattr(
        "src.orchestrator.pipeline.analyze_url_reputation",
        lambda url: {
            "status": "unknown",
            "malicious": 0,
            "suspicious": 0,
            "harmless": 0,
            "undetected": 0,
            "reason": "VirusTotal API key is not configured",
        },
    )

    artifacts = ExtractedArtifacts(
        message_id="pipeline-003",
        sender="sender@example.com",
        subject="Unverified message",
        urls=["https://example.com"],
    )

    report = analyze_artifacts(artifacts)

    assert any(
        "reputation unknown" in item.lower()
        for item in report.evidence
    )
    assert any(
        "not configured" in item.lower()
        for item in report.evidence
    )
