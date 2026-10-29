
"""Offline integration tests for the PhishGuard analysis pipeline."""

from src.schemas import (
    ActionEnum,
    ExtractedArtifacts,
    FinalSecurityReport,
    VerdictEnum,
)
from src.orchestrator.pipeline import analyze_artifacts
import pytest


@pytest.fixture(autouse=True)
def mock_file_reputation(monkeypatch):
    monkeypatch.setattr(
        "src.orchestrator.pipeline.analyze_file_reputation",
        lambda file_hash: {
            "status": "unknown",
            "reason": "Mocked in pipeline test",
        },
    )


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


def test_pipeline_includes_agent_notes_when_investigation_is_needed(monkeypatch):
    from src.orchestrator.agent import investigate_artifact

    monkeypatch.setattr(
        "src.orchestrator.pipeline.analyze_url_reputation",
        lambda url: {
            "status": "unknown",
            "reason": "Mocked unknown reputation",
        },
    )
    monkeypatch.setattr(
        "src.orchestrator.pipeline.investigate_artifact",
        lambda evidence, investigation_tool: {
            "reasoning": "Reputation is unknown; further review is needed.",
            "red_flags": ["Reputation unavailable"],
            "confidence_delta": 0.0,
            "tool_calls": 0,
            "planning_iterations": 0,
            "trace": [{"event": "mocked_investigation"}],
        },
        raising=False,
    )

    artifacts = ExtractedArtifacts(
        message_id="agent-001",
        sender="sender@example.com",
        subject="Uncertain message",
        urls=["https://example.com"],
    )

    report = analyze_artifacts(artifacts)

    assert report.agent_notes is not None
    assert "Reputation is unknown" in report.agent_notes
    assert report.verdict == VerdictEnum.INCONCLUSIVE
    assert report.action == ActionEnum.WARN


def test_pipeline_does_not_allow_agent_to_override_policy(monkeypatch):
    monkeypatch.setattr(
        "src.orchestrator.pipeline.analyze_url_reputation",
        lambda url: {
            "status": "success",
            "malicious": 8,
            "suspicious": 0,
            "harmless": 0,
            "undetected": 0,
        },
    )
    monkeypatch.setattr(
        "src.orchestrator.pipeline.investigate_artifact",
        lambda evidence, investigation_tool: {
            "reasoning": "The message is safe.",
            "red_flags": [],
            "confidence_delta": -1.0,
            "tool_calls": 0,
            "planning_iterations": 0,
            "trace": [],
        },
        raising=False,
    )

    artifacts = ExtractedArtifacts(
        message_id="agent-002",
        sender="sender@example.com",
        subject="Policy authority test",
        urls=["https://example.com"],
    )

    report = analyze_artifacts(artifacts)

    assert report.verdict == VerdictEnum.MALICIOUS
    assert report.action == ActionEnum.QUARANTINE


def test_pipeline_handles_agent_failure_without_marking_message_safe(monkeypatch):
    monkeypatch.setattr(
        "src.orchestrator.pipeline.analyze_url_reputation",
        lambda url: {
            "status": "unknown",
            "reason": "Mocked reputation unavailable",
        },
    )

    def failing_agent(*args, **kwargs):
        raise RuntimeError("Simulated agent failure")

    monkeypatch.setattr(
        "src.orchestrator.pipeline.investigate_artifact",
        failing_agent,
    )

    artifacts = ExtractedArtifacts(
        message_id="agent-failure-001",
        sender="sender@example.com",
        subject="Uncertain message",
        urls=["https://example.com"],
    )

    report = analyze_artifacts(artifacts)

    assert report.agent_notes is not None
    assert "failed" in report.agent_notes.lower()
    assert report.verdict == VerdictEnum.INCONCLUSIVE
    assert report.action == ActionEnum.WARN


def test_pipeline_runs_ml_classifier_for_each_unique_url(monkeypatch):
    predictions = []

    def fake_predict(url):
        predictions.append(url)
        return 0.20

    monkeypatch.setattr(
        "src.orchestrator.pipeline.predict_url_risk",
        fake_predict,
    )
    monkeypatch.setattr(
        "src.orchestrator.pipeline.analyze_url_reputation",
        lambda url: {
            "status": "success",
            "malicious": 0,
            "suspicious": 0,
            "harmless": 5,
            "undetected": 0,
        },
    )

    artifacts = ExtractedArtifacts(
        message_id="ml-001",
        sender="sender@example.com",
        subject="Duplicate URL test",
        urls=["https://example.com"],
        qr_urls=["https://example.com"],
    )

    report = analyze_artifacts(artifacts)

    assert predictions == ["https://example.com"]
    assert report.verdict == VerdictEnum.SAFE
    assert any("ML classifier" in item for item in report.evidence)


def test_pipeline_triggers_investigation_for_uncertain_ml_score(monkeypatch):
    investigation_calls = []

    monkeypatch.setattr(
        "src.orchestrator.pipeline.predict_url_risk",
        lambda url: 0.55,
    )
    monkeypatch.setattr(
        "src.orchestrator.pipeline.analyze_url_reputation",
        lambda url: {
            "status": "success",
            "malicious": 0,
            "suspicious": 0,
            "harmless": 5,
            "undetected": 0,
        },
    )
    monkeypatch.setattr(
        "src.orchestrator.pipeline.investigate_artifact",
        lambda evidence, investigation_tool: (
            investigation_calls.append(list(evidence))
            or {
                "reasoning": "Reviewed the uncertain ML result.",
                "red_flags": [],
                "confidence_delta": 0.0,
                "trace": [],
            }
        ),
    )

    artifacts = ExtractedArtifacts(
        message_id="ml-002",
        sender="sender@example.com",
        subject="Uncertain ML result",
        urls=["https://example.com"],
    )

    report = analyze_artifacts(artifacts)

    assert len(investigation_calls) == 1
    assert report.agent_notes is not None
    assert "uncertain ML" in " ".join(report.evidence).lower() or any(
        "uncertain probability" in item.lower()
        for item in report.evidence
    )


def test_pipeline_handles_ml_classifier_failure(monkeypatch):
    monkeypatch.setattr(
        "src.orchestrator.pipeline.predict_url_risk",
        lambda url: (_ for _ in ()).throw(RuntimeError("simulated failure")),
    )
    monkeypatch.setattr(
        "src.orchestrator.pipeline.analyze_url_reputation",
        lambda url: {
            "status": "success",
            "malicious": 0,
            "suspicious": 0,
            "harmless": 5,
            "undetected": 0,
        },
    )

    artifacts = ExtractedArtifacts(
        message_id="ml-003",
        sender="sender@example.com",
        subject="Classifier failure",
        urls=["https://example.com"],
    )

    report = analyze_artifacts(artifacts)

    assert report.verdict == VerdictEnum.INCONCLUSIVE
    assert report.action == ActionEnum.WARN
    assert any(
        "classifier was unavailable" in item.lower()
        for item in report.evidence
    )


def test_pipeline_rejects_invalid_ml_probability(monkeypatch):
    monkeypatch.setattr(
        "src.orchestrator.pipeline.predict_url_risk",
        lambda url: float("nan"),
    )
    monkeypatch.setattr(
        "src.orchestrator.pipeline.analyze_url_reputation",
        lambda url: {
            "status": "success",
            "malicious": 0,
            "suspicious": 0,
            "harmless": 5,
            "undetected": 0,
        },
    )

    artifacts = ExtractedArtifacts(
        message_id="ml-004",
        sender="sender@example.com",
        subject="Invalid classifier output",
        urls=["https://example.com"],
    )

    report = analyze_artifacts(artifacts)

    assert report.verdict == VerdictEnum.INCONCLUSIVE
    assert report.action == ActionEnum.WARN
    assert any(
        "invalid probability" in item.lower()
        for item in report.evidence
    )
def test_pipeline_reports_attachment_signature_mismatch():
    artifacts = ExtractedArtifacts(
        message_id="pipeline-signature-001",
        sender="sender@example.com",
        subject="Invoice",
        attachment_hashes=[
            {
                "filename": "invoice.pdf",
                "sha256": "a" * 64,
                "mime": "application/pdf",
            }
        ],
        attachment_validation_results=[
            {
                "filename": "invoice.pdf",
                "mime": "application/pdf",
                "status": "mismatch",
                "detail": "Attachment content does not match declared MIME type",
            }
        ],
    )

    report = analyze_artifacts(artifacts)

    assert any(
        "signature mismatch" in item.lower()
        for item in report.evidence
    )

@pytest.fixture(autouse=True)
def mock_external_services(monkeypatch):
    monkeypatch.setattr(
        "src.orchestrator.pipeline.analyze_file_reputation",
        lambda file_hash: {
            "status": "unknown",
            "reason": "Mocked in pipeline test",
        },
    )
    monkeypatch.setattr(
        "src.orchestrator.pipeline.get_gemini_api_key",
        lambda: None,
    )


def test_pipeline_triggers_investigation_for_zero_vt_detections_and_high_entropy(
    monkeypatch,
):
    investigation_calls = []

    monkeypatch.setattr(
        "src.orchestrator.pipeline.predict_url_risk",
        lambda url: 0.20,
    )
    monkeypatch.setattr(
        "src.orchestrator.pipeline.analyze_url_reputation",
        lambda url: {
            "status": "success",
            "malicious": 0,
            "suspicious": 0,
            "harmless": 5,
            "undetected": 0,
        },
    )
    monkeypatch.setattr(
        "src.orchestrator.pipeline.investigate_artifact",
        lambda evidence, investigation_tool: (
            investigation_calls.append(list(evidence))
            or {
                "reasoning": "High-entropy hostname requires review.",
                "red_flags": [],
                "confidence_delta": 0.0,
                "trace": [],
            }
        ),
    )

    artifacts = ExtractedArtifacts(
        message_id="entropy-trigger-001",
        sender="sender@example.com",
        subject="Entropy trigger test",
        urls=["https://a8K2mQ9xZ7vP4nR6.example.com"],
    )

    report = analyze_artifacts(artifacts)

    assert len(investigation_calls) == 1
    assert any(
        "entropy" in item.lower()
        for item in investigation_calls[0]
    )


def test_pipeline_does_not_use_unknown_vt_as_zero_detections(
    monkeypatch,
):
    investigation_calls = []

    monkeypatch.setattr(
        "src.orchestrator.pipeline.predict_url_risk",
        lambda url: 0.20,
    )
    monkeypatch.setattr(
        "src.orchestrator.pipeline.analyze_url_reputation",
        lambda url: {
            "status": "unknown",
            "reason": "API key is not configured",
        },
    )
    monkeypatch.setattr(
        "src.orchestrator.pipeline.investigate_artifact",
        lambda evidence, investigation_tool: (
            investigation_calls.append(list(evidence))
            or {
                "reasoning": "Review completed.",
                "red_flags": [],
                "confidence_delta": 0.0,
                "trace": [],
            }
        ),
    )

    artifacts = ExtractedArtifacts(
        message_id="entropy-unknown-001",
        sender="sender@example.com",
        subject="Unknown reputation test",
        urls=["https://a8K2mQ9xZ7vP4nR6.example.com"],
    )

    report = analyze_artifacts(artifacts)

    assert len(investigation_calls) == 1
    assert not any(
        "zero virustotal" in item.lower()
        or "zero detections" in item.lower()
        for item in investigation_calls[0]
    )


def test_pipeline_triggers_investigation_for_sender_mismatch(
    monkeypatch,
):
    investigation_calls = []

    monkeypatch.setattr(
        "src.orchestrator.pipeline.predict_url_risk",
        lambda url: 0.20,
    )
    monkeypatch.setattr(
        "src.orchestrator.pipeline.analyze_url_reputation",
        lambda url: {
            "status": "success",
            "malicious": 0,
            "suspicious": 0,
            "harmless": 5,
            "undetected": 0,
        },
    )
    monkeypatch.setattr(
        "src.orchestrator.pipeline.investigate_artifact",
        lambda evidence, investigation_tool: (
            investigation_calls.append(list(evidence))
            or {
                "reasoning": "Sender address mismatch requires review.",
                "red_flags": [],
                "confidence_delta": 0.0,
                "trace": [],
            }
        ),
    )

    artifacts = ExtractedArtifacts(
        message_id="sender-mismatch-001",
        sender="sender@example.com",
        return_path="different@example.net",
        subject="Sender mismatch test",
        urls=["https://example.com"],
    )

    report = analyze_artifacts(artifacts)

    assert len(investigation_calls) == 1
    assert any(
        "return-path" in item.lower()
        and "from" in item.lower()
        for item in investigation_calls[0]
    )
