from src.schemas import AnalysisSignals, ExtractedArtifacts
from src.orchestrator.investigation_tools import (
    inspect_sender,
    inspect_urls,
    inspect_attachments,
    run_investigation_tools,
)


def test_sender_mismatch_is_detected():
    artifacts = ExtractedArtifacts(
        message_id="1",
        sender="user@example.com",
        subject="Test",
        return_path="bounce@different.com",
    )

    result = inspect_sender(artifacts)

    assert any("mismatch" in item.lower() for item in result)


def test_matching_sender_domains_are_reported():
    artifacts = ExtractedArtifacts(
        message_id="2",
        sender="user@example.com",
        subject="Test",
        return_path="bounce@example.com",
    )

    result = inspect_sender(artifacts)

    assert any("match" in item.lower() for item in result)


def test_url_analysis_results_are_inspected():
    signals = AnalysisSignals(
        url_scores={"https://example.com": 80},
        url_ml_scores={"https://example.com": 0.85},
        vt_reputation={
            "https://example.com": {
                "malicious": 5,
                "suspicious": 2,
                "harmless": 0,
                "undetected": 0,
            }
        },
    )

    result = inspect_urls(signals)

    assert any("80" in item for item in result)
    assert any("0.850" in item for item in result)
    assert any("malicious=5" in item for item in result)


def test_attachment_metadata_is_inspected():
    artifacts = ExtractedArtifacts(
        message_id="3",
        sender="user@example.com",
        subject="Invoice",
        attachment_hashes=[
            {
                "filename": "invoice.pdf",
                "mime": "application/pdf",
                "sha256": "a" * 64,
            }
        ],
    )

    result = inspect_attachments(artifacts, AnalysisSignals())

    assert any("invoice.pdf" in item for item in result)
    assert any("SHA-256 available: True" in item for item in result)


def test_all_investigation_tools_run():
    artifacts = ExtractedArtifacts(
        message_id="4",
        sender="user@example.com",
        subject="Test",
    )

    result = run_investigation_tools(
        artifacts,
        AnalysisSignals(),
    )

    assert len(result) > 0
    assert len(result) <= 40