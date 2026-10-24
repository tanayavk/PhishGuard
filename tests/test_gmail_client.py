from types import SimpleNamespace

from src.ingestion.gmail_client import _parsed_to_artifacts


def test_parsed_to_artifacts_preserves_qr_urls():
    parsed = SimpleNamespace(
        from_header="sender@example.com",
        subject_header="QR test",
        return_path_header="sender@example.com",
        urls=["https://example.com"],
        qr_urls=["https://qr-example.com"],
        attachment_hashes=[],
    )

    result = _parsed_to_artifacts(parsed, message_id="test-123")

    assert result.message_id == "test-123"
    assert result.urls == ["https://example.com"]
    assert result.qr_urls == ["https://qr-example.com"]
