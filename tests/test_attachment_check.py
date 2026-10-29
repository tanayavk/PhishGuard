
"""Offline tests for attachment indicator analysis."""
from src.ingestion.mime_parser import parse_email
from src.detection.attachment_check import (
    analyze_attachment,
    validate_magic_bytes,
)

def test_valid_text_attachment():
    result = analyze_attachment({
        "filename": "notes.txt",
        "sha256": "a" * 64,
        "mime": "text/plain",
    })

    assert result["status"] == "analyzed"
    assert isinstance(result["flags"], list)


def test_executable_extension_is_flagged():
    result = analyze_attachment({
        "filename": "invoice.exe",
        "sha256": "a" * 64,
        "mime": "application/octet-stream",
    })

    assert any("executable" in flag.lower() for flag in result["flags"])


def test_double_extension_is_flagged():
    result = analyze_attachment({
        "filename": "invoice.pdf.exe",
        "sha256": "a" * 64,
        "mime": "application/octet-stream",
    })

    assert result["flags"]


def test_invalid_sha256_is_flagged():
    result = analyze_attachment({
        "filename": "notes.txt",
        "sha256": "not-a-valid-hash",
        "mime": "text/plain",
    })

    assert result["status"] == "unknown"
    assert result["flags"]


def test_missing_metadata_is_handled():
    result = analyze_attachment({})

    assert result["status"] == "unknown"
    assert result["flags"]


def test_empty_filename_is_handled():
    result = analyze_attachment({
        "filename": "",
        "sha256": "a" * 64,
        "mime": "application/octet-stream",
    })

    assert result["status"] == "unknown"
    assert result["flags"]

def test_pdf_signature_matches_declared_mime():
    assert validate_magic_bytes(
        "application/pdf", b"%PDF-1.7 test"
    ) is True


def test_pdf_signature_mismatch_is_detected():
    assert validate_magic_bytes(
        "application/pdf", b"MZ-not-a-pdf"
    ) is False


def test_unsupported_mime_returns_none():
    assert validate_magic_bytes(
        "text/plain", b"hello"
    ) is None


def test_signature_check_flags_mismatched_content():
    result = analyze_attachment({
        "filename": "invoice.pdf",
        "sha256": "a" * 64,
        "mime": "application/pdf",
        "content": b"MZ-not-a-pdf",
    })

    assert any(
        "does not match" in flag
        for flag in result["flags"]
    )

def test_parser_detects_pdf_signature_mismatch():
    from email.message import EmailMessage

    msg = EmailMessage()
    msg["From"] = "sender@example.com"
    msg["Subject"] = "Invoice"

    msg.set_content("Please review the attachment.")
    msg.add_attachment(
        b"MZ-not-a-pdf",
        maintype="application",
        subtype="pdf",
        filename="invoice.pdf",
    )

    result = parse_email(msg.as_bytes())

    assert result.attachment_hashes[0]["filename"] == "invoice.pdf"
    assert result.attachment_validation_results[0]["status"] == "mismatch"


def test_parser_detects_pdf_signature_match():
    from email.message import EmailMessage

    msg = EmailMessage()
    msg["From"] = "sender@example.com"
    msg["Subject"] = "PDF"

    msg.set_content("See attached.")
    msg.add_attachment(
        b"%PDF-1.7 sample content",
        maintype="application",
        subtype="pdf",
        filename="sample.pdf",
    )

    result = parse_email(msg.as_bytes())

    assert result.attachment_validation_results[0]["status"] == "match"