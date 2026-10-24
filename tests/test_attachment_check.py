
"""Offline tests for attachment indicator analysis."""

from src.detection.attachment_check import analyze_attachment


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
