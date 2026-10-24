"""Offline tests for src.ingestion.mime_parser - MIME email parsing only.

Uses only the standard library (email package). No external services.
"""

import base64

from src.ingestion.mime_parser import parse_email, ParsedEmailResult


def _make_raw_email(headers: dict, body_text: str = "", body_html: str = "") -> bytes:
    """Helper to create a minimal raw email bytes string for testing."""
    lines = []
    for k, v in headers.items():
        lines.append(f"{k}: {v}")
    lines.append("")
    if body_text:
        lines.append(body_text)
    elif body_html:
        lines.append(body_html)
    return "\r\n".join(lines).encode("utf-8")


def test_basic_plain_text_email():
    """A basic plain-text email should parse headers and body, extract URLs from text."""
    raw = _make_raw_email(
        {"From": "sender@example.com", "Subject": "Hello"},
        body_text="Check out http://example.com and https://test.org for more info.",
    )
    result = parse_email(raw)
    assert isinstance(result, ParsedEmailResult)
    assert result.from_header == "sender@example.com"
    assert result.subject_header == "Hello"
    assert "http://example.com" in result.urls
    assert "https://test.org" in result.urls


def test_multipart_email_with_html_links():
    """A multipart email with HTML should extract bodies and URLs from href attributes."""
    from email.message import EmailMessage

    msg = EmailMessage()
    msg["From"] = "sender@example.com"
    msg["Subject"] = "Newsletter"
    msg.set_content("Plain text version", subtype="plain")
    msg.add_alternative(
        "<html><body><p>Click <a href='http://link1.com'>here</a> or visit http://link2.com.</p></body></html>",
        subtype="html",
    )
    raw_bytes = msg.as_bytes()
    result = parse_email(raw_bytes)
    assert result.html_body is not None
    assert "http://link1.com" in result.urls
    assert "http://link2.com" in result.urls


def test_missing_optional_headers_and_bodies():
    """Missing Return-Path and Authentication-Results should be None. Missing body returns None."""
    raw = _make_raw_email(
        {"From": "a@b.com", "Subject": "Test"},
        body_text="",
    )
    result = parse_email(raw)
    assert result.return_path_header is None
    assert result.authentication_results is None
    # Empty body should result in None (parser normalizes empty bodies to None)
    assert result.plain_text_body is None


def test_url_deduplication():
    """URLs should be deduplicated while preserving order."""
    raw = _make_raw_email(
        {"From": "a@b.com", "Subject": "Test"},
        body_text="http://aaa.com http://bbb.com http://aaa.com http://ccc.com http://bbb.com",
    )
    result = parse_email(raw)
    # Order should be preserved: first occurrence kept
    assert result.urls == ["http://aaa.com", "http://bbb.com", "http://ccc.com"]


def test_encoded_body_content():
    """Bodies with character encoding should decode gracefully."""
    import email.message
    msg = email.message.Message()
    msg["From"] = "a@b.com"
    msg["Subject"] = "Test"
    msg.set_payload("http://example.com", charset="utf-8")
    raw_bytes = msg.as_bytes()
    result = parse_email(raw_bytes)
    assert result.plain_text_body is not None
    assert "http://example.com" in result.plain_text_body or result.urls == ["http://example.com"]
    raw_bytes = msg.as_bytes()
    result = parse_email(raw_bytes)
    assert result.plain_text_body is not None
    assert "http://example.com" in result.plain_text_body or result.urls == ["http://example.com"]


def test_malformed_input_handling():
    """Malformed input should not crash; return a valid ParsedEmailResult with empty data."""
    result = parse_email(b"")
    assert isinstance(result, ParsedEmailResult)
    assert result.urls == []

    result2 = parse_email(b"\r\n")
    assert isinstance(result2, ParsedEmailResult)


def test_return_path_header():
    """Return-Path header should be extracted."""
    raw = _make_raw_email(
        {"From": "sender@example.com", "Return-Path": "<envelope@example.com>"},
        body_text="hello",
    )
    result = parse_email(raw)
    assert result.return_path_header == "<envelope@example.com>"


def test_authentication_results_header():
    """Authentication-Results header should be extracted."""
    raw = _make_raw_email(
        {"From": "sender@example.com", "Authentication-Results": "some.domain; dspf=pass"},
        body_text="hello",
    )
    result = parse_email(raw)
    assert result.authentication_results is not None
    assert "dspf=pass" in result.authentication_results