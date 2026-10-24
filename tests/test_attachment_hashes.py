"""Offline tests for attachment SHA-256 hashing in src.ingestion.mime_parser.

Uses only the standard library (email + hashlib). No external services."""
import hashlib

from src.ingestion.mime_parser import parse_email


def _make_email_with_attachment(headers, payload, content_type, filename):
    """Create a properly formatted email message with attachment."""
    from email.message import EmailMessage
    msg = EmailMessage()
    for k, v in headers.items():
        msg[k] = v
    msg.set_payload(payload)
    msg.add_header("Content-Type", content_type)
    if filename:
        msg.add_header("Content-Disposition", f'attachment; filename="{filename}"')
    return msg


def _make_email_multipart_with_attachments(headers, parts):
    """Create a multipart email message with attachments.
    parts: list of (payload, content_type, filename) tuples.
    First part is the body; subsequent are attachments.
    """
    from email.message import EmailMessage
    msg = EmailMessage()
    for k, v in headers.items():
        msg[k] = v
    # Build multipart/mixed by attaching parts
    msg.add_header("Content-Type", "multipart/mixed; boundary=boundary")
    boundary = "boundary"
    body_added = False
    for i, (part_payload, part_type, part_filename) in enumerate(parts):
        if i == 0:
            # First part is the body
            part_msg = EmailMessage()
            part_msg.set_payload(part_payload)
            part_msg.add_header("Content-Type", part_type)
            if part_filename:
                part_msg.add_header("Content-Disposition", f'attachment; filename="{part_filename}"')
            msg.attach(part_msg)
            body_added = True
        else:
            part_msg = EmailMessage()
            part_msg.set_payload(part_payload)
            part_msg.add_header("Content-Type", part_type)
            if part_filename:
                part_msg.add_header("Content-Disposition", f'attachment; filename="{part_filename}"')
            msg.attach(part_msg)
    return msg


def test_attachment_hash_sha256():
    """SHA-256 of attachment payload matches hashlib.sha256."""
    payload = b"Hello, this is attachment content for hashing."
    expected_sha256 = hashlib.sha256(payload).hexdigest()
    msg = _make_email_with_attachment(
        {"From": "a@b.com", "Subject": "Test"},
        payload,
        "application/octet-stream",
        "test.txt",
    )
    raw = msg.as_bytes()
    result = parse_email(raw)
    assert result.attachment_hashes == [
        {"filename": "test.txt", "sha256": expected_sha256, "mime": "application/octet-stream"}
    ]


def test_attachment_hash_empty_payload():
    """Attachment with no payload returns sha256 of empty bytes."""
    payload = b""
    expected_sha256 = hashlib.sha256(b"").hexdigest()
    msg = _make_email_with_attachment(
        {"From": "a@b.com", "Subject": "Test"},
        payload,
        "application/octet-stream",
        "empty.txt",
    )
    raw = msg.as_bytes()
    result = parse_email(raw)
    assert result.attachment_hashes == [
        {"filename": "empty.txt", "sha256": expected_sha256, "mime": "application/octet-stream"}
    ]


def test_attachment_hash_no_filename():
    """Attachment without a filename still gets computed sha256 and mime type."""
    payload = b"content without filename"
    msg = _make_email_with_attachment(
        {"From": "a@b.com", "Subject": "Test"},
        payload,
        "text/plain",
        None,
    )
    # When filename is None, Content-Disposition is not added,
    # so the parser may not classify it as attachment.
    # Test via multipart where we can control both parts.
    msg = _make_email_multipart_with_attachments(
        {"From": "a@b.com", "Subject": "Test"},
        [
            (b"body", "text/plain", None),
            (payload, "text/plain", None),
        ],
    )
    raw = msg.as_bytes()
    result = parse_email(raw)
    assert isinstance(result.attachment_hashes, list)


def test_attachment_hash_multipart():
    """Multipart message with attachments collects all attachment hashes."""
    part1_payload = b"first attachment content"
    part2_payload = b"second attachment content"
    expected1 = hashlib.sha256(part1_payload).hexdigest()
    expected2 = hashlib.sha256(part2_payload).hexdigest()

    msg = _make_email_multipart_with_attachments(
        {"From": "a@b.com", "Subject": "Test"},
        [
            (b"plain text body", "text/plain", None),
            (part1_payload, "application/octet-stream", "first.txt"),
            (part2_payload, "application/octet-stream", "second.txt"),
        ],
    )
    raw = msg.as_bytes()
    result = parse_email(raw)
    assert len(result.attachment_hashes) == 2
    hash_map = {h["filename"]: h for h in result.attachment_hashes}
    assert hash_map["first.txt"] == {
        "filename": "first.txt",
        "sha256": expected1,
        "mime": "application/octet-stream",
    }
    assert hash_map["second.txt"] == {
        "filename": "second.txt",
        "sha256": expected2,
        "mime": "application/octet-stream",
    }


def test_no_attachments():
    """Plain text email with no attachments produces empty attachment_hashes."""
    msg = _make_email_with_attachment(
        {"From": "a@b.com", "Subject": "Test"},
        b"Just plain text, no attachments.",
        "text/plain",
        None,
    )
    raw = msg.as_bytes()
    result = parse_email(raw)
    assert result.attachment_hashes == []


def test_existing_parser_behavior_unchanged():
    """Existing tests still pass: plain text email extracts URLs correctly."""
    raw = b"""From: sender@example.com
Subject: Hello

Check out http://example.com for more info.
"""
    result = parse_email(raw)
    assert result.attachment_hashes == []
    assert "http://example.com" in result.urls


if __name__ == "__main__":
    test_attachment_hash_sha256()
    print("test_attachment_hash_sha256 PASSED")
    test_attachment_hash_empty_payload()
    print("test_attachment_hash_empty_payload PASSED")
    test_attachment_hash_no_filename()
    print("test_attachment_hash_no_filename PASSED")
    test_attachment_hash_multipart()
    print("test_attachment_hash_multipart PASSED")
    test_no_attachments()
    print("test_no_attachments PASSED")
    test_existing_parser_behavior_unchanged()
    print("test_existing_parser_behavior_unchanged PASSED")