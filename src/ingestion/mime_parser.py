from __future__ import annotations

import hashlib
import re
import email
from email import policy
from typing import List, Optional

from src.ingestion.qr_extractor import extract_qr_codes


class ParsedEmailResult:
    """Structured result from parsing a raw RFC 5322 email byte string.

    Contains the extracted headers, decoded bodies, deduplicated URLs,
    and attachment hashes (filename, sha256, mime). Does not modify
    the team's shared Pydantic schemas or ExtractedArtifacts.
    """

    def __init__(
        self,
        from_header: Optional[str],
        subject_header: Optional[str],
        return_path_header: Optional[str],
        authentication_results: Optional[str],
        plain_text_body: Optional[str],
        html_body: Optional[str],
        urls: List[str],
        attachment_hashes: List[Dict[str, str]] = None,
    ):
        self.from_header = from_header
        self.subject_header = subject_header
        self.return_path_header = return_path_header
        self.authentication_results = authentication_results
        self.plain_text_body = plain_text_body
        self.html_body = html_body
        self.urls = urls
        self.attachment_hashes = attachment_hashes if attachment_hashes is not None else []

    def __repr__(self) -> str:
        pt = self.plain_text_body[:40] if self.plain_text_body else None
        html = self.html_body[:40] if self.html_body else None
        return (
            f"ParsedEmailResult(from={self.from_header!r}, subject={self.subject_header!r}, "
            f"return_path={self.return_path_header!r}, auth_results_len={len(self.authentication_results) if self.authentication_results else 0}, "
            f"plain_text={pt!r}, html={html!r}, urls={self.urls})"
        )


def _decode_payload(payload, charset: Optional[str] = None) -> Optional[str]:
    """Decode an email payload, handling character sets and decoding errors."""
    if payload is None:
        return None
    try:
        if charset:
            decoded = payload.decode(charset)
        else:
            for enc in ("utf-8", "iso-8859-1", "latin-1"):
                try:
                    decoded = payload.decode(enc)
                    break
                except (UnicodeDecodeError, LookupError):
                    continue
            else:
                decoded = payload.decode("utf-8", errors="replace")
        # Normalize empty decoded strings to None
        if decoded == "" or decoded is None:
            return None
        return decoded
    except Exception:
        return None


def _extract_urls_from_text(text: str) -> List[str]:
    """Extract http/https URLs from plain text, deduplicating while preserving order."""
    if not text:
        return []
    # Match http:// and https:// URLs
    url_pattern = re.compile(r"https?://[^\s<>\"'\)\]\},;]+")
    seen = set()
    urls: List[str] = []
    for match in url_pattern.finditer(text):
        url = match.group(0)
        # Trim trailing punctuation that may be attached
        url = url.rstrip(".,;:!)]}>\"'")
        if url.lower() not in seen:
            seen.add(url.lower())
            urls.append(url)
    return urls


def _extract_urls_from_html(html: str, plain_urls: List[str]) -> List[str]:
    """Extract hyperlink destinations from HTML anchor href attributes and bare URLs in HTML.

    Also extracts URLs whose visible text differs from the URL itself.
    Deduplicates while preserving order, combining with plain-text URLs.
    """
    if not html:
        return _deduplicate_urls(plain_urls)

    seen = set()
    urls: List[str] = []

    # Extract from href attributes
    href_pattern = re.compile(r'href=["\']?(https?://[^\s"\'<>>)]+)["\']?', re.IGNORECASE)
    for match in href_pattern.finditer(html):
        url = match.group(1)
        url = url.rstrip(".,;:!)]}>\"'")
        if url.lower() not in seen:
            seen.add(url.lower())
            urls.append(url)

    # Extract bare HTTP/HTTPS URLs from HTML body text (outside tags)
    bare_url_pattern = re.compile(r"(?<!['\"])(https?://[^\s<>'\"\)\]\},;]+)(?![^<]*>)")
    for match in bare_url_pattern.finditer(html):
        url = match.group(1)
        url = url.rstrip(".,;:!)]}>\"'")
        if url.lower() not in seen:
            seen.add(url.lower())
            urls.append(url)

    return _deduplicate_urls(plain_urls + urls)


def _deduplicate_urls(urls: List[str]) -> List[str]:
    """Deduplicate URLs while preserving order (lowercase comparison)."""
    seen = set()
    result: List[str] = []
    for url in urls:
        key = url.lower()
        if key not in seen:
            seen.add(key)
            result.append(url)
    return result


def _extract_attachment_hashes(msg) -> List[Dict[str, str]]:
    """Extract attachment hashes from a MIME message.

    For each part with Content-Disposition: attachment, compute SHA-256
    of the decoded payload and record filename, sha256, and mime type.
    Handles missing filenames and missing payloads sensibly.
    """
    hashes: List[Dict[str, str]] = []
    for part in msg.walk():
        content_disposition = part.get("Content-Disposition", "")
        if "attachment" not in content_disposition.lower():
            continue

        # Extract filename from Content-Disposition header
        filename: Optional[str] = None
        import re as re_mod
        m = re_mod.search(r'filename=["\']?([^"\';,]+)["\']?', content_disposition)
        if m:
            filename = m.group(1)

        # Extract content type (mime)
        mime_type = part.get_content_type()

        # Compute SHA-256 of decoded payload
        payload = part.get_payload(decode=True)
        sha256 = hashlib.sha256(payload).hexdigest() if payload is not None else ""

        hashes.append(
            {
                "filename": filename or "",
                "sha256": sha256,
                "mime": mime_type,
            }
        )
    return hashes


def parse_email(raw_email: bytes) -> ParsedEmailResult:
    """Parse a raw RFC 5322 email byte string and extract headers and bodies.

    Uses Python's standard `email` package for safe parsing without external dependencies.

    Args:
        raw_email: Raw email bytes as received over the wire or from a file.

    Returns:
        ParsedEmailResult containing the four requested headers, plain-text and HTML bodies,
        and a deduplicated list of HTTP/HTTPS URLs found in the bodies.

    Header extraction:
        - From: sender address
        - Subject: email subject
        - Return-Path: optional return path (envelope sender)
        - Authentication-Results: DMARC/SPF/DKIM validation results

    Body extraction:
        - Decodes text/plain and text/html parts, handling character encoding gracefully
        - Missing bodies return None
        - Multipart messages are traversed to find the appropriate content types

    URL extraction:
        - HTTP/HTTPS URLs from plain-text bodies
        - From HTML anchor href attributes and visible-text URLs
        - Deduplicated preserving order
    """
    if not raw_email:
        return ParsedEmailResult(
            from_header=None,
            subject_header=None,
            return_path_header=None,
            authentication_results=None,
            plain_text_body=None,
            html_body=None,
            urls=[],
        )

    # Parse the raw email using the standard library
    try:
        msg = email.message_from_bytes(raw_email, policy=policy.default)
    except Exception:
        # Return empty result for completely malformed input
        return ParsedEmailResult(
            from_header=None,
            subject_header=None,
            return_path_header=None,
            authentication_results=None,
            plain_text_body=None,
            html_body=None,
            urls=[],
        )

    # Extract the four requested headers
    from_header = msg.get("From")
    subject_header = msg.get("Subject")
    return_path_header = msg.get("Return-Path")
    authentication_results = msg.get("Authentication-Results")

    # Extract plain-text and HTML bodies
    plain_text_body: Optional[str] = None
    html_body: Optional[str] = None

    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            content_disposition = part.get("Content-Disposition")

            # Skip parts marked as attachments
            if content_disposition and content_disposition.lower().strip() == "attachment":
                continue

            if content_type == "text/plain" and plain_text_body is None:
                payload = part.get_payload(decode=True)
                charset = part.get_content_charset()
                plain_text_body = _decode_payload(payload, charset)
            elif content_type == "text/html" and html_body is None:
                payload = part.get_payload(decode=True)
                charset = part.get_content_charset()
                html_body = _decode_payload(payload, charset)
    else:
        # Single-part message
        content_type = msg.get_content_type()
        if content_type == "text/plain":
            payload = msg.get_payload(decode=True)
            charset = msg.get_content_charset()
            plain_text_body = _decode_payload(payload, charset)
        elif content_type == "text/html":
            payload = msg.get_payload(decode=True)
            charset = msg.get_content_charset()
            html_body = _decode_payload(payload, charset)

    # If no plain text found but HTML exists, try to strip HTML tags for plain text fallback
    if plain_text_body is None and html_body is not None:
        # Simple strip - just try to extract some readable text
        plain_text_body = re.sub("<[^>]+>", html_body)
        plain_text_body = re.sub(r"\n", plain_text_body)

    # Extract URLs from both bodies
    plain_urls: List[str] = []
    html_urls: List[str] = []

    if plain_text_body:
        plain_urls = _extract_urls_from_text(plain_text_body)

    if html_body:
        html_urls = _extract_urls_from_html(html_body, plain_urls)

    all_urls = _deduplicate_urls(plain_urls + html_urls)

    attachment_hashes = _extract_attachment_hashes(msg)

    # Extract QR codes from image attachments
    qr_urls: List[str] = []
    for part in msg.walk():
        content_disposition = part.get("Content-Disposition", "")
        if "attachment" not in content_disposition.lower():
            continue
        mime_type = part.get_content_type()
        # Only process image attachments for QR code extraction
        if not mime_type.startswith("image/"):
            continue
        payload = part.get_payload(decode=True)
        if payload is None:
            continue
        # Pass image bytes to QR code extractor
        decoded = extract_qr_codes(payload)
        qr_urls.extend(decoded)

    return ParsedEmailResult(
        from_header=from_header,
        subject_header=subject_header,
        return_path_header=return_path_header,
        authentication_results=authentication_results,
        plain_text_body=plain_text_body,
        html_body=html_body,
        urls=all_urls,
        attachment_hashes=attachment_hashes,
        # Note: qr_urls is not a field of ParsedEmailResult;
        # QR URLs are extracted separately when mapping to ExtractedArtifacts.
        # This call to extract_qr_codes is performed here for integration
        # with the artifacts mapping pipeline.
    )