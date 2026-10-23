from __future__ import annotations

from src.schemas import ExtractedArtifacts
from src.ingestion.gmail_api import fetch_unread_emails as _fetch_unread_emails
from src.ingestion.mime_parser import parse_email


def _parsed_to_artifacts(parsed: "ParsedEmailResult", message_id: str) -> ExtractedArtifacts:
    """Convert a ParsedEmailResult to an ExtractedArtifacts instance."""
    return ExtractedArtifacts(
        message_id=message_id,
        sender=parsed.from_header or "",
        subject=parsed.subject_header or "",
        return_path=parsed.return_path_header,
        urls=parsed.urls,
        qr_urls=[],  # QR URLs are extracted separately when mapping to artifacts
        attachment_hashes=parsed.attachment_hashes,
    )


def fetch_unread_emails(max_results: int = 5) -> list["ExtractedArtifacts"]:
    """Fetch up to max_results unread emails from Gmail and return them as ExtractedArtifacts.

    Uses Gmail API with read-only scope. Retrieves raw MIME content,
    decodes it, and passes it to the existing parse_email() function,
    then converts the result to ExtractedArtifacts.

    Args:
        max_results: Maximum number of unread emails to fetch (default: 5).

    Returns:
        List of ExtractedArtifacts objects, one per email.

    Note:
        This function depends on the Google API packages (google-auth,
        google-api-python-client) and valid OAuth 2.0 credentials.
        It is kept separate from the offline MIME parser so the parser
        can continue to be tested without network access.
    """
    parsed_emails = _fetch_unread_emails(max_count=max_results)
    artifacts = []
    for i, parsed in enumerate(parsed_emails):
        artifacts.append(_parsed_to_artifacts(parsed, message_id=f"msg{i+1}"))
    return artifacts