
"""Offline attachment metadata and file-signature threat indicators."""

import re
from typing import Any


SHA256_PATTERN = re.compile(r"^[a-fA-F0-9]{64}$")

# Common file signatures used to compare declared MIME types with file content.
MAGIC_SIGNATURES = {
    "application/pdf": ((b"%PDF-", 0),),
    "image/png": ((b"\x89PNG\r\n\x1a\n", 0),),
    "image/jpeg": ((b"\xff\xd8\xff", 0),),
    "image/gif": ((b"GIF87a", 0), (b"GIF89a", 0)),
    "application/zip": ((b"PK\x03\x04", 0),),
    "application/x-executable": ((b"\x7fELF", 0),),
}


def validate_magic_bytes(mime: str, content: bytes) -> bool | None:
    """Compare recognized file signatures with the declared MIME type.

    Returns True for a match, False for a mismatch, and None when
    the MIME type has no supported signature.
    """
    if not isinstance(mime, str) or not isinstance(content, bytes):
        return None

    signatures = MAGIC_SIGNATURES.get(mime.lower().strip())
    if signatures is None:
        return None

    return any(content.startswith(signature) for signature, _ in signatures)
# These extensions can represent executable or script content.
RISKY_EXTENSIONS = {
    ".exe", ".dll", ".scr", ".com", ".bat", ".cmd",
    ".ps1", ".vbs", ".vbe", ".js", ".jse", ".wsf",
    ".hta", ".msi", ".jar", ".lnk",
}

# Double extensions sometimes disguise executable files as documents.
DOCUMENT_EXTENSIONS = {
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
    ".txt", ".jpg", ".jpeg", ".png",
}


def analyze_attachment(attachment: dict[str, Any]) -> dict[str, Any]:
    """Inspect attachment metadata and optionally check file signatures.

These indicators do not establish whether an attachment is malicious.
"""
    flags: list[str] = []

    if not isinstance(attachment, dict):
        return {
            "status": "unknown",
            "flags": ["Attachment metadata is missing or invalid"],
        }

    filename = attachment.get("filename")
    sha256 = attachment.get("sha256")
    mime = attachment.get("mime")

    if not isinstance(filename, str) or not filename.strip():
        flags.append("Attachment filename is missing")

    if not isinstance(sha256, str) or not SHA256_PATTERN.fullmatch(sha256):
        flags.append("SHA-256 hash is missing or malformed")

    if not isinstance(mime, str) or not mime.strip():
        flags.append("Attachment MIME type is missing")

    content = attachment.get("content")
    if content is not None:
        if not isinstance(content, bytes):
            flags.append("Attachment content must be bytes for signature validation")
        else:
            signature_match = validate_magic_bytes(mime, content)
            if signature_match is False:
                flags.append(
                    "Attachment content does not match its declared MIME type"
                )

    if flags:
        return {"status": "unknown", "flags": flags}

# Inspect the filename for risky and deceptive extensions.
    normalized_name = filename.strip().lower()
    parts = normalized_name.rsplit(".", 1)
    extension = f".{parts[1]}" if len(parts) == 2 else ""

    if extension in RISKY_EXTENSIONS:
        flags.append(f"Potentially risky executable/script extension: {extension}")

    segments = normalized_name.split(".")
    if len(segments) >= 3:
        penultimate_extension = f".{segments[-2]}"
        final_extension = f".{segments[-1]}"

        if (
            penultimate_extension in DOCUMENT_EXTENSIONS
            and final_extension in RISKY_EXTENSIONS
        ):
            flags.append("Double extension may disguise executable content")

    return {"status": "analyzed", "flags": flags}
