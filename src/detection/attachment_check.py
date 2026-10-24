
"""Offline, metadata-only attachment threat indicators."""

import re
from typing import Any


SHA256_PATTERN = re.compile(r"^[a-fA-F0-9]{64}$")

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
    """Inspect attachment metadata without opening or executing files.

    A valid hash confirms its format only. These indicators do not
    establish whether an attachment is actually malicious.
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

    if flags:
        return {"status": "unknown", "flags": flags}

    # Inspect only the filename, never the attachment's contents.
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
