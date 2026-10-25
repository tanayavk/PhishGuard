
"""VirusTotal URL reputation client with safe failure handling."""

import base64
from typing import Any
from urllib.parse import urlsplit

import requests


API_URL = "https://www.virustotal.com/api/v3/urls"
REQUEST_TIMEOUT = 10


def _unknown_result(reason: str) -> dict[str, Any]:
    """Return an inconclusive result; unknown never means safe."""
    return {
        "status": "unknown",
        "malicious": 0,
        "suspicious": 0,
        "harmless": 0,
        "undetected": 0,
        "reason": reason,
    }


def analyze_url_reputation(url: str) -> dict[str, Any]:
    """Look up a URL's existing VirusTotal report.

    Does not submit a new URL for scanning. Network requests should
    be mocked in unit tests. A successful lookup is reputation evidence,
    not a final PhishGuard verdict.
    """
    if not isinstance(url, str) or not url.strip():
        return _unknown_result("Invalid URL")

    candidate = url.strip()

    try:
        parsed = urlsplit(candidate)
        if (
            parsed.scheme.lower() not in {"http", "https"}
            or not parsed.hostname
        ):
            return _unknown_result("Invalid URL")

        # Trigger port validation and reject malformed/out-of-range ports.
        _ = parsed.port
    except (ValueError, UnicodeError):
        return _unknown_result("Invalid URL")

    from src.config import get_vt_api_key

    api_key = get_vt_api_key()
    if not api_key:
        return _unknown_result("VT_API_KEY is not configured")

    # VirusTotal v3 identifies URLs using URL-safe Base64 without padding.
    url_id = base64.urlsafe_b64encode(
        candidate.encode("utf-8")
    ).decode("ascii").rstrip("=")

    headers = {"x-apikey": api_key}

    try:
        response = requests.get(
            f"{API_URL}/{url_id}",
            headers=headers,
            timeout=REQUEST_TIMEOUT,
        )

        if response.status_code != 200:
            return _unknown_result(
                f"VirusTotal returned HTTP {response.status_code}"
            )

        payload = response.json()
        attributes = payload["data"]["attributes"]
        stats = attributes["last_analysis_stats"]

        counts = {}
        for key in ("malicious", "suspicious", "harmless", "undetected"):
            value = stats.get(key, 0)
            if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                return _unknown_result("Invalid analysis statistics")
            counts[key] = value

        return {
            "status": "success",
            **counts,
            "reason": "Existing VirusTotal URL report retrieved",
        }

    except (
        requests.RequestException,
        ValueError,
        KeyError,
        TypeError,
        UnicodeError,
    ):
        return _unknown_result("VirusTotal lookup failed or response was invalid")
