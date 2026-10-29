
"""VirusTotal URL reputation client with safe failure handling."""

import base64
from typing import Any
from urllib.parse import urlsplit
import time
from collections import deque
from threading import Lock
import requests
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from src.config import PROJECT_ROOT


API_URL = "https://www.virustotal.com/api/v3/urls"
REQUEST_TIMEOUT = 10

CACHE_DB_PATH = PROJECT_ROOT / "data" / "cache.db"
MAX_REQUESTS_PER_MINUTE = 4
RATE_LIMIT_WINDOW_SECONDS = 60

_request_timestamps = deque()
_rate_limit_lock = Lock()



def _init_cache() -> None:
    """Create the VirusTotal cache table if it does not exist."""
    CACHE_DB_PATH.parent.mkdir(parents=True, exist_ok=True)

    with sqlite3.connect(CACHE_DB_PATH, timeout=10) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS vt_cache (
                target TEXT PRIMARY KEY,
                positives INTEGER NOT NULL,
                total INTEGER NOT NULL,
                last_checked TEXT NOT NULL,
                malicious INTEGER NOT NULL DEFAULT 0,
                suspicious INTEGER NOT NULL DEFAULT 0,
                harmless INTEGER NOT NULL DEFAULT 0,
                undetected INTEGER NOT NULL DEFAULT 0
            )
            """
        )

        columns = {
            row[1]
            for row in conn.execute("PRAGMA table_info(vt_cache)")
        }

        for column in ("malicious", "suspicious", "harmless", "undetected"):
            if column not in columns:
                conn.execute(
                    f"ALTER TABLE vt_cache ADD COLUMN {column} "
                    "INTEGER NOT NULL DEFAULT 0"
                )




def _get_cached_result(target: str) -> dict[str, Any] | None:
    """Return cached VirusTotal counts, or None on a cache miss."""
    _init_cache()

    with sqlite3.connect(CACHE_DB_PATH, timeout=10) as conn:
        row = conn.execute(
            """
            SELECT malicious, suspicious, harmless, undetected, last_checked
            FROM vt_cache
            WHERE target = ?
            """,
            (target,),
        ).fetchone()

    if row is None:
        return None

    malicious, suspicious, harmless, undetected, last_checked = row

    return {
        "status": "success",
        "malicious": malicious,
        "suspicious": suspicious,
        "harmless": harmless,
        "undetected": undetected,
        "last_checked": last_checked,
        "reason": "Cached VirusTotal reputation",
    }




def _store_cached_result(target: str, result: dict[str, Any]) -> None:
    """Store a successful VirusTotal result in SQLite."""
    if result.get("status") != "success":
        return

    keys = ("malicious", "suspicious", "harmless", "undetected")
    counts = [result.get(key) for key in keys]

    if any(
        not isinstance(value, int)
        or isinstance(value, bool)
        or value < 0
        for value in counts
    ):
        return

    malicious, suspicious, harmless, undetected = counts
    positives = malicious + suspicious
    total = sum(counts)
    last_checked = datetime.now(timezone.utc).isoformat()

    _init_cache()

    with sqlite3.connect(CACHE_DB_PATH, timeout=10) as conn:
        conn.execute(
            """
            INSERT INTO vt_cache (
                target, positives, total, last_checked,
                malicious, suspicious, harmless, undetected
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(target) DO UPDATE SET
                positives = excluded.positives,
                total = excluded.total,
                last_checked = excluded.last_checked,
                malicious = excluded.malicious,
                suspicious = excluded.suspicious,
                harmless = excluded.harmless,
                undetected = excluded.undetected
            """,
            (
                target, positives, total, last_checked,
                malicious, suspicious, harmless, undetected,
            ),
        )



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

# def _allow_api_request() -> bool:
#     """Allow at most four API requests in any rolling 60-second window."""
#     now = time.monotonic()

#     with _rate_limit_lock:
#         while (
#             _request_timestamps
#             and now - _request_timestamps[0] >= RATE_LIMIT_WINDOW_SECONDS
#         ):
#             _request_timestamps.popleft()

#         if len(_request_timestamps) >= MAX_REQUESTS_PER_MINUTE:
#             return False

#         _request_timestamps.append(now)
#         return True


def _wait_for_api_slot() -> None:
    """Wait until a request slot is available under the rolling rate limit."""
    while True:
        with _rate_limit_lock:
            now = time.monotonic()

            while (
                _request_timestamps
                and now - _request_timestamps[0] >= RATE_LIMIT_WINDOW_SECONDS
            ):
                _request_timestamps.popleft()

            if len(_request_timestamps) < MAX_REQUESTS_PER_MINUTE:
                _request_timestamps.append(now)
                return

            wait_seconds = (
                RATE_LIMIT_WINDOW_SECONDS
                - (now - _request_timestamps[0])
            )

        time.sleep(max(wait_seconds, 0.01))


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
    cached_result = _get_cached_result(candidate)
    if cached_result is not None:
        return cached_result
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
        _wait_for_api_slot()
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

        result = {
            "status": "success",
            **counts,
            "reason": "Existing VirusTotal URL report retrieved",
        }
        _store_cached_result(candidate, result)
        return result

    except (
        requests.RequestException,
        ValueError,
        KeyError,
        TypeError,
        UnicodeError,
    ):
        return _unknown_result("VirusTotal lookup failed or response was invalid")



def analyze_file_reputation(file_hash: str) -> dict[str, Any]:
    """Look up an existing VirusTotal file report by SHA-256 hash."""
    import re

    if not isinstance(file_hash, str):
        return _unknown_result("Invalid SHA-256 hash")

    candidate = file_hash.strip().lower()
    if not re.fullmatch(r"[a-f0-9]{64}", candidate):
        return _unknown_result("Invalid SHA-256 hash")

    cache_key = f"file:{candidate}"
    cached_result = _get_cached_result(cache_key)
    if cached_result is not None:
        return cached_result

    from src.config import get_vt_api_key

    api_key = get_vt_api_key()
    if not api_key:
        return _unknown_result("VT_API_KEY is not configured")

    # if not _allow_api_request():
    #     return _unknown_result(
    #         "VirusTotal rate limit reached: maximum four requests per minute"
    #     )
    _wait_for_api_slot()

    try:
        response = requests.get(
            f"https://www.virustotal.com/api/v3/files/{candidate}",
            headers={"x-apikey": api_key},
            timeout=REQUEST_TIMEOUT,
        )

        if response.status_code != 200:
            return _unknown_result(
                f"VirusTotal returned HTTP {response.status_code}"
            )

        payload = response.json()
        stats = payload["data"]["attributes"]["last_analysis_stats"]

        counts = {}
        for key in ("malicious", "suspicious", "harmless", "undetected"):
            value = stats.get(key, 0)
            if (
                not isinstance(value, int)
                or isinstance(value, bool)
                or value < 0
            ):
                return _unknown_result("Invalid analysis statistics")
            counts[key] = value

        result = {
            "status": "success",
            **counts,
            "reason": "Existing VirusTotal file report retrieved",
        }
        _store_cached_result(cache_key, result)
        return result

    except (
        requests.RequestException,
        ValueError,
        KeyError,
        TypeError,
        UnicodeError,
    ):
        return _unknown_result(
            "VirusTotal file lookup failed or response was invalid"
        )
