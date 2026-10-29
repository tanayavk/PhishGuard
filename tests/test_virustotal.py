
"""Offline tests for the VirusTotal client."""
import pytest
from unittest.mock import Mock, patch


from src.detection.virustotal import analyze_url_reputation


@pytest.fixture(autouse=True)
def isolated_vt_cache(tmp_path, monkeypatch):
    import src.detection.virustotal as vt

    monkeypatch.setattr(
        vt,
        "CACHE_DB_PATH",
        tmp_path / "vt_cache.db",
    )
    monkeypatch.setattr(vt, "_request_timestamps", vt.deque())


@patch("src.detection.virustotal.requests.get")
def test_successful_lookup_returns_detection_counts(mock_get, monkeypatch):
    monkeypatch.setenv("VT_API_KEY", "test-key")

    response = Mock()
    response.status_code = 200
    response.json.return_value = {
        "data": {
            "attributes": {
                "last_analysis_stats": {
                    "malicious": 3,
                    "suspicious": 1,
                    "harmless": 20,
                    "undetected": 5,
                }
            }
        }
    }
    mock_get.return_value = response

    result = analyze_url_reputation("https://example.com")

    assert result["status"] == "success"
    assert result["malicious"] == 3
    assert result["suspicious"] == 1
    mock_get.assert_called_once()


@patch("src.detection.virustotal.requests.get")
def test_cache_hit_avoids_api_request(mock_get, monkeypatch):
    monkeypatch.setenv("VT_API_KEY", "test-key")

    from src.detection.virustotal import _store_cached_result

    _store_cached_result(
        "https://cached.example",
        {
            "status": "success",
            "malicious": 2,
            "suspicious": 1,
            "harmless": 20,
            "undetected": 3,
        },
    )

    result = analyze_url_reputation("https://cached.example")

    assert result["status"] == "success"
    assert result["malicious"] == 2
    assert result["suspicious"] == 1
    mock_get.assert_not_called()


@patch("src.detection.virustotal.requests.get")
def test_cache_miss_calls_api_and_stores_result(mock_get, monkeypatch):
    monkeypatch.setenv("VT_API_KEY", "test-key")

    response = Mock()
    response.status_code = 200
    response.json.return_value = {
        "data": {
            "attributes": {
                "last_analysis_stats": {
                    "malicious": 1,
                    "suspicious": 0,
                    "harmless": 25,
                    "undetected": 4,
                }
            }
        }
    }
    mock_get.return_value = response

    result = analyze_url_reputation("https://fresh.example")

    assert result["status"] == "success"
    mock_get.assert_called_once()

    from src.detection.virustotal import _get_cached_result

    cached = _get_cached_result("https://fresh.example")
    assert cached is not None
    assert cached["malicious"] == 1
    assert cached["harmless"] == 25



def test_missing_api_key_returns_unknown(monkeypatch):
    monkeypatch.delenv("VT_API_KEY", raising=False)

    result = analyze_url_reputation("https://example.com")

    assert result["status"] == "unknown"


@patch("src.detection.virustotal.requests.get")
def test_rate_limit_returns_unknown(mock_get, monkeypatch):
    monkeypatch.setenv("VT_API_KEY", "test-key")

    response = Mock()
    response.status_code = 429
    response.json.return_value = {}
    mock_get.return_value = response

    result = analyze_url_reputation("https://example.com")

    assert result["status"] == "unknown"


@patch("src.detection.virustotal.requests.get")
def test_network_error_returns_unknown(mock_get, monkeypatch):
    import requests

    monkeypatch.setenv("VT_API_KEY", "test-key")
    mock_get.side_effect = requests.Timeout("timed out")

    result = analyze_url_reputation("https://example.com")

    assert result["status"] == "unknown"


def test_invalid_url_does_not_make_request(monkeypatch):
    monkeypatch.setenv("VT_API_KEY", "test-key")

    with patch("src.detection.virustotal.requests.get") as mock_get:
        result = analyze_url_reputation("not a URL")

    assert result["status"] == "unknown"
    mock_get.assert_not_called()


import sqlite3
from pathlib import Path

from src.detection.virustotal import (
    analyze_url_reputation,
    _init_cache,
    _get_cached_result,
    _store_cached_result,
)


def test_cache_initialization_creates_expected_table(tmp_path, monkeypatch):
    db_path = tmp_path / "vt_cache.db"
    monkeypatch.setattr(
        "src.detection.virustotal.CACHE_DB_PATH", db_path
    )

    _init_cache()

    with sqlite3.connect(db_path) as conn:
        columns = {
            row[1]
            for row in conn.execute("PRAGMA table_info(vt_cache)")
        }

    assert {"target", "positives", "total", "last_checked"} <= columns


def test_cache_store_and_retrieve(tmp_path, monkeypatch):
    db_path = tmp_path / "vt_cache.db"
    monkeypatch.setattr(
        "src.detection.virustotal.CACHE_DB_PATH", db_path
    )

    _init_cache()
    _store_cached_result(
        "https://example.com",
        {"status": "success", "malicious": 2, "suspicious": 1,
         "harmless": 20, "undetected": 3},
    )

    cached = _get_cached_result("https://example.com")

    assert cached is not None
    assert cached["status"] == "success"
    assert cached["malicious"] == 2
    assert cached["suspicious"] == 1
    assert cached["harmless"] == 20
    assert cached["undetected"] == 3


def test_cache_miss_returns_none(tmp_path, monkeypatch):
    db_path = tmp_path / "vt_cache.db"
    monkeypatch.setattr(
        "src.detection.virustotal.CACHE_DB_PATH", db_path
    )

    _init_cache()

    assert _get_cached_result("https://not-cached.example") is None

@patch("src.detection.virustotal.requests.get")
def test_successful_file_hash_lookup(mock_get, monkeypatch):
    from src.detection.virustotal import analyze_file_reputation

    monkeypatch.setenv("VT_API_KEY", "test-key")

    response = Mock()
    response.status_code = 200
    response.json.return_value = {
        "data": {
            "attributes": {
                "last_analysis_stats": {
                    "malicious": 4,
                    "suspicious": 2,
                    "harmless": 30,
                    "undetected": 6,
                }
            }
        }
    }
    mock_get.return_value = response

    file_hash = "a" * 64
    result = analyze_file_reputation(file_hash)

    assert result["status"] == "success",repr(result)
    assert result["malicious"] == 4
    assert result["suspicious"] == 2
    mock_get.assert_called_once()

    assert mock_get.call_args.args[0] == (
        f"https://www.virustotal.com/api/v3/files/{file_hash}"
    )


def test_invalid_file_hash_does_not_make_request(monkeypatch):
    from src.detection.virustotal import analyze_file_reputation

    monkeypatch.setenv("VT_API_KEY", "test-key")

    with patch("src.detection.virustotal.requests.get") as mock_get:
        result = analyze_file_reputation("not-a-sha256-hash")

    assert result["status"] == "unknown"
    assert result["reason"] == "Invalid SHA-256 hash"
    mock_get.assert_not_called()


@patch("src.detection.virustotal.requests.get")
def test_file_hash_cache_hit_avoids_api_request(mock_get, monkeypatch):
    from src.detection.virustotal import (
        _store_cached_result,
        analyze_file_reputation,
    )

    monkeypatch.setenv("VT_API_KEY", "test-key")
    file_hash = "b" * 64

    _store_cached_result(
        f"file:{file_hash}",
        {
            "status": "success",
            "malicious": 2,
            "suspicious": 1,
            "harmless": 20,
            "undetected": 3,
        },
    )

    result = analyze_file_reputation(file_hash)

    assert result["status"] == "success"
    assert result["malicious"] == 2
    assert result["suspicious"] == 1
    mock_get.assert_not_called()


@patch("src.detection.virustotal.requests.get")
def test_rate_limiter_waits_for_fifth_request_slot(
    mock_get, monkeypatch
):
    import src.detection.virustotal as vt

    monkeypatch.setenv("VT_API_KEY", "test-key")

    mock_response = Mock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "data": {
            "attributes": {
                "last_analysis_stats": {
                    "malicious": 0,
                    "suspicious": 0,
                    "harmless": 10,
                    "undetected": 2,
                }
            }
        }
    }
    mock_get.return_value = mock_response

    # Simulate a full quota without waiting in real time.
    timestamps = [100.0, 101.0, 102.0, 103.0]
    monkeypatch.setattr(vt, "_request_timestamps", vt.deque(timestamps))

    clock = {"now": 104.0}
    sleep_calls = []

    def fake_monotonic():
        return clock["now"]

    def fake_sleep(seconds):
        sleep_calls.append(seconds)
        clock["now"] += seconds

    monkeypatch.setattr(vt.time, "monotonic", fake_monotonic)
    monkeypatch.setattr(vt.time, "sleep", fake_sleep)

    result = analyze_url_reputation(
        "https://rate-test-fifth.example"
    )

    assert result["status"] == "success"
    assert mock_get.call_count == 1
    assert sleep_calls
    assert len(vt._request_timestamps) <= vt.MAX_REQUESTS_PER_MINUTE
