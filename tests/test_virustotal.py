
"""Offline tests for the VirusTotal client."""

from unittest.mock import Mock, patch

from src.detection.virustotal import analyze_url_reputation


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
