
"""Offline tests for PhishGuard URL threat analysis."""

from src.detection.feature_extraction import analyze_url
from src.detection.feature_extraction import extract_url_features


def test_legitimate_https_url():
    result = analyze_url("https://example.com/login")

    assert result["score"] >= 0
    assert result["score"] <= 100
    assert isinstance(result["reasons"], list)


def test_http_url_is_flagged():
    result = analyze_url("http://example.com/login")

    assert result["score"] > 0
    assert any("HTTPS" in reason for reason in result["reasons"])


def test_ip_address_host_is_flagged():
    result = analyze_url("http://192.0.2.10/login")

    assert result["score"] > 0
    assert any("IP address" in reason for reason in result["reasons"])


def test_url_with_at_symbol_is_flagged():
    result = analyze_url("https://example.com@evil.example/login")

    assert result["score"] > 0
    assert result["reasons"]


def test_malformed_url_returns_safe_default():
    result = analyze_url("not a valid URL")

    assert result["score"] == 0
    assert result["reasons"]


def test_empty_url_returns_safe_default():
    result = analyze_url("")

    assert result["score"] == 0
    assert result["reasons"]


def test_score_is_bounded():
    result = analyze_url(
        "http://192.0.2.10/a/b/c?redirect=http://evil.example"
    )

    assert 0 <= result["score"] <= 100

def test_invalid_port_returns_safe_default():
    result = analyze_url("https://example.com:abc/login")

    assert result["score"] == 0
    assert result["reasons"] == ["Malformed or unsupported URL"]


def test_out_of_range_port_returns_safe_default():
    result = analyze_url("https://example.com:70000/login")

    assert result["score"] == 0
    assert result["reasons"] == ["Malformed or unsupported URL"]


def test_extract_url_features_returns_expected_keys():
    features = extract_url_features(
        "https://secure-account.example.com/login"
    )

    assert set(features) == {
        "url_length",
        "hostname_length",
        "is_ip_host",
        "dot_count",
        "hyphen_count",
        "at_count",
        "domain_entropy",
        "suspicious_keyword_count",
    }


def test_extract_url_features_detects_ip_host():
    features = extract_url_features("https://192.0.2.10/login")

    assert features["is_ip_host"] == 1.0


def test_extract_url_features_counts_domain_characters():
    features = extract_url_features(
        "https://secure-account.example.com/login"
    )

    assert features["dot_count"] == 2.0
    assert features["hyphen_count"] == 1.0
    assert features["at_count"] == 0.0


def test_extract_url_features_detects_suspicious_keywords():
    features = extract_url_features(
        "https://secure-account.example.com/login"
    )

    assert features["suspicious_keyword_count"] >= 2.0


def test_extract_url_features_handles_invalid_input():
    features = extract_url_features("not a URL")

    assert all(value == 0.0 for value in features.values())


def test_extract_url_features_handles_empty_input():
    features = extract_url_features("")

    assert all(value == 0.0 for value in features.values())
