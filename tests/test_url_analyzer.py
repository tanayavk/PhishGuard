
"""Offline tests for PhishGuard URL threat analysis."""

from src.detection.feature_extraction import analyze_url


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