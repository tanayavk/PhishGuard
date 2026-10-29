
"""Offline, heuristic-based URL threat analysis."""

from ipaddress import ip_address
from urllib.parse import urlsplit
from collections import Counter
from math import log2


SUSPICIOUS_KEYWORDS = {
    "login",
    "verify",
    "verification",
    "update",
    "secure",
    "account",
    "password",
    "signin",
    "sign-in",
    "confirm",
    "wallet",
    "banking",
    "authenticate",
    "reset",
}


def _calculate_entropy(value: str) -> float:
    """Calculate Shannon entropy for a string."""
    if not value:
        return 0.0

    length = len(value)
    frequencies = Counter(value)

    return -sum(
        (count / length) * log2(count / length)
        for count in frequencies.values()
    )


def extract_url_features(url: str) -> dict[str, float]:
    """Extract numeric lexical features without making network requests.

    Invalid URLs return zero-valued features. These values are indicators,
    not a verdict that a URL is safe or malicious.
    """
    feature_names = {
        "url_length": 0.0,
        "hostname_length": 0.0,
        "is_ip_host": 0.0,
        "dot_count": 0.0,
        "hyphen_count": 0.0,
        "at_count": 0.0,
        "domain_entropy": 0.0,
        "suspicious_keyword_count": 0.0,
    }

    if not isinstance(url, str) or not url.strip():
        return feature_names

    candidate = url.strip()

    try:
        parsed = urlsplit(candidate)

        if parsed.scheme.lower() not in {"http", "https"}:
            return feature_names

        hostname = parsed.hostname
        if not hostname:
            return feature_names

        # Validate malformed or out-of-range ports.
        _ = parsed.port

        hostname = hostname.lower()

        try:
            ip_address(hostname)
            is_ip_host = 1.0
        except ValueError:
            is_ip_host = 0.0

        searchable_text = candidate.lower()
        keyword_count = sum(
            searchable_text.count(keyword)
            for keyword in SUSPICIOUS_KEYWORDS
        )

        return {
            "url_length": float(len(candidate)),
            "hostname_length": float(len(hostname)),
            "is_ip_host": is_ip_host,
            "dot_count": float(hostname.count(".")),
            "hyphen_count": float(hostname.count("-")),
            "at_count": float(candidate.count("@")),
            "domain_entropy": float(_calculate_entropy(hostname)),
            "suspicious_keyword_count": float(keyword_count),
        }

    except (ValueError, UnicodeError):
        return feature_names

def analyze_url(url: str) -> dict:
    """Return a heuristic risk score and explainable indicators.

    This function never opens the URL or makes network requests.
    A score is an indicator, not proof that a URL is malicious.
    """
    reasons: list[str] = []
    score = 0

    if not isinstance(url, str) or not url.strip():
        return {"score": 0, "reasons": ["Empty or invalid URL input"]}

    candidate = url.strip()

    try:
        parsed = urlsplit(candidate)

        if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
            return {"score": 0, "reasons": ["Malformed or unsupported URL"]}

        hostname = parsed.hostname

        # Validate the port; accessing parsed.port raises ValueError
        # for non-numeric or out-of-range ports.
        _ = parsed.port

        # HTTP does not encrypt the connection.
        if parsed.scheme.lower() == "http":
            score += 20
            reasons.append("URL does not use HTTPS")

        # IP-address hosts can be suspicious, but are not inherently malicious.
        try:
            ip_address(hostname)
        except ValueError:
            pass
        else:
            score += 25
            reasons.append("Host is an IP address")

        # User information before @ can disguise the actual destination.
        if "@" in parsed.netloc:
            score += 25
            reasons.append("URL contains an @ symbol in its authority")

        if len(hostname) > 50:
            score += 10
            reasons.append("Hostname is unusually long")

        if hostname.count(".") >= 4:
            score += 10
            reasons.append("Hostname contains many subdomains")

        if len(candidate) > 200:
            score += 10
            reasons.append("URL is unusually long")

    except (ValueError, UnicodeError):
        return {"score": 0, "reasons": ["Malformed or unsupported URL"]}

    return {"score": min(score, 100), "reasons": reasons}
