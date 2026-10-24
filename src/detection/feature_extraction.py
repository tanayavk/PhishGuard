
"""Offline, heuristic-based URL threat analysis."""

from ipaddress import ip_address
from urllib.parse import urlsplit


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
