"""Safe, read-only evidence inspection tools for PhishGuard."""

from __future__ import annotations

import re
from email.utils import parseaddr
from math import isfinite

from src.schemas import AnalysisSignals, ExtractedArtifacts


def inspect_sender(artifacts: ExtractedArtifacts) -> list[str]:
    """Check whether the From and Return-Path domains differ."""

    sender = parseaddr(artifacts.sender or "")[1]
    return_path = parseaddr(artifacts.return_path or "")[1]

    if not sender or not return_path:
        return ["Sender identity comparison unavailable."]

    sender_domain = sender.rsplit("@", 1)[-1].casefold()
    return_domain = return_path.rsplit("@", 1)[-1].casefold()

    if sender_domain != return_domain:
        return [
            f"Sender domain mismatch: From={sender_domain}, "
            f"Return-Path={return_domain}"
        ]

    return ["Sender and Return-Path domains match."]


def inspect_urls(signals: AnalysisSignals) -> list[str]:
    """Summarize existing URL analysis without visiting URLs."""

    findings = []

    urls = (
        set(signals.url_scores)
        | set(signals.url_ml_scores)
        | set(signals.vt_reputation)
    )

    for url in sorted(urls):
        details = [f"URL: {url}"]

        heuristic = signals.url_scores.get(url)
        if isinstance(heuristic, (int, float)) and not isinstance(heuristic, bool) and isfinite(heuristic):
            details.append(f"Heuristic score: {heuristic}")

        ml_score = signals.url_ml_scores.get(url)
        if isinstance(ml_score, (int, float)) and not isinstance(ml_score, bool) and isfinite(ml_score):
            details.append(f"ML risk probability: {ml_score:.3f}")

        reputation = signals.vt_reputation.get(url)

        if isinstance(reputation, dict):
            malicious = reputation.get("malicious", 0)
            suspicious = reputation.get("suspicious", 0)

            if (
                isinstance(malicious, int)
                and not isinstance(malicious, bool)
                and malicious >= 0
                and isinstance(suspicious, int)
                and not isinstance(suspicious, bool)
                and suspicious >= 0
            ):
                details.append(
                    f"VirusTotal detections: "
                    f"malicious={malicious}, suspicious={suspicious}"
                )

        findings.append("; ".join(details))

    return findings or ["No URL analysis results available."]


def inspect_attachments(
    artifacts: ExtractedArtifacts,
    signals: AnalysisSignals,
) -> list[str]:
    """Inspect attachment metadata and existing static-analysis findings."""

    findings = []

    for attachment in artifacts.attachment_hashes:
        filename = str(attachment.get("filename", "unknown"))[:150]
        mime = str(attachment.get("mime", "unknown"))[:100]
        file_hash = attachment.get("sha256", "")

        valid_hash = (
            isinstance(file_hash, str)
            and re.fullmatch(r"[a-fA-F0-9]{64}", file_hash) is not None
        )

        findings.append(
            f"Attachment: {filename}; MIME: {mime}; "
            f"SHA-256 available: {valid_hash}"
        )

    findings.extend(
        f"Static attachment finding: {flag}"
        for flag in signals.static_attachment_flags
        if isinstance(flag, str) and flag.strip()
    )

    for result in artifacts.attachment_validation_results:
        findings.append(
            f"Attachment validation: "
            f"{str(result.get('filename', 'unknown'))[:150]} - "
            f"{str(result.get('status', 'unknown'))[:50]}"
        )

    return findings or ["No attachment analysis results available."]


def run_investigation_tools(
    artifacts: ExtractedArtifacts,
    signals: AnalysisSignals,
) -> list[str]:
    """Run all local, read-only investigation tools."""

    findings = []

    findings.extend(inspect_sender(artifacts))
    findings.extend(inspect_urls(signals))
    findings.extend(inspect_attachments(artifacts, signals))

    return findings[:40]