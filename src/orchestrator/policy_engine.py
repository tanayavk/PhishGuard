
"""Deterministic, explainable PhishGuard risk scoring."""

from typing import Any

from src.schemas import AnalysisSignals, ActionEnum, VerdictEnum


def score_risk(signals: AnalysisSignals) -> dict[str, Any]:
    """Score supplied security indicators on a 0-100 scale.

    These are initial heuristic weights, not calibrated probabilities.
    Unknown external reputation results do not count as safe evidence.
    """
    score = 0.0
    evidence: list[str] = []

    # URL indicators: use the highest score to reduce duplicate counting
    # when a URL appears in both email text and a QR code.
    valid_url_scores = []
    for url, value in signals.url_scores.items():
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            valid_url_scores.append(max(0.0, min(float(value), 100.0)))

    if valid_url_scores:
        highest_url_score = max(valid_url_scores)
        contribution = highest_url_score * 0.75
        score += contribution
        evidence.append(
            f"URL heuristic indicators: highest score {highest_url_score:.0f}/100 "
            f"(contribution {contribution:.1f})"
        )

    # VirusTotal: only valid, explicitly successful reports contribute.
    for url, reputation in signals.vt_reputation.items():
        if not isinstance(reputation, dict):
            evidence.append(f"VirusTotal reputation unknown for {url}")
            continue

        if reputation.get("status", "success") != "success":
            evidence.append(f"VirusTotal reputation unknown for {url}")
            continue

        malicious = reputation.get("malicious", 0)
        suspicious = reputation.get("suspicious", 0)

        if (
            not isinstance(malicious, int)
            or isinstance(malicious, bool)
            or malicious < 0
            or not isinstance(suspicious, int)
            or isinstance(suspicious, bool)
            or suspicious < 0
        ):
            evidence.append(f"VirusTotal reputation data invalid for {url}")
            continue

        if malicious > 0:
            contribution = min(60.0, malicious * 10.0)
            score += contribution
            evidence.append(
                f"VirusTotal reported {malicious} malicious detection(s) "
                f"for {url} (contribution {contribution:.1f})"
            )

        if suspicious > 0:
            contribution = min(20.0, suspicious * 5.0)
            score += contribution
            evidence.append(
                f"VirusTotal reported {suspicious} suspicious detection(s) "
                f"for {url} (contribution {contribution:.1f})"
            )

        if malicious == 0 and suspicious == 0:
            evidence.append(
                f"VirusTotal reported no malicious or suspicious detections for {url}; "
                "this alone does not prove the URL is safe"
            )

    # Attachment flags are indicators, not proof of maliciousness.
    unique_flags = sorted({
        flag.strip()
        for flag in signals.static_attachment_flags
        if isinstance(flag, str) and flag.strip()
    })

    if unique_flags:
        contribution = min(30.0, len(unique_flags) * 15.0)
        score += contribution
        evidence.extend(
            f"Attachment indicator: {flag}" for flag in unique_flags
        )

    if signals.needs_agent_investigation:
        evidence.append("Additional investigation is recommended")

    score = round(min(max(score, 0.0), 100.0), 1)

    # if score >= 60:
    #     verdict = VerdictEnum.MALICIOUS
    #     action = ActionEnum.QUARANTINE
    # elif score >= 25:
    #     verdict = VerdictEnum.SUSPICIOUS
    #     action = ActionEnum.WARN
    # else:
    #     verdict = VerdictEnum.SAFE
    #     action = ActionEnum.ALLOW

    if score >= 60:
        verdict = VerdictEnum.MALICIOUS
        action = ActionEnum.QUARANTINE
    elif score >= 25:
        verdict = VerdictEnum.SUSPICIOUS
        action = ActionEnum.WARN
    elif signals.analysis_incomplete:
        verdict = VerdictEnum.INCONCLUSIVE
        action = ActionEnum.WARN
        evidence.append(
            "Analysis is incomplete; the available evidence is insufficient "
            "to establish that the message is safe"
        )
    else:
        verdict = VerdictEnum.SAFE
        action = ActionEnum.ALLOW

    if not evidence:
        evidence.append("No risk indicators were supplied; this is not proof of safety")

    return {
        "score": score,
        "verdict": verdict,
        "action": action,
        "evidence": evidence,
    }
