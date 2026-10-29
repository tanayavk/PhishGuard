
"""Orchestrate offline indicators, reputation lookups, scoring, and reporting."""

from __future__ import annotations

from src.schemas import AnalysisSignals, ExtractedArtifacts, FinalSecurityReport
from src.detection.feature_extraction import analyze_url
from src.detection.attachment_check import analyze_attachment
from src.orchestrator.policy_engine import score_risk
from src.reporting.report_builder import build_report
from src.orchestrator.agent import investigate_artifact
from src.config import get_gemini_api_key
from src.orchestrator.gemini_provider import investigate_with_gemini
from src.detection.ml_classifier import predict_url_risk
from src.detection.virustotal import (
    analyze_url_reputation,
    analyze_file_reputation,
)
from urllib.parse import urlparse
from math import log2
from collections import Counter

def _domain_entropy(url: str) -> float:
    """Calculate Shannon entropy of a URL hostname."""
    hostname = urlparse(url).hostname or ""
    if not hostname:
        return 0.0

    length = len(hostname)
    frequencies = Counter(hostname.lower())

    return -sum(
        (count / length) * log2(count / length)
        for count in frequencies.values()
    )

def analyze_artifacts(artifacts: ExtractedArtifacts) -> FinalSecurityReport:
    """Analyze extracted email artifacts and return a validated security report."""

    # Combine URLs found in email text and QR codes, preserving order.
    urls: list[str] = []
    seen_urls: set[str] = set()

    for url in artifacts.urls + artifacts.qr_urls:
        if not isinstance(url, str) or not url.strip():
            continue

        candidate = url.strip()
        deduplication_key = candidate.casefold()

        if deduplication_key not in seen_urls:
            seen_urls.add(deduplication_key)
            urls.append(candidate)
    url_scores: dict[str, float] = {}
    url_ml_scores: dict[str, float] = {}
    successful_reputations: dict[str, dict[str, int]] = {}
    extra_evidence: list[str] = []
    analysis_incomplete: bool = False
    needs_agent_investigation: bool = False

    # URL heuristics run locally. VirusTotal checks are handled separately.
    for url in urls:
        heuristic_result = analyze_url(url)
        url_score = heuristic_result.get("score", 0)

        # ML predictions are probabilities, separate from heuristic scores.
        try:
            ml_score = predict_url_risk(url)

            if (
                isinstance(ml_score, (int, float))
                and not isinstance(ml_score, bool)
                and 0.0 <= ml_score <= 1.0
            ):
                url_ml_scores[url] = float(ml_score)
                extra_evidence.append(
                    f"URL ML classifier risk probability: {ml_score:.3f}"
                )

                if 0.40 <= ml_score <= 0.70:
                    needs_agent_investigation = True
                    extra_evidence.append(
                        "URL ML classifier returned an uncertain probability; "
                        "additional investigation is recommended"
                    )
            else:
                analysis_incomplete = True
                extra_evidence.append(
                    "URL ML classifier returned an invalid probability"
                )

        except Exception:
            # A classifier failure must not crash analysis or imply safety.
            analysis_incomplete = True
            extra_evidence.append(
                "URL ML classifier was unavailable; this result is inconclusive"
            )


        if (
            isinstance(url_score, (int, float))
            and not isinstance(url_score, bool)
        ):
            url_scores[url] = float(url_score)
        else:
            url_scores[url] = 0.0
            analysis_incomplete = True
            extra_evidence.append(
                f"URL analysis returned an invalid score for {url}"
            )

        for reason in heuristic_result.get("reasons", []):
            if isinstance(reason, str) and reason.strip():
                extra_evidence.append(f"URL indicator for {url}: {reason}")

        # This function is patched by the integration tests, so tests remain offline.
        try:
            reputation = analyze_url_reputation(url)
        except Exception:
            # A reputation service failure must not crash the email pipeline.
            reputation = {
                "status": "unknown",
                "reason": "Reputation lookup failed unexpectedly",
            }

        if not isinstance(reputation, dict):
            reputation = {
                "status": "unknown",
                "reason": "Reputation service returned an invalid result",
            }

        if reputation.get("status") == "success":
            counts: dict[str, int] = {}
            valid_counts = True

            for key in ("malicious", "suspicious", "harmless", "undetected"):
                value = reputation.get(key, 0)

                if (
                    not isinstance(value, int)
                    or isinstance(value, bool)
                    or value < 0
                ):
                    valid_counts = False
                    break

                counts[key] = value

            if valid_counts:
                # The schema stores integer counts only, not a status string.
                successful_reputations[url] = counts
                detections = counts["malicious"] + counts["suspicious"]
                entropy = _domain_entropy(url)

                if detections == 0 and entropy >= 3.5:
                  needs_agent_investigation = True
                  extra_evidence.append(
                  f"URL has zero VirusTotal malicious/suspicious detections "
                  f"but high hostname entropy ({entropy:.2f}): {url}"
    )
            else:
                analysis_incomplete = True
                extra_evidence.append(
                    f"VirusTotal reputation data is invalid for {url}"
                )
        else:
            analysis_incomplete = True
            reason = reputation.get("reason", "No reputation result available")
            if not isinstance(reason, str) or not reason.strip():
                reason = "No reputation result available"

            extra_evidence.append(
                f"VirusTotal reputation unknown for {url}: {reason}"
            )
    # Analyze attachment metadata and check existing VirusTotal file reports.
    # Never execute, open, or upload attachments.
    attachment_flags: list[str] = []

    for attachment in artifacts.attachment_hashes:
        attachment_result = analyze_attachment(attachment)

        if attachment_result.get("status") != "analyzed":
            analysis_incomplete = True

        for flag in attachment_result.get("flags", []):
            if isinstance(flag, str) and flag.strip():
                attachment_flags.append(flag.strip())

        file_hash = attachment.get("sha256")
        if isinstance(file_hash, str) and file_hash.strip():
            try:
                file_reputation = analyze_file_reputation(file_hash)
            except Exception:
                file_reputation = {
                    "status": "unknown",
                    "reason": "File reputation lookup failed unexpectedly",
                }

            if (
                isinstance(file_reputation, dict)
                and file_reputation.get("status") == "success"
            ):
                counts = {}
                valid_counts = True

                for key in (
                    "malicious",
                    "suspicious",
                    "harmless",
                    "undetected",
                ):
                    value = file_reputation.get(key, 0)

                    if (
                        not isinstance(value, int)
                        or isinstance(value, bool)
                        or value < 0
                    ):
                        valid_counts = False
                        break

                    counts[key] = value

                if valid_counts:
                    detections = counts["malicious"] + counts["suspicious"]
                    extra_evidence.append(
                        f"VirusTotal file reputation for "
                        f"{attachment.get('filename', 'unknown attachment')}: "
                        f"{detections} detections "
                        f"(malicious={counts['malicious']}, "
                        f"suspicious={counts['suspicious']})"
                    )

                    if detections > 0:
                        attachment_flags.append(
                            f"VirusTotal reported {detections} detections "
                            f"for attachment "
                            f"{attachment.get('filename', 'unknown attachment')}"
                        )
                else:
                    analysis_incomplete = True
                    extra_evidence.append(
                        "VirusTotal returned invalid file reputation counts"
                    )
            else:
                analysis_incomplete = True
                reason = (
                    file_reputation.get("reason", "No reputation result available")
                    if isinstance(file_reputation, dict)
                    else "Invalid reputation response"
                )
                extra_evidence.append(
                    f"VirusTotal file reputation unknown for "
                    f"{attachment.get('filename', 'unknown attachment')}: "
                    f"{reason}"
                )
        else:
            analysis_incomplete = True
            extra_evidence.append(
                f"Attachment {attachment.get('filename', 'unknown attachment')} "
                "has no usable SHA-256 hash for VirusTotal lookup"
            )


        if attachment_result.get("status") != "analyzed":
            analysis_incomplete = True

        for flag in attachment_result.get("flags", []):
            if isinstance(flag, str) and flag.strip():
                attachment_flags.append(flag.strip())

        # Include signature validation performed while attachment bytes were available.
    for result in artifacts.attachment_validation_results:
        status = result.get("status")
        filename = result.get("filename", "unknown attachment")
        detail = result.get("detail", "No validation detail available")

        if status == "mismatch":
            attachment_flags.append(
                f"Attachment signature mismatch for {filename}: {detail}"
            )
        elif status == "unknown":
            analysis_incomplete = True
            extra_evidence.append(
                f"Attachment signature validation inconclusive for {filename}: {detail}"
            )

    sender = (artifacts.sender or "").strip()
    return_path = (artifacts.return_path or "").strip()

    if sender and return_path and sender.casefold() != return_path.casefold():
        needs_agent_investigation = True
        extra_evidence.append(
            "Return-Path and From addresses differ; "
            "additional investigation is recommended"
        )
    # Construct signals after processing all attachments.
    signals = AnalysisSignals(
        url_scores=url_scores,
        url_ml_scores=url_ml_scores,
        vt_reputation=successful_reputations,
        static_attachment_flags=attachment_flags,
        needs_agent_investigation=(
            analysis_incomplete or needs_agent_investigation
        ),
        analysis_incomplete=analysis_incomplete,
    )

    risk_result = score_risk(signals)

    # Retain detailed heuristic reasons and unknown-service results in the report.
    combined_evidence = list(risk_result["evidence"])
    for item in extra_evidence:
        if item not in combined_evidence:
            combined_evidence.append(item)

    risk_result["evidence"] = combined_evidence

    agent_notes: str | None = None

    # Investigate uncertain cases only. Use Gemini when configured;
    # otherwise preserve the safe offline fallback.
    if signals.needs_agent_investigation:
        def offline_investigation_tool(
            question: str,
        ) -> dict[str, object]:
            return {
                "reasoning": (
                    "The available analysis is incomplete. "
                    "No additional live investigation provider is configured."
                ),
                "red_flags": [
                    "Additional investigation is unavailable in offline mode"
                ],
                "confidence_delta": 0.0,
                "continue_investigation": False,
            }

        investigation_tool = (
            investigate_with_gemini
            if get_gemini_api_key()
            else offline_investigation_tool
        )


        try:
            agent_result = investigate_artifact(
                evidence=combined_evidence,
                investigation_tool=investigation_tool,
            )

            notes = [
                agent_result.get("reasoning", ""),
                *agent_result.get("red_flags", []),
            ]
            agent_notes = "\n".join(
                item.strip()
                for item in notes
                if isinstance(item, str) and item.strip()
            )

            trace = agent_result.get("trace", [])
            if trace:
                agent_notes += (
                    "\nInvestigation trace: "
                    + str([
                        event.get("event")
                        for event in trace
                        if isinstance(event, dict)
                    ])
                )

        except Exception:
            # Agent failure must not make uncertain evidence look safe.
            agent_notes = "Additional investigation failed; analysis remains incomplete."

    return build_report(artifacts, risk_result, agent_notes=agent_notes)
