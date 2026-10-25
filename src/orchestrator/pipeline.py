
"""Orchestrate offline indicators, reputation lookups, scoring, and reporting."""

from __future__ import annotations

from src.schemas import AnalysisSignals, ExtractedArtifacts, FinalSecurityReport
from src.detection.feature_extraction import analyze_url
from src.detection.virustotal import analyze_url_reputation
from src.detection.attachment_check import analyze_attachment
from src.orchestrator.policy_engine import score_risk
from src.reporting.report_builder import build_report
from src.orchestrator.agent import investigate_artifact
from src.config import get_gemini_api_key
from src.orchestrator.gemini_provider import investigate_with_gemini


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
    successful_reputations: dict[str, dict[str, int]] = {}
    extra_evidence: list[str] = []
    analysis_incomplete: bool = False

    # URL heuristics run locally. VirusTotal checks are handled separately.
    for url in urls:
        heuristic_result = analyze_url(url)
        url_score = heuristic_result.get("score", 0)

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

    # Analyze attachment metadata only; never execute or open attachments.
    attachment_flags: list[str] = []

    for attachment in artifacts.attachment_hashes:
        attachment_result = analyze_attachment(attachment)

        if attachment_result.get("status") != "analyzed":
            analysis_incomplete = True

        for flag in attachment_result.get("flags", []):
            if isinstance(flag, str) and flag.strip():
                attachment_flags.append(flag.strip())

    signals = AnalysisSignals(
        url_scores=url_scores,
        vt_reputation=successful_reputations,
        static_attachment_flags=attachment_flags,
        needs_agent_investigation=analysis_incomplete,
        analysis_incomplete=analysis_incomplete
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
