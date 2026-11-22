"""Orchestrate offline indicators, reputation lookups, scoring, and reporting."""

from __future__ import annotations

from collections import Counter
from email.utils import parseaddr
from math import log2
from urllib.parse import urlparse

from src.schemas import AnalysisSignals, ExtractedArtifacts, FinalSecurityReport
from src.detection.feature_extraction import analyze_url
from src.detection.attachment_check import analyze_attachment
from src.detection.ml_classifier import predict_url_risk
from src.detection.virustotal import (
    analyze_url_reputation,
    analyze_file_reputation,
)
from src.orchestrator.policy_engine import score_risk
from src.orchestrator.agent import investigate_artifact
from src.orchestrator.gemini_provider import investigate_with_gemini
from src.orchestrator.investigation_tools import run_investigation_tools
from src.config import get_gemini_api_key
from src.reporting.report_builder import build_report
from src.reporting.audit_logger import log_analysis

MAX_REPORT_EVIDENCE_ITEMS = 100
MAX_REPORT_EVIDENCE_LENGTH = 1000
MAX_AGENT_NOTES_LENGTH = 5000
MAX_AUDIT_ITEMS = 100
MAX_AUDIT_LENGTH = 500


def _sanitize_evidence(items: list) -> list[str]:
    """Validate, normalize, deduplicate and limit report evidence."""

    sanitized = []
    seen = set()

    for item in items:
        if not isinstance(item, str):
            continue

        item = " ".join(item.split())
        item = item[:MAX_REPORT_EVIDENCE_LENGTH]

        if not item or item in seen:
            continue

        seen.add(item)
        sanitized.append(item)

        if len(sanitized) >= MAX_REPORT_EVIDENCE_ITEMS:
            break

    return sanitized


def _sanitize_agent_notes(notes: str | None) -> str | None:
    """Validate and limit investigation notes."""

    if not isinstance(notes, str):
        return None

    notes = notes.strip()

    if not notes:
        return None

    return notes[:MAX_AGENT_NOTES_LENGTH]


def _sanitize_audit(items: list[str]) -> list[str]:
    """Validate and limit audit entries."""

    sanitized = []
    seen = set()

    for item in items:
        if not isinstance(item, str):
            continue

        item = " ".join(item.split())
        item = item[:MAX_AUDIT_LENGTH]

        if not item or item in seen:
            continue

        seen.add(item)
        sanitized.append(item)

        if len(sanitized) >= MAX_AUDIT_ITEMS:
            break

    return sanitized


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


def analyze_artifacts(
    artifacts: ExtractedArtifacts,
) -> FinalSecurityReport:
    """Analyze extracted email artifacts and return a validated report."""

    analysis_audit: list[str] = ["Email analysis started"]

    # --------------------------------------------------
    # 1. Collect and deduplicate URLs
    # --------------------------------------------------

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

    analysis_incomplete = False
    needs_agent_investigation = False

    # --------------------------------------------------
    # 2. URL heuristic, ML and VirusTotal analysis
    # --------------------------------------------------

    for url in urls:

        # URL heuristic analysis
        heuristic_result = analyze_url(url)
        url_score = heuristic_result.get("score", 0)

        # ML classification
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
                        "URL ML classifier returned an uncertain "
                        "probability; additional investigation is recommended"
                    )

            else:
                analysis_incomplete = True

                extra_evidence.append(
                    "URL ML classifier returned an invalid probability"
                )

        except Exception:
            analysis_incomplete = True

            extra_evidence.append(
                "URL ML classifier was unavailable; "
                "this result is inconclusive"
            )

        # Validate heuristic score
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

        # Include heuristic explanations
        for reason in heuristic_result.get("reasons", []):
            if isinstance(reason, str) and reason.strip():
                extra_evidence.append(
                    f"URL indicator for {url}: {reason}"
                )

        # VirusTotal URL reputation
        try:
            reputation = analyze_url_reputation(url)

        except Exception:
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

            for key in (
                "malicious",
                "suspicious",
                "harmless",
                "undetected",
            ):
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

                successful_reputations[url] = counts

                detections = (
                    counts["malicious"] + counts["suspicious"]
                )

                entropy = _domain_entropy(url)

                if detections == 0 and entropy >= 3.5:
                    needs_agent_investigation = True

                    extra_evidence.append(
                        "URL has zero VirusTotal malicious/suspicious "
                        f"detections but high hostname entropy "
                        f"({entropy:.2f}): {url}"
                    )

            else:
                analysis_incomplete = True

                extra_evidence.append(
                    f"VirusTotal reputation data is invalid for {url}"
                )

        else:
            analysis_incomplete = True

            reason = reputation.get(
                "reason",
                "No reputation result available",
            )

            if not isinstance(reason, str) or not reason.strip():
                reason = "No reputation result available"

            extra_evidence.append(
                f"VirusTotal reputation unknown for {url}: {reason}"
            )

    # Record URL analysis stages AFTER processing all URLs.
    analysis_audit.append(
        f"URL heuristic analysis completed: {len(url_scores)} URL(s)"
    )

    analysis_audit.append(
        f"ML classification: {len(url_ml_scores)} valid prediction(s)"
    )

    analysis_audit.append(
        f"VirusTotal URL checks: "
        f"{len(successful_reputations)} successful result(s) "
        f"out of {len(urls)}"
    )

    # --------------------------------------------------
    # 3. Attachment analysis
    # --------------------------------------------------

    attachment_flags: list[str] = []
    successful_file_reputations = 0

    for attachment in artifacts.attachment_hashes:

        # Static attachment analysis
        try:
            attachment_result = analyze_attachment(attachment)

        except Exception:
            attachment_result = {
                "status": "unknown",
                "flags": [],
            }

            analysis_incomplete = True

            extra_evidence.append(
                "Static attachment analysis failed; "
                "manual review is recommended"
            )

        if attachment_result.get("status") != "analyzed":
            analysis_incomplete = True

        for flag in attachment_result.get("flags", []):
            if isinstance(flag, str) and flag.strip():
                attachment_flags.append(flag.strip())

        # VirusTotal file reputation
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

                    successful_file_reputations += 1

                    detections = (
                        counts["malicious"] + counts["suspicious"]
                    )

                    filename = attachment.get(
                        "filename",
                        "unknown attachment",
                    )

                    extra_evidence.append(
                        f"VirusTotal file reputation for {filename}: "
                        f"{detections} detections "
                        f"(malicious={counts['malicious']}, "
                        f"suspicious={counts['suspicious']})"
                    )

                    if detections > 0:
                        attachment_flags.append(
                            f"VirusTotal reported {detections} detections "
                            f"for attachment {filename}"
                        )

                else:
                    analysis_incomplete = True

                    extra_evidence.append(
                        "VirusTotal returned invalid file reputation counts"
                    )

            else:
                analysis_incomplete = True

                reason = (
                    file_reputation.get(
                        "reason",
                        "No reputation result available",
                    )
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

    analysis_audit.append(
        f"Static attachment analysis completed: "
        f"{len(artifacts.attachment_hashes)} attachment(s) processed"
    )

    analysis_audit.append(
        f"VirusTotal file checks: {successful_file_reputations} "
        f"successful result(s)"
    )

    # --------------------------------------------------
    # 4. Attachment signature validation
    # --------------------------------------------------

    for result in artifacts.attachment_validation_results:

        status = result.get("status")
        filename = result.get("filename", "unknown attachment")
        detail = result.get(
            "detail",
            "No validation detail available",
        )

        if status == "mismatch":

            attachment_flags.append(
                f"Attachment signature mismatch for {filename}: {detail}"
            )

        elif status == "unknown":

            analysis_incomplete = True

            extra_evidence.append(
                f"Attachment signature validation inconclusive "
                f"for {filename}: {detail}"
            )

    analysis_audit.append(
        f"Attachment signature validation: "
        f"{len(artifacts.attachment_validation_results)} result(s) processed"
    )

    # --------------------------------------------------
    # 5. Sender and Return-Path validation
    # --------------------------------------------------

    sender = (artifacts.sender or "").strip()
    return_path = (artifacts.return_path or "").strip()

    if sender and return_path:

        sender_email = parseaddr(sender)[1].strip()
        return_path_email = parseaddr(return_path)[1].strip()

        if "@" in sender_email and "@" in return_path_email:

            sender_domain = (
                sender_email.rsplit("@", 1)[1]
                .casefold()
                .rstrip(".")
            )

            return_path_domain = (
                return_path_email.rsplit("@", 1)[1]
                .casefold()
                .rstrip(".")
            )

            if sender_domain != return_path_domain:

                needs_agent_investigation = True

                extra_evidence.append(
                    "From and Return-Path domains differ; "
                    "additional investigation is recommended"
                )

                analysis_audit.append(
                    "Sender and Return-Path domain mismatch detected"
                )

            else:
                analysis_audit.append(
                    "Sender and Return-Path domains match"
                )

    else:
        analysis_audit.append(
            "Sender/Return-Path comparison unavailable"
        )

    # --------------------------------------------------
    # 6. Construct analysis signals
    # --------------------------------------------------

    signals = AnalysisSignals(
        url_scores=url_scores,
        url_ml_scores=url_ml_scores,
        vt_reputation=successful_reputations,
        static_attachment_flags=attachment_flags,
        needs_agent_investigation=(
            analysis_incomplete or needs_agent_investigation
        ),
        analysis_incomplete=(
            analysis_incomplete or needs_agent_investigation
        ),
    )

    # --------------------------------------------------
    # 7. Deterministic risk scoring
    # --------------------------------------------------

    risk_result = score_risk(signals)

    combined_evidence = list(risk_result["evidence"])

    for item in extra_evidence:
        if item not in combined_evidence:
            combined_evidence.append(item)

    risk_result["evidence"] = combined_evidence

    analysis_audit.append(
        "Deterministic risk scoring completed"
    )

    # --------------------------------------------------
    # 8. Bounded AI investigation
    # --------------------------------------------------

    agent_notes: str | None = None

    if signals.needs_agent_investigation:

        analysis_audit.append(
            "Additional investigation started"
        )

        gemini_configured = bool(get_gemini_api_key())

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

        if gemini_configured:

            investigation_tool = investigate_with_gemini

            analysis_audit.append(
                "Gemini investigation provider selected"
            )

        else:

            investigation_tool = offline_investigation_tool

            analysis_audit.append(
                "Offline investigation fallback selected"
            )

        try:

            # Local, read-only investigation tools.
            tool_findings = run_investigation_tools(
                artifacts,
                signals,
            )

            investigation_evidence = combined_evidence + [
                f"Investigation tool finding: {finding}"
                for finding in tool_findings
            ]

            agent_result = investigate_artifact(
                evidence=investigation_evidence,
                investigation_tool=investigation_tool,
            )

            # Construct agent notes.
            notes = [
                agent_result.get("reasoning", ""),
                *agent_result.get("red_flags", []),
            ]

            agent_notes = "\n".join(
                item.strip()
                for item in notes
                if isinstance(item, str) and item.strip()
            )

            # Agent findings are advisory only.
            advisory_findings = []

            for finding in tool_findings[:20]:

                if isinstance(finding, str) and finding.strip():

                    advisory_findings.append(
                        f"Investigation tool finding: {finding[:500]}"
                    )

            for flag in agent_result.get("red_flags", [])[:20]:

                if isinstance(flag, str) and flag.strip():

                    advisory_findings.append(
                        f"Agent-reported concern: {flag[:500]}"
                    )

            reasoning = agent_result.get("reasoning", "")

            if isinstance(reasoning, str) and reasoning.strip():

                advisory_findings.append(
                    f"Agent assessment (advisory): {reasoning[:500]}"
                )

            for finding in advisory_findings:

                if finding not in risk_result["evidence"]:
                    risk_result["evidence"].append(finding)

            # Record investigation trace.
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

            analysis_audit.append(
                "Agent investigation completed"
            )

        except Exception:

            # Agent failure never changes deterministic policy results.
            agent_notes = (
                "Additional investigation failed; "
                "analysis remains incomplete."
            )

            analysis_audit.append(
                "Agent investigation failed"
            )

    else:

        analysis_audit.append(
            "Additional investigation not required"
        )

    # --------------------------------------------------
    # 9. Final evidence and report sanitization
    # --------------------------------------------------

    risk_result["evidence"] = _sanitize_evidence(
        risk_result.get("evidence", [])
    )

    agent_notes = _sanitize_agent_notes(agent_notes)

    # --------------------------------------------------
    # 10. Final policy decision audit
    # --------------------------------------------------

    analysis_audit.append(
        f"Policy decision: verdict={risk_result['verdict']}, "
        f"action={risk_result['action']}, "
        f"risk_score={risk_result['score']}"
    )

    analysis_audit.append(
        "Email analysis completed"
    )

    analysis_audit = _sanitize_audit(analysis_audit)

    # --------------------------------------------------
    # 11. Build final validated security report
    # --------------------------------------------------

    report = build_report(
    artifacts,
    risk_result,
    agent_notes=agent_notes,
    analysis_audit=analysis_audit,
    )

    # Persist audit history without interrupting email analysis
    # if the audit database is temporarily unavailable.
    try:
        audit_id = log_analysis(report)

        report.analysis_audit.append(
            f"Persistent audit record saved: {audit_id}"
        )

    except Exception:
        report.analysis_audit.append(
            "Persistent audit storage failed"
        )

    return report