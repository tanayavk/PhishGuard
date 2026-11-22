"""Gmail-to-PhishGuard analysis and security labeling."""

from src.ingestion.gmail_client import fetch_unread_emails
from src.ingestion.gmail_api import apply_label
from src.ingestion.processed_registry import (
    claim_message,
    mark_completed,
    mark_failed,
)
from src.orchestrator.pipeline import analyze_artifacts


class GmailRunnerError(Exception):
    """Raised when Gmail fetching fails."""


LABEL_MAP = {
    "safe": "PhishGuard/Safe",
    "suspicious": "PhishGuard/Suspicious",
    "malicious": "PhishGuard/Malicious",
    "inconclusive": "PhishGuard/Needs Review",
}


def get_security_label(verdict: str) -> str:
    """Return the Gmail label corresponding to a security verdict."""

    if verdict not in LABEL_MAP:
        raise ValueError(f"Unsupported security verdict: {verdict}")

    return LABEL_MAP[verdict]


def run_gmail_analysis(max_results: int = 5) -> dict:
    """Fetch, analyze, and label unread Gmail messages."""

    if (
        not isinstance(max_results, int)
        or isinstance(max_results, bool)
        or max_results < 1
    ):
        raise ValueError("max_results must be a positive integer")

    try:
        emails = fetch_unread_emails(max_results=max_results)
    except Exception as error:
        raise GmailRunnerError(
            "Unable to fetch unread Gmail messages."
        ) from error

    results = []
    successful = 0
    failed = 0
    skipped = 0
    labeling_failed = 0

    for artifacts in emails:
        message_id = artifacts.message_id

        try:
            if not claim_message(message_id):
                results.append({
                    "message_id": message_id,
                    "status": "skipped",
                    "reason": "Already processed or currently being analyzed.",
                })
                skipped += 1
                continue

            report = analyze_artifacts(artifacts)

            # Persist the analysis before attempting Gmail labeling.
            mark_completed(message_id, report)

            verdict = report.verdict.value
            label_name = get_security_label(verdict)

            label_applied = False
            label_error = None

            try:
                label_applied = apply_label(
                    message_id=message_id,
                    label_name=label_name,
                )
            except Exception:
                label_error = "Gmail security label could not be applied."
                labeling_failed += 1

            results.append({
                "message_id": message_id,
                "status": "success",
                "verdict": verdict,
                "action": report.action.value,
                "risk_score": report.composite_risk_score,
                "label": label_name,
                "label_applied": label_applied,
                "label_error": label_error,
                "report": report,
            })

            successful += 1

        except Exception:
            try:
                mark_failed(message_id)
            except Exception:
                pass

            results.append({
                "message_id": message_id,
                "status": "failed",
                "error": "Email analysis or processing failed.",
            })

            failed += 1

    return {
        "total_fetched": len(emails),
        "successful": successful,
        "failed": failed,
        "skipped": skipped,
        "labeling_failed": labeling_failed,
        "results": results,
    }