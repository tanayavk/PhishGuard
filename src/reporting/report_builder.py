
"""Build validated final security reports for PhishGuard."""

from typing import Any, Mapping

from src.schemas import (
    ActionEnum,
    ExtractedArtifacts,
    FinalSecurityReport,
    VerdictEnum,
)


def build_report(
    artifacts: ExtractedArtifacts,
    risk_result: Mapping[str, Any],
    agent_notes: str | None = None,
) -> FinalSecurityReport:
    """Build a validated report from extracted artifacts and risk output.

    The risk scorer remains responsible for assigning the verdict and action.
    This function validates and assembles the final report.
    """
    score = risk_result.get("score")

    if (
        not isinstance(score, (int, float))
        or isinstance(score, bool)
        or not 0 <= score <= 100
    ):
        raise ValueError("Risk score must be a number between 0 and 100")

    try:
        verdict = VerdictEnum(risk_result["verdict"])
        action = ActionEnum(risk_result["action"])
    except (KeyError, ValueError, TypeError) as error:
        raise ValueError("Risk result contains an invalid verdict or action") from error

    evidence = risk_result.get("evidence")
    if not isinstance(evidence, list) or not all(
        isinstance(item, str) and item.strip() for item in evidence
    ):
        raise ValueError("Risk result evidence must be a list of non-empty strings")

    if agent_notes is not None and not isinstance(agent_notes, str):
        raise ValueError("Agent notes must be a string or None")

    return FinalSecurityReport(
        message_id=artifacts.message_id,
        sender=artifacts.sender,
        subject=artifacts.subject,
        verdict=verdict,
        action=action,
        composite_risk_score=float(score),
        evidence=evidence,
        agent_notes=agent_notes,
    )
