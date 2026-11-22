"""Build validated final security reports for PhishGuard."""

from typing import Any, Mapping

from src.schemas import (
    ActionEnum,
    ExtractedArtifacts,
    FinalSecurityReport,
    VerdictEnum,
)


def _validate_policy_decision(
    score: float,
    verdict: VerdictEnum,
    action: ActionEnum,
) -> None:
    """Ensure the risk score, verdict and action are consistent."""

    expected_actions = {
        VerdictEnum.SAFE: ActionEnum.ALLOW,
        VerdictEnum.SUSPICIOUS: ActionEnum.WARN,
        VerdictEnum.MALICIOUS: ActionEnum.QUARANTINE,
        VerdictEnum.INCONCLUSIVE: ActionEnum.WARN,
    }

    if expected_actions[verdict] != action:
        raise ValueError(
            "The selected action does not match the security verdict"
        )

    if score >= 60 and verdict != VerdictEnum.MALICIOUS:
        raise ValueError(
            "Risk scores of 60 or higher must be MALICIOUS"
        )

    if 25 <= score < 60 and verdict != VerdictEnum.SUSPICIOUS:
        raise ValueError(
            "Risk scores between 25 and 59.9 must be SUSPICIOUS"
        )

    if score < 25 and verdict not in {
        VerdictEnum.SAFE,
        VerdictEnum.INCONCLUSIVE,
    }:
        raise ValueError(
            "Risk scores below 25 must be SAFE or INCONCLUSIVE"
        )


def _prepare_audit(
    analysis_audit: list[str] | None,
    score: float,
    verdict: VerdictEnum,
    action: ActionEnum,
) -> list[str]:
    """Validate audit entries and generate a canonical policy record."""

    if analysis_audit is None:
        analysis_audit = []

    if not isinstance(analysis_audit, list):
        raise ValueError("Analysis audit must be a list")

    audit = []

    for item in analysis_audit:
        if not isinstance(item, str) or not item.strip():
            raise ValueError(
                "Analysis audit entries must be non-empty strings"
            )

        item = " ".join(item.split())[:500]

        # Never trust an upstream policy-decision audit entry.
        if item.startswith("Policy decision:"):
            continue

        if item not in audit:
            audit.append(item)

    # Generate the policy record from validated report values.
    audit.append(
        f"Policy decision: verdict={verdict.value}, "
        f"action={action.value}, risk_score={score}"
    )

    if "Email analysis completed" not in audit:
        audit.append("Email analysis completed")

    return audit[:100]


def build_report(
    artifacts: ExtractedArtifacts,
    risk_result: Mapping[str, Any],
    agent_notes: str | None = None,
    analysis_audit: list[str] | None = None,
) -> FinalSecurityReport:
    """Build a validated report from extracted artifacts and risk output.

    The deterministic risk scorer remains responsible for the decision.
    This function validates the decision before producing the report.
    """

    # 1. Validate risk score.
    score = risk_result.get("score")

    if (
        not isinstance(score, (int, float))
        or isinstance(score, bool)
        or not 0 <= score <= 100
    ):
        raise ValueError(
            "Risk score must be a number between 0 and 100"
        )

    score = round(float(score), 1)

    # 2. Validate verdict and action.
    try:
        verdict = VerdictEnum(risk_result["verdict"])
        action = ActionEnum(risk_result["action"])

    except (KeyError, ValueError, TypeError) as error:
        raise ValueError(
            "Risk result contains an invalid verdict or action"
        ) from error

    # 3. Verify deterministic policy consistency.
    _validate_policy_decision(score, verdict, action)

    # 4. Validate evidence.
    evidence = risk_result.get("evidence")

    if not isinstance(evidence, list) or not all(
        isinstance(item, str) and item.strip()
        for item in evidence
    ):
        raise ValueError(
            "Risk result evidence must be a list of non-empty strings"
        )

    # 5. Validate agent notes.
    if agent_notes is not None and not isinstance(agent_notes, str):
        raise ValueError(
            "Agent notes must be a string or None"
        )

    if agent_notes is not None:
        agent_notes = agent_notes[:5000] or None

    # 6. Validate and normalize audit trail.
    validated_audit = _prepare_audit(
        analysis_audit,
        score,
        verdict,
        action,
    )

    # 7. Construct final validated report.
    return FinalSecurityReport(
        message_id=artifacts.message_id,
        sender=artifacts.sender,
        subject=artifacts.subject,
        verdict=verdict,
        action=action,
        composite_risk_score=score,
        evidence=evidence,
        agent_notes=agent_notes,
        analysis_audit=validated_audit,
    )