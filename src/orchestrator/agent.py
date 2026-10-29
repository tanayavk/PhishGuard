


"""Bounded, provider-independent investigation for PhishGuard."""

from __future__ import annotations

from typing import Any, Callable

from pydantic import ValidationError

from src.schemas import AgentInvestigationResult


MAX_PLANNING_ITERATIONS = 3
MAX_TOOL_CALLS = 4


def investigate_artifact(
    evidence: list[str],
    investigation_tool: Callable[[str], dict[str, Any]],
) -> dict[str, Any]:
    """Run a bounded investigation using an injected, controlled tool.

    The tool must not make unauthorized changes or treat missing evidence
    as proof of safety. Final security decisions remain outside this module.
    """
    trace: list[dict[str, Any]] = []
    findings: list[str] = []
    tool_calls = 0
    reasoning = "Investigation was not completed."
    confidence_delta = 0.0
    next_question: str | None = None

    question = (
        "Review the supplied evidence for contradictions, missing "
        "information, or additional red flags. Do not infer safety "
        "from missing reputation data. Evidence: "
        + " | ".join(str(item) for item in evidence)
    )

    for iteration in range(1, MAX_PLANNING_ITERATIONS + 1):
        if tool_calls >= MAX_TOOL_CALLS:
            trace.append({
                "event": "limit_reached",
                "reason": "Maximum tool-call count reached",
                "iteration": iteration,
            })
            break

        trace.append({
            "event": "plan",
            "iteration": iteration,
            "question": question,
        })

        try:
            tool_calls += 1
            observation = investigation_tool(question)

            if not isinstance(observation, dict):
                raise ValueError("Investigation tool must return a dictionary")

            trace.append({
                "event": "observe",
                "iteration": iteration,
                "tool_call": tool_calls,
                "observation": observation,
            })

            result = AgentInvestigationResult.model_validate(observation)
            reasoning = result.reasoning
            confidence_delta = result.confidence_delta

            for flag in result.red_flags:
                if flag not in findings:
                    findings.append(flag)

            trace.append({
                "event": "validated_result",
                "iteration": iteration,
                "red_flags": list(result.red_flags),
                "confidence_delta": result.confidence_delta,
                "continue_investigation": result.continue_investigation,
            })

            if not result.continue_investigation:
                trace.append({
                    "event": "investigation_complete",
                    "iteration": iteration,
                })
                break

            if iteration == MAX_PLANNING_ITERATIONS:
                trace.append({
                    "event": "limit_reached",
                    "reason": "Maximum planning iterations reached",
                    "iteration": iteration,
                })
                break

            if tool_calls >= MAX_TOOL_CALLS:
                trace.append({
                    "event": "limit_reached",
                    "reason": "Maximum tool-call count reached",
                    "iteration": iteration,
                })
                break

            if not result.next_question or not result.next_question.strip():
                trace.append({
                    "event": "replan_stopped",
                    "reason": "No valid next question was provided",
                    "iteration": iteration,
                })
                break

            question = result.next_question.strip()

        except (ValidationError, ValueError, TypeError) as error:
            reasoning = "Investigation returned an invalid result."
            trace.append({
                "event": "tool_error",
                "iteration": iteration,
                "tool_call": tool_calls,
                "error_type": type(error).__name__,
            })
            break
        except Exception as error:
            reasoning = "Investigation tool failed."
            trace.append({
                "event": "tool_error",
                "iteration": iteration,
                "tool_call": tool_calls,
                "error_type": type(error).__name__,
            })
            break

    return {
        "reasoning": reasoning,
        "red_flags": findings,
        "confidence_delta": confidence_delta,
        "tool_calls": tool_calls,
        "planning_iterations": sum(
            event["event"] == "plan" for event in trace
        ),
        "trace": trace,
    }
