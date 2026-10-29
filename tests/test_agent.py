


import pytest

from src.orchestrator.agent import (
    MAX_PLANNING_ITERATIONS,
    MAX_TOOL_CALLS,
    investigate_artifact,
)


def test_agent_accepts_valid_investigation_result():
    def mock_tool(question):
        assert "supplied evidence" in question
        return {
            "reasoning": "The URL indicators require further review.",
            "red_flags": ["URL uses HTTP"],
            "confidence_delta": 0.2,
        }

    result = investigate_artifact(
        ["URL heuristic indicates an insecure scheme"],
        mock_tool,
    )

    assert result["reasoning"] == "The URL indicators require further review."
    assert result["red_flags"] == ["URL uses HTTP"]
    assert result["confidence_delta"] == 0.2
    assert result["tool_calls"] <= MAX_TOOL_CALLS
    assert result["planning_iterations"] <= MAX_PLANNING_ITERATIONS


def test_agent_records_invalid_tool_result_without_crashing():
    result = investigate_artifact(
        ["Reputation unavailable"],
        lambda question: {"red_flags": ["unknown reputation"]},
    )

    assert result["reasoning"] == "Investigation returned an invalid result."
    assert result["red_flags"] == []
    assert result["tool_calls"] == 1
    assert any(
        event["event"] == "tool_error"
        for event in result["trace"]
    )


def test_agent_records_tool_failure_without_crashing():
    def failing_tool(question):
        raise RuntimeError("Private diagnostic detail")

    result = investigate_artifact(
        ["Uncertain indicator"],
        failing_tool,
    )

    assert result["reasoning"] == "Investigation tool failed."
    assert result["tool_calls"] == 1
    assert "Private diagnostic detail" not in str(result["trace"])



def test_agent_trace_records_successful_observation():
    result = investigate_artifact(
        ["Conflicting indicators"],
        lambda question: {
            "reasoning": "Evidence is inconclusive.",
            "red_flags": [],
            "confidence_delta": 0.0,
        },
    )

    event_names = [event["event"] for event in result["trace"]]

    assert event_names == [
        "plan",
        "observe",
        "validated_result",
        "investigation_complete",
    ]
    assert result["planning_iterations"] == 1
    assert result["tool_calls"] == 1



def test_agent_limits_are_positive_and_bounded():
    assert 1 <= MAX_PLANNING_ITERATIONS <= 3
    assert 1 <= MAX_TOOL_CALLS <= 4


def test_agent_stops_after_maximum_planning_iterations():
    calls = []

    def requesting_tool(question):
        calls.append(question)
        return {
            "reasoning": "More investigation is needed.",
            "red_flags": ["Reputation remains uncertain"],
            "confidence_delta": 0.0,
            "continue_investigation": True,
            "next_question": "Investigate another indicator",
        }

    result = investigate_artifact(
        ["Uncertain reputation"],
        requesting_tool,
    )

    assert len(calls) == MAX_PLANNING_ITERATIONS
    assert result["planning_iterations"] == MAX_PLANNING_ITERATIONS
    assert result["tool_calls"] == MAX_PLANNING_ITERATIONS
    assert any(
        event.get("reason") == "Maximum planning iterations reached"
        for event in result["trace"]
    )


def test_agent_deduplicates_red_flags_across_iterations():
    calls = 0

    def requesting_tool(question):
        nonlocal calls
        calls += 1

        return {
            "reasoning": "Additional review completed.",
            "red_flags": ["Reputation remains uncertain"],
            "confidence_delta": 0.0,
            "continue_investigation": calls < 2,
            "next_question": (
                "Review remaining indicators" if calls < 2 else None
            ),
        }

    result = investigate_artifact(
        ["Uncertain reputation"],
        requesting_tool,
    )

    assert result["tool_calls"] == 2
    assert result["planning_iterations"] == 2
    assert result["red_flags"] == ["Reputation remains uncertain"]


def test_agent_never_exceeds_maximum_tool_calls():
    calls = 0

    def requesting_tool(question):
        nonlocal calls
        calls += 1
        return {
            "reasoning": "Another investigation step was requested.",
            "red_flags": [],
            "confidence_delta": 0.0,
            "continue_investigation": True,
            "next_question": "Continue investigating",
        }

    result = investigate_artifact(
        ["Uncertain indicators"],
        requesting_tool,
    )

    assert calls <= MAX_TOOL_CALLS
    assert result["tool_calls"] <= MAX_TOOL_CALLS
    assert result["planning_iterations"] <= MAX_PLANNING_ITERATIONS
