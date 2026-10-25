import json
from unittest.mock import Mock, patch

import pytest

from src.orchestrator.gemini_provider import (
    GeminiProviderError,
    investigate_with_gemini,
)


VALID_RESULT = {
    "reasoning": "The evidence contains indicators requiring review.",
    "red_flags": ["Reputation is unavailable"],
    "confidence_delta": 0.1,
    "continue_investigation": False,
    "next_question": None,
}


def test_missing_api_key_fails_safely(monkeypatch):
    monkeypatch.setattr(
        "src.orchestrator.gemini_provider.get_gemini_api_key",
        lambda: None,
    )

    with pytest.raises(GeminiProviderError, match="not configured"):
        investigate_with_gemini("Review the evidence")


def test_empty_question_is_rejected(monkeypatch):
    monkeypatch.setattr(
        "src.orchestrator.gemini_provider.get_gemini_api_key",
        lambda: "test-key",
    )

    with pytest.raises(ValueError, match="must not be empty"):
        investigate_with_gemini("  ")


@patch("src.orchestrator.gemini_provider.genai.Client")
def test_valid_structured_response_is_returned(mock_client_class, monkeypatch):
    monkeypatch.setattr(
        "src.orchestrator.gemini_provider.get_gemini_api_key",
        lambda: "test-key",
    )
    monkeypatch.setattr(
        "src.orchestrator.gemini_provider.get_gemini_model",
        lambda: "test-model",
    )

    mock_client = Mock()
    mock_response = Mock()
    mock_response.text = json.dumps(VALID_RESULT)
    mock_client.models.generate_content.return_value = mock_response
    mock_client_class.return_value = mock_client

    result = investigate_with_gemini("Review supplied evidence")

    assert result == VALID_RESULT
    mock_client_class.assert_called_once_with(api_key="test-key")
    mock_client.models.generate_content.assert_called_once()


@patch("src.orchestrator.gemini_provider.genai.Client")
def test_provider_error_does_not_expose_api_diagnostics(
    mock_client_class, monkeypatch
):
    monkeypatch.setattr(
        "src.orchestrator.gemini_provider.get_gemini_api_key",
        lambda: "test-key",
    )

    mock_client = Mock()
    mock_client.models.generate_content.side_effect = RuntimeError(
        "Sensitive provider diagnostic"
    )
    mock_client_class.return_value = mock_client

    with pytest.raises(GeminiProviderError, match="request failed") as exc_info:
        investigate_with_gemini("Review supplied evidence")

    assert "Sensitive provider diagnostic" not in str(exc_info.value)


@patch("src.orchestrator.gemini_provider.genai.Client")
def test_malformed_response_is_rejected(mock_client_class, monkeypatch):
    monkeypatch.setattr(
        "src.orchestrator.gemini_provider.get_gemini_api_key",
        lambda: "test-key",
    )

    mock_client = Mock()
    mock_response = Mock()
    mock_response.text = '{"reasoning": "missing required fields"}'
    mock_client.models.generate_content.return_value = mock_response
    mock_client_class.return_value = mock_client

    with pytest.raises(GeminiProviderError, match="invalid structured result"):
        investigate_with_gemini("Review supplied evidence")


@patch("src.orchestrator.gemini_provider.genai.Client")
def test_empty_response_is_rejected(mock_client_class, monkeypatch):
    monkeypatch.setattr(
        "src.orchestrator.gemini_provider.get_gemini_api_key",
        lambda: "test-key",
    )

    mock_client = Mock()
    mock_response = Mock()
    mock_response.text = ""
    mock_client.models.generate_content.return_value = mock_response
    mock_client_class.return_value = mock_client

    with pytest.raises(GeminiProviderError, match="empty response"):
        investigate_with_gemini("Review supplied evidence")
