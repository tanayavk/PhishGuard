"""Shared environment configuration for PhishGuard."""

import os
from pathlib import Path

from dotenv import load_dotenv


PROJECT_ROOT = Path(__file__).resolve().parent.parent

load_dotenv(PROJECT_ROOT / ".env", override=False)


def get_vt_api_key() -> str | None:
    """Return the configured VirusTotal API key, if available."""
    value = os.getenv("VT_API_KEY", "").strip()
    return value or None


def get_gemini_api_key() -> str | None:
    """Return the configured Gemini API key, if available."""
    value = os.getenv("GEMINI_API_KEY", "").strip()
    return value or None


def get_gemini_model() -> str:
    """Return the configured Gemini model name."""
    return os.getenv("GEMINI_MODEL", "gemini-3.8-flash").strip() or "gemini-3.8-flash"
