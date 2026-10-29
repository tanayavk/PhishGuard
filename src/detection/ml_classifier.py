
"""Runtime prediction for PhishGuard's lexical URL classifier."""

from pathlib import Path
from typing import Any

import joblib

from src.detection.feature_extraction import extract_url_features


PROJECT_ROOT = Path(__file__).resolve().parents[2]
MODEL_PATH = PROJECT_ROOT / "data" / "models" / "url_phish_model.joblib"

EXPECTED_FEATURE_NAMES = [
    "url_length",
    "hostname_length",
    "is_ip_host",
    "dot_count",
    "hyphen_count",
    "at_count",
    "domain_entropy",
    "suspicious_keyword_count",
]

_model_artifact: dict[str, Any] | None = None


class ModelUnavailableError(RuntimeError):
    """Raised when the trained URL model cannot be loaded or used."""


def _load_model_artifact() -> dict[str, Any]:
    """Load and validate the model artifact once per process."""
    global _model_artifact

    if _model_artifact is not None:
        return _model_artifact

    if not MODEL_PATH.is_file() or MODEL_PATH.stat().st_size == 0:
        raise ModelUnavailableError("URL classification model is missing.")

    try:
        artifact = joblib.load(MODEL_PATH)
    except Exception as exc:
        raise ModelUnavailableError(
            "URL classification model could not be loaded."
        ) from exc

    if not isinstance(artifact, dict):
        raise ModelUnavailableError("URL model artifact has an invalid format.")

    if artifact.get("feature_names") != EXPECTED_FEATURE_NAMES:
        raise ModelUnavailableError(
            "URL model feature configuration does not match the application."
        )

    model = artifact.get("model")
    if not callable(getattr(model, "predict_proba", None)):
        raise ModelUnavailableError(
            "URL model does not support probability predictions."
        )

    classes = list(getattr(model, "classes_", []))
    if 0 not in classes or 1 not in classes:
        raise ModelUnavailableError(
            "URL model does not contain the expected classes."
        )

    _model_artifact = artifact
    return artifact


def predict_url_risk(url: str) -> float:
    """Return the model's estimated phishing probability, from 0.0 to 1.0.

    Raises:
        ValueError: If the URL is empty or cannot be parsed into features.
        ModelUnavailableError: If the model is missing, invalid, or unusable.
    """
    if not isinstance(url, str) or not url.strip():
        raise ValueError("A non-empty URL is required.")

    features = extract_url_features(url)

    if not any(features.values()):
        raise ValueError("URL is malformed or unsupported.")

    artifact = _load_model_artifact()
    model = artifact["model"]

    vector = [[features[name] for name in EXPECTED_FEATURE_NAMES]]
    probabilities = model.predict_proba(vector)[0]
    classes = list(model.classes_)

    phishing_index = classes.index(0)
    risk = float(probabilities[phishing_index])

    if not 0.0 <= risk <= 1.0:
        raise ModelUnavailableError(
            "URL model returned an invalid probability."
        )

    return risk
