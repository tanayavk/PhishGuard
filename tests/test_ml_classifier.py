
"""Offline tests for PhishGuard's ML URL classifier."""

import pytest

from src.detection import ml_classifier
from src.detection.feature_extraction import extract_url_features


class FakeModel:
    """Small test double; avoids loading the real model."""

    classes_ = [0, 1]

    def __init__(self, probabilities):
        self.probabilities = probabilities
        self.received_features = None

    def predict_proba(self, features):
        self.received_features = features
        return [self.probabilities]


def install_fake_model(monkeypatch, probabilities=(0.8, 0.2)):
    model = FakeModel(probabilities)
    artifact = {
        "model": model,
        "feature_names": ml_classifier.EXPECTED_FEATURE_NAMES,
        "label_mapping": {0: "phishing", 1: "legitimate"},
        "dataset": "test dataset",
    }
    monkeypatch.setattr(ml_classifier, "_model_artifact", artifact)
    return model


def test_predict_url_risk_returns_phishing_probability(monkeypatch):
    install_fake_model(monkeypatch, probabilities=(0.8, 0.2))

    result = ml_classifier.predict_url_risk("https://example.com/login")

    assert result == pytest.approx(0.8)


def test_predict_url_risk_uses_phishing_class_index(monkeypatch):
    model = FakeModel((0.35, 0.65))
    model.classes_ = [1, 0]

    artifact = {
        "model": model,
        "feature_names": ml_classifier.EXPECTED_FEATURE_NAMES,
        "label_mapping": {0: "phishing", 1: "legitimate"},
        "dataset": "test dataset",
    }
    monkeypatch.setattr(ml_classifier, "_model_artifact", artifact)

    result = ml_classifier.predict_url_risk("https://example.com/login")

    assert result == pytest.approx(0.65)


def test_predict_url_risk_uses_expected_feature_order(monkeypatch):
    model = install_fake_model(monkeypatch)

    url = "https://secure-account.example.com/login"
    ml_classifier.predict_url_risk(url)

    extracted = extract_url_features(url)
    expected = [
        extracted[name]
        for name in ml_classifier.EXPECTED_FEATURE_NAMES
    ]

    assert model.received_features == [expected]


@pytest.mark.parametrize("url", ["", "   ", None, 123])
def test_predict_url_risk_rejects_empty_or_invalid_input(
    monkeypatch, url
):
    install_fake_model(monkeypatch)

    with pytest.raises(ValueError):
        ml_classifier.predict_url_risk(url)


def test_predict_url_risk_rejects_malformed_url(monkeypatch):
    install_fake_model(monkeypatch)

    with pytest.raises(ValueError):
        ml_classifier.predict_url_risk("not a URL")


def test_predict_url_risk_rejects_missing_model(monkeypatch, tmp_path):
    monkeypatch.setattr(ml_classifier, "_model_artifact", None)
    monkeypatch.setattr(
        ml_classifier,
        "MODEL_PATH",
        tmp_path / "missing-model.joblib",
    )

    with pytest.raises(ml_classifier.ModelUnavailableError):
        ml_classifier.predict_url_risk("https://example.com/login")


def test_predict_url_risk_rejects_mismatched_feature_configuration(
    monkeypatch, tmp_path
):
    model_path = tmp_path / "model.joblib"
    model_path.write_bytes(b"test")

    bad_artifact = {
        "model": FakeModel((0.8, 0.2)),
        "feature_names": ["wrong_feature"],
    }

    monkeypatch.setattr(ml_classifier, "_model_artifact", None)
    monkeypatch.setattr(ml_classifier, "MODEL_PATH", model_path)
    monkeypatch.setattr(
        ml_classifier.joblib,
        "load",
        lambda path: bad_artifact,
    )

    with pytest.raises(ml_classifier.ModelUnavailableError):
        ml_classifier.predict_url_risk("https://example.com/login")
