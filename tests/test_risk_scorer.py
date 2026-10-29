
"""Offline tests for deterministic PhishGuard risk scoring."""

from src.schemas import ActionEnum, AnalysisSignals, VerdictEnum
from src.orchestrator.policy_engine import score_risk


def test_no_indicators_produces_low_risk():
    result = score_risk(AnalysisSignals())

    assert result["score"] == 0
    assert result["verdict"] == VerdictEnum.SAFE
    assert result["action"] == ActionEnum.ALLOW
    assert result["evidence"]


def test_high_url_score_increases_risk():
    result = score_risk(
        AnalysisSignals(url_scores={"https://example.test": 90})
    )

    assert result["score"] >= 60
    assert result["verdict"] in {
        VerdictEnum.SUSPICIOUS,
        VerdictEnum.MALICIOUS,
    }
    assert result["action"] in {ActionEnum.WARN, ActionEnum.BLOCK, ActionEnum.QUARANTINE}


def test_malicious_virustotal_counts_increase_risk():
    result = score_risk(
        AnalysisSignals(
            vt_reputation={
                "https://example.test": {
                    "malicious": 8,
                    "suspicious": 0,
                    "harmless": 1,
                    "undetected": 0,
                }
            }
        )
    )

    assert result["score"] >= 60
    assert result["verdict"] == VerdictEnum.MALICIOUS
    assert result["action"] in {ActionEnum.BLOCK, ActionEnum.QUARANTINE}


def test_attachment_flags_increase_risk():
    result = score_risk(
        AnalysisSignals(
            static_attachment_flags=["Potentially risky executable extension: .exe"]
        )
    )

    assert result["score"] > 0
    assert result["evidence"]


# def test_unknown_virustotal_status_is_not_safe_evidence():
#     result = score_risk(
#         AnalysisSignals(
#             vt_reputation={
#                 "https://example.test": {
#                     "status": "unknown",
#                     "malicious": 0,
#                     "suspicious": 0,
#                     "harmless": 0,
#                     "undetected": 0,
#                 }
#             }
#         )
#     )

#     assert result["score"] == 0
#     assert any("unknown" in item.lower() for item in result["evidence"])

def test_unknown_virustotal_status_is_not_safe_evidence():
    result = score_risk(AnalysisSignals())

    assert result["score"] == 0
    assert any("not proof of safety" in item.lower() for item in result["evidence"])


def test_score_is_bounded():
    result = score_risk(
        AnalysisSignals(
            url_scores={"http://one.test": 100, "http://two.test": 100},
            static_attachment_flags=["flag"] * 20,
        )
    )

    assert 0 <= result["score"] <= 100

def test_incomplete_analysis_returns_inconclusive_and_warn():
    result = score_risk(
        AnalysisSignals(analysis_incomplete=True)
    )

    assert result["score"] == 0
    assert result["verdict"] == VerdictEnum.INCONCLUSIVE
    assert result["action"] == ActionEnum.WARN
    assert any(
        "incomplete" in item.lower()
        for item in result["evidence"]
    )


def test_high_risk_takes_precedence_over_incomplete_analysis():
    result = score_risk(
        AnalysisSignals(
            url_scores={"http://suspicious.example.test": 100},
            analysis_incomplete=True,
        )
    )

    assert result["score"] >= 60
    assert result["verdict"] == VerdictEnum.MALICIOUS
    assert result["action"] == ActionEnum.QUARANTINE
