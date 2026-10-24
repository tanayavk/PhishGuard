from src.schemas import (
    VerdictEnum,
    ActionEnum,
    ExtractedArtifacts,
    AnalysisSignals,
    AgentInvestigationResult,
    FinalSecurityReport,
)


def test_verdict_enum():
    assert VerdictEnum.SAFE == "safe"
    assert VerdictEnum.SUSPICIOUS == "suspicious"
    assert VerdictEnum.MALICIOUS == "malicious"


def test_action_enum():
    assert ActionEnum.ALLOW == "allow"
    assert ActionEnum.WARN == "warn"
    assert ActionEnum.BLOCK == "block"
    assert ActionEnum.QUARANTINE == "quarantine"


def test_extracted_artifacts_defaults():
    data = {
        "message_id": "msg-001",
        "sender": "test@example.com",
        "subject": "Test",
    }
    m = ExtractedArtifacts(**data)
    assert m.message_id == "msg-001"
    assert m.sender == "test@example.com"
    assert m.subject == "Test"
    assert m.return_path is None
    assert m.urls == []
    assert m.qr_urls == []
    assert m.attachment_hashes == []


def test_extracted_artifacts_with_fields():
    m = ExtractedArtifacts(
        message_id="msg-002",
        sender="sender@example.com",
        subject="Subject",
        return_path="rp@example.com",
        urls=["http://example.com"],
        qr_urls=["http://qr.example.com"],
        attachment_hashes=[{"hash": "abc123"}],
    )
    assert m.message_id == "msg-002"
    assert m.return_path == "rp@example.com"
    assert len(m.urls) == 1
    assert len(m.qr_urls) == 1
    assert len(m.attachment_hashes) == 1


def test_analysis_signals_defaults():
    s = AnalysisSignals()
    assert s.url_scores == {}
    assert s.vt_reputation == {}
    assert s.static_attachment_flags == []
    assert s.needs_agent_investigation is False


def test_agent_investigation_result():
    result = AgentInvestigationResult(
        reasoning="suspicious links",
        red_flags=["unknown_sender"],
        confidence_delta=0.3,
    )
    assert result.reasoning == "suspicious links"
    assert result.red_flags == ["unknown_sender"]
    assert result.confidence_delta == 0.3


def test_final_security_report():
    report = FinalSecurityReport(
        message_id="msg-003",
        sender="spoof@example.com",
        subject="Phishing attempt",
        verdict=VerdictEnum.MALICIOUS,
        action=ActionEnum.BLOCK,
        composite_risk_score=0.95,
        evidence=["suspicious link", "bad sender"],
    )
    assert report.verdict == VerdictEnum.MALICIOUS
    assert report.action == ActionEnum.BLOCK
    assert report.composite_risk_score == 0.95
    assert report.agent_notes is None

    report2 = FinalSecurityReport(
        message_id="msg-004",
        sender="safe@example.com",
        subject="Safe mail",
        verdict=VerdictEnum.SAFE,
        action=ActionEnum.ALLOW,
        composite_risk_score=0.01,
        evidence=[],
        agent_notes="all good",
    )
    assert report2.agent_notes == "all good"