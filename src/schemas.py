from __future__ import annotations

from enum import Enum
from typing import Dict, List, Optional

from pydantic import BaseModel, Field


class VerdictEnum(str, Enum):
    SAFE = "safe"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"
    INCONCLUSIVE = "inconclusive"


class ActionEnum(str, Enum):
    ALLOW = "allow"
    WARN = "warn"
    BLOCK = "block"
    QUARANTINE = "quarantine"


class ExtractedArtifacts(BaseModel):
    message_id: str
    sender: str
    subject: str
    return_path: Optional[str] = None
    urls: List[str] = Field(default_factory=list)
    qr_urls: List[str] = Field(default_factory=list)
    attachment_hashes: List[Dict[str, str]] = Field(default_factory=list)


class AnalysisSignals(BaseModel):
    url_scores: Dict[str, float] = Field(default_factory=dict)
    vt_reputation: Dict[str, Dict[str, int]] = Field(default_factory=dict)
    static_attachment_flags: List[str] = Field(default_factory=list)
    needs_agent_investigation: bool = False
    analysis_incomplete: bool = False


class AgentInvestigationResult(BaseModel):
    reasoning: str
    red_flags: List[str]
    confidence_delta: float


class FinalSecurityReport(BaseModel):
    message_id: str
    sender: str
    subject: str
    verdict: VerdictEnum
    action: ActionEnum
    composite_risk_score: float
    evidence: List[str]
    agent_notes: Optional[str] = None