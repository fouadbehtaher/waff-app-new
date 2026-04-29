from pydantic import BaseModel, Field
from enum import Enum
from typing import Dict, List, Optional
from datetime import datetime


class Decision(str, Enum):
    ALLOW = "allow"
    BLOCK = "block"


class ThreatLevel(str, Enum):
    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class RequestMetadata(BaseModel):
    method: str
    path: str
    query_string: str = ""
    headers: Dict[str, str] = Field(default_factory=dict)
    body_preview: str = ""
    source_ip: str = ""
    timestamp: datetime = Field(default_factory=datetime.utcnow)


class AIStrategyResult(BaseModel):
    strategy_name: str
    decision: Decision
    threat_level: ThreatLevel = ThreatLevel.NONE
    confidence: float = Field(ge=0.0, le=1.0, default=0.0)
    reason: str = ""
    matched_patterns: List[str] = Field(default_factory=list)


class AIAnalysisResult(BaseModel):
    overall_decision: Decision
    overall_threat_level: ThreatLevel = ThreatLevel.NONE
    confidence: float = Field(ge=0.0, le=1.0, default=0.0)
    reasoning: str = ""
    strategy_results: List[AIStrategyResult] = Field(default_factory=list)


class WAFMetrics(BaseModel):
    total_requests: int = 0
    blocked_requests: int = 0
    allowed_requests: int = 0
    avg_analysis_time_ms: float = 0.0
