from pydantic import BaseModel, Field
from typing import Optional, List, Dict
from enum import Enum
from datetime import datetime

class ViolationType(str, Enum):
    PII = "PII"
    PROMPT_INJECTION = "PromptInjection"
    SQLI = "SQLi"
    NONE = "None"

class GovernanceVerdict(BaseModel):
    is_safe: bool = Field(..., description="Whether the content is safe to release")
    violation_type: ViolationType = Field(..., description="Type of violation detected, if any")
    reasoning: str = Field(..., description="Explanation for the verdict")
    confidence_score: float = Field(..., ge=0.0, le=1.0, description="Confidence score of the verdict")
    flagged_content: Optional[str] = Field(None, description="Specific content that triggered the violation")
    timestamp: datetime = Field(default_factory=datetime.utcnow, description="Time of verdict")
    governor_version: str = Field("v1.0", description="Version of the Governor prompt/model used")

class ConversationContext(BaseModel):
    messages: List[Dict[str, str]] = Field(..., description="List of message dictionaries (role, content)")
    cumulative_risk_score: float = Field(0.0, description="Cumulative risk score across the conversation")
