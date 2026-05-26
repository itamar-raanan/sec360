import uuid
from pydantic import BaseModel


class RiskScore(BaseModel):
    entity_id: uuid.UUID
    entity_type: str  # "user" or "endpoint"
    score: float
    level: str  # low/medium/high/critical
    factors: list[str]


class RiskSummary(BaseModel):
    low: int
    medium: int
    high: int
    critical: int
    total: int
