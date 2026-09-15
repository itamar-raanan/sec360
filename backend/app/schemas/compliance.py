import uuid
from datetime import datetime
from pydantic import BaseModel, Field, field_validator


class ComplianceStatusBase(BaseModel):
    edr_installed:  bool = False
    edr_version_ok: bool = False
    dlp_installed:  bool = False
    dlp_version_ok: bool = False
    wss_installed:  bool = False
    wss_version_ok: bool = False


class ComplianceStatusCreate(ComplianceStatusBase):
    endpoint_id: uuid.UUID


class ComplianceStatusUpdate(ComplianceStatusBase):
    status: str = "non_compliant"
    last_evaluated: datetime


class ComplianceStatusResponse(ComplianceStatusBase):
    model_config = {"from_attributes": True}

    id: uuid.UUID
    endpoint_id: uuid.UUID
    status: str
    agent_presence: dict[str, bool] = Field(default_factory=dict)
    last_evaluated: datetime


class ComplianceExclusionUpdate(BaseModel):
    exclude_all: bool = False
    excluded_agents: list[str] = Field(default_factory=list, max_length=20)
    reason: str | None = Field(default=None, max_length=1000)

    @field_validator("excluded_agents")
    @classmethod
    def unique_agent_keys(cls, value: list[str]) -> list[str]:
        return list(dict.fromkeys(key.strip() for key in value if key.strip()))

    @field_validator("reason")
    @classmethod
    def clean_reason(cls, value: str | None) -> str | None:
        return value.strip() if value and value.strip() else None


class ComplianceSummaryStats(BaseModel):
    total: int
    compliant: int
    partial: int
    non_compliant: int
    compliant_pct: float
    no_edr: int
    edr_outdated: int
    no_dlp: int
    dlp_outdated: int
