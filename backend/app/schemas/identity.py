import uuid
from datetime import datetime
from typing import Optional
from pydantic import BaseModel


class AgentSummary(BaseModel):
    model_config = {"from_attributes": True}

    id: uuid.UUID
    product_name: str
    status: str
    version: Optional[str] = None
    last_seen: Optional[datetime] = None


class ComplianceSummary(BaseModel):
    model_config = {"from_attributes": True}

    status: str
    edr_installed: bool
    edr_version_ok: bool
    dlp_installed: bool
    dlp_version_ok: bool
    disk_encrypted: Optional[bool] = None
    device_control_enabled: Optional[bool] = None
    last_evaluated: datetime


class EndpointIdentity(BaseModel):
    model_config = {"from_attributes": True}

    id: uuid.UUID
    hostname: str
    os_version: Optional[str] = None
    ip_address: Optional[str] = None
    location: Optional[str] = None
    username: Optional[str] = None
    last_seen: Optional[datetime] = None
    risk_score: float
    agents: list[AgentSummary] = []
    compliance: Optional[ComplianceSummary] = None
    # Which products cover this endpoint
    agent_products: list[str] = []


class UserIdentity(BaseModel):
    model_config = {"from_attributes": True}

    id: uuid.UUID
    full_name: str
    email: str
    department: Optional[str] = None
    manager: Optional[str] = None
    employment_status: str
    mfa_enabled: bool
    last_login: Optional[datetime] = None
    risk_score: float
    created_at: datetime
    updated_at: datetime

    # Profile extras
    job_title: Optional[str] = None
    phone: Optional[str] = None
    sources: Optional[dict] = None        # {"jumpcloud": {...}, "google": {...}}

    # Enriched identity fields
    endpoints: list[EndpointIdentity] = []
    data_sources: list[str] = []          # legacy fallback
    total_endpoints: int = 0
    endpoints_with_sentinelone: int = 0
    endpoints_with_symantec: int = 0
    endpoints_compliant: int = 0
    endpoints_non_compliant: int = 0
    all_agents_ok: bool = False
