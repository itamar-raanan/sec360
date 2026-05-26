import uuid
from datetime import datetime
from typing import Optional
from pydantic import BaseModel


class EndpointBase(BaseModel):
    hostname: str
    serial_number: Optional[str] = None
    os_version: Optional[str] = None
    username: Optional[str] = None
    ip_address: Optional[str] = None
    location: Optional[str] = None


class EndpointCreate(EndpointBase):
    owner_user_id: Optional[uuid.UUID] = None


class EndpointUpdate(BaseModel):
    hostname: Optional[str] = None
    os_version: Optional[str] = None
    username: Optional[str] = None
    ip_address: Optional[str] = None
    location: Optional[str] = None
    owner_user_id: Optional[uuid.UUID] = None


class AgentSummary(BaseModel):
    model_config = {"from_attributes": True}

    id: uuid.UUID
    product_name: str
    status: str
    version: Optional[str] = None
    last_seen: Optional[datetime] = None
    agent_group: Optional[str] = None


class ComplianceSummary(BaseModel):
    model_config = {"from_attributes": True}

    status: str
    edr_installed: bool
    edr_version_ok: bool
    dlp_installed: bool
    dlp_version_ok: bool
    gp_installed: bool = False
    gp_version_ok: bool = False
    wss_installed: bool = False
    wss_version_ok: bool = False
    disk_encrypted: Optional[bool] = None
    device_control_enabled: Optional[bool] = None
    last_evaluated: datetime


class OwnerSummary(BaseModel):
    model_config = {"from_attributes": True}

    id: uuid.UUID
    full_name: str
    email: str
    department: Optional[str] = None


class EndpointResponse(EndpointBase):
    model_config = {"from_attributes": True}

    id: uuid.UUID
    last_seen: Optional[datetime] = None
    last_reboot: Optional[datetime] = None
    all_ips: Optional[str] = None
    external_ip: Optional[str] = None
    risk_score: float
    risk_score_override: Optional[float] = None
    risk_score_note: Optional[str] = None
    tags: Optional[str] = None
    source: Optional[str] = None
    owner_user_id: Optional[uuid.UUID] = None
    owner: Optional[OwnerSummary] = None
    agents: list[AgentSummary] = []
    compliance_status: Optional[ComplianceSummary] = None
    created_at: datetime
    updated_at: datetime


class AgentDetail(BaseModel):
    installed: bool
    status: Optional[str] = None
    version: Optional[str] = None
    last_seen: Optional[datetime] = None
    disk_encrypted: Optional[bool] = None
    encryption_status: Optional[str] = None
    device_control_enabled: Optional[bool] = None
    agent_group: Optional[str] = None
    agent_state: Optional[str] = None


class EndpointDetail(EndpointResponse):
    agents: list[AgentSummary] = []
    compliance_status: Optional[ComplianceSummary] = None
    # Per-product breakdown for the detail panel
    sentinelone: AgentDetail = AgentDetail(installed=False)
    symantec_dlp: AgentDetail = AgentDetail(installed=False)
    globalprotect: AgentDetail = AgentDetail(installed=False)
    symantec_wss: AgentDetail = AgentDetail(installed=False)
