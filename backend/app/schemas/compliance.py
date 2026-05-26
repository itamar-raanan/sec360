import uuid
from datetime import datetime
from pydantic import BaseModel


class ComplianceStatusBase(BaseModel):
    edr_installed:  bool = False
    edr_version_ok: bool = False
    dlp_installed:  bool = False
    dlp_version_ok: bool = False
    gp_installed:   bool = False
    gp_version_ok:  bool = False
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
    last_evaluated: datetime


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
