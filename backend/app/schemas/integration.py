import uuid
from datetime import datetime
from typing import Optional, Dict, Any
from pydantic import BaseModel


class IntegrationCredentials(BaseModel):
    # JumpCloud
    api_key: Optional[str] = None
    # SentinelOne
    console_url: Optional[str] = None
    # Symantec DLP (DB)
    db_host: Optional[str] = None
    db_port: Optional[int] = None
    db_name: Optional[str] = None
    db_user: Optional[str] = None
    db_password: Optional[str] = None
    db_type: Optional[str] = None  # postgresql, mssql, oracle
    # Google Workspace
    service_account_json: Optional[str] = None
    admin_email: Optional[str] = None
    # HiBob
    service_user_id: Optional[str] = None
    service_user_token: Optional[str] = None


class IntegrationConfigUpdate(BaseModel):
    credentials: Dict[str, Any]
    is_enabled: bool = True


class IntegrationConfigResponse(BaseModel):
    model_config = {"from_attributes": True}

    id: uuid.UUID
    integration_type: str
    display_name: str
    is_enabled: bool
    status: str
    last_sync: Optional[datetime] = None
    last_error: Optional[str] = None
    records_synced: Optional[str] = None
    credentials_configured: bool = False  # True if credentials exist (don't return raw creds)


class SyncResult(BaseModel):
    success: bool
    message: str
    records_synced: Optional[int] = None
    error: Optional[str] = None


class CustomIntegrationCreate(BaseModel):
    integration_type: str  # e.g. "custom_api_my-salesforce" — caller provides slug
    display_name: str
    credentials: Dict[str, Any]
    is_enabled: bool = True
