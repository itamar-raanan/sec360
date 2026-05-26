import uuid
from datetime import datetime
from typing import Optional
from pydantic import BaseModel, EmailStr, field_validator


class UserBase(BaseModel):
    full_name: str
    email: EmailStr
    department: Optional[str] = None
    manager: Optional[str] = None
    employment_status: str = "active"
    mfa_enabled: bool = False

    @field_validator("employment_status")
    @classmethod
    def validate_status(cls, v: str) -> str:
        allowed = {"active", "inactive", "on_leave"}
        if v not in allowed:
            raise ValueError(f"employment_status must be one of {allowed}")
        return v


class UserCreate(UserBase):
    pass


class UserUpdate(BaseModel):
    full_name: Optional[str] = None
    department: Optional[str] = None
    manager: Optional[str] = None
    employment_status: Optional[str] = None
    mfa_enabled: Optional[bool] = None


class UserResponse(UserBase):
    model_config = {"from_attributes": True}

    id: uuid.UUID
    suspended: bool = False
    last_login: Optional[datetime] = None
    risk_score: float
    job_title: Optional[str] = None
    phone: Optional[str] = None
    sources: Optional[dict] = None
    endpoint_count: int = 0
    created_at: datetime
    updated_at: datetime


class UserDetail(UserResponse):
    endpoints: list = []
    recent_events: list = []


class AuthUserCreate(BaseModel):
    email: EmailStr
    password: str
    role: str = "viewer"

    @field_validator("role")
    @classmethod
    def validate_role(cls, v: str) -> str:
        allowed = {"admin", "analyst", "viewer"}
        if v not in allowed:
            raise ValueError(f"role must be one of {allowed}")
        return v


class AuthUserResponse(BaseModel):
    model_config = {"from_attributes": True}

    id: uuid.UUID
    email: str
    role: str
    is_active: bool


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: AuthUserResponse


class LoginRequest(BaseModel):
    email: str
    password: str
    totp_code: str | None = None
