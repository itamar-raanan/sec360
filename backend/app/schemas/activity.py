import uuid
from datetime import datetime
from typing import Optional, Any
from pydantic import BaseModel


class ActivityEventBase(BaseModel):
    user_id: Optional[uuid.UUID] = None
    event_type: str
    timestamp: datetime
    location: Optional[str] = None
    device_id: Optional[str] = None
    ip_address: Optional[str] = None
    country: Optional[str] = None
    details: Optional[dict[str, Any]] = None
    is_suspicious: bool = False


class ActivityEventCreate(ActivityEventBase):
    pass


class UserSummary(BaseModel):
    model_config = {"from_attributes": True}

    id: uuid.UUID
    full_name: str
    email: str


class ActivityEventResponse(ActivityEventBase):
    model_config = {"from_attributes": True}

    id: uuid.UUID
    user: Optional[UserSummary] = None
    created_at: datetime


class ActivityListResponse(BaseModel):
    items: list[ActivityEventResponse]
    total: int
