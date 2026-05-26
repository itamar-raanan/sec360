import uuid
from datetime import datetime
from typing import Optional
from pydantic import BaseModel


class AgentBase(BaseModel):
    endpoint_id: uuid.UUID
    product_name: str
    status: str = "unknown"
    version: Optional[str] = None
    last_seen: Optional[datetime] = None


class AgentCreate(AgentBase):
    pass


class AgentUpdate(BaseModel):
    status: Optional[str] = None
    version: Optional[str] = None
    last_seen: Optional[datetime] = None


class AgentResponse(AgentBase):
    model_config = {"from_attributes": True}

    id: uuid.UUID
    created_at: datetime
    updated_at: datetime
