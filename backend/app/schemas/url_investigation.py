import uuid
from typing import Literal

from pydantic import BaseModel, Field


class IndicatorPreviewRequest(BaseModel):
    indicator: str = Field(min_length=1, max_length=4096)


class InvestigationCreateRequest(IndicatorPreviewRequest):
    acknowledge_disclosure: bool = False
    force_refresh: bool = False


class ActiveOperationRequest(BaseModel):
    operation: Literal["scan", "screenshot"]
    acknowledge_active_submission: bool = False


class HistoryQuery(BaseModel):
    limit: int = Field(default=50, ge=1, le=200)


class InvestigationIdResponse(BaseModel):
    id: uuid.UUID
    deduplicated: bool = False

