from typing import Optional
from datetime import datetime
from fastapi import APIRouter, Depends, Query, Response
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from sqlalchemy.orm import selectinload

from app.api.deps import get_db, get_current_user, require_role
from app.models.user import AuthUser
from app.models.activity import ActivityEvent
from app.schemas.activity import ActivityEventResponse

router = APIRouter(prefix="/activity", tags=["activity"])


@router.get("", response_model=list[ActivityEventResponse])
async def list_activity(
    response: Response,
    event_type: Optional[str] = Query(None),
    source: Optional[str] = Query(None),   # e.g. "jumpcloud" or "google_workspace"
    user_id: Optional[str] = Query(None),
    country: Optional[str] = Query(None),
    is_suspicious: Optional[bool] = Query(None),
    date_from: Optional[datetime] = Query(None),
    date_to: Optional[datetime] = Query(None),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db),
    _: AuthUser = Depends(require_role("viewer")),
):
    query = select(ActivityEvent).options(selectinload(ActivityEvent.user))

    if event_type:
        types = [t.strip() for t in event_type.split(",") if t.strip()]
        if len(types) == 1:
            query = query.where(ActivityEvent.event_type == types[0])
        else:
            query = query.where(ActivityEvent.event_type.in_(types))
    if source:
        query = query.where(ActivityEvent.details["app"].as_string() == source)
    if user_id:
        query = query.where(ActivityEvent.user_id == user_id)
    if country:
        query = query.where(ActivityEvent.country == country)
    if is_suspicious is not None:
        query = query.where(ActivityEvent.is_suspicious == is_suspicious)
    if date_from:
        query = query.where(ActivityEvent.timestamp >= date_from)
    if date_to:
        query = query.where(ActivityEvent.timestamp <= date_to)

    count_q = select(func.count()).select_from(query.subquery())
    total = (await db.execute(count_q)).scalar_one()
    response.headers["X-Total-Count"] = str(total)

    result = await db.execute(
        query.order_by(ActivityEvent.timestamp.desc()).limit(limit).offset(offset)
    )
    events = result.scalars().all()
    return [ActivityEventResponse.model_validate(e) for e in events]


@router.get("/suspicious", response_model=list[ActivityEventResponse])
async def get_suspicious_activity(
    response: Response,
    event_type: Optional[str] = Query(None),
    user_id: Optional[str] = Query(None),
    country: Optional[str] = Query(None),
    date_from: Optional[datetime] = Query(None),
    date_to: Optional[datetime] = Query(None),
    source: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db),
    _: AuthUser = Depends(require_role("viewer")),
):
    query = (
        select(ActivityEvent)
        .options(selectinload(ActivityEvent.user))
        .where(ActivityEvent.is_suspicious == True)  # noqa: E712
    )

    if event_type:
        types = [t.strip() for t in event_type.split(",") if t.strip()]
        if len(types) == 1:
            query = query.where(ActivityEvent.event_type == types[0])
        else:
            query = query.where(ActivityEvent.event_type.in_(types))
    if source:
        query = query.where(ActivityEvent.details["app"].as_string() == source)
    if user_id:
        query = query.where(ActivityEvent.user_id == user_id)
    if country:
        query = query.where(ActivityEvent.country == country)
    if date_from:
        query = query.where(ActivityEvent.timestamp >= date_from)
    if date_to:
        query = query.where(ActivityEvent.timestamp <= date_to)

    count_q = select(func.count()).select_from(query.subquery())
    total = (await db.execute(count_q)).scalar_one()
    response.headers["X-Total-Count"] = str(total)

    result = await db.execute(
        query.order_by(ActivityEvent.timestamp.desc()).limit(limit).offset(offset)
    )
    events = result.scalars().all()
    return [ActivityEventResponse.model_validate(e) for e in events]
