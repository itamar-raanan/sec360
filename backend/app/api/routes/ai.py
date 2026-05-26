"""
AI security insights router.

Prefix : /ai
Tags   : AI

Endpoints
---------
GET  /ai/insights              — paginated list of AI insights
GET  /ai/insights/stats        — severity + new-count summary
POST /ai/insights/{id}/dismiss — mark dismissed
POST /ai/insights/{id}/undismiss — unmark dismissed
POST /ai/analyze               — run full detection pass (analyst+)
POST /ai/explain               — explain a single event (all roles)
"""

from __future__ import annotations

import uuid
import logging
from datetime import datetime, timezone, timedelta
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Body, status
from pydantic import BaseModel, Field, ConfigDict
from sqlalchemy import select, func, and_, or_
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_db, get_current_user, require_role
from app.models.user import AuthUser, User
from app.models.ai_insight import AIInsight
from app.models.activity import ActivityEvent

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/ai", tags=["AI"])


# ---------------------------------------------------------------------------
# Pydantic schemas
# ---------------------------------------------------------------------------


class AIInsightSchema(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    insight_type: str
    severity: str
    title: str
    description: str
    user_id: Optional[uuid.UUID] = None
    user_name: Optional[str] = None
    user_email: Optional[str] = None
    evidence: Optional[dict] = None
    event_ids: Optional[list] = None
    is_dismissed: bool
    is_new: bool
    created_at: datetime
    expires_at: Optional[datetime] = None


class AIInsightListResponse(BaseModel):
    data: list[AIInsightSchema]
    total: int


class AIInsightStatsResponse(BaseModel):
    total: int
    critical: int
    high: int
    warning: int
    info: int
    new_count: int


class AnalyzeResponse(BaseModel):
    insights_created: int
    insights_total: int


class ExplainRequest(BaseModel):
    event_id: str = Field(..., description="UUID of the ActivityEvent to explain")


class ExplainResponse(BaseModel):
    explanation: str


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _insight_to_schema(insight: AIInsight, user: Optional[User] = None) -> AIInsightSchema:
    return AIInsightSchema(
        id=insight.id,
        insight_type=insight.insight_type,
        severity=insight.severity,
        title=insight.title,
        description=insight.description,
        user_id=insight.user_id,
        user_name=user.full_name if user else None,
        user_email=user.email if user else None,
        evidence=insight.evidence,
        event_ids=insight.event_ids,
        is_dismissed=insight.is_dismissed,
        is_new=insight.is_new,
        created_at=insight.created_at,
        expires_at=insight.expires_at,
    )


async def _load_user(db: AsyncSession, user_id: Optional[uuid.UUID]) -> Optional[User]:
    if user_id is None:
        return None
    result = await db.execute(select(User).where(User.id == user_id))
    return result.scalar_one_or_none()


# ---------------------------------------------------------------------------
# GET /ai/insights
# ---------------------------------------------------------------------------


@router.get("/insights", response_model=AIInsightListResponse)
async def list_insights(
    severity: Optional[str] = Query(None, description="Filter by severity level"),
    insight_type: Optional[str] = Query(None, description="Filter by insight type"),
    user_id: Optional[str] = Query(None, description="Filter by user UUID"),
    show_dismissed: bool = Query(False, description="Include dismissed insights"),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db),
    _: AuthUser = Depends(require_role("viewer")),
) -> AIInsightListResponse:
    query = select(AIInsight)

    if not show_dismissed:
        query = query.where(AIInsight.is_dismissed == False)  # noqa: E712

    if severity:
        query = query.where(AIInsight.severity == severity)

    if insight_type:
        query = query.where(AIInsight.insight_type == insight_type)

    if user_id:
        try:
            uid = uuid.UUID(user_id)
        except ValueError:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="Invalid user_id UUID",
            )
        query = query.where(AIInsight.user_id == uid)

    # Total count
    count_query = select(func.count()).select_from(query.subquery())
    total = (await db.execute(count_query)).scalar_one()

    # Paginated results, newest first
    query = query.order_by(AIInsight.created_at.desc()).limit(limit).offset(offset)
    result = await db.execute(query)
    insights = result.scalars().all()

    # Bulk-load associated users
    user_ids = list({i.user_id for i in insights if i.user_id is not None})
    users_by_id: dict[uuid.UUID, User] = {}
    if user_ids:
        users_result = await db.execute(select(User).where(User.id.in_(user_ids)))
        for u in users_result.scalars().all():
            users_by_id[u.id] = u

    data = [
        _insight_to_schema(ins, users_by_id.get(ins.user_id) if ins.user_id else None)
        for ins in insights
    ]

    return AIInsightListResponse(data=data, total=total)


# ---------------------------------------------------------------------------
# GET /ai/insights/stats
# ---------------------------------------------------------------------------


@router.get("/insights/stats", response_model=AIInsightStatsResponse)
async def get_insight_stats(
    db: AsyncSession = Depends(get_db),
    _: AuthUser = Depends(require_role("viewer")),
) -> AIInsightStatsResponse:
    # Active (non-dismissed) insights
    base = select(AIInsight).where(AIInsight.is_dismissed == False)  # noqa: E712

    total_res = await db.execute(select(func.count()).select_from(base.subquery()))
    total = total_res.scalar_one()

    # Per-severity counts
    sev_res = await db.execute(
        select(AIInsight.severity, func.count(AIInsight.id))
        .where(AIInsight.is_dismissed == False)  # noqa: E712
        .group_by(AIInsight.severity)
    )
    sev_map: dict[str, int] = {row[0]: row[1] for row in sev_res.fetchall()}

    new_res = await db.execute(
        select(func.count(AIInsight.id)).where(
            and_(AIInsight.is_new == True, AIInsight.is_dismissed == False)  # noqa: E712
        )
    )
    new_count = new_res.scalar_one()

    return AIInsightStatsResponse(
        total=total,
        critical=sev_map.get("critical", 0),
        high=sev_map.get("high", 0),
        warning=sev_map.get("warning", 0),
        info=sev_map.get("info", 0),
        new_count=new_count,
    )


# ---------------------------------------------------------------------------
# POST /ai/insights/{insight_id}/dismiss
# ---------------------------------------------------------------------------


@router.post("/insights/{insight_id}/dismiss", response_model=AIInsightSchema)
async def dismiss_insight(
    insight_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    _: AuthUser = Depends(require_role("analyst")),
) -> AIInsightSchema:
    result = await db.execute(select(AIInsight).where(AIInsight.id == insight_id))
    insight = result.scalar_one_or_none()
    if not insight:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Insight not found")

    insight.is_dismissed = True
    insight.is_new = False
    await db.flush()

    user = await _load_user(db, insight.user_id)
    return _insight_to_schema(insight, user)


# ---------------------------------------------------------------------------
# POST /ai/insights/{insight_id}/undismiss
# ---------------------------------------------------------------------------


@router.post("/insights/{insight_id}/undismiss", response_model=AIInsightSchema)
async def undismiss_insight(
    insight_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    _: AuthUser = Depends(require_role("analyst")),
) -> AIInsightSchema:
    result = await db.execute(select(AIInsight).where(AIInsight.id == insight_id))
    insight = result.scalar_one_or_none()
    if not insight:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Insight not found")

    insight.is_dismissed = False
    await db.flush()

    user = await _load_user(db, insight.user_id)
    return _insight_to_schema(insight, user)


# ---------------------------------------------------------------------------
# POST /ai/analyze
# ---------------------------------------------------------------------------


@router.post("/analyze", response_model=AnalyzeResponse)
async def run_analysis(
    hours_back: int = Query(24, ge=1, le=168, description="Hours of history to analyse"),
    db: AsyncSession = Depends(get_db),
    _: AuthUser = Depends(require_role("analyst")),
) -> AnalyzeResponse:
    """
    Trigger a full anomaly-detection pass and persist new insights.

    Skips inserting a new insight if a non-dismissed record with the same
    (insight_type, user_id, severity) already exists within the last 24 hours.
    """
    from app.engines.anomaly_engine import run_all_detections
    from app.engines.ai_explainer import generate_insight_description

    detections = await run_all_detections(db, hours_back=hours_back)

    # Pre-load user details for description generation (bulk)
    user_ids_needed = list({
        uuid.UUID(d["user_id"])
        for d in detections
        if d.get("user_id")
    })
    users_map: dict[uuid.UUID, User] = {}
    if user_ids_needed:
        u_result = await db.execute(select(User).where(User.id.in_(user_ids_needed)))
        for u in u_result.scalars().all():
            users_map[u.id] = u

    # Deduplication window: 24 hours
    dedup_cutoff = datetime.now(timezone.utc) - timedelta(hours=24)

    # Fetch existing insights in the window to avoid duplicates
    existing_result = await db.execute(
        select(AIInsight.insight_type, AIInsight.user_id, AIInsight.severity)
        .where(
            and_(
                AIInsight.created_at >= dedup_cutoff,
                AIInsight.is_dismissed == False,  # noqa: E712
            )
        )
    )
    existing_keys: set[tuple[str, Optional[str], str]] = {
        (row[0], str(row[1]) if row[1] else None, row[2])
        for row in existing_result.fetchall()
    }

    created_count = 0
    for detection in detections:
        insight_type = detection["insight_type"]
        user_id_str = detection.get("user_id")
        severity = detection["severity"]
        dedup_key = (insight_type, user_id_str, severity)

        if dedup_key in existing_keys:
            continue  # Already recorded within the last 24 hours

        uid: Optional[uuid.UUID] = None
        if user_id_str:
            try:
                uid = uuid.UUID(user_id_str)
            except ValueError:
                uid = None

        user = users_map.get(uid) if uid else None
        user_name = user.full_name if user else "Unknown"
        user_email = user.email if user else ""
        user_dept = user.department if user else None

        try:
            description = await generate_insight_description(
                insight_type=insight_type,
                title=detection["title"],
                evidence=detection.get("evidence") or {},
                user_name=user_name,
                user_email=user_email,
                user_dept=user_dept,
            )
        except Exception as exc:
            logger.warning(
                "Failed to generate description for %s: %s", insight_type, exc
            )
            description = detection["title"]

        event_ids = detection.get("event_ids") or []

        new_insight = AIInsight(
            insight_type=insight_type,
            severity=severity,
            title=detection["title"],
            description=description,
            user_id=uid,
            evidence=detection.get("evidence"),
            event_ids=event_ids,
            is_dismissed=False,
            is_new=True,
        )
        db.add(new_insight)
        existing_keys.add(dedup_key)  # prevent in-batch duplicates
        created_count += 1

    await db.flush()

    # Total active insights count
    total_res = await db.execute(
        select(func.count(AIInsight.id)).where(AIInsight.is_dismissed == False)  # noqa: E712
    )
    total = total_res.scalar_one()

    return AnalyzeResponse(insights_created=created_count, insights_total=total)


# ---------------------------------------------------------------------------
# POST /ai/explain
# ---------------------------------------------------------------------------


@router.post("/explain", response_model=ExplainResponse)
async def explain_event_endpoint(
    body: ExplainRequest = Body(...),
    db: AsyncSession = Depends(get_db),
    _: AuthUser = Depends(get_current_user),
) -> ExplainResponse:
    """
    Fetch an ActivityEvent by ID and return a plain-English explanation.
    Available to all authenticated users.
    """
    from app.engines.ai_explainer import explain_event

    try:
        event_uuid = uuid.UUID(body.event_id)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Invalid event_id UUID",
        )

    ev_result = await db.execute(
        select(ActivityEvent).where(ActivityEvent.id == event_uuid)
    )
    event = ev_result.scalar_one_or_none()
    if not event:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Event not found")

    # Resolve user details
    user_name = "Unknown"
    user_email = ""
    if event.user_id:
        user = await _load_user(db, event.user_id)
        if user:
            user_name = user.full_name or user.email
            user_email = user.email

    explanation = await explain_event(
        event_type=event.event_type,
        details=event.details or {},
        user_name=user_name,
        user_email=user_email,
        timestamp=event.timestamp.isoformat(),
        country=event.country,
        ip_address=event.ip_address,
        is_suspicious=event.is_suspicious,
    )

    # Mark event as no longer new in any associated insight
    # (best-effort: don't fail the request if this errors)
    try:
        related = await db.execute(
            select(AIInsight).where(
                and_(
                    AIInsight.is_new == True,  # noqa: E712
                    AIInsight.event_ids.contains([str(event_uuid)]),  # JSONB contains
                )
            )
        )
        for ins in related.scalars().all():
            ins.is_new = False
        await db.flush()
    except Exception as exc:
        logger.debug("Could not mark related insights as viewed: %s", exc)

    return ExplainResponse(explanation=explanation)
