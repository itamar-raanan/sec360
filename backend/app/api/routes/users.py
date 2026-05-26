from typing import Optional
from fastapi import APIRouter, Depends, Query, Response
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, or_
from sqlalchemy.orm import selectinload

from app.api.deps import get_db, get_current_user, require_role
from app.models.user import AuthUser, User
from app.models.endpoint import Endpoint
from app.models.agent import SecurityAgent
from app.models.compliance import ComplianceStatus
from app.models.activity import ActivityEvent
from app.schemas.user import UserResponse, UserDetail
from app.schemas.endpoint import EndpointResponse
from app.schemas.activity import ActivityEventResponse
from app.schemas.identity import UserIdentity, EndpointIdentity, AgentSummary, ComplianceSummary

router = APIRouter(prefix="/users", tags=["users"])


@router.get("", response_model=list[UserResponse])
async def list_users(
    response: Response,
    department: Optional[str] = Query(None),
    employment_status: Optional[str] = Query(None),
    risk_level: Optional[str] = Query(None),
    search: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=2000),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db),
    _: AuthUser = Depends(require_role("viewer")),
):
    query = select(User)

    if department:
        query = query.where(User.department == department)
    if employment_status:
        query = query.where(User.employment_status == employment_status)
    if risk_level:
        thresholds = {"low": (0, 25), "medium": (26, 50), "high": (51, 75), "critical": (76, 100)}
        if risk_level in thresholds:
            lo, hi = thresholds[risk_level]
            query = query.where(User.risk_score >= lo, User.risk_score <= hi)
    if search:
        pattern = f"%{search}%"
        query = query.where(
            or_(User.full_name.ilike(pattern), User.email.ilike(pattern))
        )

    count_q = select(func.count()).select_from(query.subquery())
    total = (await db.execute(count_q)).scalar_one()
    response.headers["X-Total-Count"] = str(total)

    result = await db.execute(query.order_by(User.risk_score.desc()).limit(limit).offset(offset))
    users = result.scalars().all()

    # Build endpoint counts in one extra query
    user_ids = [u.id for u in users]
    ep_counts: dict = {}
    if user_ids:
        counts_result = await db.execute(
            select(Endpoint.owner_user_id, func.count(Endpoint.id).label("cnt"))
            .where(Endpoint.owner_user_id.in_(user_ids), Endpoint.is_active == True)  # noqa: E712
            .group_by(Endpoint.owner_user_id)
        )
        ep_counts = {row.owner_user_id: row.cnt for row in counts_result}

    responses = []
    for u in users:
        r = UserResponse.model_validate(u)
        r.endpoint_count = ep_counts.get(u.id, 0)
        responses.append(r)
    return responses


@router.get("/anomalies", response_model=dict)
async def get_user_anomalies(
    db: AsyncSession = Depends(get_db),
    _: AuthUser = Depends(require_role("viewer")),
):
    """Return users with cross-source anomalies (status/MFA mismatch, single-source users)."""
    result = await db.execute(select(User).where(User.sources.isnot(None)))
    all_users = result.scalars().all()

    anomalies = []
    for user in all_users:
        sources = user.sources or {}
        if not sources:
            continue

        anomaly_types = []
        jc = sources.get("jumpcloud")
        gw = sources.get("google")

        if jc and gw:
            # Status mismatch: active in one, not in the other
            jc_active = jc.get("active", True) and not jc.get("suspended", False)
            gw_active = gw.get("active", True) and not gw.get("suspended", False)
            if jc_active != gw_active:
                anomaly_types.append("status_mismatch")

            # MFA mismatch
            if jc.get("mfa") != gw.get("mfa"):
                anomaly_types.append("mfa_mismatch")
        elif gw and not jc:
            anomaly_types.append("google_only")
        elif jc and not gw:
            anomaly_types.append("jumpcloud_only")

        if anomaly_types:
            anomalies.append({
                "user_id": str(user.id),
                "email": user.email,
                "full_name": user.full_name,
                "anomaly_types": anomaly_types,
                "sources": sources,
            })

    return {"anomalies": anomalies, "total": len(anomalies)}


@router.get("/{user_id}", response_model=UserDetail)
async def get_user(
    user_id: str,
    db: AsyncSession = Depends(get_db),
    _: AuthUser = Depends(require_role("viewer")),
):
    result = await db.execute(
        select(User).options(selectinload(User.endpoints)).where(User.id == user_id)
    )
    user = result.scalar_one_or_none()
    if not user:
        from fastapi import HTTPException, status
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    events_result = await db.execute(
        select(ActivityEvent)
        .where(ActivityEvent.user_id == user_id)
        .order_by(ActivityEvent.timestamp.desc())
        .limit(20)
    )
    events = events_result.scalars().all()

    detail = UserDetail.model_validate(user)
    detail.endpoints = [EndpointResponse.model_validate(e) for e in user.endpoints]
    detail.recent_events = [ActivityEventResponse.model_validate(e) for e in events]
    return detail


@router.get("/{user_id}/timeline", response_model=list[ActivityEventResponse])
async def get_user_timeline(
    user_id: str,
    days: int = Query(7, ge=1, le=90),
    limit: int = Query(200, ge=1, le=1000),
    db: AsyncSession = Depends(get_db),
    _: AuthUser = Depends(require_role("viewer")),
):
    from datetime import datetime, timezone, timedelta
    since = datetime.now(timezone.utc) - timedelta(days=days)

    result = await db.execute(
        select(ActivityEvent)
        .where(ActivityEvent.user_id == user_id, ActivityEvent.timestamp >= since)
        .order_by(ActivityEvent.timestamp.desc())
        .limit(limit)
    )
    events = result.scalars().all()
    return [ActivityEventResponse.model_validate(e) for e in events]


@router.get("/{user_id}/devices", response_model=list[EndpointResponse])
async def get_user_devices(
    user_id: str,
    db: AsyncSession = Depends(get_db),
    _: AuthUser = Depends(require_role("viewer")),
):
    result = await db.execute(
        select(Endpoint)
        .options(selectinload(Endpoint.agents), selectinload(Endpoint.compliance_status))
        .where(Endpoint.owner_user_id == user_id, Endpoint.is_active == True)  # noqa: E712
    )
    endpoints = result.scalars().all()
    return [EndpointResponse.model_validate(e) for e in endpoints]


@router.get("/{user_id}/identity", response_model=UserIdentity)
async def get_user_identity(
    user_id: str,
    db: AsyncSession = Depends(get_db),
    _: AuthUser = Depends(require_role("viewer")),
):
    """Full identity profile: user + all endpoints + all agents + compliance."""
    from fastapi import HTTPException, status as http_status

    result = await db.execute(
        select(User)
        .options(
            selectinload(User.endpoints).selectinload(Endpoint.agents),
            selectinload(User.endpoints).selectinload(Endpoint.compliance_status),
        )
        .where(User.id == user_id)
    )
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=http_status.HTTP_404_NOT_FOUND, detail="User not found")

    endpoint_identities: list[EndpointIdentity] = []
    s1_count = symantec_count = compliant_count = noncompliant_count = 0

    for ep in user.endpoints:
        agents = [AgentSummary.model_validate(a) for a in ep.agents]
        products = [a.product_name for a in ep.agents]

        compliance = None
        if ep.compliance_status:
            compliance = ComplianceSummary.model_validate(ep.compliance_status)

        if "sentinelone" in products:
            s1_count += 1
        if "symantec" in products:
            symantec_count += 1

        if ep.compliance_status:
            if ep.compliance_status.status == "compliant":
                compliant_count += 1
            elif ep.compliance_status.status == "non_compliant":
                noncompliant_count += 1

        endpoint_identities.append(
            EndpointIdentity(
                id=ep.id,
                hostname=ep.hostname,
                os_version=ep.os_version,
                ip_address=ep.ip_address,
                location=ep.location,
                username=ep.username,
                last_seen=ep.last_seen,
                risk_score=ep.risk_score,
                agents=agents,
                compliance=compliance,
                agent_products=products,
            )
        )

    total = len(user.endpoints)

    identity = UserIdentity(
        id=user.id,
        full_name=user.full_name,
        email=user.email,
        department=user.department,
        manager=user.manager,
        employment_status=user.employment_status,
        mfa_enabled=user.mfa_enabled,
        last_login=user.last_login,
        risk_score=user.risk_score,
        created_at=user.created_at,
        updated_at=user.updated_at,
        job_title=user.job_title,
        phone=user.phone,
        sources=user.sources,
        endpoints=endpoint_identities,
        data_sources=_infer_sources(user),
        total_endpoints=total,
        endpoints_with_sentinelone=s1_count,
        endpoints_with_symantec=symantec_count,
        endpoints_compliant=compliant_count,
        endpoints_non_compliant=noncompliant_count,
        all_agents_ok=total > 0 and s1_count == total and symantec_count == total,
    )
    return identity


def _infer_sources(user: User) -> list[str]:
    """Guess which systems this user was synced from based on available fields."""
    sources = []
    if user.email:
        sources.append("jumpcloud")
    if user.department or user.manager:
        sources.append("hibob")
    return sources


@router.post("/correlate", status_code=200)
async def trigger_correlation(
    db: AsyncSession = Depends(get_db),
    _: AuthUser = Depends(require_role("admin")),
):
    """Manually trigger endpoint deduplication + user-endpoint linking."""
    from app.engines.correlation import run_full_correlation
    from app.core.database import AsyncSessionLocal

    async with AsyncSessionLocal() as session:
        try:
            result = await run_full_correlation(session)
            await session.commit()
            return {"success": True, **result}
        except Exception as e:
            await session.rollback()
            return {"success": False, "error": str(e)}
