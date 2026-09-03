from typing import Optional
from fastapi import APIRouter, Depends, Query, Response, HTTPException, Request, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, or_, exists
from sqlalchemy.orm import selectinload

from app.api.deps import get_db, get_current_user, require_role, audit_action
from app.models.user import AuthUser
from app.models.endpoint import Endpoint
from app.models.agent import SecurityAgent
from app.schemas.endpoint import EndpointResponse, EndpointDetail, AgentSummary, AgentDetail
from app.services.endpoint_inventory import current_endpoint_clause
from pydantic import BaseModel

router = APIRouter(prefix="/endpoints", tags=["endpoints"])

@router.get("", response_model=list[EndpointResponse])
async def list_endpoints(
    response: Response,
    compliance_status: Optional[str] = Query(None),
    agent_status: Optional[str] = Query(None),
    os_filter: Optional[str] = Query(None),
    search: Optional[str] = Query(None),
    has_s1: Optional[bool] = Query(None),          # true = has SentinelOne, false = missing
    has_dlp: Optional[bool] = Query(None),         # true = has Symantec DLP, false = missing
    has_gp: Optional[bool] = Query(None),          # true = has GlobalProtect, false = missing
    has_wss: Optional[bool] = Query(None),         # true = has Symantec WSS, false = missing
    unassigned: Optional[bool] = Query(None),      # true = no owner linked
    active_only: bool = Query(True),               # false = include stale endpoints
    limit: int = Query(50, ge=1, le=5000),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db),
    _: AuthUser = Depends(require_role("viewer")),
):
    from app.models.compliance import ComplianceStatus

    query = select(Endpoint).options(
        selectinload(Endpoint.owner),
        selectinload(Endpoint.compliance_status),
        selectinload(Endpoint.agents),
    ).where(Endpoint.is_active == True)  # noqa: E712

    if compliance_status:
        query = query.join(
            ComplianceStatus, Endpoint.id == ComplianceStatus.endpoint_id
        ).where(ComplianceStatus.status == compliance_status)

    if os_filter:
        OS_PATTERNS = {"windows": "%windows%", "macos": "%mac%", "linux": "%linux%"}
        pattern = OS_PATTERNS.get(os_filter.lower(), f"%{os_filter}%")
        query = query.where(Endpoint.os_version.ilike(pattern))

    if search:
        pattern = f"%{search}%"
        query = query.where(
            or_(
                Endpoint.hostname.ilike(pattern),
                Endpoint.ip_address.ilike(pattern),
                Endpoint.username.ilike(pattern),
            )
        )

    # Agent presence filters using EXISTS subquery
    if has_s1 is not None:
        s1_exists = exists().where(
            SecurityAgent.endpoint_id == Endpoint.id,
            SecurityAgent.product_name == "sentinelone",
        )
        query = query.where(s1_exists if has_s1 else ~s1_exists)

    if has_dlp is not None:
        dlp_exists = exists().where(
            SecurityAgent.endpoint_id == Endpoint.id,
            SecurityAgent.product_name == "symantec",
        )
        query = query.where(dlp_exists if has_dlp else ~dlp_exists)

    if has_gp is not None:
        gp_exists = exists().where(
            SecurityAgent.endpoint_id == Endpoint.id,
            SecurityAgent.product_name == "globalprotect",
        )
        query = query.where(gp_exists if has_gp else ~gp_exists)

    if has_wss is not None:
        wss_exists = exists().where(
            SecurityAgent.endpoint_id == Endpoint.id,
            SecurityAgent.product_name == "symantec_wss",
        )
        query = query.where(wss_exists if has_wss else ~wss_exists)

    if unassigned is True:
        query = query.where(Endpoint.owner_user_id.is_(None))
    elif unassigned is False:
        query = query.where(Endpoint.owner_user_id.isnot(None))

    # Activity filter: show only endpoints seen within the last 60 days
    # (via JumpCloud last_seen OR any agent last_seen)
    if active_only:
        query = query.where(current_endpoint_clause())

    count_q = select(func.count()).select_from(query.subquery())
    total = (await db.execute(count_q)).scalar_one()
    response.headers["X-Total-Count"] = str(total)

    result = await db.execute(
        query.order_by(Endpoint.risk_score.desc()).limit(limit).offset(offset)
    )
    endpoints = result.scalars().all()
    return [EndpointResponse.model_validate(e) for e in endpoints]


@router.get("/{endpoint_id}", response_model=EndpointDetail)
async def get_endpoint(
    endpoint_id: str,
    db: AsyncSession = Depends(get_db),
    _: AuthUser = Depends(require_role("viewer")),
):
    result = await db.execute(
        select(Endpoint)
        .options(
            selectinload(Endpoint.owner),
            selectinload(Endpoint.agents),
            selectinload(Endpoint.compliance_status),
        )
        .where(Endpoint.id == endpoint_id)
    )
    endpoint = result.scalar_one_or_none()
    if not endpoint:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Endpoint not found")

    detail = EndpointDetail.model_validate(endpoint)

    # Build per-product agent breakdown
    for agent in endpoint.agents:
        agent_detail = AgentDetail(
            installed=True,
            status=agent.status,
            version=agent.version,
            last_seen=agent.last_seen,
            disk_encrypted=getattr(agent, "disk_encrypted", None),
            encryption_status=getattr(agent, "encryption_status", None),
            device_control_enabled=getattr(agent, "device_control_enabled", None),
            agent_group=getattr(agent, "agent_group", None),
            agent_state=getattr(agent, "agent_state", None),
        )
        if agent.product_name == "sentinelone":
            detail.sentinelone = agent_detail
        elif agent.product_name == "symantec":
            detail.symantec_dlp = agent_detail
        elif agent.product_name == "globalprotect":
            detail.globalprotect = agent_detail
        elif agent.product_name == "symantec_wss":
            detail.symantec_wss = agent_detail

    return detail


class RiskOverrideRequest(BaseModel):
    override: Optional[float] = None   # None = clear the override
    note: Optional[str] = None


class BulkAssignRequest(BaseModel):
    ids: list[str]
    owner_user_id: Optional[str] = None   # None = unassign


@router.patch("/{endpoint_id}/risk-override")
async def set_risk_override(
    endpoint_id: str,
    data: RiskOverrideRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current: AuthUser = Depends(require_role("analyst")),
):
    result = await db.execute(select(Endpoint).where(Endpoint.id == endpoint_id))
    endpoint = result.scalar_one_or_none()
    if not endpoint:
        raise HTTPException(status_code=404, detail="Endpoint not found")

    if data.override is not None and not (0.0 <= data.override <= 100.0):
        raise HTTPException(status_code=400, detail="Override must be between 0 and 100")

    endpoint.risk_score_override = data.override
    endpoint.risk_score_note = data.note
    await db.flush()
    await audit_action(
        "risk_override", "endpoint", endpoint_id, request, db, current,
        {"override": data.override, "note": data.note, "hostname": endpoint.hostname},
    )
    return {"id": str(endpoint.id), "risk_score_override": endpoint.risk_score_override, "risk_score_note": endpoint.risk_score_note}


@router.post("/bulk")
async def bulk_update(
    data: BulkAssignRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current: AuthUser = Depends(require_role("analyst")),
):
    if not data.ids:
        raise HTTPException(status_code=400, detail="No endpoint IDs provided")
    if len(data.ids) > 500:
        raise HTTPException(status_code=400, detail="Cannot update more than 500 endpoints at once")

    from sqlalchemy import update as sql_update
    import uuid as _uuid

    # owner_user_id is an auth_user UUID — resolve to the matching HR user by email
    owner_uuid: _uuid.UUID | None = None
    if data.owner_user_id:
        from app.models.user import User as HrUser
        try:
            auth_uuid = _uuid.UUID(data.owner_user_id)
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid owner_user_id UUID")

        auth_user = (await db.execute(select(AuthUser).where(AuthUser.id == auth_uuid))).scalar_one_or_none()
        if not auth_user:
            raise HTTPException(status_code=404, detail="System user not found")

        hr_user = (await db.execute(select(HrUser).where(HrUser.email == auth_user.email))).scalar_one_or_none()
        if not hr_user:
            raise HTTPException(
                status_code=422,
                detail=f"No employee record found for {auth_user.email}. "
                       "The user must exist in the directory (JumpCloud) before they can be set as an owner.",
            )
        owner_uuid = hr_user.id

    ids_as_uuid = []
    for raw_id in data.ids:
        try:
            ids_as_uuid.append(_uuid.UUID(raw_id))
        except ValueError:
            raise HTTPException(status_code=400, detail=f"Invalid UUID: {raw_id}")
    stmt = (
        sql_update(Endpoint)
        .where(Endpoint.id.in_(ids_as_uuid))
        .values(owner_user_id=owner_uuid)
        .execution_options(synchronize_session="fetch")
    )
    await db.execute(stmt)
    await db.flush()
    await audit_action(
        "bulk_assign_owner", "endpoint", None, request, db, current,
        {"count": len(data.ids), "owner_user_id": data.owner_user_id},
    )
    return {"updated": len(data.ids)}


@router.get("/{endpoint_id}/agents", response_model=list[AgentSummary])
async def get_endpoint_agents(
    endpoint_id: str,
    db: AsyncSession = Depends(get_db),
    _: AuthUser = Depends(require_role("viewer")),
):
    result = await db.execute(
        select(SecurityAgent).where(SecurityAgent.endpoint_id == endpoint_id)
    )
    agents = result.scalars().all()
    return [AgentSummary.model_validate(a) for a in agents]
