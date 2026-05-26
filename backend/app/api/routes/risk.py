from fastapi import APIRouter, Depends, Query, Response
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, case

from app.api.deps import get_db, get_current_user, require_role
from app.models.user import AuthUser, User
from app.models.endpoint import Endpoint
from app.schemas.user import UserResponse
from app.schemas.endpoint import EndpointResponse
from app.schemas.risk import RiskSummary

router = APIRouter(prefix="/risk", tags=["risk"])


def risk_level(score: float) -> str:
    if score <= 25:
        return "low"
    elif score <= 50:
        return "medium"
    elif score <= 75:
        return "high"
    return "critical"


@router.get("/users", response_model=list[UserResponse])
async def get_risky_users(
    response: Response,
    min_score: float = Query(0.0),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db),
    _: AuthUser = Depends(require_role("viewer")),
):
    from sqlalchemy import func
    query = select(User).where(User.risk_score >= min_score)
    total = (await db.execute(select(func.count()).select_from(query.subquery()))).scalar_one()
    response.headers["X-Total-Count"] = str(total)

    result = await db.execute(
        query.order_by(User.risk_score.desc()).limit(limit).offset(offset)
    )
    users = result.scalars().all()
    return [UserResponse.model_validate(u) for u in users]


@router.get("/endpoints", response_model=list[EndpointResponse])
async def get_risky_endpoints(
    response: Response,
    min_score: float = Query(0.0),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db),
    _: AuthUser = Depends(require_role("viewer")),
):
    from sqlalchemy import func
    from sqlalchemy.orm import selectinload

    query = select(Endpoint).options(
        selectinload(Endpoint.owner),
        selectinload(Endpoint.compliance_status),
        selectinload(Endpoint.agents),
    ).where(Endpoint.risk_score >= min_score, Endpoint.is_active == True)  # noqa: E712

    total = (await db.execute(select(func.count()).select_from(query.subquery()))).scalar_one()
    response.headers["X-Total-Count"] = str(total)

    result = await db.execute(
        query.order_by(Endpoint.risk_score.desc()).limit(limit).offset(offset)
    )
    endpoints = result.scalars().all()
    return [EndpointResponse.model_validate(e) for e in endpoints]


def _bucket_query(model, score_col):
    return select(
        func.count().label("total"),
        func.coalesce(func.sum(case((score_col <= 25,                       1), else_=0)), 0).label("low"),
        func.coalesce(func.sum(case(((score_col > 25) & (score_col <= 50),  1), else_=0)), 0).label("medium"),
        func.coalesce(func.sum(case(((score_col > 50) & (score_col <= 75),  1), else_=0)), 0).label("high"),
        func.coalesce(func.sum(case((score_col > 75,                        1), else_=0)), 0).label("critical"),
    )


@router.get("/summary")
async def get_risk_summary(
    db: AsyncSession = Depends(get_db),
    _: AuthUser = Depends(require_role("viewer")),
):
    u = (await db.execute(_bucket_query(User, User.risk_score))).one()
    e = (await db.execute(_bucket_query(Endpoint, Endpoint.risk_score))).one()

    return {
        "users":     {"total": u.total, "low": u.low, "medium": u.medium, "high": u.high, "critical": u.critical},
        "endpoints": {"total": e.total, "low": e.low, "medium": e.medium, "high": e.high, "critical": e.critical},
    }
