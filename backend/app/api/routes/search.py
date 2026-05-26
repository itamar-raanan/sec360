from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, or_
from sqlalchemy.orm import selectinload

from app.api.deps import get_db, get_current_user, require_role
from app.models.user import AuthUser, User
from app.models.endpoint import Endpoint
from app.schemas.user import UserResponse
from app.schemas.endpoint import EndpointResponse

router = APIRouter(prefix="/search", tags=["search"])


@router.get("")
async def search(
    q: str = Query(..., min_length=3),
    db: AsyncSession = Depends(get_db),
    _: AuthUser = Depends(require_role("viewer")),
):
    pattern = f"%{q}%"

    user_result = await db.execute(
        select(User)
        .where(or_(User.full_name.ilike(pattern), User.email.ilike(pattern)))
        .limit(10)
    )
    users = user_result.scalars().all()

    endpoint_result = await db.execute(
        select(Endpoint)
        .options(
            selectinload(Endpoint.owner),
            selectinload(Endpoint.compliance_status),
            selectinload(Endpoint.agents),
        )
        .where(
            Endpoint.is_active == True,  # noqa: E712
            or_(Endpoint.hostname.ilike(pattern), Endpoint.ip_address.ilike(pattern)),
        )
        .limit(10)
    )
    endpoints = endpoint_result.scalars().all()

    return {
        "users": [UserResponse.model_validate(u) for u in users],
        "endpoints": [EndpointResponse.model_validate(e) for e in endpoints],
    }
