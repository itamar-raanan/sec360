import csv
import io
import json
import uuid
from datetime import datetime, timezone
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field
from sqlalchemy import String, asc, cast, delete, desc, exists, func, or_, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_db, require_connected_integration, require_role
from app.models.puppet import (
    PuppetFact,
    PuppetFactFavorite,
    PuppetFactSavedView,
    PuppetNode,
)
from app.models.user import AuthUser


router = APIRouter(
    prefix="/puppet-facts",
    tags=["puppet-facts"],
    dependencies=[Depends(require_connected_integration("puppet"))],
)

ValueType = Literal["string", "number", "boolean", "array", "object", "null"]
SortField = Literal["certname", "name", "value_type", "environment", "synced_at"]
SortOrder = Literal["asc", "desc"]


class SavedViewDefinition(BaseModel):
    search: str = Field(default="", max_length=500)
    certname: str = Field(default="", max_length=500)
    names: list[str] = Field(default_factory=list, max_length=100)
    environment: str = Field(default="", max_length=255)
    value_types: list[ValueType] = Field(default_factory=list)
    favorites_only: bool = False
    page_size: Literal[25, 50, 100] = 50
    sort: SortField = "certname"
    order: SortOrder = "asc"


class FavoriteCreate(BaseModel):
    fact_name: str = Field(min_length=1, max_length=500)


class SavedViewCreate(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    definition: SavedViewDefinition
    is_default: bool = False


class SavedViewUpdate(SavedViewCreate):
    pass


def _csv_list(value: str | None, *, maximum: int = 100) -> list[str]:
    if not value:
        return []
    return list(dict.fromkeys(item.strip() for item in value.split(",") if item.strip()))[:maximum]


def _filtered_query(
    *,
    search=None,
    certname=None,
    names: list[str] | None = None,
    environment=None,
    value_types: list[str] | None = None,
    favorites_only=False,
    user_id=None,
):
    query = select(PuppetFact)
    if search:
        pattern = f"%{search.strip()}%"
        query = query.where(or_(
            PuppetFact.certname.ilike(pattern),
            PuppetFact.name.ilike(pattern),
            cast(PuppetFact.value, String).ilike(pattern),
        ))
    if certname:
        query = query.where(PuppetFact.certname.ilike(f"%{certname.strip()}%"))
    if names:
        query = query.where(PuppetFact.name.in_(names))
    if environment:
        query = query.where(PuppetFact.environment == environment)
    if value_types:
        query = query.where(PuppetFact.value_type.in_(value_types))
    if favorites_only and user_id:
        query = query.where(exists().where(
            PuppetFactFavorite.user_id == user_id,
            PuppetFactFavorite.fact_name == PuppetFact.name,
        ))
    return query


def _sort_query(query, sort: SortField, order: SortOrder):
    columns = {
        "certname": PuppetFact.certname,
        "name": PuppetFact.name,
        "value_type": PuppetFact.value_type,
        "environment": PuppetFact.environment,
        "synced_at": PuppetFact.synced_at,
    }
    direction = desc if order == "desc" else asc
    primary = columns[sort]
    return query.order_by(direction(primary), asc(PuppetFact.certname), asc(PuppetFact.name))


def _csv_safe(value):
    text = str(value)
    return f"'{text}" if text.startswith(("=", "+", "-", "@")) else text


def _payload(fact: PuppetFact) -> dict:
    return {
        "id": str(fact.id),
        "certname": fact.certname,
        "name": fact.name,
        "value": fact.value,
        "value_type": fact.value_type,
        "environment": fact.environment,
        "synced_at": fact.synced_at,
    }


def _view_payload(view: PuppetFactSavedView) -> dict:
    return {
        "id": str(view.id),
        "name": view.name,
        "definition": view.definition,
        "is_default": view.is_default,
        "created_at": view.created_at,
        "updated_at": view.updated_at,
    }


@router.get("/summary")
async def puppet_fact_summary(
    search: str | None = Query(None, max_length=500),
    certname: str | None = Query(None, max_length=500),
    name: str | None = Query(None, max_length=500),
    names: str | None = Query(None, max_length=10_000),
    environment: str | None = Query(None, max_length=255),
    value_types: str | None = Query(None, max_length=200),
    favorites_only: bool = False,
    db: AsyncSession = Depends(get_db),
    current: AuthUser = Depends(require_role("analyst")),
):
    filtered = _filtered_query(
        search=search,
        certname=certname,
        names=_csv_list(names) or ([name] if name else []),
        environment=environment,
        value_types=_csv_list(value_types, maximum=6),
        favorites_only=favorites_only,
        user_id=current.id,
    ).subquery()
    row = (await db.execute(select(
        func.count(filtered.c.id).label("facts"),
        func.count(func.distinct(filtered.c.name)).label("fact_names"),
        func.count(func.distinct(filtered.c.certname)).label("nodes"),
        func.max(filtered.c.synced_at).label("last_sync"),
    ))).one()
    status_rows = (await db.execute(
        select(PuppetNode.latest_report_status, func.count())
        .group_by(PuppetNode.latest_report_status)
    )).all()
    return {
        "facts": row.facts or 0,
        "fact_names": row.fact_names or 0,
        "nodes": row.nodes or 0,
        "last_sync": row.last_sync,
        "report_statuses": {(status or "unknown"): count for status, count in status_rows},
    }


@router.get("/facets")
async def puppet_fact_facets(
    db: AsyncSession = Depends(get_db),
    _: AuthUser = Depends(require_role("analyst")),
):
    names = (await db.execute(
        select(PuppetFact.name).distinct().order_by(PuppetFact.name).limit(5_000)
    )).scalars().all()
    environments = (await db.execute(
        select(PuppetFact.environment)
        .where(PuppetFact.environment.isnot(None))
        .distinct()
        .order_by(PuppetFact.environment)
    )).scalars().all()
    return {
        "names": names,
        "environments": environments,
        "value_types": ["string", "number", "boolean", "array", "object", "null"],
    }


@router.get("/favorites")
async def list_favorites(
    db: AsyncSession = Depends(get_db),
    current: AuthUser = Depends(require_role("analyst")),
):
    favorites = (await db.execute(
        select(PuppetFactFavorite)
        .where(PuppetFactFavorite.user_id == current.id)
        .order_by(PuppetFactFavorite.fact_name)
    )).scalars().all()
    return [{"id": str(item.id), "fact_name": item.fact_name, "created_at": item.created_at} for item in favorites]


@router.post("/favorites", status_code=status.HTTP_201_CREATED)
async def create_favorite(
    payload: FavoriteCreate,
    db: AsyncSession = Depends(get_db),
    current: AuthUser = Depends(require_role("analyst")),
):
    fact_name = payload.fact_name.strip()
    if not fact_name:
        raise HTTPException(status_code=422, detail="Fact name cannot be empty")
    existing = await db.scalar(select(PuppetFactFavorite).where(
        PuppetFactFavorite.user_id == current.id,
        PuppetFactFavorite.fact_name == fact_name,
    ))
    if existing:
        return {"id": str(existing.id), "fact_name": existing.fact_name, "created_at": existing.created_at}
    favorite = PuppetFactFavorite(user_id=current.id, fact_name=fact_name)
    db.add(favorite)
    await db.commit()
    await db.refresh(favorite)
    return {"id": str(favorite.id), "fact_name": favorite.fact_name, "created_at": favorite.created_at}


@router.delete("/favorites/{favorite_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_favorite(
    favorite_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current: AuthUser = Depends(require_role("analyst")),
):
    favorite = await db.scalar(select(PuppetFactFavorite).where(
        PuppetFactFavorite.id == favorite_id,
        PuppetFactFavorite.user_id == current.id,
    ))
    if not favorite:
        raise HTTPException(status_code=404, detail="Favourite fact not found")
    await db.delete(favorite)
    await db.commit()


@router.get("/saved-views")
async def list_saved_views(
    db: AsyncSession = Depends(get_db),
    current: AuthUser = Depends(require_role("analyst")),
):
    views = (await db.execute(
        select(PuppetFactSavedView)
        .where(PuppetFactSavedView.user_id == current.id)
        .order_by(desc(PuppetFactSavedView.is_default), PuppetFactSavedView.name)
    )).scalars().all()
    return [_view_payload(view) for view in views]


async def _clear_default_view(db: AsyncSession, user_id: uuid.UUID) -> None:
    await db.execute(update(PuppetFactSavedView).where(
        PuppetFactSavedView.user_id == user_id
    ).values(is_default=False))


@router.post("/saved-views", status_code=status.HTTP_201_CREATED)
async def create_saved_view(
    payload: SavedViewCreate,
    db: AsyncSession = Depends(get_db),
    current: AuthUser = Depends(require_role("analyst")),
):
    name = payload.name.strip()
    if not name:
        raise HTTPException(status_code=422, detail="Saved view name cannot be empty")
    if payload.is_default:
        await _clear_default_view(db, current.id)
    view = PuppetFactSavedView(
        user_id=current.id,
        name=name,
        definition=payload.definition.model_dump(),
        is_default=payload.is_default,
    )
    db.add(view)
    try:
        await db.commit()
    except IntegrityError:
        await db.rollback()
        raise HTTPException(status_code=409, detail="A saved view with this name already exists")
    await db.refresh(view)
    return _view_payload(view)


@router.put("/saved-views/{view_id}")
async def update_saved_view(
    view_id: uuid.UUID,
    payload: SavedViewUpdate,
    db: AsyncSession = Depends(get_db),
    current: AuthUser = Depends(require_role("analyst")),
):
    view = await db.scalar(select(PuppetFactSavedView).where(
        PuppetFactSavedView.id == view_id,
        PuppetFactSavedView.user_id == current.id,
    ))
    if not view:
        raise HTTPException(status_code=404, detail="Saved view not found")
    name = payload.name.strip()
    if not name:
        raise HTTPException(status_code=422, detail="Saved view name cannot be empty")
    if payload.is_default:
        await _clear_default_view(db, current.id)
    view.name = name
    view.definition = payload.definition.model_dump()
    view.is_default = payload.is_default
    view.updated_at = datetime.now(timezone.utc)
    try:
        await db.commit()
    except IntegrityError:
        await db.rollback()
        raise HTTPException(status_code=409, detail="A saved view with this name already exists")
    await db.refresh(view)
    return _view_payload(view)


@router.delete("/saved-views/{view_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_saved_view(
    view_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current: AuthUser = Depends(require_role("analyst")),
):
    result = await db.execute(delete(PuppetFactSavedView).where(
        PuppetFactSavedView.id == view_id,
        PuppetFactSavedView.user_id == current.id,
    ))
    if result.rowcount == 0:
        raise HTTPException(status_code=404, detail="Saved view not found")
    await db.commit()


@router.get("")
async def list_puppet_facts(
    response: Response,
    search: str | None = Query(None, max_length=500),
    certname: str | None = Query(None, max_length=500),
    name: str | None = Query(None, max_length=500),
    names: str | None = Query(None, max_length=10_000),
    environment: str | None = Query(None, max_length=255),
    value_types: str | None = Query(None, max_length=200),
    favorites_only: bool = False,
    sort: SortField = "certname",
    order: SortOrder = "asc",
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db),
    current: AuthUser = Depends(require_role("analyst")),
):
    query = _filtered_query(
        search=search,
        certname=certname,
        names=_csv_list(names) or ([name] if name else []),
        environment=environment,
        value_types=_csv_list(value_types, maximum=6),
        favorites_only=favorites_only,
        user_id=current.id,
    )
    total = await db.scalar(select(func.count()).select_from(query.subquery()))
    response.headers["X-Total-Count"] = str(total or 0)
    facts = (await db.execute(
        _sort_query(query, sort, order).limit(limit).offset(offset)
    )).scalars().all()
    return [_payload(fact) for fact in facts]


@router.get("/export.csv")
async def export_puppet_facts(
    search: str | None = Query(None, max_length=500),
    certname: str | None = Query(None, max_length=500),
    name: str | None = Query(None, max_length=500),
    names: str | None = Query(None, max_length=10_000),
    environment: str | None = Query(None, max_length=255),
    value_types: str | None = Query(None, max_length=200),
    favorites_only: bool = False,
    sort: SortField = "certname",
    order: SortOrder = "asc",
    db: AsyncSession = Depends(get_db),
    current: AuthUser = Depends(require_role("analyst")),
):
    query = _filtered_query(
        search=search,
        certname=certname,
        names=_csv_list(names) or ([name] if name else []),
        environment=environment,
        value_types=_csv_list(value_types, maximum=6),
        favorites_only=favorites_only,
        user_id=current.id,
    )
    facts = (await db.execute(_sort_query(query, sort, order))).scalars().all()
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["CERTNAME", "FACT", "VALUE", "TYPE", "ENVIRONMENT", "SYNCED_AT"])
    for fact in facts:
        value = json.dumps(fact.value, ensure_ascii=False) if not isinstance(fact.value, str) else fact.value
        writer.writerow([
            _csv_safe(fact.certname),
            _csv_safe(fact.name),
            _csv_safe(value),
            fact.value_type,
            _csv_safe(fact.environment or ""),
            fact.synced_at.isoformat(),
        ])
    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": "attachment; filename=puppet_facts.csv"},
    )
