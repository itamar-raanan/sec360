import csv
import io
import json

from fastapi import APIRouter, Depends, Query, Response
from fastapi.responses import StreamingResponse
from sqlalchemy import String, cast, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_db, require_connected_integration, require_role
from app.models.puppet import PuppetFact, PuppetNode
from app.models.user import AuthUser


router = APIRouter(
    prefix="/puppet-facts",
    tags=["puppet-facts"],
    dependencies=[Depends(require_connected_integration("puppet"))],
)


def _filtered_query(*, search=None, certname=None, name=None, environment=None):
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
    if name:
        query = query.where(PuppetFact.name == name)
    if environment:
        query = query.where(PuppetFact.environment == environment)
    return query


def _value_type(value) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, (int, float)):
        return "number"
    if isinstance(value, list):
        return "array"
    if isinstance(value, dict):
        return "object"
    return "string"


def _csv_safe(value):
    text = str(value)
    return f"'{text}" if text.startswith(("=", "+", "-", "@")) else text


def _payload(fact: PuppetFact) -> dict:
    return {
        "id": str(fact.id),
        "certname": fact.certname,
        "name": fact.name,
        "value": fact.value,
        "value_type": _value_type(fact.value),
        "environment": fact.environment,
        "synced_at": fact.synced_at,
    }


@router.get("/summary")
async def puppet_fact_summary(
    db: AsyncSession = Depends(get_db),
    _: AuthUser = Depends(require_role("analyst")),
):
    row = (await db.execute(select(
        func.count(PuppetFact.id).label("facts"),
        func.count(func.distinct(PuppetFact.name)).label("fact_names"),
        func.count(func.distinct(PuppetFact.certname)).label("nodes"),
        func.max(PuppetFact.synced_at).label("last_sync"),
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
        "report_statuses": {
            (status or "unknown"): count for status, count in status_rows
        },
    }


@router.get("/facets")
async def puppet_fact_facets(
    db: AsyncSession = Depends(get_db),
    _: AuthUser = Depends(require_role("analyst")),
):
    names = (await db.execute(
        select(PuppetFact.name).distinct().order_by(PuppetFact.name).limit(2_000)
    )).scalars().all()
    environments = (await db.execute(
        select(PuppetFact.environment)
        .where(PuppetFact.environment.isnot(None))
        .distinct()
        .order_by(PuppetFact.environment)
    )).scalars().all()
    return {"names": names, "environments": environments}


@router.get("")
async def list_puppet_facts(
    response: Response,
    search: str | None = Query(None, max_length=500),
    certname: str | None = Query(None, max_length=500),
    name: str | None = Query(None, max_length=500),
    environment: str | None = Query(None, max_length=255),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db),
    _: AuthUser = Depends(require_role("analyst")),
):
    query = _filtered_query(
        search=search, certname=certname, name=name, environment=environment
    )
    total = await db.scalar(select(func.count()).select_from(query.subquery()))
    response.headers["X-Total-Count"] = str(total or 0)
    facts = (await db.execute(
        query.order_by(PuppetFact.certname, PuppetFact.name).limit(limit).offset(offset)
    )).scalars().all()
    return [_payload(fact) for fact in facts]


@router.get("/export.csv")
async def export_puppet_facts(
    search: str | None = Query(None, max_length=500),
    certname: str | None = Query(None, max_length=500),
    name: str | None = Query(None, max_length=500),
    environment: str | None = Query(None, max_length=255),
    db: AsyncSession = Depends(get_db),
    _: AuthUser = Depends(require_role("analyst")),
):
    query = _filtered_query(
        search=search, certname=certname, name=name, environment=environment
    )
    facts = (await db.execute(
        query.order_by(PuppetFact.certname, PuppetFact.name)
    )).scalars().all()
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["CERTNAME", "FACT", "VALUE", "TYPE", "ENVIRONMENT", "SYNCED_AT"])
    for fact in facts:
        value = json.dumps(fact.value, ensure_ascii=False) if not isinstance(fact.value, str) else fact.value
        writer.writerow([
            _csv_safe(fact.certname),
            _csv_safe(fact.name),
            _csv_safe(value),
            _value_type(fact.value),
            _csv_safe(fact.environment or ""),
            fact.synced_at.isoformat(),
        ])
    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": "attachment; filename=puppet_facts.csv"},
    )
