import csv
import io
import uuid
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Response
from fastapi.responses import StreamingResponse
from sqlalchemy import case, desc, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import joinedload

from app.api.deps import get_db, require_role
from app.models.application import ApplicationVulnerability
from app.models.endpoint import Endpoint
from app.models.user import AuthUser


router = APIRouter(prefix="/application-vulnerabilities", tags=["application-vulnerabilities"])


def _csv_safe(value):
    """Prevent spreadsheet formula execution in analyst exports."""
    if value is None:
        return None
    text = str(value)
    return f"'{text}" if text.startswith(("=", "+", "-", "@")) else value


def _base_query():
    return select(ApplicationVulnerability).options(
        joinedload(ApplicationVulnerability.endpoint).joinedload(Endpoint.owner)
    )


def _apply_filters(query, *, search=None, severity=None, status=None, mitigation=None, exploit=None, os_type=None):
    if search:
        pattern = f"%{search.strip()}%"
        query = query.where(or_(
            ApplicationVulnerability.application.ilike(pattern),
            ApplicationVulnerability.application_name.ilike(pattern),
            ApplicationVulnerability.application_vendor.ilike(pattern),
            ApplicationVulnerability.application_version.ilike(pattern),
            ApplicationVulnerability.cve_id.ilike(pattern),
            ApplicationVulnerability.endpoint_name.ilike(pattern),
        ))
    if severity:
        query = query.where(ApplicationVulnerability.severity == severity.upper())
    if status:
        query = query.where(ApplicationVulnerability.status.ilike(status))
    if mitigation:
        query = query.where(ApplicationVulnerability.mitigation_status.ilike(mitigation))
    if os_type:
        query = query.where(ApplicationVulnerability.os_type.ilike(os_type))
    if exploit is True:
        query = query.where(
            ApplicationVulnerability.exploit_code_maturity.isnot(None),
            ~func.lower(ApplicationVulnerability.exploit_code_maturity).in_(("unknown", "unproven", "none", "")),
        )
    elif exploit is False:
        query = query.where(or_(
            ApplicationVulnerability.exploit_code_maturity.is_(None),
            func.lower(ApplicationVulnerability.exploit_code_maturity).in_(("unknown", "unproven", "none", "")),
        ))
    return query


def _payload(item: ApplicationVulnerability, *, include_raw: bool = False) -> dict:
    endpoint = item.endpoint
    data = {
        "id": str(item.id),
        "sentinelone_id": item.sentinelone_id,
        "sentinelone_endpoint_id": item.sentinelone_endpoint_id,
        "application": item.application,
        "application_name": item.application_name,
        "application_vendor": item.application_vendor,
        "application_version": item.application_version,
        "cve_id": item.cve_id,
        "cvss_version": item.cvss_version,
        "nvd_cvss_version": item.nvd_cvss_version,
        "nvd_base_score": item.nvd_base_score,
        "risk_score": item.risk_score,
        "severity": item.severity,
        "endpoint_name": item.endpoint_name,
        "endpoint_type": item.endpoint_type,
        "os_type": item.os_type,
        "days_detected": item.days_detected,
        "detection_date": item.detection_date,
        "published_date": item.published_date,
        "last_scan_date": item.last_scan_date,
        "last_scan_result": item.last_scan_result,
        "exploit_code_maturity": item.exploit_code_maturity,
        "remediation_level": item.remediation_level,
        "report_confidence": item.report_confidence,
        "mitigation_status": item.mitigation_status,
        "mitigation_status_change_time": item.mitigation_status_change_time,
        "mitigation_status_changed_by": item.mitigation_status_changed_by,
        "mitigation_status_reason": item.mitigation_status_reason,
        "status": item.status,
        "mark_type": item.mark_type,
        "marked_by": item.marked_by,
        "marked_date": item.marked_date,
        "reason": item.reason,
        "synced_at": item.synced_at,
        "endpoint": ({
            "id": str(endpoint.id),
            "hostname": endpoint.hostname,
            "owner_name": endpoint.owner.full_name if endpoint.owner else None,
            "owner_email": endpoint.owner.email if endpoint.owner else None,
        } if endpoint else None),
    }
    if include_raw:
        data["raw_json"] = item.raw_json
    return data


@router.get("/summary")
async def vulnerability_summary(
    db: AsyncSession = Depends(get_db),
    _: AuthUser = Depends(require_role("viewer")),
):
    severity_order = case(
        (ApplicationVulnerability.severity == "CRITICAL", 4),
        (ApplicationVulnerability.severity == "HIGH", 3),
        (ApplicationVulnerability.severity == "MEDIUM", 2),
        (ApplicationVulnerability.severity == "LOW", 1),
        else_=0,
    )
    row = (await db.execute(select(
        func.count().label("total"),
        func.count(func.distinct(ApplicationVulnerability.cve_id)).label("unique_cves"),
        func.count(func.distinct(ApplicationVulnerability.application_name)).label("applications"),
        func.count(func.distinct(ApplicationVulnerability.sentinelone_endpoint_id)).label("endpoints"),
        func.sum(case((ApplicationVulnerability.severity == "CRITICAL", 1), else_=0)).label("critical"),
        func.sum(case((ApplicationVulnerability.severity == "HIGH", 1), else_=0)).label("high"),
        func.sum(case((ApplicationVulnerability.severity == "MEDIUM", 1), else_=0)).label("medium"),
        func.sum(case((ApplicationVulnerability.severity == "LOW", 1), else_=0)).label("low"),
        func.sum(case((func.lower(ApplicationVulnerability.mitigation_status) == "not mitigated", 1), else_=0)).label("not_mitigated"),
        func.max(ApplicationVulnerability.synced_at).label("last_sync"),
    ))).one()
    exploit_count = (await db.execute(
        select(func.count()).select_from(ApplicationVulnerability).where(
            ApplicationVulnerability.exploit_code_maturity.isnot(None),
            ~func.lower(ApplicationVulnerability.exploit_code_maturity).in_(("unknown", "unproven", "none", "")),
        )
    )).scalar_one()
    top_apps = (await db.execute(
        select(
            ApplicationVulnerability.application_name,
            func.count().label("findings"),
            func.count(func.distinct(ApplicationVulnerability.cve_id)).label("cves"),
            func.max(ApplicationVulnerability.nvd_base_score).label("max_cvss"),
            func.max(severity_order).label("severity_rank"),
        )
        .group_by(ApplicationVulnerability.application_name)
        .order_by(desc("severity_rank"), desc("findings"))
        .limit(8)
    )).all()
    return {
        "total": row.total or 0,
        "unique_cves": row.unique_cves or 0,
        "applications": row.applications or 0,
        "endpoints": row.endpoints or 0,
        "severity": {
            "critical": row.critical or 0,
            "high": row.high or 0,
            "medium": row.medium or 0,
            "low": row.low or 0,
        },
        "exploit_available": exploit_count,
        "not_mitigated": row.not_mitigated or 0,
        "last_sync": row.last_sync,
        "top_applications": [
            {"name": app.application_name, "findings": app.findings, "cves": app.cves, "max_cvss": app.max_cvss}
            for app in top_apps
        ],
    }


@router.get("/facets")
async def vulnerability_facets(
    db: AsyncSession = Depends(get_db),
    _: AuthUser = Depends(require_role("viewer")),
):
    async def values(column):
        return [value for value in (await db.execute(
            select(column).where(column.isnot(None)).distinct().order_by(column)
        )).scalars().all() if value]
    return {
        "severities": await values(ApplicationVulnerability.severity),
        "statuses": await values(ApplicationVulnerability.status),
        "mitigations": await values(ApplicationVulnerability.mitigation_status),
        "os_types": await values(ApplicationVulnerability.os_type),
    }


@router.get("")
async def list_vulnerabilities(
    response: Response,
    search: str | None = Query(None),
    severity: str | None = Query(None),
    status: str | None = Query(None),
    mitigation: str | None = Query(None),
    exploit: bool | None = Query(None),
    os_type: str | None = Query(None),
    sort: Literal["severity", "cvss", "risk", "detected", "application", "endpoint"] = Query("severity"),
    order: Literal["asc", "desc"] = Query("desc"),
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db),
    _: AuthUser = Depends(require_role("viewer")),
):
    query = _apply_filters(_base_query(), search=search, severity=severity, status=status, mitigation=mitigation, exploit=exploit, os_type=os_type)
    total = (await db.execute(select(func.count()).select_from(query.subquery()))).scalar_one()
    response.headers["X-Total-Count"] = str(total)
    severity_order = case(
        (ApplicationVulnerability.severity == "CRITICAL", 4),
        (ApplicationVulnerability.severity == "HIGH", 3),
        (ApplicationVulnerability.severity == "MEDIUM", 2),
        (ApplicationVulnerability.severity == "LOW", 1),
        else_=0,
    )
    sort_columns = {
        "severity": severity_order,
        "cvss": ApplicationVulnerability.nvd_base_score,
        "risk": ApplicationVulnerability.risk_score,
        "detected": ApplicationVulnerability.detection_date,
        "application": ApplicationVulnerability.application_name,
        "endpoint": ApplicationVulnerability.endpoint_name,
    }
    column = sort_columns[sort]
    query = query.order_by(column.asc() if order == "asc" else column.desc(), ApplicationVulnerability.cve_id.asc())
    items = (await db.execute(query.limit(limit).offset(offset))).scalars().unique().all()
    return [_payload(item) for item in items]


@router.get("/export.csv")
async def export_vulnerabilities(
    search: str | None = Query(None),
    severity: str | None = Query(None),
    status: str | None = Query(None),
    mitigation: str | None = Query(None),
    exploit: bool | None = Query(None),
    os_type: str | None = Query(None),
    db: AsyncSession = Depends(get_db),
    _: AuthUser = Depends(require_role("viewer")),
):
    query = _apply_filters(_base_query(), search=search, severity=severity, status=status, mitigation=mitigation, exploit=exploit, os_type=os_type)
    items = (await db.execute(query.order_by(ApplicationVulnerability.severity, ApplicationVulnerability.application_name))).scalars().unique().all()
    output = io.StringIO()
    fields = [
        "application", "application_name", "application_vendor", "application_version", "cve_id",
        "cvss_version", "nvd_cvss_version", "nvd_base_score", "risk_score", "severity",
        "endpoint_name", "endpoint_type", "os_type", "days_detected", "detection_date",
        "published_date", "last_scan_date", "last_scan_result", "exploit_code_maturity",
        "remediation_level", "report_confidence", "mitigation_status", "status", "reason",
    ]
    writer = csv.DictWriter(output, fieldnames=fields)
    writer.writeheader()
    for item in items:
        data = _payload(item)
        writer.writerow({field: _csv_safe(data.get(field)) for field in fields})
    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": "attachment; filename=sentinelone_application_vulnerabilities.csv"},
    )


@router.get("/{finding_id}")
async def get_vulnerability(
    finding_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    _: AuthUser = Depends(require_role("viewer")),
):
    item = (await db.execute(
        _base_query().where(ApplicationVulnerability.id == finding_id)
    )).scalar_one_or_none()
    if not item:
        raise HTTPException(status_code=404, detail="Application vulnerability not found")
    return _payload(item, include_raw=True)
