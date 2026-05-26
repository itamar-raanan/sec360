"""
Reports — generate, export (CSV), and schedule recurring email reports.
"""
import csv
import io
import logging
from datetime import datetime, timezone, timedelta
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, case

from app.api.deps import get_db, require_role, audit_action, get_current_user
from app.models.user import AuthUser, User
from app.models.endpoint import Endpoint
from app.models.compliance import ComplianceStatus
from app.models.activity import ActivityEvent
from app.models.report import ScheduledReport

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/reports", tags=["reports"])

REPORT_TYPES = {"compliance", "risk", "users", "endpoints", "activity"}
FREQUENCIES   = {"daily", "weekly", "monthly"}
MAX_EXPORT_ROWS = 10_000


# ── Pydantic schemas ──────────────────────────────────────────────────────────

class ScheduledReportCreate(BaseModel):
    name: str
    report_type: str
    frequency: str
    recipients: list[str]
    filters: dict = {}


class ScheduledReportOut(BaseModel):
    model_config = {"from_attributes": True}
    id: str
    name: str
    report_type: str
    frequency: str
    recipients: list[str]
    filters: dict
    is_active: bool
    last_sent: Optional[datetime]
    next_send: Optional[datetime]
    created_by: str
    created_at: datetime

    @classmethod
    def from_orm(cls, r: ScheduledReport):
        return cls(
            id=str(r.id),
            name=r.name,
            report_type=r.report_type,
            frequency=r.frequency,
            recipients=r.recipients or [],
            filters=r.filters or {},
            is_active=r.is_active,
            last_sent=r.last_sent,
            next_send=r.next_send,
            created_by=r.created_by,
            created_at=r.created_at,
        )


# ── Report data generators ────────────────────────────────────────────────────

async def _compliance_data(db: AsyncSession, filters: dict) -> tuple[list[str], list[list]]:
    status_filter = filters.get("status")
    q = (
        select(
            Endpoint.hostname,
            Endpoint.os_version,
            ComplianceStatus.status,
            ComplianceStatus.edr_installed,
            ComplianceStatus.edr_version_ok,
            ComplianceStatus.dlp_installed,
            ComplianceStatus.dlp_version_ok,
            ComplianceStatus.last_evaluated,
        )
        .join(ComplianceStatus, Endpoint.id == ComplianceStatus.endpoint_id)
        .order_by(ComplianceStatus.status, Endpoint.hostname)
    )
    if status_filter:
        q = q.where(ComplianceStatus.status == status_filter)

    rows = (await db.execute(q.limit(MAX_EXPORT_ROWS + 1))).all()
    headers = ["Hostname", "OS", "Status", "EDR Installed", "EDR Version OK",
               "DLP Installed", "DLP Version OK", "Last Evaluated"]
    data = [
        [r.hostname, r.os_version, r.status,
         str(r.edr_installed), str(r.edr_version_ok),
         str(r.dlp_installed), str(r.dlp_version_ok),
         r.last_evaluated.isoformat() if r.last_evaluated else ""]
        for r in rows
    ]
    return headers, data


async def _risk_data(db: AsyncSession, filters: dict) -> tuple[list[str], list[list]]:
    min_score = float(filters.get("min_score", 0))
    entity = filters.get("entity", "all")  # users | endpoints | all

    result_rows: list[list] = []
    headers = ["Type", "Name / Hostname", "Email / IP", "Risk Score", "Risk Level", "Department / OS"]

    if entity in ("all", "users"):
        q = select(User.full_name, User.email, User.risk_score, User.department).where(
            User.risk_score >= min_score
        ).order_by(User.risk_score.desc())
        for r in (await db.execute(q)).all():
            level = "critical" if r.risk_score > 75 else "high" if r.risk_score > 50 else "medium" if r.risk_score > 25 else "low"
            result_rows.append(["User", r.full_name, r.email, str(round(r.risk_score, 1)), level, r.department or ""])

    if entity in ("all", "endpoints"):
        q = select(Endpoint.hostname, Endpoint.ip_address, Endpoint.risk_score, Endpoint.os_version).where(
            Endpoint.risk_score >= min_score
        ).order_by(Endpoint.risk_score.desc())
        for r in (await db.execute(q)).all():
            level = "critical" if r.risk_score > 75 else "high" if r.risk_score > 50 else "medium" if r.risk_score > 25 else "low"
            result_rows.append(["Endpoint", r.hostname, r.ip_address or "", str(round(r.risk_score, 1)), level, r.os_version or ""])

    return headers, result_rows


async def _users_data(db: AsyncSession, filters: dict) -> tuple[list[str], list[list]]:
    dept = filters.get("department")
    risk_min = float(filters.get("risk_min", 0))
    q = select(User).where(User.risk_score >= risk_min).order_by(User.risk_score.desc())
    if dept:
        q = q.where(User.department == dept)
    users = (await db.execute(q.limit(MAX_EXPORT_ROWS + 1))).scalars().all()
    headers = ["Full Name", "Email", "Department", "Manager", "Employment Status",
               "MFA Enabled", "Risk Score", "Last Login", "Created"]
    data = [
        [u.full_name, u.email, u.department or "", u.manager or "",
         u.employment_status, str(u.mfa_enabled), str(round(u.risk_score, 1)),
         u.last_login.isoformat() if u.last_login else "",
         u.created_at.isoformat()]
        for u in users
    ]
    return headers, data


async def _endpoints_data(db: AsyncSession, filters: dict) -> tuple[list[str], list[list]]:
    comp = filters.get("compliance_status")
    q = select(Endpoint).where(Endpoint.is_active == True).order_by(Endpoint.risk_score.desc())  # noqa: E712
    if comp:
        q = q.join(ComplianceStatus, Endpoint.id == ComplianceStatus.endpoint_id).where(
            ComplianceStatus.status == comp
        )
    endpoints = (await db.execute(q.limit(MAX_EXPORT_ROWS + 1))).scalars().all()
    headers = ["Hostname", "IP Address", "OS", "Username", "Location",
               "Risk Score", "Last Seen", "Source"]
    data = [
        [e.hostname, e.ip_address or "", e.os_version or "", e.username or "",
         e.location or "", str(round(e.risk_score, 1)),
         e.last_seen.isoformat() if e.last_seen else "", e.source or ""]
        for e in endpoints
    ]
    return headers, data


async def _activity_data(db: AsyncSession, filters: dict) -> tuple[list[str], list[list]]:
    since_days = int(filters.get("days", 7))
    event_type = filters.get("event_type")
    suspicious_only = filters.get("suspicious_only", False)
    since = datetime.now(timezone.utc) - timedelta(days=since_days)

    q = select(ActivityEvent).where(ActivityEvent.timestamp >= since).order_by(
        ActivityEvent.timestamp.desc()
    )
    if event_type:
        q = q.where(ActivityEvent.event_type == event_type)
    if suspicious_only:
        q = q.where(ActivityEvent.is_suspicious == True)  # noqa: E712

    events = (await db.execute(q)).scalars().all()
    headers = ["Timestamp", "Event Type", "Country", "IP Address", "Suspicious", "User ID"]
    data = [
        [e.timestamp.isoformat(), e.event_type, e.country or "",
         e.ip_address or "", str(e.is_suspicious), str(e.user_id) if e.user_id else ""]
        for e in events
    ]
    return headers, data


async def _generate_report(report_type: str, filters: dict, db: AsyncSession) -> tuple[list[str], list[list]]:
    if report_type == "compliance":
        return await _compliance_data(db, filters)
    if report_type == "risk":
        return await _risk_data(db, filters)
    if report_type == "users":
        return await _users_data(db, filters)
    if report_type == "endpoints":
        return await _endpoints_data(db, filters)
    if report_type == "activity":
        return await _activity_data(db, filters)
    raise ValueError(f"Unknown report type: {report_type}")


def _to_csv_bytes(headers: list[str], rows: list[list]) -> bytes:
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(headers)
    writer.writerows(rows)
    return buf.getvalue().encode("utf-8-sig")  # BOM for Excel compatibility


def _next_send(frequency: str) -> datetime:
    now = datetime.now(timezone.utc)
    if frequency == "daily":
        return now + timedelta(days=1)
    if frequency == "weekly":
        return now + timedelta(weeks=1)
    return now + timedelta(days=30)  # monthly


# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.get("/generate")
async def generate_report(
    report_type: str = Query(..., description="compliance|risk|users|endpoints|activity"),
    filters: str = Query("{}", description="JSON-encoded filter dict"),
    db: AsyncSession = Depends(get_db),
    _: AuthUser = Depends(require_role("analyst")),
):
    """Return report data as JSON (preview). Max 500 rows."""
    import json
    if report_type not in REPORT_TYPES:
        raise HTTPException(400, f"report_type must be one of {sorted(REPORT_TYPES)}")
    try:
        parsed_filters = json.loads(filters)
    except Exception:
        raise HTTPException(400, "filters must be valid JSON")

    headers, rows = await _generate_report(report_type, parsed_filters, db)
    return {
        "report_type": report_type,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "row_count": len(rows),
        "headers": headers,
        "rows": rows[:500],
        "truncated": len(rows) > 500,
    }


@router.get("/export/csv")
async def export_csv(
    report_type: str = Query(...),
    filters: str = Query("{}"),
    db: AsyncSession = Depends(get_db),
    _: AuthUser = Depends(require_role("analyst")),
):
    """Stream report data as a CSV file download."""
    import json
    if report_type not in REPORT_TYPES:
        raise HTTPException(400, f"report_type must be one of {sorted(REPORT_TYPES)}")
    try:
        parsed_filters = json.loads(filters)
    except Exception:
        raise HTTPException(400, "filters must be valid JSON")

    headers, rows = await _generate_report(report_type, parsed_filters, db)
    truncated = len(rows) > MAX_EXPORT_ROWS
    csv_bytes = _to_csv_bytes(headers, rows[:MAX_EXPORT_ROWS])
    filename = f"{report_type}_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.csv"

    resp_headers = {"Content-Disposition": f'attachment; filename="{filename}"'}
    if truncated:
        resp_headers["X-Truncated"] = f"true; capped at {MAX_EXPORT_ROWS} rows"

    return StreamingResponse(
        io.BytesIO(csv_bytes),
        media_type="text/csv",
        headers=resp_headers,
    )


# ── Scheduled reports CRUD ────────────────────────────────────────────────────

@router.get("/scheduled")
async def list_scheduled_reports(
    db: AsyncSession = Depends(get_db),
    _: AuthUser = Depends(require_role("analyst")),
):
    result = await db.execute(select(ScheduledReport).order_by(ScheduledReport.created_at.desc()))
    return [ScheduledReportOut.from_orm(r) for r in result.scalars().all()]


@router.post("/scheduled", status_code=201)
async def create_scheduled_report(
    data: ScheduledReportCreate,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current: AuthUser = Depends(require_role("analyst")),
):
    if data.report_type not in REPORT_TYPES:
        raise HTTPException(400, f"report_type must be one of {sorted(REPORT_TYPES)}")
    if data.frequency not in FREQUENCIES:
        raise HTTPException(400, f"frequency must be one of {sorted(FREQUENCIES)}")
    if not data.recipients:
        raise HTTPException(400, "At least one recipient is required")

    report = ScheduledReport(
        name=data.name,
        report_type=data.report_type,
        frequency=data.frequency,
        recipients=data.recipients,
        filters=data.filters,
        is_active=True,
        next_send=_next_send(data.frequency),
        created_by=current.email,
    )
    db.add(report)
    await db.flush()
    await audit_action("create_scheduled_report", "scheduled_report", str(report.id),
                       request, db, current, {"name": data.name, "type": data.report_type})
    return ScheduledReportOut.from_orm(report)


@router.patch("/scheduled/{report_id}")
async def update_scheduled_report(
    report_id: str,
    data: ScheduledReportCreate,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current: AuthUser = Depends(require_role("analyst")),
):
    r = (await db.execute(select(ScheduledReport).where(ScheduledReport.id == report_id))).scalar_one_or_none()
    if not r:
        raise HTTPException(404, "Scheduled report not found")
    if data.report_type not in REPORT_TYPES:
        raise HTTPException(400, f"report_type must be one of {sorted(REPORT_TYPES)}")
    if data.frequency not in FREQUENCIES:
        raise HTTPException(400, f"frequency must be one of {sorted(FREQUENCIES)}")

    r.name = data.name
    r.report_type = data.report_type
    r.frequency = data.frequency
    r.recipients = data.recipients
    r.filters = data.filters
    if r.frequency != data.frequency:
        r.next_send = _next_send(data.frequency)
    await db.flush()
    await audit_action("update_scheduled_report", "scheduled_report", report_id,
                       request, db, current, {"name": data.name})
    return ScheduledReportOut.from_orm(r)


@router.patch("/scheduled/{report_id}/toggle")
async def toggle_scheduled_report(
    report_id: str,
    db: AsyncSession = Depends(get_db),
    _: AuthUser = Depends(require_role("analyst")),
):
    r = (await db.execute(select(ScheduledReport).where(ScheduledReport.id == report_id))).scalar_one_or_none()
    if not r:
        raise HTTPException(404, "Scheduled report not found")
    r.is_active = not r.is_active
    await db.flush()
    return ScheduledReportOut.from_orm(r)


@router.delete("/scheduled/{report_id}", status_code=204)
async def delete_scheduled_report(
    report_id: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current: AuthUser = Depends(require_role("analyst")),
):
    r = (await db.execute(select(ScheduledReport).where(ScheduledReport.id == report_id))).scalar_one_or_none()
    if not r:
        raise HTTPException(404, "Scheduled report not found")
    await audit_action("delete_scheduled_report", "scheduled_report", report_id,
                       request, db, current, {"name": r.name})
    await db.delete(r)


@router.post("/scheduled/{report_id}/send-now")
async def send_report_now(
    report_id: str,
    db: AsyncSession = Depends(get_db),
    _: AuthUser = Depends(require_role("analyst")),
):
    """Immediately send a scheduled report email."""
    r = (await db.execute(select(ScheduledReport).where(ScheduledReport.id == report_id))).scalar_one_or_none()
    if not r:
        raise HTTPException(404, "Scheduled report not found")
    if not r.recipients:
        raise HTTPException(400, "No recipients configured")

    headers, rows = await _generate_report(r.report_type, r.filters or {}, db)
    csv_bytes = _to_csv_bytes(headers, rows)
    summary_html = f"<p style='color:#374151;'><strong>{len(rows)}</strong> records in this report.</p>"

    from app.services.email import send_report_email
    sent = send_report_email(r.recipients, r.name, r.report_type, csv_bytes, summary_html)
    r.last_sent = datetime.now(timezone.utc)
    await db.flush()
    return {"sent": sent, "recipients": r.recipients, "rows": len(rows)}
