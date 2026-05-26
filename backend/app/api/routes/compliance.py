from typing import Optional
from fastapi import APIRouter, Depends, Query, Response, HTTPException, status, BackgroundTasks
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, case, or_
from sqlalchemy.orm import joinedload

from app.api.deps import get_db, get_current_user, require_role
from app.models.user import AuthUser
from app.models.compliance import ComplianceStatus
from app.models.endpoint import Endpoint
from app.schemas.compliance import ComplianceStatusResponse, ComplianceSummaryStats

router = APIRouter(prefix="/compliance", tags=["compliance"])


@router.get("/dashboard")
async def get_compliance_dashboard(
    db: AsyncSession = Depends(get_db),
    _: AuthUser = Depends(require_role("viewer")),
):
    """Rich analytics payload for the Compliance dashboard page."""

    # ── Summary counts via SQL ────────────────────────────────────────────────
    summary_q = await db.execute(
        select(
            func.count().label("total"),
            func.sum(case((ComplianceStatus.status == "compliant",     1), else_=0)).label("compliant"),
            func.sum(case((ComplianceStatus.status == "partial",       1), else_=0)).label("partial"),
            func.sum(case((ComplianceStatus.status == "non_compliant", 1), else_=0)).label("non_compliant"),
            func.sum(case((ComplianceStatus.edr_installed == False,    1), else_=0)).label("no_edr"),     # noqa: E712
            func.sum(case(((ComplianceStatus.edr_installed == True)  & (ComplianceStatus.edr_version_ok == False), 1), else_=0)).label("edr_outdated"),   # noqa: E712
            func.sum(case((ComplianceStatus.dlp_installed == False,    1), else_=0)).label("no_dlp"),     # noqa: E712
            func.sum(case(((ComplianceStatus.dlp_installed == True)  & (ComplianceStatus.dlp_version_ok == False), 1), else_=0)).label("dlp_outdated"),   # noqa: E712
            func.sum(case((ComplianceStatus.gp_installed == False,     1), else_=0)).label("no_gp"),      # noqa: E712
            func.sum(case(((ComplianceStatus.gp_installed == True)   & (ComplianceStatus.gp_version_ok == False),  1), else_=0)).label("gp_outdated"),    # noqa: E712
            func.sum(case((ComplianceStatus.wss_installed == False,    1), else_=0)).label("no_wss"),     # noqa: E712
            func.sum(case(((ComplianceStatus.wss_installed == True)  & (ComplianceStatus.wss_version_ok == False), 1), else_=0)).label("wss_outdated"),   # noqa: E712
            # Endpoints with neither GP nor WSS — the actual compliance gap
            func.sum(case(
                ((ComplianceStatus.gp_installed == False) & (ComplianceStatus.wss_installed == False), 1),  # noqa: E712
                else_=0,
            )).label("no_network_security"),
            # S1 enrichment — only count endpoints where S1 has reported the value
            func.sum(case((ComplianceStatus.disk_encrypted == False,          1), else_=0)).label("not_encrypted"),   # noqa: E712
            func.sum(case((ComplianceStatus.device_control_enabled == False,  1), else_=0)).label("no_device_control"),  # noqa: E712
        )
    )
    row = summary_q.one()
    total = row.total or 0

    if total == 0:
        return {
            "summary": {"total": 0, "compliant": 0, "partial": 0, "non_compliant": 0, "compliant_pct": 0.0},
            "issues": {"no_edr": 0, "edr_outdated": 0, "no_dlp": 0, "dlp_outdated": 0, "no_gp": 0, "gp_outdated": 0, "no_wss": 0, "wss_outdated": 0, "not_encrypted": 0, "no_device_control": 0},
            "os_breakdown": [],
            "worst_offenders": [],
        }

    # ── OS breakdown via SQL GROUP BY ─────────────────────────────────────────
    os_case = case(
        (Endpoint.os_version.ilike("%windows%"),                              "Windows"),
        (Endpoint.os_version.ilike("%mac%") | Endpoint.os_version.ilike("%darwin%"), "macOS"),
        (Endpoint.os_version.ilike("%linux%")  | Endpoint.os_version.ilike("%ubuntu%") |
         Endpoint.os_version.ilike("%centos%") | Endpoint.os_version.ilike("%debian%"), "Linux"),
        (Endpoint.os_version.ilike("%ios%")    | Endpoint.os_version.ilike("%ipad%"),   "iOS/iPadOS"),
        (Endpoint.os_version.ilike("%android%"),                              "Android"),
        else_="Other",
    ).label("os_family")

    os_q = await db.execute(
        select(
            os_case,
            func.count().label("total"),
            func.sum(case((ComplianceStatus.status == "compliant",     1), else_=0)).label("compliant"),
            func.sum(case((ComplianceStatus.status == "non_compliant", 1), else_=0)).label("non_compliant"),
        )
        .join(Endpoint, ComplianceStatus.endpoint_id == Endpoint.id)
        .group_by(os_case)
        .order_by(func.count().desc())
    )
    os_breakdown = [
        {"os": r.os_family, "total": r.total, "compliant": r.compliant, "non_compliant": r.non_compliant}
        for r in os_q.all()
    ]

    # ── Worst offenders — pull top 25 non/partial with their failure details ──
    fail_count_expr = (
        case((ComplianceStatus.edr_installed == False, 1), else_=0) +   # noqa: E712
        case(((ComplianceStatus.edr_installed == True) & (ComplianceStatus.edr_version_ok == False), 1), else_=0) +  # noqa: E712
        case((ComplianceStatus.dlp_installed == False, 1), else_=0) +   # noqa: E712
        case(((ComplianceStatus.dlp_installed == True) & (ComplianceStatus.dlp_version_ok == False), 1), else_=0) +  # noqa: E712
        case((ComplianceStatus.disk_encrypted == False, 1), else_=0) +   # noqa: E712
        case((ComplianceStatus.device_control_enabled == False, 1), else_=0)   # noqa: E712
    ).label("failure_count")

    worst_q = await db.execute(
        select(ComplianceStatus, fail_count_expr)
        .join(Endpoint, ComplianceStatus.endpoint_id == Endpoint.id)
        .options(joinedload(ComplianceStatus.endpoint).joinedload(Endpoint.owner))
        .where(ComplianceStatus.status.in_(["non_compliant", "partial"]))
        .order_by(fail_count_expr.desc())
        .limit(25)
    )

    worst_offenders = []
    for cs, fc in worst_q.all():
        ep = cs.endpoint
        failures = []
        if not cs.edr_installed:                                  failures.append("No EDR")
        elif not cs.edr_version_ok:                               failures.append("EDR Outdated")
        if not cs.dlp_installed:                                  failures.append("No DLP")
        elif not cs.dlp_version_ok:                               failures.append("DLP Outdated")
        if not cs.gp_installed and not cs.wss_installed:          failures.append("No Network Security (need GP or WSS)")
        else:
            if cs.gp_installed and not cs.gp_version_ok:         failures.append("GP Outdated")
            if cs.wss_installed and not cs.wss_version_ok:        failures.append("WSS Outdated")
        if cs.disk_encrypted is False:                            failures.append("Not Encrypted")
        if cs.device_control_enabled is False:                    failures.append("Device Control Off")
        worst_offenders.append({
            "endpoint_id":   str(ep.id),
            "hostname":      ep.hostname,
            "os_version":    ep.os_version,
            "owner_email":   ep.owner.email     if ep.owner else None,
            "owner_name":    ep.owner.full_name if ep.owner else None,
            "status":        cs.status,
            "failures":      failures,
            "failure_count": fc,
        })

    return {
        "summary": {
            "total":         total,
            "compliant":     row.compliant or 0,
            "partial":       row.partial or 0,
            "non_compliant": row.non_compliant or 0,
            "compliant_pct": round((row.compliant or 0) / total * 100, 1),
        },
        "issues": {
            "no_edr":              row.no_edr or 0,
            "edr_outdated":        row.edr_outdated or 0,
            "no_dlp":              row.no_dlp or 0,
            "dlp_outdated":        row.dlp_outdated or 0,
            "no_gp":               row.no_gp or 0,
            "gp_outdated":         row.gp_outdated or 0,
            "no_wss":              row.no_wss or 0,
            "wss_outdated":        row.wss_outdated or 0,
            "no_network_security": row.no_network_security or 0,
            "not_encrypted":       row.not_encrypted or 0,
            "no_device_control":   row.no_device_control or 0,
        },
        "os_breakdown":    os_breakdown,
        "worst_offenders": worst_offenders,
    }


@router.get("/summary", response_model=ComplianceSummaryStats)
async def get_compliance_summary(
    db: AsyncSession = Depends(get_db),
    _: AuthUser = Depends(require_role("viewer")),
):
    row = (await db.execute(
        select(
            func.count().label("total"),
            func.sum(case((ComplianceStatus.status == "compliant",     1), else_=0)).label("compliant"),
            func.sum(case((ComplianceStatus.status == "partial",       1), else_=0)).label("partial"),
            func.sum(case((ComplianceStatus.status == "non_compliant", 1), else_=0)).label("non_compliant"),
            func.sum(case((ComplianceStatus.edr_installed == False,    1), else_=0)).label("no_edr"),       # noqa: E712
            func.sum(case((ComplianceStatus.agent_up_to_date == False, 1), else_=0)).label("outdated_agent"),  # noqa: E712
            func.sum(case((ComplianceStatus.last_seen_recent == False, 1), else_=0)).label("offline"),      # noqa: E712
            func.sum(case((ComplianceStatus.disk_encrypted == False,   1), else_=0)).label("no_encryption"),  # noqa: E712
        )
    )).one()

    total = row.total or 0
    compliant = row.compliant or 0
    return ComplianceSummaryStats(
        total=total,
        compliant=compliant,
        partial=row.partial or 0,
        non_compliant=row.non_compliant or 0,
        compliant_pct=round(compliant / total * 100, 1) if total > 0 else 0.0,
        no_edr=row.no_edr or 0,
        outdated_agent=row.outdated_agent or 0,
        offline=row.offline or 0,
        no_encryption=row.no_encryption or 0,
    )


@router.get("", response_model=list[ComplianceStatusResponse])
async def list_compliance(
    response: Response,
    compliance_status: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db),
    _: AuthUser = Depends(require_role("viewer")),
):
    query = select(ComplianceStatus)
    if compliance_status:
        query = query.where(ComplianceStatus.status == compliance_status)

    count_q = select(func.count()).select_from(query.subquery())
    total = (await db.execute(count_q)).scalar_one()
    response.headers["X-Total-Count"] = str(total)

    result = await db.execute(query.limit(limit).offset(offset))
    items = result.scalars().all()
    return [ComplianceStatusResponse.model_validate(i) for i in items]


# NOTE: this route MUST appear before GET /{endpoint_id} to avoid shadowing
@router.get("/endpoints")
async def list_compliance_endpoints(
    response: Response,
    comp_status: Optional[str] = Query(None, alias="status"),
    issue: Optional[str] = Query(None),
    os_family: Optional[str] = Query(None, alias="os"),
    search: Optional[str] = Query(None),
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db),
    _: AuthUser = Depends(require_role("viewer")),
):
    """Filtered list of endpoints with compliance details for the drill-down panel."""
    from sqlalchemy import and_ as sa_and

    query = (
        select(ComplianceStatus)
        .join(Endpoint, ComplianceStatus.endpoint_id == Endpoint.id)
        .options(joinedload(ComplianceStatus.endpoint).joinedload(Endpoint.owner))
    )

    if comp_status:
        query = query.where(ComplianceStatus.status == comp_status)

    ISSUE_FILTERS = {
        "no_edr":            ComplianceStatus.edr_installed == False,   # noqa: E712
        "edr_outdated":      sa_and(ComplianceStatus.edr_installed == True,  ComplianceStatus.edr_version_ok == False),   # noqa: E712
        "no_dlp":            ComplianceStatus.dlp_installed == False,   # noqa: E712
        "dlp_outdated":      sa_and(ComplianceStatus.dlp_installed == True,  ComplianceStatus.dlp_version_ok == False),   # noqa: E712
        "not_encrypted":     ComplianceStatus.disk_encrypted == False,   # noqa: E712
        "no_device_control": ComplianceStatus.device_control_enabled == False,   # noqa: E712
    }
    if issue and issue in ISSUE_FILTERS:
        query = query.where(ISSUE_FILTERS[issue])

    OS_PATTERNS: dict[str, list[str]] = {
        "Windows":    ["%windows%"],
        "macOS":      ["%mac%", "%darwin%"],
        "Linux":      ["%linux%", "%ubuntu%", "%centos%", "%debian%", "%fedora%"],
        "iOS/iPadOS": ["%ios%", "%ipad%"],
        "Android":    ["%android%"],
    }
    if os_family:
        patterns = OS_PATTERNS.get(os_family)
        if patterns:
            query = query.where(or_(*[Endpoint.os_version.ilike(p) for p in patterns]))
        elif os_family == "Other":
            all_known = [p for ps in OS_PATTERNS.values() for p in ps]
            query = query.where(~or_(*[Endpoint.os_version.ilike(p) for p in all_known]))

    if search:
        query = query.where(Endpoint.hostname.ilike(f"%{search}%"))

    # COUNT query for total
    count_q = select(func.count()).select_from(query.subquery())
    total = (await db.execute(count_q)).scalar_one()
    response.headers["X-Total-Count"] = str(total)

    # Apply SQL ordering and pagination
    paged_query = (
        query
        .order_by(
            case(
                (ComplianceStatus.status == "non_compliant", 0),
                (ComplianceStatus.status == "partial", 1),
                else_=2,
            ),
            Endpoint.hostname,
        )
        .limit(limit)
        .offset(offset)
    )
    paged_result = await db.execute(paged_query)
    items = paged_result.scalars().unique().all()

    def _fail_count(s: ComplianceStatus) -> int:
        return sum([
            not s.edr_installed,
            s.edr_installed and not s.edr_version_ok,
            not s.dlp_installed,
            s.dlp_installed and not s.dlp_version_ok,
            s.disk_encrypted is False,
            s.device_control_enabled is False,
        ])

    def _failures(s: ComplianceStatus) -> list[str]:
        out = []
        if not s.edr_installed:              out.append("No EDR")
        elif not s.edr_version_ok:           out.append("EDR Outdated")
        if not s.dlp_installed:              out.append("No DLP")
        elif not s.dlp_version_ok:           out.append("DLP Outdated")
        if s.disk_encrypted is False:        out.append("Not Encrypted")
        if s.device_control_enabled is False: out.append("Device Control Off")
        return out

    return [
        {
            "endpoint_id":            str(s.endpoint_id),
            "hostname":               s.endpoint.hostname,
            "os_version":             s.endpoint.os_version,
            "owner_email":            s.endpoint.owner.email     if s.endpoint.owner else None,
            "owner_name":             s.endpoint.owner.full_name if s.endpoint.owner else None,
            "status":                 s.status,
            "edr_installed":          s.edr_installed,
            "edr_version_ok":         s.edr_version_ok,
            "dlp_installed":          s.dlp_installed,
            "dlp_version_ok":         s.dlp_version_ok,
            "disk_encrypted":         s.disk_encrypted,
            "device_control_enabled": s.device_control_enabled,
            "failure_count":          _fail_count(s),
            "failures":               _failures(s),
            "last_evaluated":         s.last_evaluated.isoformat() if s.last_evaluated else None,
        }
        for s in items
    ]


@router.get("/{endpoint_id}", response_model=ComplianceStatusResponse)
async def get_endpoint_compliance(
    endpoint_id: str,
    db: AsyncSession = Depends(get_db),
    _: AuthUser = Depends(require_role("viewer")),
):
    result = await db.execute(
        select(ComplianceStatus).where(ComplianceStatus.endpoint_id == endpoint_id)
    )
    cs = result.scalar_one_or_none()
    if not cs:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Compliance record not found")
    return ComplianceStatusResponse.model_validate(cs)


@router.post("/evaluate")
async def trigger_compliance_evaluation(
    background_tasks: BackgroundTasks,
    _: AuthUser = Depends(require_role("analyst")),
):
    from app.engines.compliance import run_full_compliance
    from app.core.database import AsyncSessionLocal

    async def _run():
        async with AsyncSessionLocal() as db:
            await run_full_compliance(db)
            await db.commit()

    background_tasks.add_task(_run)
    return {"message": "Compliance evaluation triggered"}
