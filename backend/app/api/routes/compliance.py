from typing import Optional
from fastapi import APIRouter, Depends, Query, Response, HTTPException, status, BackgroundTasks, Request
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, case, false, literal, or_, exists, delete
from sqlalchemy.orm import joinedload

from app.api.deps import audit_action, get_db, require_role
from app.models.user import AuthUser
from app.models.compliance import ComplianceExclusion, ComplianceStatus
from app.models.endpoint import Endpoint
from app.schemas.compliance import ComplianceExclusionUpdate, ComplianceStatusResponse, ComplianceSummaryStats
from app.services.endpoint_inventory import current_endpoint_clause
from app.services.product_scope import load_product_tags
from app.services.compliance_agents import COMPLIANCE_AGENT_BY_KEY, load_required_compliance_agents

router = APIRouter(prefix="/compliance", tags=["compliance"])


def _csv_filter_values(plural: Optional[str], singular: Optional[str]) -> list[str]:
    """Parse repeated facet values while preserving legacy single-value parameters."""
    raw = plural or singular or ""
    return list(dict.fromkeys(value.strip() for value in raw.split(",") if value.strip()))


def _has_exclusion(agent_key: str):
    return exists().where(
        ComplianceExclusion.endpoint_id == Endpoint.id,
        ComplianceExclusion.agent_key == agent_key,
    )


def _in_compliance_scope():
    return current_endpoint_clause() & ~_has_exclusion("*")


def _exclusion_payload(endpoint: Endpoint) -> dict:
    exclusions = list(endpoint.compliance_exclusions or [])
    full = next((item for item in exclusions if item.agent_key == "*"), None)
    agents = [item for item in exclusions if item.agent_key != "*"]
    newest = max(exclusions, key=lambda item: item.created_at) if exclusions else None
    return {
        "compliance_excluded": full is not None,
        "excluded_agents": [item.agent_key for item in agents],
        "exclusion_reason": newest.reason if newest else None,
        "exclusion_changed_at": newest.created_at.isoformat() if newest else None,
        "exclusion_changed_by": newest.created_by if newest else None,
    }


@router.get("/dashboard")
async def get_compliance_dashboard(
    db: AsyncSession = Depends(get_db),
    _: AuthUser = Depends(require_role("viewer")),
):
    """Rich analytics payload for the Compliance dashboard page."""
    active_product_tags = await load_product_tags(db)
    required_agents = await load_required_compliance_agents(db)
    required_keys = {agent.key for agent in required_agents}
    use_s1 = "sentinelone" in required_keys
    use_dlp = "symantec_dlp" in required_keys
    use_wss = "symantec_wss" in required_keys

    def issue_metric(enabled, condition, label, agent_key=None):
        if agent_key:
            condition = condition & ~_has_exclusion(agent_key)
        expression = func.sum(case((condition, 1), else_=0)) if enabled else literal(0)
        return expression.label(label)

    # ── Summary counts via SQL ────────────────────────────────────────────────
    summary_q = await db.execute(
        select(
            func.count().label("total"),
            func.sum(case((ComplianceStatus.status == "compliant",     1), else_=0)).label("compliant"),
            func.sum(case((ComplianceStatus.status == "partial",       1), else_=0)).label("partial"),
            func.sum(case((ComplianceStatus.status == "non_compliant", 1), else_=0)).label("non_compliant"),
            issue_metric(use_s1, ComplianceStatus.edr_installed == False, "no_edr", "sentinelone"),  # noqa: E712
            issue_metric(use_s1, (ComplianceStatus.edr_installed == True) & (ComplianceStatus.edr_version_ok == False), "edr_outdated", "sentinelone"),  # noqa: E712
            issue_metric(use_dlp, ComplianceStatus.dlp_installed == False, "no_dlp", "symantec_dlp"),  # noqa: E712
            issue_metric(use_dlp, (ComplianceStatus.dlp_installed == True) & (ComplianceStatus.dlp_version_ok == False), "dlp_outdated", "symantec_dlp"),  # noqa: E712
            issue_metric(use_wss, ComplianceStatus.wss_installed == False, "no_wss", "symantec_wss"),  # noqa: E712
            issue_metric(use_wss, (ComplianceStatus.wss_installed == True) & (ComplianceStatus.wss_version_ok == False), "wss_outdated", "symantec_wss"),  # noqa: E712
            issue_metric(use_wss, ComplianceStatus.wss_installed == False, "no_network_security", "symantec_wss"),  # noqa: E712
            # S1 enrichment — only count endpoints where S1 has reported the value
            issue_metric(use_s1, ComplianceStatus.disk_encrypted == False, "not_encrypted", "sentinelone"),  # noqa: E712
            issue_metric(use_s1, ComplianceStatus.device_control_enabled == False, "no_device_control", "sentinelone"),  # noqa: E712
        )
        .join(Endpoint, ComplianceStatus.endpoint_id == Endpoint.id)
        .where(_in_compliance_scope())
    )
    row = summary_q.one()
    total = row.total or 0

    excluded_total = await db.scalar(
        select(func.count()).select_from(ComplianceStatus)
        .join(Endpoint, ComplianceStatus.endpoint_id == Endpoint.id)
        .where(current_endpoint_clause(), _has_exclusion("*"))
    ) or 0

    presence_rows = (await db.execute(
        select(ComplianceStatus.endpoint_id, ComplianceStatus.agent_presence)
        .join(Endpoint, ComplianceStatus.endpoint_id == Endpoint.id)
        .where(_in_compliance_scope())
    )).all()
    agent_exclusion_rows = (await db.execute(
        select(ComplianceExclusion.endpoint_id, ComplianceExclusion.agent_key)
        .join(Endpoint, ComplianceExclusion.endpoint_id == Endpoint.id)
        .where(current_endpoint_clause(), ComplianceExclusion.agent_key != "*")
    )).all()
    agent_exclusions = {(row.endpoint_id, row.agent_key) for row in agent_exclusion_rows}
    agent_coverage = []
    for agent in required_agents:
        excluded_count = sum((endpoint_id, agent.key) in agent_exclusions for endpoint_id, _ in presence_rows)
        has_count = sum(
            bool((presence or {}).get(agent.key)) and (endpoint_id, agent.key) not in agent_exclusions
            for endpoint_id, presence in presence_rows
        )
        in_scope = max(total - excluded_count, 0)
        missing_count = max(in_scope - has_count, 0)
        agent_coverage.append({
            "key": agent.key,
            "label": agent.label,
            "description": agent.description,
            "has": has_count,
            "missing": missing_count,
            "excluded": excluded_count,
            "in_scope": in_scope,
            "coverage_pct": round(has_count / in_scope * 100, 1) if in_scope else 0.0,
        })

    if total == 0:
        return {
            "summary": {"total": 0, "compliant": 0, "partial": 0, "non_compliant": 0, "compliant_pct": 0.0},
            "issues": {"no_edr": 0, "edr_outdated": 0, "no_dlp": 0, "dlp_outdated": 0, "no_wss": 0, "wss_outdated": 0, "no_network_security": 0, "not_encrypted": 0, "no_device_control": 0},
            "os_breakdown": [],
            "worst_offenders": [],
            "active_product_tags": list(active_product_tags),
            "agent_coverage": agent_coverage,
            "excluded_total": excluded_total,
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
        .where(_in_compliance_scope())
        .group_by(os_case)
        .order_by(func.count().desc())
    )
    os_breakdown = [
        {"os": r.os_family, "total": r.total, "compliant": r.compliant, "non_compliant": r.non_compliant}
        for r in os_q.all()
    ]

    # ── Worst offenders — pull top 25 non/partial with their failure details ──
    fail_count_expr = (
        (case(((ComplianceStatus.edr_installed == False) & ~_has_exclusion("sentinelone"), 1), else_=0) if use_s1 else literal(0)) +  # noqa: E712
        (case(((ComplianceStatus.edr_installed == True) & (ComplianceStatus.edr_version_ok == False) & ~_has_exclusion("sentinelone"), 1), else_=0) if use_s1 else literal(0)) +  # noqa: E712
        (case(((ComplianceStatus.dlp_installed == False) & ~_has_exclusion("symantec_dlp"), 1), else_=0) if use_dlp else literal(0)) +  # noqa: E712
        (case(((ComplianceStatus.dlp_installed == True) & (ComplianceStatus.dlp_version_ok == False) & ~_has_exclusion("symantec_dlp"), 1), else_=0) if use_dlp else literal(0)) +  # noqa: E712
        (case(((ComplianceStatus.wss_installed == False) & ~_has_exclusion("symantec_wss"), 1), else_=0) if use_wss else literal(0)) +  # noqa: E712
        (case(((ComplianceStatus.wss_installed == True) & (ComplianceStatus.wss_version_ok == False) & ~_has_exclusion("symantec_wss"), 1), else_=0) if use_wss else literal(0)) +  # noqa: E712
        (case(((ComplianceStatus.disk_encrypted == False) & ~_has_exclusion("sentinelone"), 1), else_=0) if use_s1 else literal(0)) +  # noqa: E712
        (case(((ComplianceStatus.device_control_enabled == False) & ~_has_exclusion("sentinelone"), 1), else_=0) if use_s1 else literal(0))  # noqa: E712
    )
    for agent in required_agents:
        if agent.key not in {"sentinelone", "symantec_dlp", "symantec_wss"}:
            fail_count_expr += case(
                (
                    (ComplianceStatus.agent_presence[agent.key].as_boolean() == False)  # noqa: E712
                    & ~_has_exclusion(agent.key),
                    1,
                ),
                else_=0,
            )
    fail_count_expr = fail_count_expr.label("failure_count")

    worst_q = await db.execute(
        select(ComplianceStatus, fail_count_expr)
        .join(Endpoint, ComplianceStatus.endpoint_id == Endpoint.id)
        .options(
            joinedload(ComplianceStatus.endpoint).joinedload(Endpoint.owner),
            joinedload(ComplianceStatus.endpoint).joinedload(Endpoint.compliance_exclusions),
        )
        .where(
            _in_compliance_scope(),
            ComplianceStatus.status.in_(["non_compliant", "partial"]),
        )
        .order_by(fail_count_expr.desc())
        .limit(25)
    )

    worst_offenders = []
    for cs, fc in worst_q.unique().all():
        ep = cs.endpoint
        excluded_keys = {item.agent_key for item in ep.compliance_exclusions}
        failures = []
        if use_s1 and "sentinelone" not in excluded_keys and not cs.edr_installed: failures.append("No EDR")
        elif use_s1 and "sentinelone" not in excluded_keys and not cs.edr_version_ok: failures.append("EDR Outdated")
        if use_dlp and "symantec_dlp" not in excluded_keys and not cs.dlp_installed: failures.append("No DLP")
        elif use_dlp and "symantec_dlp" not in excluded_keys and not cs.dlp_version_ok: failures.append("DLP Outdated")
        if use_wss and "symantec_wss" not in excluded_keys and not cs.wss_installed: failures.append("No Symantec WSS")
        elif use_wss and "symantec_wss" not in excluded_keys and not cs.wss_version_ok: failures.append("WSS Outdated")
        if use_s1 and "sentinelone" not in excluded_keys and cs.disk_encrypted is False: failures.append("Not Encrypted")
        if use_s1 and "sentinelone" not in excluded_keys and cs.device_control_enabled is False: failures.append("Device Control Off")
        for agent in required_agents:
            if agent.key not in {"sentinelone", "symantec_dlp", "symantec_wss"} and agent.key not in excluded_keys and not (cs.agent_presence or {}).get(agent.key):
                failures.append(f"No {agent.label}")
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
            "no_wss":              row.no_wss or 0,
            "wss_outdated":        row.wss_outdated or 0,
            "no_network_security": row.no_network_security or 0,
            "not_encrypted":       row.not_encrypted or 0,
            "no_device_control":   row.no_device_control or 0,
        },
        "os_breakdown":    os_breakdown,
        "worst_offenders": worst_offenders,
        "active_product_tags": list(active_product_tags),
        "agent_coverage": agent_coverage,
        "excluded_total": excluded_total,
    }


@router.get("/summary", response_model=ComplianceSummaryStats)
async def get_compliance_summary(
    db: AsyncSession = Depends(get_db),
    _: AuthUser = Depends(require_role("viewer")),
):
    required_keys = {agent.key for agent in await load_required_compliance_agents(db)}
    use_s1 = "sentinelone" in required_keys
    use_dlp = "symantec_dlp" in required_keys

    def issue_metric(enabled, condition, label):
        expression = func.sum(case((condition, 1), else_=0)) if enabled else literal(0)
        return expression.label(label)

    row = (await db.execute(
        select(
            func.count().label("total"),
            func.sum(case((ComplianceStatus.status == "compliant",     1), else_=0)).label("compliant"),
            func.sum(case((ComplianceStatus.status == "partial",       1), else_=0)).label("partial"),
            func.sum(case((ComplianceStatus.status == "non_compliant", 1), else_=0)).label("non_compliant"),
            issue_metric(use_s1, (ComplianceStatus.edr_installed == False) & ~_has_exclusion("sentinelone"), "no_edr"),  # noqa: E712
            issue_metric(use_s1, (ComplianceStatus.edr_installed == True) & (ComplianceStatus.edr_version_ok == False) & ~_has_exclusion("sentinelone"), "edr_outdated"),  # noqa: E712
            issue_metric(use_dlp, (ComplianceStatus.dlp_installed == False) & ~_has_exclusion("symantec_dlp"), "no_dlp"),  # noqa: E712
            issue_metric(use_dlp, (ComplianceStatus.dlp_installed == True) & (ComplianceStatus.dlp_version_ok == False) & ~_has_exclusion("symantec_dlp"), "dlp_outdated"),  # noqa: E712
        )
        .join(Endpoint, ComplianceStatus.endpoint_id == Endpoint.id)
        .where(_in_compliance_scope())
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
        edr_outdated=row.edr_outdated or 0,
        no_dlp=row.no_dlp or 0,
        dlp_outdated=row.dlp_outdated or 0,
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
    query = (
        select(ComplianceStatus)
        .join(Endpoint, ComplianceStatus.endpoint_id == Endpoint.id)
        .where(_in_compliance_scope())
    )
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
    statuses: Optional[str] = Query(None, max_length=200),
    issue: Optional[str] = Query(None),
    issues: Optional[str] = Query(None, max_length=500),
    os_family: Optional[str] = Query(None, alias="os"),
    os_families: Optional[str] = Query(None, alias="oses", max_length=300),
    agents: Optional[str] = Query(None, max_length=500),
    scope: str = Query("included", pattern="^(included|excluded|all)$"),
    search: Optional[str] = Query(None),
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db),
    _: AuthUser = Depends(require_role("viewer")),
):
    """Filtered list of endpoints with compliance details for the drill-down panel."""
    from sqlalchemy import and_ as sa_and
    required_agents = await load_required_compliance_agents(db)
    required_keys = {agent.key for agent in required_agents}
    use_s1 = "sentinelone" in required_keys
    use_dlp = "symantec_dlp" in required_keys
    use_wss = "symantec_wss" in required_keys

    query = (
        select(ComplianceStatus)
        .join(Endpoint, ComplianceStatus.endpoint_id == Endpoint.id)
        .options(
            joinedload(ComplianceStatus.endpoint).joinedload(Endpoint.owner),
            joinedload(ComplianceStatus.endpoint).joinedload(Endpoint.compliance_exclusions),
        )
        .where(current_endpoint_clause())
    )
    if scope == "included":
        query = query.where(~_has_exclusion("*"))
    elif scope == "excluded":
        query = query.where(_has_exclusion("*"))

    status_values = _csv_filter_values(statuses, comp_status)
    if status_values:
        allowed_statuses = {"compliant", "partial", "non_compliant"}
        selected_statuses = [value for value in status_values if value in allowed_statuses]
        query = query.where(
            ComplianceStatus.status.in_(selected_statuses) if selected_statuses else false()
        )

    issue_filters = {}
    if use_s1:
        issue_filters.update({
            "no_edr": sa_and(ComplianceStatus.edr_installed == False, ~_has_exclusion("sentinelone")),  # noqa: E712
            "edr_outdated": sa_and(ComplianceStatus.edr_installed == True, ComplianceStatus.edr_version_ok == False, ~_has_exclusion("sentinelone")),  # noqa: E712
            "not_encrypted": sa_and(ComplianceStatus.disk_encrypted == False, ~_has_exclusion("sentinelone")),  # noqa: E712
            "no_device_control": sa_and(ComplianceStatus.device_control_enabled == False, ~_has_exclusion("sentinelone")),  # noqa: E712
        })
    if use_dlp:
        issue_filters.update({
            "no_dlp": sa_and(ComplianceStatus.dlp_installed == False, ~_has_exclusion("symantec_dlp")),  # noqa: E712
            "dlp_outdated": sa_and(ComplianceStatus.dlp_installed == True, ComplianceStatus.dlp_version_ok == False, ~_has_exclusion("symantec_dlp")),  # noqa: E712
        })
    if use_wss:
        issue_filters.update({
            "no_network_security": sa_and(ComplianceStatus.wss_installed == False, ~_has_exclusion("symantec_wss")),  # noqa: E712
            "wss_outdated": sa_and(ComplianceStatus.wss_installed == True, ComplianceStatus.wss_version_ok == False, ~_has_exclusion("symantec_wss")),  # noqa: E712
        })
    issue_values = _csv_filter_values(issues, issue)
    if issue_values:
        selected_issue_filters = [
            issue_filters[value] for value in issue_values if value in issue_filters
        ]
        query = query.where(
            or_(*selected_issue_filters) if selected_issue_filters else false()
        )

    agent_values = _csv_filter_values(agents, None)
    for value in agent_values:
        try:
            agent_key, presence_state = value.rsplit(":", 1)
        except ValueError:
            query = query.where(false())
            continue
        if agent_key not in required_keys or presence_state not in {"has", "missing"}:
            query = query.where(false())
            continue
        expected = presence_state == "has"
        query = query.where(
            ComplianceStatus.agent_presence[agent_key].as_boolean() == expected,  # noqa: E712
            ~_has_exclusion(agent_key),
        )

    OS_PATTERNS: dict[str, list[str]] = {
        "Windows":    ["%windows%"],
        "macOS":      ["%mac%", "%darwin%"],
        "Linux":      ["%linux%", "%ubuntu%", "%centos%", "%debian%", "%fedora%"],
        "iOS/iPadOS": ["%ios%", "%ipad%"],
        "Android":    ["%android%"],
    }
    os_values = _csv_filter_values(os_families, os_family)
    if os_values:
        os_filters = []
        all_known = [pattern for patterns in OS_PATTERNS.values() for pattern in patterns]
        for value in os_values:
            patterns = OS_PATTERNS.get(value)
            if patterns:
                os_filters.append(or_(*[Endpoint.os_version.ilike(pattern) for pattern in patterns]))
            elif value == "Other":
                os_filters.append(~or_(*[Endpoint.os_version.ilike(pattern) for pattern in all_known]))
        query = query.where(or_(*os_filters) if os_filters else false())

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
        excluded_keys = {item.agent_key for item in s.endpoint.compliance_exclusions}
        return sum([
            use_s1 and "sentinelone" not in excluded_keys and not s.edr_installed,
            use_s1 and "sentinelone" not in excluded_keys and s.edr_installed and not s.edr_version_ok,
            use_dlp and "symantec_dlp" not in excluded_keys and not s.dlp_installed,
            use_dlp and "symantec_dlp" not in excluded_keys and s.dlp_installed and not s.dlp_version_ok,
            use_wss and "symantec_wss" not in excluded_keys and not s.wss_installed,
            use_wss and "symantec_wss" not in excluded_keys and s.wss_installed and not s.wss_version_ok,
            use_s1 and "sentinelone" not in excluded_keys and s.disk_encrypted is False,
            use_s1 and "sentinelone" not in excluded_keys and s.device_control_enabled is False,
            *[
                agent.key not in excluded_keys and not (s.agent_presence or {}).get(agent.key, False)
                for agent in required_agents
                if agent.key not in {"sentinelone", "symantec_dlp", "symantec_wss"}
            ],
        ])

    def _failures(s: ComplianceStatus) -> list[str]:
        out = []
        excluded_keys = {item.agent_key for item in s.endpoint.compliance_exclusions}
        if use_s1 and "sentinelone" not in excluded_keys and not s.edr_installed: out.append("No EDR")
        elif use_s1 and "sentinelone" not in excluded_keys and not s.edr_version_ok: out.append("EDR Outdated")
        if use_dlp and "symantec_dlp" not in excluded_keys and not s.dlp_installed: out.append("No DLP")
        elif use_dlp and "symantec_dlp" not in excluded_keys and not s.dlp_version_ok: out.append("DLP Outdated")
        if use_wss and "symantec_wss" not in excluded_keys and not s.wss_installed: out.append("No Symantec WSS")
        elif use_wss and "symantec_wss" not in excluded_keys and not s.wss_version_ok: out.append("WSS Outdated")
        if use_s1 and "sentinelone" not in excluded_keys and s.disk_encrypted is False: out.append("Not Encrypted")
        if use_s1 and "sentinelone" not in excluded_keys and s.device_control_enabled is False: out.append("Device Control Off")
        for agent in required_agents:
            if agent.key not in {"sentinelone", "symantec_dlp", "symantec_wss"} and agent.key not in excluded_keys and not (s.agent_presence or {}).get(agent.key):
                out.append(f"No {agent.label}")
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
            "agent_presence":         s.agent_presence or {},
            **_exclusion_payload(s.endpoint),
            "last_evaluated":         s.last_evaluated.isoformat() if s.last_evaluated else None,
        }
        for s in items
    ]


@router.put("/endpoints/{endpoint_id}/exclusions")
async def update_compliance_exclusions(
    endpoint_id: str,
    body: ComplianceExclusionUpdate,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current: AuthUser = Depends(require_role("analyst")),
):
    """Replace an endpoint's full and per-agent compliance exclusions."""
    endpoint = (await db.execute(
        select(Endpoint)
        .where(Endpoint.id == endpoint_id)
    )).scalar_one_or_none()
    if endpoint is None:
        raise HTTPException(status_code=404, detail="Endpoint not found")

    unknown = sorted(set(body.excluded_agents) - set(COMPLIANCE_AGENT_BY_KEY))
    if unknown:
        raise HTTPException(
            status_code=422,
            detail=f"Unknown compliance agent(s): {', '.join(unknown)}",
        )
    if (body.exclude_all or body.excluded_agents) and not body.reason:
        raise HTTPException(status_code=422, detail="A reason is required for compliance exclusions")

    await db.execute(
        delete(ComplianceExclusion).where(ComplianceExclusion.endpoint_id == endpoint.id)
    )
    keys = ["*"] if body.exclude_all else body.excluded_agents
    for key in keys:
        db.add(ComplianceExclusion(
            endpoint_id=endpoint.id,
            agent_key=key,
            reason=body.reason or "",
            created_by=current.email,
        ))
    await db.flush()

    from app.engines.compliance import evaluate_endpoint
    from app.engines.risk import endpoint_risk_score

    compliance = await evaluate_endpoint(endpoint.id, db)
    risk = await endpoint_risk_score(str(endpoint.id), db)
    endpoint.risk_score = risk["score"]
    await audit_action(
        "update_compliance_exclusions",
        "endpoint",
        str(endpoint.id),
        request,
        db,
        current,
        {
            "hostname": endpoint.hostname,
            "exclude_all": body.exclude_all,
            "excluded_agents": body.excluded_agents,
            "reason": body.reason,
        },
    )
    return {
        "endpoint_id": str(endpoint.id),
        "status": compliance.status if compliance else None,
        "compliance_excluded": body.exclude_all,
        "excluded_agents": [] if body.exclude_all else body.excluded_agents,
        "exclusion_reason": body.reason if keys else None,
        "exclusion_changed_by": current.email if keys else None,
    }


@router.get("/{endpoint_id}", response_model=ComplianceStatusResponse)
async def get_endpoint_compliance(
    endpoint_id: str,
    db: AsyncSession = Depends(get_db),
    _: AuthUser = Depends(require_role("viewer")),
):
    result = await db.execute(
        select(ComplianceStatus)
        .join(Endpoint, ComplianceStatus.endpoint_id == Endpoint.id)
        .where(
            ComplianceStatus.endpoint_id == endpoint_id,
            current_endpoint_clause(),
        )
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
