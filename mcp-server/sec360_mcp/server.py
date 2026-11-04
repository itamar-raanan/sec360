"""MCP tools for querying SEC360 through a personal read-only API key."""

from __future__ import annotations

import asyncio
import json
from typing import Any, Literal

from mcp.server import MCPServer

from sec360_mcp.client import Sec360Client
from sec360_mcp.config import Settings


mcp = MCPServer(
    "SEC360",
    instructions=(
        "Read security posture data from SEC360. All tools are read-only. "
        "Use summary tools before detailed lists, keep result limits small, and preserve "
        "exact identifiers when requesting details. The API key owner's live role, enabled "
        "features, and connected integrations control access."
    ),
)


def _bounded(value: int, maximum: int = 200) -> int:
    return max(1, min(value, maximum))


async def _get(path: str, **params: Any) -> Any:
    async with Sec360Client(Settings.from_env()) as client:
        result = await client.get(path, params)
    return result.as_tool_result()


async def _get_many(requests: list[tuple[str, dict[str, Any]]]) -> list[Any]:
    async with Sec360Client(Settings.from_env()) as client:
        results = await asyncio.gather(*(client.get(path, params) for path, params in requests))
    return [item.as_tool_result() for item in results]


@mcp.resource("sec360://capabilities")
def capabilities() -> str:
    """Describe the data domains exposed by this read-only server."""
    return json.dumps({
        "read_only": True,
        "domains": [
            "endpoints and security agents", "users and correlated identities",
            "compliance and risk", "activity and suspicious events",
            "SentinelOne application vulnerabilities", "Symantec DLP exclusions",
            "Puppet facts", "Linux CIS audits", "proxy policy audits",
            "network map", "integration status",
        ],
        "authorization": "Every request inherits the API key owner's live SEC360 role.",
    }, indent=2)


@mcp.tool()
async def sec360_health() -> dict[str, Any]:
    """Check SEC360 backend, database, and scheduler health."""
    return await _get("/api/health")


@mcp.tool()
async def get_current_user() -> dict[str, Any]:
    """Return the SEC360 user and role represented by the configured API key."""
    return await _get("/api/auth/me")


@mcp.tool()
async def get_integration_status() -> list[dict[str, Any]]:
    """List SEC360 products, connection state, last sync, and available features."""
    return await _get("/api/integrations")


@mcp.tool()
async def search_sec360(query: str) -> dict[str, Any]:
    """Search users and endpoints by name, email, hostname, or IP address."""
    return await _get("/api/search", q=query)


@mcp.tool()
async def list_endpoints(
    search: str | None = None,
    compliance_status: str | None = None,
    operating_system: str | None = None,
    has_sentinelone: bool | None = None,
    has_dlp: bool | None = None,
    has_wss: bool | None = None,
    unassigned: bool | None = None,
    limit: int = 50,
    offset: int = 0,
) -> dict[str, Any]:
    """List active endpoints with owner, risk, compliance, agent, and OS filters."""
    return await _get(
        "/api/endpoints", search=search, compliance_status=compliance_status,
        os_filter=operating_system, has_s1=has_sentinelone, has_dlp=has_dlp,
        has_wss=has_wss, unassigned=unassigned, limit=_bounded(limit, 500),
        offset=max(0, offset),
    )


@mcp.tool()
async def get_endpoint(endpoint_id: str) -> dict[str, Any]:
    """Return full endpoint detail and linked security-agent records."""
    detail, agents = await _get_many([
        (f"/api/endpoints/{endpoint_id}", {}),
        (f"/api/endpoints/{endpoint_id}/agents", {}),
    ])
    return {"endpoint": detail, "agents": agents}


@mcp.tool()
async def list_users(
    search: str | None = None,
    department: str | None = None,
    employment_status: str | None = None,
    risk_level: Literal["low", "medium", "high", "critical"] | None = None,
    limit: int = 50,
    offset: int = 0,
) -> dict[str, Any]:
    """List correlated users with department, status, risk, and text filters."""
    return await _get(
        "/api/users", search=search, department=department,
        employment_status=employment_status, risk_level=risk_level,
        limit=_bounded(limit, 500), offset=max(0, offset),
    )


@mcp.tool()
async def get_user(user_id: str, timeline_limit: int = 50) -> dict[str, Any]:
    """Return a user with correlated identity, devices, and recent activity."""
    detail, identity, devices, timeline = await _get_many([
        (f"/api/users/{user_id}", {}),
        (f"/api/users/{user_id}/identity", {}),
        (f"/api/users/{user_id}/devices", {}),
        (f"/api/users/{user_id}/timeline", {"limit": _bounded(timeline_limit, 200)}),
    ])
    return {"user": detail, "identity": identity, "devices": devices, "timeline": timeline}


@mcp.tool()
async def get_user_anomalies() -> dict[str, Any]:
    """Find identity mismatches and users present in only one connected source."""
    return await _get("/api/users/anomalies")


@mcp.tool()
async def get_compliance_overview() -> dict[str, Any]:
    """Return compliance KPIs, agent coverage, OS breakdown, and worst offenders."""
    dashboard, summary = await _get_many([
        ("/api/compliance/dashboard", {}), ("/api/compliance/summary", {}),
    ])
    return {"dashboard": dashboard, "summary": summary}


@mcp.tool()
async def list_compliance_endpoints(
    statuses: list[str] | None = None,
    issues: list[str] | None = None,
    operating_systems: list[str] | None = None,
    agents: list[str] | None = None,
    scope: Literal["included", "excluded", "all"] = "included",
    search: str | None = None,
    limit: int = 100,
    offset: int = 0,
) -> dict[str, Any]:
    """List compliance endpoints using multi-select status, issue, OS, agent, and scope filters."""
    return await _get(
        "/api/compliance/endpoints", statuses=statuses, issues=issues,
        oses=operating_systems, agents=agents, scope=scope, search=search,
        limit=_bounded(limit, 500), offset=max(0, offset),
    )


@mcp.tool()
async def get_risk_overview(min_score: float = 51, limit: int = 25) -> dict[str, Any]:
    """Return risk summary plus highest-risk users and endpoints above a score."""
    size = _bounded(limit, 100)
    summary, users, endpoints = await _get_many([
        ("/api/risk/summary", {}),
        ("/api/risk/users", {"min_score": min_score, "limit": size}),
        ("/api/risk/endpoints", {"min_score": min_score, "limit": size}),
    ])
    return {"summary": summary, "users": users, "endpoints": endpoints}


@mcp.tool()
async def list_activity(
    suspicious_only: bool = False,
    event_types: list[str] | None = None,
    source: str | None = None,
    user_id: str | None = None,
    country: str | None = None,
    date_from: str | None = None,
    date_to: str | None = None,
    limit: int = 50,
    offset: int = 0,
) -> dict[str, Any]:
    """List identity activity, optionally suspicious-only and within an ISO-8601 range."""
    path = "/api/activity/suspicious" if suspicious_only else "/api/activity"
    return await _get(
        path, event_type=event_types, source=source, user_id=user_id, country=country,
        date_from=date_from, date_to=date_to, limit=_bounded(limit, 200),
        offset=max(0, offset),
    )


@mcp.tool()
async def get_application_vulnerability_overview() -> dict[str, Any]:
    """Return SentinelOne vulnerability totals, severity counts, facets, and top apps."""
    summary, facets = await _get_many([
        ("/api/application-vulnerabilities/summary", {}),
        ("/api/application-vulnerabilities/facets", {}),
    ])
    return {"summary": summary, "facets": facets}


@mcp.tool()
async def list_application_vulnerabilities(
    search: str | None = None,
    severity: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW"] | None = None,
    status: str | None = None,
    mitigation: str | None = None,
    exploit_available: bool | None = None,
    operating_system: str | None = None,
    sort: Literal["severity", "cvss", "risk", "detected", "application", "endpoint"] = "severity",
    order: Literal["asc", "desc"] = "desc",
    limit: int = 100,
    offset: int = 0,
) -> dict[str, Any]:
    """Query SentinelOne application vulnerability findings."""
    return await _get(
        "/api/application-vulnerabilities", search=search, severity=severity,
        status=status, mitigation=mitigation, exploit=exploit_available,
        os_type=operating_system, sort=sort, order=order,
        limit=_bounded(limit, 500), offset=max(0, offset),
    )


@mcp.tool()
async def get_application_vulnerability(finding_id: str) -> dict[str, Any]:
    """Return complete details and source data for one vulnerability finding."""
    return await _get(f"/api/application-vulnerabilities/{finding_id}")


@mcp.tool()
async def search_dlp_policy_exclusions(
    search: str | None = None,
    used_as: Literal["SENDER", "RECIPIENT", "UNUSED"] | None = None,
    active_objects_only: bool = True,
    limit: int = 100,
) -> dict[str, Any]:
    """Query live Symantec DLP user exclusions and narrow the returned policies."""
    payload = await _get("/api/dlp-policy-search")
    items = payload.get("items", []) if isinstance(payload, dict) else []
    needle = search.casefold().strip() if search else ""

    def matches(item: dict[str, Any]) -> bool:
        if used_as and item.get("used_as") != used_as:
            return False
        if active_objects_only and item.get("object_status") != "ACTIVE":
            return False
        fields = (
            item.get("object_name"), item.get("policy_name"), item.get("user_patterns"),
            item.get("modified_by_name"), item.get("ip_addresses"), item.get("url_domains"),
        )
        return not needle or any(needle in str(value).casefold() for value in fields if value is not None)

    matched = [item for item in items if isinstance(item, dict) and matches(item)]
    return {
        "items": matched[:_bounded(limit, 200)], "matched_count": len(matched),
        "source_row_count": payload.get("row_count") if isinstance(payload, dict) else None,
        "source_truncated": payload.get("truncated") if isinstance(payload, dict) else None,
        "source_refreshed_at": payload.get("source_refreshed_at") if isinstance(payload, dict) else None,
    }


@mcp.tool()
async def query_puppet_facts(
    search: str | None = None,
    certname: str | None = None,
    fact_names: list[str] | None = None,
    environment: str | None = None,
    value_types: list[Literal["string", "number", "boolean", "array", "object", "null"]] | None = None,
    favorites_only: bool = False,
    limit: int = 50,
    offset: int = 0,
) -> dict[str, Any]:
    """Query Puppet facts by node, name, value, environment, type, or favorites."""
    return await _get(
        "/api/puppet-facts", search=search, certname=certname, names=fact_names,
        environment=environment, value_types=value_types, favorites_only=favorites_only,
        limit=_bounded(limit, 500), offset=max(0, offset),
    )


@mcp.tool()
async def get_puppet_facts_overview() -> dict[str, Any]:
    """Return Puppet fact totals, facets, favorites, and saved views."""
    summary, facets, favorites, views = await _get_many([
        ("/api/puppet-facts/summary", {}), ("/api/puppet-facts/facets", {}),
        ("/api/puppet-facts/favorites", {}), ("/api/puppet-facts/saved-views", {}),
    ])
    return {"summary": summary, "facets": facets, "favorites": favorites, "saved_views": views}


@mcp.tool()
async def list_linux_audits(
    search: str | None = None,
    profile: str | None = None,
    result: Literal["pass", "attention"] | None = None,
    limit: int = 100,
    offset: int = 0,
) -> dict[str, Any]:
    """List Debian CIS audit reports and filter servers requiring attention."""
    return await _get(
        "/api/linux-audits", search=search, profile=profile, result=result,
        limit=_bounded(limit, 500), offset=max(0, offset),
    )


@mcp.tool()
async def get_linux_audit(report_id: str) -> dict[str, Any]:
    """Return a Linux CIS report with individual control results."""
    return await _get(f"/api/linux-audits/{report_id}")


@mcp.tool()
async def get_linux_audit_overview() -> dict[str, Any]:
    """Return Linux Audit feature state and report/server/failure totals."""
    status, summary = await _get_many([
        ("/api/linux-audits/status", {}), ("/api/linux-audits/summary", {}),
    ])
    return {"status": status, "summary": summary}


@mcp.tool()
async def list_proxy_audit_events(
    search: str | None = None,
    object_type: Literal["policy", "shared_object"] | None = None,
    author: str | None = None,
    limit: int = 100,
    offset: int = 0,
) -> dict[str, Any]:
    """List Management Center policy and shared-object revision events."""
    return await _get(
        "/api/proxy-audit", search=search, object_type=object_type, author=author,
        limit=_bounded(limit, 500), offset=max(0, offset),
    )


@mcp.tool()
async def get_proxy_audit_event(event_id: str) -> dict[str, Any]:
    """Return a proxy policy revision with its full diff and summary."""
    return await _get(f"/api/proxy-audit/{event_id}")


@mcp.tool()
async def get_proxy_audit_overview() -> dict[str, Any]:
    """Return Proxy Audit feature state and revision totals."""
    status, summary = await _get_many([
        ("/api/proxy-audit/status", {}), ("/api/proxy-audit/summary", {}),
    ])
    return {"status": status, "summary": summary}


@mcp.tool()
async def get_network_map() -> dict[str, Any]:
    """Return current network topology, clients, infrastructure, and placement."""
    return await _get("/api/network-map")


@mcp.tool()
async def list_entity_notes(
    entity_type: Literal["endpoint", "user"],
    entity_id: str,
) -> list[dict[str, Any]]:
    """Read analyst notes attached to one endpoint or user."""
    return await _get("/api/notes", entity_type=entity_type, entity_id=entity_id)


@mcp.tool()
async def generate_report(
    report_type: Literal["compliance", "risk", "users", "endpoints", "activity"],
    filters: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Generate a read-only report preview containing at most 500 rows."""
    return await _get(
        "/api/reports/generate",
        report_type=report_type,
        filters=json.dumps(filters or {}, separators=(",", ":")),
    )


@mcp.tool()
async def list_scheduled_reports() -> list[dict[str, Any]]:
    """Read configured report schedules without creating or sending reports."""
    return await _get("/api/reports/scheduled")


@mcp.tool()
async def list_security_audit_events(limit: int = 50, offset: int = 0) -> dict[str, Any]:
    """Read administrator audit events, including API-key lifecycle changes."""
    return await _get(
        "/api/settings/audit", limit=_bounded(limit, 200), offset=max(0, offset),
    )


@mcp.tool()
async def list_security_change_events(
    entity_type: Literal["endpoint", "user"] | None = None,
    event_type: str | None = None,
    category: Literal["agents", "users", "dlp"] | None = None,
    severity: Literal["info", "warning", "error"] | None = None,
    limit: int = 50,
    offset: int = 0,
) -> dict[str, Any]:
    """Read high-signal SEC360 endpoint, user, agent, and DLP change events."""
    return await _get(
        "/api/settings/change-events", entity_type=entity_type, event_type=event_type,
        category=category, severity=severity, limit=_bounded(limit, 500),
        offset=max(0, offset),
    )


def main() -> None:
    settings = Settings.from_env()
    if settings.transport == "stdio":
        mcp.run()
        return
    mcp.run(
        transport="streamable-http", host=settings.host, port=settings.port,
        stateless_http=True, json_response=True,
    )


if __name__ == "__main__":
    main()
