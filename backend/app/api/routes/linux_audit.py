"""Manual ingestion and review of Debian CIS audit reports."""

import hashlib
import ipaddress
import json
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal

from fastapi import APIRouter, Depends, File, Form, HTTPException, Query, Request, Response, UploadFile, status
from sqlalchemy import desc, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import audit_action, get_current_user, get_db, require_role
from app.models.endpoint import Endpoint
from app.models.linux_audit import LinuxAuditReport
from app.models.system_settings import SystemSettings
from app.models.user import AuthUser


router = APIRouter(prefix="/linux-audits", tags=["linux-audits"])
MAX_REPORT_BYTES = 15 * 1024 * 1024
MAX_RESULTS = 5_000
VALID_STATUSES = {"PASS", "FAIL", "REVIEW", "EXCLUDED", "ERROR", "NOT_APPLICABLE"}


def _reject_json_constant(value: str) -> None:
    raise ValueError(f"Unsupported JSON value: {value}")


async def _require_enabled(
    _: AuthUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> None:
    enabled = await db.scalar(
        select(SystemSettings.linux_audit_enabled).where(SystemSettings.id == 1)
    )
    if not enabled:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Enable Linux Audit in Platform Settings to use this feature.",
        )


def _as_int(value: Any) -> int:
    try:
        return max(0, int(value or 0))
    except (TypeError, ValueError):
        return 0


def _text(value: Any, maximum: int) -> str | None:
    return str(value or "").strip()[:maximum] or None


def _normalize_ip(value: Any, *, field: str) -> str | None:
    text = str(value or "").strip()
    if not text:
        return None
    try:
        return str(ipaddress.ip_address(text))
    except ValueError as exc:
        raise HTTPException(422, f"The report {field} value is invalid") from exc


def _parse_datetime(value: Any) -> datetime:
    if not isinstance(value, str) or not value.strip():
        raise HTTPException(422, "The report is missing a valid generated_at timestamp")
    try:
        parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError as exc:
        raise HTTPException(422, "The report generated_at timestamp is invalid") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _validate_report(payload: Any) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise HTTPException(422, "The uploaded report must be a JSON object")

    hostname = payload.get("host")
    benchmark = payload.get("benchmark")
    system = payload.get("system") or {}
    audit_tool = payload.get("audit_tool") or {}
    summary = payload.get("summary")
    results = payload.get("results")
    if not isinstance(hostname, str) or not hostname.strip():
        raise HTTPException(422, "This is not a supported CIS report: host is missing")
    if not isinstance(benchmark, dict) or not isinstance(benchmark.get("name"), str):
        raise HTTPException(422, "This is not a supported CIS report: benchmark metadata is missing")
    if not isinstance(summary, dict):
        raise HTTPException(422, "This is not a supported CIS report: summary is missing")
    if not isinstance(results, list):
        raise HTTPException(422, "This is not a supported CIS report: results must be an array")
    if len(results) > MAX_RESULTS:
        raise HTTPException(413, f"Reports may contain at most {MAX_RESULTS:,} controls")
    if any(not isinstance(item, dict) for item in results):
        raise HTTPException(422, "Every report result must be a JSON object")
    if not isinstance(system, dict):
        raise HTTPException(422, "The report system metadata must be an object")
    if not isinstance(audit_tool, dict):
        raise HTTPException(422, "The report audit_tool metadata must be an object")

    primary_ip = _normalize_ip(payload.get("ip_address"), field="ip_address")
    raw_ip_addresses = payload.get("ip_addresses") or []
    if not isinstance(raw_ip_addresses, list):
        raise HTTPException(422, "The report ip_addresses value must be an array")
    if len(raw_ip_addresses) > 100:
        raise HTTPException(422, "The report contains too many IP addresses")
    ip_addresses = list(dict.fromkeys(
        address for address in (
            _normalize_ip(value, field="ip_addresses") for value in raw_ip_addresses
        ) if address and not ipaddress.ip_address(address).is_loopback
    ))
    if primary_ip and primary_ip not in ip_addresses:
        ip_addresses.insert(0, primary_ip)

    machine_id_hash = _text(system.get("machine_id_hash"), 64)
    if machine_id_hash and not re.fullmatch(r"[0-9a-fA-F]{64}", machine_id_hash):
        raise HTTPException(422, "The report machine_id_hash must be a SHA-256 value")

    observed = {key: 0 for key in VALID_STATUSES}
    for item in results:
        result_status = str(item.get("status") or "").upper()
        if result_status in observed:
            observed[result_status] += 1

    return {
        "schema_version": _text(payload.get("schema_version"), 20),
        "hostname": hostname.strip()[:255],
        "fqdn": _text(payload.get("fqdn"), 255),
        "ip_address": primary_ip,
        "ip_addresses": ip_addresses,
        "profile": _text(payload.get("profile"), 100),
        "benchmark_name": benchmark["name"].strip()[:255],
        "benchmark_version": _text(benchmark.get("version"), 100),
        "os_name": " ".join(value for value in (
            _text(system.get("distribution"), 120),
            _text(system.get("distribution_version"), 120),
        ) if value)[:255] or " ".join(value for value in (
            _text(benchmark.get("target_distribution"), 120),
            _text(benchmark.get("target_major_version"), 120),
        ) if value)[:255] or None,
        "kernel": _text(system.get("kernel"), 255),
        "architecture": _text(system.get("architecture"), 100),
        "virtualization_type": _text(system.get("virtualization_type"), 100),
        "machine_id_hash": machine_id_hash.lower() if machine_id_hash else None,
        "audit_tool_version": _text(audit_tool.get("version"), 100),
        "audit_tool_git_commit": _text(audit_tool.get("git_commit"), 64),
        "generated_at": _parse_datetime(payload.get("generated_at")),
        "total_count": _as_int(summary.get("total")) or len(results),
        "pass_count": _as_int(summary.get("pass")) or observed["PASS"],
        "fail_count": _as_int(summary.get("fail")) or observed["FAIL"],
        "review_count": _as_int(summary.get("review")) or observed["REVIEW"],
        "excluded_count": _as_int(summary.get("excluded")) or observed["EXCLUDED"],
        "error_count": _as_int(summary.get("error")) or observed["ERROR"],
    }


async def _find_endpoint(
    db: AsyncSession,
    hostname: str,
    fqdn: str | None,
    ip_addresses: list[str],
    machine_id_hash: str | None,
) -> Endpoint | None:
    normalized_names = {
        value.strip().lower().rstrip(".")
        for value in (hostname, fqdn)
        if value and value.strip()
    }
    exact = await db.scalar(select(Endpoint).where(
        func.lower(Endpoint.hostname).in_(normalized_names)
    ).order_by(desc(Endpoint.last_seen).nullslast()).limit(1))
    if exact:
        return exact
    short_names = {name.split(".", 1)[0] for name in normalized_names}
    hostname_match = await db.scalar(
        select(Endpoint)
        .where(or_(
            func.lower(Endpoint.hostname).in_(short_names),
            *(func.lower(Endpoint.hostname).like(f"{short}.%") for short in short_names),
        ))
        .order_by(desc(Endpoint.last_seen).nullslast())
        .limit(1)
    )
    if hostname_match:
        return hostname_match
    if ip_addresses:
        ip_match = await db.scalar(
            select(Endpoint)
            .where(Endpoint.ip_address.in_(ip_addresses))
            .order_by(desc(Endpoint.last_seen).nullslast())
            .limit(1)
        )
        if ip_match:
            return ip_match
    if machine_id_hash:
        previous_endpoint_id = await db.scalar(
            select(LinuxAuditReport.endpoint_id)
            .where(
                LinuxAuditReport.machine_id_hash == machine_id_hash,
                LinuxAuditReport.endpoint_id.isnot(None),
            )
            .order_by(desc(LinuxAuditReport.generated_at))
            .limit(1)
        )
        if previous_endpoint_id:
            previous_endpoint = await db.get(Endpoint, previous_endpoint_id)
            if previous_endpoint:
                return previous_endpoint
    if not ip_addresses:
        return None
    candidates = (await db.execute(
        select(Endpoint)
        .where(Endpoint.all_ips.isnot(None))
        .order_by(desc(Endpoint.last_seen).nullslast())
    )).scalars().all()
    expected = set(ip_addresses)
    return next((endpoint for endpoint in candidates if expected.intersection(
        value.strip() for value in (endpoint.all_ips or "").split(",") if value.strip()
    )), None)


def _report_payload(report: LinuxAuditReport, *, include_results: bool = False) -> dict[str, Any]:
    scored = report.pass_count + report.fail_count + report.error_count
    data: dict[str, Any] = {
        "id": str(report.id),
        "schema_version": report.schema_version,
        "hostname": report.hostname,
        "fqdn": report.fqdn,
        "ip_address": report.ip_address,
        "ip_addresses": report.ip_addresses or [],
        "endpoint_id": str(report.endpoint_id) if report.endpoint_id else None,
        "os_name": report.os_name,
        "kernel": report.kernel,
        "architecture": report.architecture,
        "virtualization_type": report.virtualization_type,
        "machine_id_hash": report.machine_id_hash,
        "profile": report.profile,
        "benchmark_name": report.benchmark_name,
        "benchmark_version": report.benchmark_version,
        "audit_tool_version": report.audit_tool_version,
        "audit_tool_git_commit": report.audit_tool_git_commit,
        "generated_at": report.generated_at,
        "total_count": report.total_count,
        "pass_count": report.pass_count,
        "fail_count": report.fail_count,
        "review_count": report.review_count,
        "excluded_count": report.excluded_count,
        "error_count": report.error_count,
        "pass_rate": round((report.pass_count / scored) * 100, 1) if scored else 0.0,
        "filename": report.filename,
        "uploaded_by_email": report.uploaded_by_email,
        "uploaded_at": report.uploaded_at,
    }
    if include_results:
        data["results"] = report.report_data.get("results", [])
        data["benchmark"] = report.report_data.get("benchmark", {})
    return data


@router.get("/status")
async def linux_audit_status(
    db: AsyncSession = Depends(get_db),
    _: AuthUser = Depends(get_current_user),
):
    enabled = await db.scalar(
        select(SystemSettings.linux_audit_enabled).where(SystemSettings.id == 1)
    )
    return {"enabled": bool(enabled)}


@router.get("/summary", dependencies=[Depends(_require_enabled)])
async def linux_audit_summary(
    db: AsyncSession = Depends(get_db),
    _: AuthUser = Depends(require_role("viewer")),
):
    row = (await db.execute(select(
        func.count(LinuxAuditReport.id),
        func.count(func.distinct(func.coalesce(
            LinuxAuditReport.machine_id_hash,
            func.lower(LinuxAuditReport.hostname),
        ))),
        func.max(LinuxAuditReport.generated_at),
        func.sum(LinuxAuditReport.fail_count),
        func.sum(LinuxAuditReport.error_count),
    ))).one()
    return {
        "reports": row[0] or 0,
        "servers": row[1] or 0,
        "last_audit": row[2],
        "failed_controls": row[3] or 0,
        "error_controls": row[4] or 0,
    }


@router.get("", dependencies=[Depends(_require_enabled)])
async def list_linux_audits(
    response: Response,
    search: str | None = Query(None, max_length=255),
    profile: str | None = Query(None, max_length=100),
    result: Literal["pass", "attention"] | None = None,
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db),
    _: AuthUser = Depends(require_role("viewer")),
):
    query = select(LinuxAuditReport)
    if search:
        pattern = f"%{search.strip()}%"
        query = query.where(or_(
            LinuxAuditReport.hostname.ilike(pattern),
            LinuxAuditReport.fqdn.ilike(pattern),
            LinuxAuditReport.ip_address.ilike(pattern),
            LinuxAuditReport.os_name.ilike(pattern),
            LinuxAuditReport.kernel.ilike(pattern),
            LinuxAuditReport.architecture.ilike(pattern),
            LinuxAuditReport.virtualization_type.ilike(pattern),
            LinuxAuditReport.benchmark_name.ilike(pattern),
        ))
    if profile:
        query = query.where(LinuxAuditReport.profile == profile)
    if result == "pass":
        query = query.where(LinuxAuditReport.fail_count == 0, LinuxAuditReport.error_count == 0)
    elif result == "attention":
        query = query.where(or_(LinuxAuditReport.fail_count > 0, LinuxAuditReport.error_count > 0))

    total = await db.scalar(select(func.count()).select_from(query.subquery())) or 0
    reports = (await db.execute(
        query.order_by(desc(LinuxAuditReport.generated_at), desc(LinuxAuditReport.uploaded_at))
        .offset(offset)
        .limit(limit)
    )).scalars().all()
    response.headers["X-Total-Count"] = str(total)
    return [_report_payload(report) for report in reports]


@router.post("/upload", status_code=status.HTTP_201_CREATED, dependencies=[Depends(_require_enabled)])
async def upload_linux_audit(
    request: Request,
    file: UploadFile = File(...),
    ip_address: str | None = Form(None),
    db: AsyncSession = Depends(get_db),
    current: AuthUser = Depends(require_role("analyst")),
):
    filename = Path(file.filename or "linux-audit.json").name[:500]
    if not filename.lower().endswith(".json"):
        raise HTTPException(415, "Upload the JSON report generated by debian13-cis-audit")
    content = await file.read(MAX_REPORT_BYTES + 1)
    if not content:
        raise HTTPException(400, "The uploaded report is empty")
    if len(content) > MAX_REPORT_BYTES:
        raise HTTPException(413, "Linux audit reports must be 15 MB or smaller")
    try:
        payload = json.loads(
            content.decode("utf-8-sig"),
            parse_constant=_reject_json_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise HTTPException(422, "The uploaded file is not valid UTF-8 JSON") from exc

    metadata = _validate_report(payload)
    digest = hashlib.sha256(content).hexdigest()
    duplicate = await db.scalar(
        select(LinuxAuditReport.id).where(LinuxAuditReport.content_hash == digest)
    )
    if duplicate:
        raise HTTPException(409, "This exact audit report has already been uploaded")

    normalized_ip = _normalize_ip(ip_address, field="IP override") if ip_address else metadata["ip_address"]
    correlation_ips = list(dict.fromkeys(
        [value for value in [normalized_ip, *metadata["ip_addresses"]] if value]
    ))
    endpoint = await _find_endpoint(
        db,
        metadata["hostname"],
        metadata["fqdn"],
        correlation_ips,
        metadata["machine_id_hash"],
    )
    if endpoint:
        inventory_ip = endpoint.ip_address
        if not inventory_ip and endpoint.all_ips:
            inventory_ip = endpoint.all_ips.split(",", 1)[0].strip() or None
        normalized_ip = normalized_ip or inventory_ip
        metadata["os_name"] = metadata["os_name"] or endpoint.os_version

    if normalized_ip and normalized_ip not in metadata["ip_addresses"]:
        metadata["ip_addresses"].insert(0, normalized_ip)
    metadata["ip_address"] = normalized_ip

    report = LinuxAuditReport(
        **metadata,
        endpoint_id=endpoint.id if endpoint else None,
        filename=filename,
        content_hash=digest,
        report_data=payload,
        uploaded_by_id=current.id,
        uploaded_by_email=current.email,
    )
    db.add(report)
    await db.flush()
    await audit_action(
        "upload_linux_audit",
        "linux_audit_report",
        str(report.id),
        request,
        db,
        current,
        {"hostname": report.hostname, "filename": filename, "generated_at": report.generated_at.isoformat()},
    )
    return _report_payload(report)


@router.get("/{report_id}", dependencies=[Depends(_require_enabled)])
async def get_linux_audit(
    report_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    _: AuthUser = Depends(require_role("viewer")),
):
    report = await db.get(LinuxAuditReport, report_id)
    if not report:
        raise HTTPException(404, "Linux audit report not found")
    return _report_payload(report, include_results=True)
