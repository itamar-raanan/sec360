import uuid
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response, status
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import audit_action, get_db, require_role
from app.investigations.indicators import normalize_indicator
from app.investigations.providers import PROVIDER_ADAPTERS
from app.investigations.service import PROVIDERS, dispatch_active_operation, dispatch_investigation
from app.models.integration import IntegrationConfig
from app.models.url_investigation import (
    UrlInvestigation,
    UrlInvestigationArtifact,
    UrlInvestigationProviderResult,
)
from app.models.user import AuthUser
from app.schemas.url_investigation import (
    ActiveOperationRequest,
    IndicatorPreviewRequest,
    InvestigationCreateRequest,
    InvestigationIdResponse,
)


router = APIRouter(prefix="/url-investigations", tags=["url-investigations"])

PROVIDER_LABELS = {
    "virustotal": "VirusTotal",
    "abuseipdb": "AbuseIPDB",
    "cloudflare_url_scanner": "Cloudflare URL Scanner",
    "site_shot": "Site-Shot",
    "cisco_talos": "Cisco Talos",
}
ACTIVE_OPERATIONS = {
    ("virustotal", "scan"),
    ("cloudflare_url_scanner", "scan"),
    ("site_shot", "screenshot"),
}


async def _provider_configuration(db: AsyncSession) -> dict[str, IntegrationConfig]:
    rows = (await db.execute(select(IntegrationConfig).where(
        IntegrationConfig.integration_type.in_(PROVIDERS)
    ))).scalars().all()
    return {row.integration_type: row for row in rows}


def _provider_preview(provider: str, config: IntegrationConfig | None, indicator: dict) -> dict:
    adapter = PROVIDER_ADAPTERS[provider]
    configured = bool(config and config.is_enabled and (config.credentials or provider == "cisco_talos"))
    if provider == "abuseipdb":
        sent = indicator["resolved_ips"]
        scope = "Resolved public IP addresses"
    elif provider == "cisco_talos":
        sent = [indicator["hostname"]]
        scope = "Manual navigation only; nothing sent during automated investigation"
    elif provider == "site_shot":
        sent = [indicator["scan_target"]]
        scope = "Only after explicit screenshot consent"
    elif provider == "virustotal" and indicator["indicator_type"] == "url":
        sent = [indicator["preview"], indicator["hostname"]]
        scope = "Exact URL and related hostname"
    else:
        sent = [indicator["preview"]]
        scope = "Exact URL" if indicator["indicator_type"] == "url" else "Exact hostname"
    return {
        "provider": provider,
        "label": PROVIDER_LABELS[provider],
        "enabled": configured,
        "status": config.status if config else "unconfigured",
        "sent_indicators": sent,
        "scope": scope,
        "capabilities": {
            "lookup": adapter.capabilities.existing_report_lookup,
            "scan": adapter.capabilities.new_scan_submission,
            "screenshot": adapter.capabilities.screenshot_capture,
        },
    }


def _result_payload(result: UrlInvestigationProviderResult, artifacts: list[UrlInvestigationArtifact]) -> dict:
    return {
        "id": str(result.id),
        "provider": result.provider,
        "label": PROVIDER_LABELS.get(result.provider, result.provider),
        "operation": result.operation,
        "queried_scope": result.queried_scope,
        "queried_indicator": result.queried_indicator_preview,
        "status": result.status,
        "native_verdict": result.native_verdict,
        "native_metrics": result.native_metrics or {},
        "assessment": result.assessment or {},
        "findings": result.findings or [],
        "evidence": result.evidence or {},
        "report_url": result.report_url,
        "observed_at": result.observed_at,
        "fetched_at": result.fetched_at,
        "cache_status": result.cache_status,
        "error_code": result.error_code,
        "error_message": result.error_message,
        "raw_response": result.raw_response,
        "artifacts": [
            {
                "id": str(artifact.id),
                "type": artifact.artifact_type,
                "content_type": artifact.content_type,
                "size_bytes": artifact.size_bytes,
                "captured_at": artifact.captured_at,
                "url": f"/api/url-investigations/artifacts/{artifact.id}",
            }
            for artifact in artifacts if artifact.provider == result.provider
        ],
    }


def _investigation_payload(investigation: UrlInvestigation, *, include_details: bool = True) -> dict:
    base = {
        "id": str(investigation.id),
        "indicator": investigation.indicator_data if include_details else None,
        "indicator_preview": investigation.indicator_preview,
        "indicator_type": investigation.indicator_type,
        "hostname": investigation.hostname,
        "registrable_domain": investigation.registrable_domain,
        "status": investigation.status,
        "is_sensitive": investigation.is_sensitive,
        "sensitive_reasons": investigation.sensitive_reasons or [],
        "requested_by": investigation.requested_by_email,
        "risk_score": investigation.risk_score,
        "risk_level": investigation.risk_level,
        "evidence_confidence": investigation.evidence_confidence,
        "coverage": investigation.coverage or {},
        "reasons": investigation.reasons or [],
        "provider_contributions": investigation.provider_contributions or [],
        "scoring_version": investigation.scoring_version,
        "created_at": investigation.created_at,
        "updated_at": investigation.updated_at,
        "completed_at": investigation.completed_at,
    }
    if include_details:
        grouped: dict[str, list[UrlInvestigationProviderResult]] = {provider: [] for provider in PROVIDERS}
        for result in investigation.provider_results:
            grouped[result.provider].append(result)
        providers = []
        for provider in PROVIDERS:
            operations = sorted(
                grouped[provider],
                key=lambda item: item.updated_at or item.created_at,
                reverse=True,
            )
            if not operations:
                continue
            primary = next((item for item in operations if item.status in {"queued", "running"}), operations[0])
            payload = _result_payload(primary, list(investigation.artifacts))
            payload["operations"] = [
                _result_payload(item, list(investigation.artifacts)) for item in operations
            ]
            providers.append(payload)
        base["providers"] = providers
    return base


@router.post("/preview")
async def preview_indicator(
    body: IndicatorPreviewRequest,
    db: AsyncSession = Depends(get_db),
    _: AuthUser = Depends(require_role("analyst")),
):
    indicator = await normalize_indicator(body.indicator)
    configs = await _provider_configuration(db)
    data = indicator.to_dict()
    return {
        "indicator": data,
        "providers": [_provider_preview(provider, configs.get(provider), data) for provider in PROVIDERS],
        "disclosure_notice": (
            "External providers receive the indicated URL, hostname, or resolved IP. Existing-report lookups "
            "are not necessarily private and provider policies may permit storage, scanning, or sharing."
        ),
        "sensitive_notice": (
            "Automated checks cannot identify every secret. Use domain-only investigation when the exact URL should not be disclosed."
        ),
    }


@router.post("", response_model=InvestigationIdResponse, status_code=status.HTTP_202_ACCEPTED)
async def create_investigation(
    body: InvestigationCreateRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current: AuthUser = Depends(require_role("analyst")),
):
    if not body.acknowledge_disclosure:
        raise HTTPException(400, "Confirm the external-provider disclosure notice before investigating")
    indicator = await normalize_indicator(body.indicator)
    if indicator.is_sensitive and current.role != "admin":
        raise HTTPException(
            403,
            "This URL appears to contain sensitive parameters or an account-action link. An administrator must approve it, or investigate the domain only.",
        )
    recent_cutoff = datetime.now(timezone.utc) - timedelta(minutes=5)
    existing = (await db.execute(select(UrlInvestigation).where(
        UrlInvestigation.indicator_hash == indicator.indicator_hash,
        UrlInvestigation.status.in_(["queued", "running"]),
        UrlInvestigation.created_at >= recent_cutoff,
    ).order_by(UrlInvestigation.created_at.desc()))).scalars().first()
    if existing:
        return InvestigationIdResponse(id=existing.id, deduplicated=True)

    investigation = UrlInvestigation(
        indicator_data=indicator.to_dict(),
        indicator_hash=indicator.indicator_hash,
        indicator_preview=indicator.preview,
        indicator_type=indicator.indicator_type,
        hostname=indicator.hostname,
        registrable_domain=indicator.registrable_domain,
        is_sensitive=indicator.is_sensitive,
        sensitive_reasons=indicator.sensitive_reasons,
        options={"force_refresh": body.force_refresh},
        requested_by_id=current.id,
        requested_by_email=current.email,
        coverage={"usable": 0, "applicable": 3, "label": "0 of 3 applicable reputation sources returned usable results"},
        reasons=["Provider lookups are queued."],
    )
    db.add(investigation)
    try:
        await db.flush()
    except IntegrityError:
        await db.rollback()
        existing = (await db.execute(select(UrlInvestigation).where(
            UrlInvestigation.indicator_hash == indicator.indicator_hash,
            UrlInvestigation.status.in_(["queued", "running"]),
        ).order_by(UrlInvestigation.created_at.desc()))).scalars().first()
        if existing:
            return InvestigationIdResponse(id=existing.id, deduplicated=True)
        raise
    for provider in PROVIDERS:
        if provider == "abuseipdb":
            scope, preview = "resolved_ip", indicator.hostname
        elif provider == "cisco_talos":
            scope, preview = "hostname", indicator.hostname
        else:
            scope, preview = ("exact_url", indicator.preview) if indicator.indicator_type == "url" else ("hostname", indicator.hostname)
        db.add(UrlInvestigationProviderResult(
            investigation_id=investigation.id,
            provider=provider,
            queried_scope=scope,
            queried_indicator_preview=preview,
            status="queued",
        ))
    await db.flush()
    await audit_action(
        "create_url_investigation", "url_investigation", str(investigation.id), request, db, current,
        {"indicator_type": indicator.indicator_type, "hostname": indicator.hostname, "sensitive": indicator.is_sensitive},
    )
    await db.commit()
    dispatch_investigation(investigation.id)
    return InvestigationIdResponse(id=investigation.id)


@router.get("")
async def list_investigations(
    limit: int = Query(default=50, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
    _: AuthUser = Depends(require_role("analyst")),
):
    investigations = (await db.execute(
        select(UrlInvestigation).order_by(UrlInvestigation.created_at.desc()).limit(limit)
    )).scalars().all()
    return [_investigation_payload(item, include_details=False) for item in investigations]


@router.get("/detail/{investigation_id}")
async def get_investigation(
    investigation_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    _: AuthUser = Depends(require_role("analyst")),
):
    investigation = (await db.execute(select(UrlInvestigation).where(
        UrlInvestigation.id == investigation_id
    ))).scalar_one_or_none()
    if not investigation:
        raise HTTPException(404, "Investigation not found")
    return _investigation_payload(investigation)


@router.post("/{investigation_id}/actions/{provider}", status_code=status.HTTP_202_ACCEPTED)
async def run_provider_action(
    investigation_id: uuid.UUID,
    provider: str,
    body: ActiveOperationRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current: AuthUser = Depends(require_role("analyst")),
):
    if (provider, body.operation) not in ACTIVE_OPERATIONS:
        raise HTTPException(400, "This provider does not support the requested active operation")
    if not body.acknowledge_active_submission:
        raise HTTPException(400, "Explicit confirmation is required before active scanning or screenshot capture")
    investigation = (await db.execute(select(UrlInvestigation).where(
        UrlInvestigation.id == investigation_id
    ))).scalar_one_or_none()
    if not investigation:
        raise HTTPException(404, "Investigation not found")
    if investigation.is_sensitive and current.role != "admin":
        raise HTTPException(403, "Administrator approval is required for active submission of this sensitive URL")
    rows = [item for item in investigation.provider_results if item.provider == provider]
    if not rows:
        raise HTTPException(404, "Provider result not found")
    if any(row.status in {"queued", "running"} for row in rows):
        raise HTTPException(409, "This provider already has an operation in progress")
    await audit_action(
        "run_url_investigation_active_operation", "url_investigation", str(investigation_id), request, db, current,
        {"provider": provider, "operation": body.operation, "target": investigation.indicator_preview},
    )
    await db.commit()
    dispatch_active_operation(investigation_id, provider, body.operation)
    return {"success": True, "message": f"{PROVIDER_LABELS[provider]} {body.operation} queued"}


@router.get("/artifacts/{artifact_id}")
async def get_artifact(
    artifact_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    _: AuthUser = Depends(require_role("analyst")),
):
    artifact = (await db.execute(select(UrlInvestigationArtifact).where(
        UrlInvestigationArtifact.id == artifact_id
    ))).scalar_one_or_none()
    if not artifact:
        raise HTTPException(404, "Artifact not found")
    return Response(
        content=artifact.content,
        media_type=artifact.content_type,
        headers={
            "Cache-Control": "private, no-store",
            "Content-Security-Policy": "default-src 'none'; sandbox",
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "no-referrer",
        },
    )


@router.delete("/{investigation_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_investigation(
    investigation_id: uuid.UUID,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current: AuthUser = Depends(require_role("analyst")),
):
    investigation = (await db.execute(select(UrlInvestigation).where(
        UrlInvestigation.id == investigation_id
    ))).scalar_one_or_none()
    if not investigation:
        raise HTTPException(404, "Investigation not found")
    if current.role != "admin" and investigation.requested_by_id != current.id:
        raise HTTPException(403, "Only the initiating analyst or an administrator can delete this snapshot")
    await audit_action("delete_url_investigation", "url_investigation", str(investigation_id), request, db, current, {
        "indicator_type": investigation.indicator_type, "hostname": investigation.hostname,
    })
    await db.delete(investigation)
