import asyncio
import logging
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import select

from app.core.database import AsyncSessionLocal
from app.core.config import settings
from app.investigations.providers import PROVIDER_ADAPTERS
from app.investigations.providers.base import (
    AuthenticationError,
    ProviderError,
    ProviderOutcome,
    ProviderTimeoutError,
    RateLimitedError,
)
from app.investigations.scoring import score_results
from app.models.integration import IntegrationConfig
from app.models.url_investigation import (
    UrlInvestigation,
    UrlInvestigationArtifact,
    UrlInvestigationProviderResult,
)


logger = logging.getLogger(__name__)
PROVIDERS = tuple(PROVIDER_ADAPTERS)
TERMINAL_STATUSES = {
    "completed", "no_data", "not_configured", "unsupported", "awaiting_consent",
    "rate_limited", "timeout", "authentication_error", "failed",
}
_tasks: dict[uuid.UUID, asyncio.Task] = {}
_active_tasks: dict[uuid.UUID, asyncio.Task] = {}
_provider_locks = {provider: asyncio.Lock() for provider in PROVIDERS}
_provider_last_request: dict[str, float] = {}
_overall_semaphore = asyncio.Semaphore(3)


def _result_dict(result: UrlInvestigationProviderResult) -> dict[str, Any]:
    return {
        "provider": result.provider,
        "status": result.status,
        "queried_scope": result.queried_scope,
        "native_metrics": result.native_metrics or {},
        "assessment": result.assessment or {},
        "observed_at": result.observed_at.isoformat() if result.observed_at else None,
    }


async def _recalculate(investigation_id: uuid.UUID) -> None:
    async with AsyncSessionLocal() as db:
        investigation = (await db.execute(
            select(UrlInvestigation).where(UrlInvestigation.id == investigation_id)
        )).scalar_one_or_none()
        if not investigation:
            return
        results = list(investigation.provider_results)
        latest_by_provider: dict[str, UrlInvestigationProviderResult] = {}
        for item in sorted(results, key=lambda value: value.updated_at or value.created_at):
            if item.operation in {"lookup", "scan"}:
                latest_by_provider[item.provider] = item
        score = score_results(
            [_result_dict(item) for item in latest_by_provider.values()],
            (
                settings.URL_RISK_MODERATE_THRESHOLD,
                settings.URL_RISK_HIGH_THRESHOLD,
                settings.URL_RISK_CRITICAL_THRESHOLD,
            ),
        )
        investigation.risk_score = score["risk_score"]
        investigation.risk_level = score["risk_level"]
        investigation.evidence_confidence = score["evidence_confidence"]
        investigation.coverage = score["coverage"]
        investigation.reasons = score["reasons"]
        investigation.provider_contributions = score["provider_contributions"]
        investigation.scoring_version = score["scoring_version"]
        if all(item.status in TERMINAL_STATUSES for item in results):
            investigation.status = "completed"
            investigation.completed_at = datetime.now(timezone.utc)
        else:
            investigation.status = "running"
        await db.commit()


async def _rate_limit(provider: str, credentials: dict[str, Any]) -> None:
    per_minute = max(1, min(int(credentials.get("rate_limit_per_minute", 60)), 600))
    interval = 60 / per_minute
    async with _provider_locks[provider]:
        now = asyncio.get_running_loop().time()
        wait = interval - (now - _provider_last_request.get(provider, 0))
        if wait > 0:
            await asyncio.sleep(wait)
        _provider_last_request[provider] = asyncio.get_running_loop().time()


async def _cached_result(
    investigation: UrlInvestigation,
    row: UrlInvestigationProviderResult,
    cache_minutes: int,
) -> UrlInvestigationProviderResult | None:
    if cache_minutes <= 0 or investigation.options.get("force_refresh"):
        return None
    cutoff = datetime.now(timezone.utc) - timedelta(minutes=cache_minutes)
    async with AsyncSessionLocal() as db:
        return (await db.execute(
            select(UrlInvestigationProviderResult)
            .join(UrlInvestigation)
            .where(
                UrlInvestigation.indicator_hash == investigation.indicator_hash,
                UrlInvestigation.id != investigation.id,
                UrlInvestigationProviderResult.provider == row.provider,
                UrlInvestigationProviderResult.operation == "lookup",
                UrlInvestigationProviderResult.status.in_(["completed", "no_data"]),
                UrlInvestigationProviderResult.fetched_at >= cutoff,
            )
            .order_by(UrlInvestigationProviderResult.fetched_at.desc())
            .limit(1)
        )).scalar_one_or_none()


def _apply_outcome(row: UrlInvestigationProviderResult, outcome: ProviderOutcome) -> None:
    row.status = outcome.status
    row.queried_scope = outcome.queried_scope
    row.queried_indicator_preview = outcome.queried_indicator_preview
    row.native_verdict = outcome.native_verdict
    row.native_metrics = outcome.native_metrics
    row.assessment = outcome.assessment
    row.findings = outcome.findings
    row.evidence = outcome.evidence
    row.report_url = outcome.report_url
    row.observed_at = outcome.observed_at
    row.fetched_at = outcome.fetched_at
    row.error_code = outcome.error_code
    row.error_message = outcome.error_message
    row.raw_response = outcome.raw_response


async def _store_artifact(
    db,
    investigation_id: uuid.UUID,
    provider: str,
    indicator: dict[str, Any],
    content: bytes,
    content_type: str,
) -> None:
    db.add(UrlInvestigationArtifact(
        investigation_id=investigation_id,
        provider=provider,
        content_type=content_type,
        content=content,
        size_bytes=len(content),
        target_data={"target": indicator["scan_target"]},
        captured_at=datetime.now(timezone.utc),
    ))


async def _run_provider(investigation_id: uuid.UUID, provider: str) -> None:
    async with _overall_semaphore:
        async with AsyncSessionLocal() as db:
            investigation = (await db.execute(
                select(UrlInvestigation).where(UrlInvestigation.id == investigation_id)
            )).scalar_one()
            row = next(
                item for item in investigation.provider_results
                if item.provider == provider and item.operation == "lookup"
            )
            config = (await db.execute(
                select(IntegrationConfig).where(IntegrationConfig.integration_type == provider)
            )).scalar_one_or_none()
            indicator = dict(investigation.indicator_data or {})
            if provider == "cisco_talos":
                credentials = (config.credentials or {}) if config else {}
            elif not config or not config.is_enabled or not config.credentials:
                row.status = "not_configured"
                row.error_message = "Provider is not enabled and configured"
                await db.commit()
                await _recalculate(investigation_id)
                return
            else:
                credentials = dict(config.credentials)
            cached = await _cached_result(
                investigation, row, max(0, min(int(credentials.get("cache_ttl_minutes", 60)), 10080))
            )
            if cached and provider not in {"site_shot", "cisco_talos"}:
                for field in (
                    "queried_scope", "queried_indicator_preview", "status", "native_verdict",
                    "native_metrics", "assessment", "findings", "evidence", "report_url",
                    "observed_at", "fetched_at", "error_code", "error_message", "raw_response",
                ):
                    setattr(row, field, getattr(cached, field))
                row.cache_status = "cached"
                await db.commit()
                await _recalculate(investigation_id)
                return
            row.status = "running"
            await db.commit()

        adapter = PROVIDER_ADAPTERS[provider](credentials)
        try:
            await _rate_limit(provider, credentials)
            outcome = await asyncio.wait_for(
                adapter.lookup(indicator), timeout=min(adapter.timeout * 4, 90)
            )
        except AuthenticationError as exc:
            outcome = ProviderOutcome("authentication_error", "unknown", investigation.indicator_preview, error_code=exc.code, error_message=str(exc))
        except RateLimitedError as exc:
            outcome = ProviderOutcome("rate_limited", "unknown", investigation.indicator_preview, error_code=exc.code, error_message=str(exc), evidence={"retry_after": exc.retry_after})
        except (ProviderTimeoutError, asyncio.TimeoutError) as exc:
            outcome = ProviderOutcome("timeout", "unknown", investigation.indicator_preview, error_code="timeout", error_message=str(exc) or "Provider deadline exceeded")
        except ProviderError as exc:
            outcome = ProviderOutcome("failed", "unknown", investigation.indicator_preview, error_code=exc.code, error_message=str(exc))
        except Exception:
            logger.exception("URL investigation provider failed: provider=%s investigation=%s", provider, investigation_id)
            outcome = ProviderOutcome("failed", "unknown", investigation.indicator_preview, error_code="failed", error_message="Provider returned an unexpected response")

        async with AsyncSessionLocal() as db:
            row = (await db.execute(
                select(UrlInvestigationProviderResult).where(
                    UrlInvestigationProviderResult.investigation_id == investigation_id,
                    UrlInvestigationProviderResult.provider == provider,
                    UrlInvestigationProviderResult.operation == "lookup",
                )
            )).scalar_one()
            _apply_outcome(row, outcome)
            if outcome.artifact and outcome.artifact_content_type:
                await _store_artifact(db, investigation_id, provider, indicator, outcome.artifact, outcome.artifact_content_type)
            if provider == "cloudflare_url_scanner" and outcome.status == "completed":
                scan_id = str(outcome.evidence.get("scan_id") or "")
                if scan_id and outcome.evidence.get("screenshot_available"):
                    try:
                        content, content_type = await adapter.fetch_screenshot(scan_id)
                        await _store_artifact(db, investigation_id, provider, indicator, content, content_type)
                    except ProviderError:
                        outcome.evidence["screenshot_error"] = "Screenshot was unavailable"
                        row.evidence = outcome.evidence
            await db.commit()
        await _recalculate(investigation_id)


async def run_investigation(investigation_id: uuid.UUID) -> None:
    try:
        async with AsyncSessionLocal() as db:
            investigation = (await db.execute(
                select(UrlInvestigation).where(UrlInvestigation.id == investigation_id)
            )).scalar_one_or_none()
            if not investigation:
                return
            investigation.status = "running"
            await db.commit()
        await asyncio.gather(*(_run_provider(investigation_id, provider) for provider in PROVIDERS))
        await _recalculate(investigation_id)
    finally:
        _tasks.pop(investigation_id, None)


def dispatch_investigation(investigation_id: uuid.UUID) -> None:
    existing = _tasks.get(investigation_id)
    if existing and not existing.done():
        return
    _tasks[investigation_id] = asyncio.create_task(run_investigation(investigation_id))


async def run_active_operation(investigation_id: uuid.UUID, provider: str, operation: str) -> None:
    async with AsyncSessionLocal() as db:
        investigation = (await db.execute(
            select(UrlInvestigation).where(UrlInvestigation.id == investigation_id)
        )).scalar_one()
        existing = next(
            (
                item for item in investigation.provider_results
                if item.provider == provider and item.operation == operation
            ),
            None,
        )
        if existing is None:
            row = UrlInvestigationProviderResult(
                investigation_id=investigation_id,
                provider=provider,
                operation=operation,
                queried_scope="exact_url",
                queried_indicator_preview=investigation.indicator_preview,
                status="queued",
            )
            db.add(row)
            await db.flush()
        else:
            row = existing
        config = (await db.execute(
            select(IntegrationConfig).where(IntegrationConfig.integration_type == provider)
        )).scalar_one_or_none()
        if not config or not config.is_enabled or not config.credentials:
            row.status = "not_configured"
            row.error_message = "Provider is not enabled and configured"
            await db.commit()
            return
        credentials = dict(config.credentials)
        indicator = dict(investigation.indicator_data or {})
        row.status = "running"
        row.error_code = None
        row.error_message = None
        investigation.status = "running"
        investigation.completed_at = None
        await db.commit()

    adapter = PROVIDER_ADAPTERS[provider](credentials)
    try:
        await _rate_limit(provider, credentials)
        outcome = await asyncio.wait_for(adapter.active(indicator, operation), timeout=min(adapter.timeout * 8, 180))
    except AuthenticationError as exc:
        outcome = ProviderOutcome("authentication_error", "unknown", indicator["preview"], error_code=exc.code, error_message=str(exc))
    except RateLimitedError as exc:
        outcome = ProviderOutcome("rate_limited", "unknown", indicator["preview"], error_code=exc.code, error_message=str(exc), evidence={"retry_after": exc.retry_after})
    except (ProviderTimeoutError, asyncio.TimeoutError):
        outcome = ProviderOutcome("timeout", "unknown", indicator["preview"], error_code="timeout", error_message="Provider deadline exceeded")
    except ProviderError as exc:
        outcome = ProviderOutcome("failed", "unknown", indicator["preview"], error_code=exc.code, error_message=str(exc))
    except Exception:
        logger.exception("Active URL investigation operation failed")
        outcome = ProviderOutcome("failed", "unknown", indicator["preview"], error_code="failed", error_message="Provider returned an unexpected response")

    async with AsyncSessionLocal() as db:
        row = (await db.execute(select(UrlInvestigationProviderResult).where(
            UrlInvestigationProviderResult.investigation_id == investigation_id,
            UrlInvestigationProviderResult.provider == provider,
            UrlInvestigationProviderResult.operation == operation,
        ))).scalar_one()
        _apply_outcome(row, outcome)
        if outcome.artifact and outcome.artifact_content_type:
            await _store_artifact(db, investigation_id, provider, indicator, outcome.artifact, outcome.artifact_content_type)
        await db.commit()
    await _recalculate(investigation_id)


async def _run_active_operation_tracked(investigation_id: uuid.UUID, provider: str, operation: str) -> None:
    try:
        await run_active_operation(investigation_id, provider, operation)
    finally:
        _active_tasks.pop(investigation_id, None)


def dispatch_active_operation(investigation_id: uuid.UUID, provider: str, operation: str) -> None:
    existing = _active_tasks.get(investigation_id)
    if existing and not existing.done():
        return
    _active_tasks[investigation_id] = asyncio.create_task(
        _run_active_operation_tracked(investigation_id, provider, operation)
    )


async def resume_pending_investigations() -> None:
    async with AsyncSessionLocal() as db:
        pending = (await db.execute(select(UrlInvestigation).where(
            UrlInvestigation.status.in_(["queued", "running"])
        ))).scalars().all()
        ids = []
        for investigation in pending:
            running_task = _tasks.get(investigation.id)
            active_task = _active_tasks.get(investigation.id)
            if (running_task and not running_task.done()) or (active_task and not active_task.done()):
                continue
            active_running = any(
                result.status == "running" and result.operation != "lookup"
                for result in investigation.provider_results
            )
            if active_running:
                for result in investigation.provider_results:
                    if result.status == "running" and result.operation != "lookup":
                        result.status = "failed"
                        result.error_code = "interrupted"
                        result.error_message = "Active submission was interrupted; retry manually to avoid duplicate paid scans"
                investigation.status = "completed"
                investigation.completed_at = datetime.now(timezone.utc)
            else:
                for result in investigation.provider_results:
                    if result.status == "running":
                        result.status = "queued"
                ids.append(investigation.id)
        await db.commit()
    for investigation_id in ids:
        dispatch_investigation(investigation_id)
