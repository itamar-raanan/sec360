import asyncio
import logging
from datetime import datetime, timezone

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.interval import IntervalTrigger

from app.core.config import settings
from app.core.database import AsyncSessionLocal

logger = logging.getLogger(__name__)

scheduler = AsyncIOScheduler()


async def _get_integration_config(integration_type: str):
    """Fetch integration config from DB and return credentials if enabled."""
    from sqlalchemy import select
    from app.models.integration import IntegrationConfig

    async with AsyncSessionLocal() as db:
        result = await db.execute(
            select(IntegrationConfig).where(IntegrationConfig.integration_type == integration_type)
        )
        config = result.scalar_one_or_none()
        if not config:
            return None, None
        if not config.is_enabled or not config.credentials:
            return None, None
        return config.id, config.credentials


async def _update_integration_status(integration_type: str, success: bool, error: str = None, records: int = None):
    """Update integration status after collection run."""
    from sqlalchemy import select
    from app.models.integration import IntegrationConfig

    async with AsyncSessionLocal() as db:
        result = await db.execute(
            select(IntegrationConfig).where(IntegrationConfig.integration_type == integration_type)
        )
        config = result.scalar_one_or_none()
        if config:
            config.last_sync = datetime.now(timezone.utc)
            if success:
                config.status = "connected"
                config.last_error = None
                if records is not None:
                    config.records_synced = str(records)
            else:
                config.status = "error"
                config.last_error = error
            await db.commit()


async def collect_jumpcloud():
    config_id, credentials = await _get_integration_config("jumpcloud")
    if not credentials:
        logger.debug("Scheduler: JumpCloud not configured or disabled, skipping")
        return

    logger.info("Scheduler: Running JumpCloud collection")
    try:
        from app.collectors.jumpcloud import JumpCloudCollector
        async with AsyncSessionLocal() as db:
            collector = JumpCloudCollector(credentials=credentials, db=db)
            result = await collector.collect()
            await db.commit()

        if result.get("error"):
            await _update_integration_status("jumpcloud", False, error=result["error"])
        else:
            await _update_integration_status("jumpcloud", True, records=result.get("records_synced", 0))
    except Exception as e:
        logger.error(f"Scheduler: JumpCloud collection failed: {e}", exc_info=True)
        await _update_integration_status("jumpcloud", False, error=str(e))


async def collect_sentinelone():
    config_id, credentials = await _get_integration_config("sentinelone")
    if not credentials:
        logger.debug("Scheduler: SentinelOne not configured or disabled, skipping")
        return

    logger.info("Scheduler: Running SentinelOne collection")
    try:
        from app.collectors.sentinelone import SentinelOneCollector
        async with AsyncSessionLocal() as db:
            collector = SentinelOneCollector(credentials=credentials, db=db)
            result = await collector.collect()
            await db.commit()

        if result.get("error"):
            await _update_integration_status("sentinelone", False, error=result["error"])
        else:
            await _update_integration_status("sentinelone", True, records=result.get("records_synced", 0))
    except Exception as e:
        logger.error(f"Scheduler: SentinelOne collection failed: {e}", exc_info=True)
        await _update_integration_status("sentinelone", False, error=str(e))


async def collect_google():
    config_id, credentials = await _get_integration_config("google_workspace")
    if not credentials:
        logger.debug("Scheduler: Google Workspace not configured or disabled, skipping")
        return

    logger.info("Scheduler: Running Google Workspace collection")
    try:
        from app.collectors.google_workspace import GoogleWorkspaceCollector
        async with AsyncSessionLocal() as db:
            collector = GoogleWorkspaceCollector(credentials=credentials, db=db)
            result = await collector.collect()
            await db.commit()

        if result.get("error"):
            await _update_integration_status("google_workspace", False, error=result["error"])
        else:
            await _update_integration_status("google_workspace", True, records=result.get("records_synced", 0))
    except Exception as e:
        logger.error(f"Scheduler: Google Workspace collection failed: {e}", exc_info=True)
        await _update_integration_status("google_workspace", False, error=str(e))


async def collect_symantec():
    config_id, credentials = await _get_integration_config("symantec_dlp")
    if not credentials:
        logger.debug("Scheduler: Symantec DLP not configured or disabled, skipping")
        return

    logger.info("Scheduler: Running Symantec DLP collection")
    try:
        from app.collectors.symantec import SymantecCollector
        async with AsyncSessionLocal() as db:
            collector = SymantecCollector(credentials=credentials, db=db)
            result = await collector.collect()
            await db.commit()

        if result.get("error"):
            await _update_integration_status("symantec_dlp", False, error=result["error"])
        else:
            await _update_integration_status("symantec_dlp", True, records=result.get("records_synced", 0))
    except Exception as e:
        logger.error(f"Scheduler: Symantec DLP collection failed: {e}", exc_info=True)
        await _update_integration_status("symantec_dlp", False, error=str(e))


async def collect_catalog_product(integration_type: str, display_name: str):
    """Collect a configured store product that does not need bespoke scheduling."""
    _, credentials = await _get_integration_config(integration_type)
    if not credentials:
        logger.debug("Scheduler: %s not configured or disabled, skipping", display_name)
        return

    logger.info("Scheduler: Running %s collection", display_name)
    try:
        from app.integrations.registry import get_collector_class

        collector_class = get_collector_class(integration_type)
        if collector_class is None:
            raise RuntimeError(f"No collector registered for {integration_type}")
        async with AsyncSessionLocal() as db:
            collector = collector_class(credentials=credentials, db=db)
            result = await collector.collect()
            await db.commit()

        if result.get("error"):
            await _update_integration_status(
                integration_type, False, error=result["error"]
            )
        else:
            await _update_integration_status(
                integration_type, True, records=result.get("records_synced", 0)
            )
    except Exception as exc:
        logger.error("Scheduler: %s collection failed: %s", display_name, exc, exc_info=True)
        await _update_integration_status(integration_type, False, error=str(exc))


async def collect_puppet():
    await collect_catalog_product("puppet", "Puppet")


async def collect_active_directory():
    await collect_catalog_product("active_directory", "Active Directory")


async def collect_adfs():
    await collect_catalog_product("adfs", "ADFS")


async def send_scheduled_reports():
    """Check for due scheduled reports and send them."""
    from sqlalchemy import select
    from app.models.report import ScheduledReport
    from app.api.routes.reports import _generate_report, _to_csv_bytes

    now = datetime.now(timezone.utc)
    async with AsyncSessionLocal() as db:
        result = await db.execute(
            select(ScheduledReport).where(
                ScheduledReport.is_active == True,       # noqa: E712
                ScheduledReport.next_send <= now,
                ScheduledReport.recipients != None,      # noqa: E711
            )
        )
        due = result.scalars().all()

    for r in due:
        try:
            async with AsyncSessionLocal() as db:
                headers, rows = await _generate_report(r.report_type, r.filters or {}, db)
            csv_bytes = _to_csv_bytes(headers, rows)
            summary_html = f"<p><strong>{len(rows)}</strong> records.</p>"

            from app.services.email import send_report_email
            from app.api.routes.reports import _next_send
            send_report_email(r.recipients, r.name, r.report_type, csv_bytes, summary_html)

            async with AsyncSessionLocal() as db:
                from sqlalchemy import select as sa_select
                rep = (await db.execute(sa_select(ScheduledReport).where(ScheduledReport.id == r.id))).scalar_one_or_none()
                if rep:
                    rep.last_sent = now
                    rep.next_send = _next_send(rep.frequency)
                    await db.commit()
            logger.info("Sent scheduled report '%s' to %s", r.name, r.recipients)
        except Exception as e:
            logger.error("Failed to send scheduled report '%s': %s", r.name, e, exc_info=True)


async def purge_google_workspace_data():
    """
    Delete Google Workspace activity events and raw data older than 7 days.
    User directory info (sources["google"] on User rows) is kept — it reflects
    current state, not historical events.
    """
    from datetime import timedelta
    from sqlalchemy import text

    cutoff = datetime.now(timezone.utc) - timedelta(days=7)
    logger.info("Scheduler: Purging Google Workspace data older than %s", cutoff.date())

    try:
        async with AsyncSessionLocal() as db:
            # Delete activity events sourced from Google Workspace
            result = await db.execute(
                text(
                    "DELETE FROM activity_events "
                    "WHERE timestamp < :cutoff "
                    "  AND (details->>'app' = 'google_workspace')"
                ),
                {"cutoff": cutoff},
            )
            events_deleted = result.rowcount

            # Delete raw data rows from Google Workspace sources
            result2 = await db.execute(
                text(
                    "DELETE FROM raw_data "
                    "WHERE ingested_at < :cutoff "
                    "  AND source IN ('google_workspace', 'google_workspace_oauth')"
                ),
                {"cutoff": cutoff},
            )
            raw_deleted = result2.rowcount

            await db.commit()

        logger.info(
            "Scheduler: Google Workspace purge complete — "
            "%d activity events, %d raw rows deleted",
            events_deleted, raw_deleted,
        )
    except Exception as e:
        logger.error("Scheduler: Google Workspace purge failed: %s", e, exc_info=True)


async def purge_old_audit_logs():
    """
    Delete audit_logs entries older than 90 days.
    Runs daily to keep the audit_logs table from growing unbounded.
    """
    from datetime import timedelta
    from sqlalchemy import text

    cutoff = datetime.now(timezone.utc) - timedelta(days=90)
    logger.info("Scheduler: Purging audit_logs older than %s", cutoff.date())

    try:
        async with AsyncSessionLocal() as db:
            result = await db.execute(
                text("DELETE FROM audit_logs WHERE timestamp < :cutoff"),
                {"cutoff": cutoff},
            )
            deleted = result.rowcount
            await db.commit()
        logger.info("Scheduler: audit_logs purge complete — %d rows deleted", deleted)
    except Exception as e:
        logger.error("Scheduler: audit_logs purge failed: %s", e, exc_info=True)


async def run_correlation_and_risk():
    """Run correlation → compliance → risk engines.  Called after every collection cycle."""
    from app.engines.correlation import run_full_correlation
    from app.engines.compliance import run_full_compliance
    from app.engines.risk import update_all_risk_scores
    logger.info("Scheduler: Running post-collection engines")
    try:
        async with AsyncSessionLocal() as db:
            await run_full_correlation(db)
            await db.commit()
        async with AsyncSessionLocal() as db:
            await run_full_compliance(db)
            await db.commit()
        async with AsyncSessionLocal() as db:
            await update_all_risk_scores(db)
            await db.commit()
    except Exception as e:
        logger.error(f"Scheduler: Engines failed: {e}", exc_info=True)


async def collect_all_and_process():
    """
    Full collection cycle — then immediately run correlation → compliance → risk.

    Ordering matters:
    - JumpCloud first: creates the canonical endpoint + user records.
    - Directory and infrastructure products establish canonical inventory.
    - SentinelOne and Symantec then enrich endpoints with security posture.
    Running these collectors sequentially avoids deadlocks from concurrent writes
    to the same endpoint/agent rows.
    """
    import asyncio

    logger.info("Scheduler: Starting full collection cycle")

    # ── Phase 1: endpoint collectors (sequential to avoid row-level deadlocks) ──
    for name, coro_fn in (
        ("jumpcloud",       collect_jumpcloud),
        ("active_directory", collect_active_directory),
        ("puppet",          collect_puppet),
        ("sentinelone",     collect_sentinelone),
        ("symantec",        collect_symantec),
    ):
        try:
            await coro_fn()
        except Exception as e:
            logger.error("Scheduler: %s collector raised: %s", name, e, exc_info=True)

    # ── Phase 2: independent identity services (parallel) ──
    identity_results = await asyncio.gather(
        collect_google(),
        collect_adfs(),
        return_exceptions=True,
    )
    for name, r in zip(("google", "adfs"), identity_results):
        if isinstance(r, Exception):
            logger.error("Scheduler: %s collector raised: %s", name, r, exc_info=True)

    # ── Phase 3: post-processing ──
    await run_correlation_and_risk()
    logger.info("Scheduler: Full collection cycle complete")


def start_scheduler():
    interval_minutes = settings.COLLECTOR_INTERVAL_MINUTES

    # Single job — collects all sources then immediately processes the results.
    # This guarantees correlation/compliance/risk always sees fresh data and
    # removes the "independent clock drift" that the old per-collector jobs had.
    scheduler.add_job(
        collect_all_and_process,
        trigger=IntervalTrigger(minutes=interval_minutes),
        id="collect_all_and_process",
        replace_existing=True,
    )
    scheduler.add_job(
        send_scheduled_reports,
        trigger=IntervalTrigger(minutes=30),
        id="send_scheduled_reports",
        replace_existing=True,
    )
    scheduler.add_job(
        purge_google_workspace_data,
        trigger=IntervalTrigger(hours=24),
        id="purge_google_workspace",
        replace_existing=True,
    )
    scheduler.add_job(
        purge_old_audit_logs,
        trigger=IntervalTrigger(hours=24),
        id="purge_audit_logs",
        replace_existing=True,
    )
    scheduler.start()
    logger.info(f"Scheduler started with {interval_minutes}min interval")


def stop_scheduler():
    if scheduler.running:
        scheduler.shutdown()
        logger.info("Scheduler stopped")
