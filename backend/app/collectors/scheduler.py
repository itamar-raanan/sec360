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


async def collect_hibob():
    config_id, credentials = await _get_integration_config("hibob")
    if not credentials:
        logger.debug("Scheduler: HiBob not configured or disabled, skipping")
        return

    logger.info("Scheduler: Running HiBob collection")
    try:
        from app.collectors.hibob import HiBobCollector
        async with AsyncSessionLocal() as db:
            collector = HiBobCollector(credentials=credentials, db=db)
            result = await collector.collect()
            await db.commit()

        if result.get("error"):
            await _update_integration_status("hibob", False, error=result["error"])
        else:
            await _update_integration_status("hibob", True, records=result.get("records_synced", 0))
    except Exception as e:
        logger.error(f"Scheduler: HiBob collection failed: {e}", exc_info=True)
        await _update_integration_status("hibob", False, error=str(e))


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


async def collect_cloudsoc():
    config_id, credentials = await _get_integration_config("cloudsoc")
    if not credentials:
        logger.debug("Scheduler: CloudSOC not configured or disabled, skipping")
        return

    logger.info("Scheduler: Running CloudSOC collection")
    try:
        from app.collectors.cloudsoc import CloudSOCCollector
        async with AsyncSessionLocal() as db:
            collector = CloudSOCCollector(credentials=credentials, db=db)
            result = await collector.collect()
            await db.commit()

        if result.get("error"):
            await _update_integration_status("cloudsoc", False, error=result["error"])
        else:
            await _update_integration_status("cloudsoc", True, records=result.get("records_synced", 0))
    except Exception as e:
        logger.error(f"Scheduler: CloudSOC collection failed: {e}", exc_info=True)
        await _update_integration_status("cloudsoc", False, error=str(e))


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
    - SentinelOne second: enriches those records with agent data.
    - Symantec third: further enriches with DLP agent data.
    Running these three sequentially avoids deadlocks from concurrent writes
    to the same endpoint/agent rows.

    HiBob and Google Workspace only write to the users table and are run in
    parallel with each other after the endpoint collectors finish.
    """
    import asyncio

    logger.info("Scheduler: Starting full collection cycle")

    # ── Phase 1: endpoint collectors (sequential to avoid row-level deadlocks) ──
    for name, coro_fn in (
        ("jumpcloud",   collect_jumpcloud),
        ("sentinelone", collect_sentinelone),
        ("symantec",    collect_symantec),
    ):
        try:
            await coro_fn()
        except Exception as e:
            logger.error("Scheduler: %s collector raised: %s", name, e, exc_info=True)

    # ── Phase 2: user/HR + activity collectors (parallel) ──
    hr_results = await asyncio.gather(
        collect_hibob(),
        collect_google(),
        collect_cloudsoc(),
        return_exceptions=True,
    )
    for name, r in zip(("hibob", "google", "cloudsoc"), hr_results):
        if isinstance(r, Exception):
            logger.error("Scheduler: %s collector raised: %s", name, r, exc_info=True)

    # ── Phase 3: post-processing ──
    await run_correlation_and_risk()
    logger.info("Scheduler: Full collection cycle complete")


async def run_ai_analysis():
    """Run AI anomaly detection engine and persist new insights."""
    logger.info("Scheduler: Running AI analysis engine")
    try:
        from app.engines.anomaly_engine import run_all_detections
        from app.engines.ai_explainer import generate_insight_description
        from app.models.ai_insight import AIInsight
        from app.models.user import User
        from sqlalchemy import select, func, and_
        from datetime import timedelta
        import uuid as _uuid
        from typing import Optional

        async with AsyncSessionLocal() as db:
            candidates = await run_all_detections(db, hours_back=24)
            if not candidates:
                logger.info("Scheduler: AI analysis — no anomalies detected")
                return

            logger.info("Scheduler: AI analysis found %d candidate insights", len(candidates))

            # ── Bulk dedup: load all non-dismissed insights created in last 24h ──
            cutoff = datetime.now(timezone.utc) - timedelta(hours=24)
            existing_rows = (await db.execute(
                select(AIInsight.insight_type, AIInsight.user_id)
                .where(
                    and_(
                        AIInsight.created_at >= cutoff,
                        AIInsight.is_dismissed == False,  # noqa: E712
                    )
                )
            )).fetchall()
            # Set of (insight_type, user_id_str_or_None) already present
            existing_keys: set[tuple[str, Optional[str]]] = {
                (row[0], str(row[1]) if row[1] else None)
                for row in existing_rows
            }
            logger.info("Scheduler: %d insight(s) already exist in dedup window", len(existing_keys))

            # ── Bulk-load users referenced by per-user candidates ──
            user_ids_needed = list({
                _uuid.UUID(c["user_id"]) for c in candidates if c.get("user_id")
            })
            users_map: dict[_uuid.UUID, User] = {}
            if user_ids_needed:
                u_rows = (await db.execute(
                    select(User).where(User.id.in_(user_ids_needed))
                )).scalars().all()
                users_map = {u.id: u for u in u_rows}

            # ── Create new insights ──
            created = 0
            for c in candidates:
                insight_type = c["insight_type"]
                user_id_str: Optional[str] = c.get("user_id")
                dedup_key = (insight_type, user_id_str)

                if dedup_key in existing_keys:
                    logger.debug("Scheduler: skipping duplicate %s (user=%s)", insight_type, user_id_str)
                    continue

                uid: Optional[_uuid.UUID] = None
                if user_id_str:
                    try:
                        uid = _uuid.UUID(user_id_str)
                    except ValueError:
                        pass

                user = users_map.get(uid) if uid else None
                user_name = (user.full_name or user.email) if user else "Unknown"
                user_email = user.email if user else ""
                user_dept = user.department if user else None

                try:
                    description = await generate_insight_description(
                        insight_type=insight_type,
                        title=c["title"],
                        evidence=c.get("evidence") or {},
                        user_name=user_name,
                        user_email=user_email,
                        user_dept=user_dept,
                    )
                except Exception as desc_err:
                    logger.warning(
                        "Scheduler: description generation failed for %s: %s — using title as fallback",
                        insight_type, desc_err,
                    )
                    description = c["title"]

                try:
                    db.add(AIInsight(
                        insight_type=insight_type,
                        severity=c["severity"],
                        title=c["title"],
                        description=description,
                        user_id=uid,
                        evidence=c.get("evidence"),
                        event_ids=c.get("event_ids") or [],
                        is_dismissed=False,
                        is_new=True,
                        expires_at=datetime.now(timezone.utc) + timedelta(days=7),
                    ))
                    existing_keys.add(dedup_key)  # prevent in-batch duplicates
                    created += 1
                    logger.debug("Scheduler: queued insight %s [%s]", insight_type, c["severity"])
                except Exception as add_err:
                    logger.error("Scheduler: failed to add insight %s: %s", insight_type, add_err)

            await db.commit()
            logger.info(
                "Scheduler: AI analysis complete — %d new insight(s) created, %d skipped (duplicates)",
                created, len(candidates) - created,
            )
    except Exception as e:
        logger.error("Scheduler: AI analysis failed: %s", e, exc_info=True)


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
    scheduler.add_job(
        run_ai_analysis,
        trigger=IntervalTrigger(hours=1),
        id="ai_analysis",
        replace_existing=True,
    )

    scheduler.start()
    logger.info(f"Scheduler started with {interval_minutes}min interval")


def stop_scheduler():
    if scheduler.running:
        scheduler.shutdown()
        logger.info("Scheduler stopped")
