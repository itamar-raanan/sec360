import logging
from datetime import datetime, timezone
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import delete, func, select

from app.services.endpoint_inventory import current_endpoint_clause

logger = logging.getLogger(__name__)


def _version_ok(installed: str | None, minimum: str | None) -> bool:
    """
    Return True if installed >= minimum (semver-style comparison).
    Returns True when minimum is empty/None (= not configured, skip check).
    Returns False when installed is empty/None and minimum is set.
    """
    if not minimum or not minimum.strip():
        return True   # not configured → always pass
    if not installed or not installed.strip():
        return False  # no version reported → fail
    try:
        inst = [int(x) for x in installed.strip().split(".")]
        minv = [int(x) for x in minimum.strip().split(".")]
        n = max(len(inst), len(minv))
        inst += [0] * (n - len(inst))
        minv += [0] * (n - len(minv))
        return inst >= minv
    except ValueError:
        return True   # unparseable → don't penalise


async def evaluate_endpoint(endpoint_id, db: AsyncSession):
    """Evaluate compliance for a single endpoint (EDR + DLP checks only)."""
    from app.models.endpoint import Endpoint
    from app.models.agent import SecurityAgent
    from app.models.compliance import ComplianceStatus
    from app.models.system_settings import SystemSettings

    result = await db.execute(
        select(Endpoint).where(
            Endpoint.id == endpoint_id,
            current_endpoint_clause(),
        )
    )
    endpoint = result.scalar_one_or_none()
    if not endpoint:
        return None

    agents_result = await db.execute(
        select(SecurityAgent).where(SecurityAgent.endpoint_id == endpoint_id)
    )
    agents = agents_result.scalars().all()

    # Load min-version thresholds from settings (row id=1)
    cfg = (await db.execute(select(SystemSettings).where(SystemSettings.id == 1))).scalar_one_or_none()
    min_s1_ver  = (cfg.min_s1_version  or "").strip() if cfg else ""
    min_dlp_ver = (cfg.min_dlp_version or "").strip() if cfg else ""
    min_wss_ver = (cfg.min_wss_version or "").strip() if cfg else ""

    # ── SentinelOne EDR ──────────────────────────────────────────────────────
    s1_agent = next((a for a in agents if a.product_name == "sentinelone"), None)
    edr_installed  = s1_agent is not None
    edr_version_ok = _version_ok(s1_agent.version if s1_agent else None, min_s1_ver)
    if not edr_installed:
        edr_version_ok = False

    # ── Symantec DLP ─────────────────────────────────────────────────────────
    dlp_agent = next((a for a in agents if a.product_name == "symantec"), None)
    dlp_installed  = dlp_agent is not None
    dlp_version_ok = _version_ok(dlp_agent.version if dlp_agent else None, min_dlp_ver)
    if not dlp_installed:
        dlp_version_ok = False

    # ── Symantec WSS Agent (detected via S1 app inventory) ──────────────────
    wss_agent = next((a for a in agents if a.product_name == "symantec_wss"), None)
    wss_installed  = wss_agent is not None
    wss_version_ok = _version_ok(wss_agent.version if wss_agent else None, min_wss_ver)
    if not wss_installed:
        wss_version_ok = False

    # ── S1 enrichment checks (only when S1 data is available) ────────────────
    disk_encrypted: bool | None = s1_agent.disk_encrypted if s1_agent else None
    device_control_enabled: bool | None = s1_agent.device_control_enabled if s1_agent else None

    # ── Overall status ───────────────────────────────────────────────────────
    # Core mandatory checks (EDR + DLP always required)
    checks: list[bool] = [edr_installed, dlp_installed]
    if min_s1_ver:
        checks.append(edr_version_ok)
    if min_dlp_ver:
        checks.append(dlp_version_ok)
    # WSS becomes mandatory when a minimum version is configured.
    if min_wss_ver:
        checks.append(wss_installed)
        if wss_installed:
            checks.append(wss_version_ok)
    # Include encryption/device_control only when S1 has reported a value
    if disk_encrypted is not None:
        checks.append(disk_encrypted)
    if device_control_enabled is not None:
        checks.append(device_control_enabled)

    passed = sum(checks)
    if passed == len(checks):
        status = "compliant"
    elif passed == 0:
        status = "non_compliant"
    else:
        status = "partial"

    now = datetime.now(timezone.utc)

    # ── Upsert compliance record ─────────────────────────────────────────────
    cs_result = await db.execute(
        select(ComplianceStatus).where(ComplianceStatus.endpoint_id == endpoint_id)
    )
    cs = cs_result.scalar_one_or_none()

    if cs:
        cs.edr_installed          = edr_installed
        cs.edr_version_ok         = edr_version_ok
        cs.dlp_installed          = dlp_installed
        cs.dlp_version_ok         = dlp_version_ok
        cs.wss_installed          = wss_installed
        cs.wss_version_ok         = wss_version_ok
        cs.disk_encrypted         = disk_encrypted
        cs.device_control_enabled = device_control_enabled
        cs.status                 = status
        cs.last_evaluated         = now
    else:
        cs = ComplianceStatus(
            endpoint_id           = endpoint_id,
            edr_installed         = edr_installed,
            edr_version_ok        = edr_version_ok,
            dlp_installed         = dlp_installed,
            dlp_version_ok        = dlp_version_ok,
            wss_installed         = wss_installed,
            wss_version_ok        = wss_version_ok,
            disk_encrypted        = disk_encrypted,
            device_control_enabled= device_control_enabled,
            status                = status,
            last_evaluated        = now,
        )
        db.add(cs)

    return cs


async def run_full_compliance(db: AsyncSession) -> dict:
    """Evaluate current endpoints and remove derived rows for stale inventory."""
    from app.models.endpoint import Endpoint
    from app.models.compliance import ComplianceStatus

    active_endpoint_ids = select(Endpoint.id).where(current_endpoint_clause())
    stale_count = await db.scalar(
        select(func.count()).select_from(ComplianceStatus).where(
            ComplianceStatus.endpoint_id.not_in(active_endpoint_ids)
        )
    )
    if stale_count:
        await db.execute(
            delete(ComplianceStatus).where(
                ComplianceStatus.endpoint_id.not_in(active_endpoint_ids)
            )
        )

    result = await db.execute(active_endpoint_ids)
    endpoint_ids = [row[0] for row in result.fetchall()]

    evaluated = 0
    for eid in endpoint_ids:
        try:
            await evaluate_endpoint(eid, db)
            evaluated += 1
        except Exception as e:
            logger.error(f"Compliance: Failed to evaluate endpoint {eid}: {e}")

    logger.info(
        "Compliance: evaluated %d/%d current endpoints; removed %d stale records",
        evaluated,
        len(endpoint_ids),
        stale_count or 0,
    )
    return {
        "evaluated": evaluated,
        "total": len(endpoint_ids),
        "stale_records_removed": stale_count or 0,
    }
