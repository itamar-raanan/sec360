import logging
from datetime import datetime, timezone, timedelta
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

logger = logging.getLogger(__name__)


def risk_level(score: float) -> str:
    if score <= 25:
        return "low"
    elif score <= 50:
        return "medium"
    elif score <= 75:
        return "high"
    return "critical"


async def user_risk_score(user_id: str, db: AsyncSession) -> dict:
    from app.models.user import User
    from app.models.activity import ActivityEvent
    from app.models.compliance import ComplianceStatus
    from app.models.endpoint import Endpoint

    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user:
        return {"score": 0, "level": "low", "factors": []}

    score = 0.0
    factors = []
    now = datetime.now(timezone.utc)

    # Check impossible travel
    events_result = await db.execute(
        select(ActivityEvent)
        .where(ActivityEvent.user_id == user_id, ActivityEvent.event_type == "login")
        .order_by(ActivityEvent.timestamp.asc())
    )
    events = events_result.scalars().all()

    if len(events) >= 2:
        for i in range(1, len(events)):
            prev = events[i - 1]
            curr = events[i]
            if prev.country and curr.country and prev.country != curr.country:
                delta = (curr.timestamp - prev.timestamp).total_seconds() / 3600
                if delta < 6:  # Impossible to travel between countries in 6 hours
                    score += 30
                    factors.append(f"impossible_travel:{prev.country}->{curr.country}")
                    break

    # New country login
    countries = [e.country for e in events if e.country]
    unique_countries = set(countries)
    if len(events) > 5 and len(unique_countries) > 3:
        score += 20
        factors.append(f"multiple_countries:{len(unique_countries)}")

    # Non-compliant device
    endpoints_result = await db.execute(
        select(Endpoint).where(Endpoint.owner_user_id == user_id)
    )
    endpoints = endpoints_result.scalars().all()
    for ep in endpoints:
        cs_result = await db.execute(
            select(ComplianceStatus).where(ComplianceStatus.endpoint_id == ep.id)
        )
        cs = cs_result.scalar_one_or_none()
        if cs and cs.status == "non_compliant":
            score += 25
            factors.append("non_compliant_device")
            break

    # No MFA
    if not user.mfa_enabled:
        score += 15
        factors.append("no_mfa")

    # Inactive > 30 days
    if user.last_login:
        days_inactive = (now - user.last_login).days
        if days_inactive > 30:
            score += 10
            factors.append(f"inactive_{days_inactive}_days")

    score = min(score, 100)
    return {"score": score, "level": risk_level(score), "factors": factors}


async def endpoint_risk_score(endpoint_id: str, db: AsyncSession) -> dict:
    from app.models.endpoint import Endpoint
    from app.models.compliance import ComplianceStatus
    from app.models.system_settings import SystemSettings

    result = await db.execute(select(Endpoint).where(Endpoint.id == endpoint_id))
    endpoint = result.scalars().first()
    if not endpoint:
        return {"score": 0, "level": "low", "factors": []}

    cs_result = await db.execute(
        select(ComplianceStatus).where(ComplianceStatus.endpoint_id == endpoint_id)
    )
    cs = cs_result.scalars().first()

    cfg = (await db.execute(select(SystemSettings).where(SystemSettings.id == 1))).scalars().first()
    w_no_edr     = cfg.risk_weight_no_edr     if cfg else 30.0
    w_edr_ver    = cfg.risk_weight_edr_version if cfg else 20.0
    w_no_dlp     = cfg.risk_weight_no_dlp      if cfg else 25.0
    w_dlp_ver    = cfg.risk_weight_dlp_version if cfg else 15.0
    w_no_user    = cfg.risk_weight_no_user     if cfg else 10.0

    score = 0.0
    factors = []

    if not cs:
        score += 50
        factors.append("no_compliance_data")
        return {"score": min(score, 100), "level": risk_level(score), "factors": factors}

    if not cs.edr_installed:
        score += w_no_edr
        factors.append("no_edr")

    if not cs.edr_version_ok:
        score += w_edr_ver
        factors.append("edr_outdated")

    if not cs.dlp_installed:
        score += w_no_dlp
        factors.append("no_dlp")

    if not cs.dlp_version_ok:
        score += w_dlp_ver
        factors.append("dlp_outdated")

    if not endpoint.owner_user_id:
        score += w_no_user
        factors.append("no_user_assigned")

    score = min(score, 100)
    return {"score": score, "level": risk_level(score), "factors": factors}


async def update_all_risk_scores(db: AsyncSession) -> dict:
    from app.models.user import User
    from app.models.endpoint import Endpoint

    users_result = await db.execute(select(User.id))
    user_ids = [str(row[0]) for row in users_result.fetchall()]

    endpoints_result = await db.execute(select(Endpoint.id))
    endpoint_ids = [str(row[0]) for row in endpoints_result.fetchall()]

    for uid in user_ids:
        try:
            risk = await user_risk_score(uid, db)
            user_result = await db.execute(select(User).where(User.id == uid))
            user = user_result.scalar_one_or_none()
            if user:
                user.risk_score = risk["score"]
        except Exception as e:
            logger.error(f"Risk: Failed to score user {uid}: {e}")

    for eid in endpoint_ids:
        try:
            risk = await endpoint_risk_score(eid, db)
            ep_result = await db.execute(select(Endpoint).where(Endpoint.id == eid))
            endpoint = ep_result.scalar_one_or_none()
            if endpoint:
                endpoint.risk_score = risk["score"]
        except Exception as e:
            logger.error(f"Risk: Failed to score endpoint {eid}: {e}")

    logger.info(f"Risk: Updated {len(user_ids)} users and {len(endpoint_ids)} endpoints")
    return {"users_updated": len(user_ids), "endpoints_updated": len(endpoint_ids)}
