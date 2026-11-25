import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from uuid import UUID
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import exists, select

from app.services.posture_snapshot import PostureSnapshot, load_posture_snapshot

logger = logging.getLogger(__name__)


def risk_level(score: float) -> str:
    if score <= 25:
        return "low"
    elif score <= 50:
        return "medium"
    elif score <= 75:
        return "high"
    return "critical"


@dataclass
class _LoginStats:
    count: int = 0
    countries: set[str] = field(default_factory=set)
    travel: str | None = None
    previous_country: str | None = None
    previous_timestamp: datetime | None = None

    def observe(self, country, timestamp):
        self.count += 1
        if country:
            self.countries.add(country)
        if self.travel is None and self.previous_country and country and self.previous_country != country:
            delta = (timestamp - self.previous_timestamp).total_seconds() / 3600
            if delta < 6:
                self.travel = f"impossible_travel:{self.previous_country}->{country}"
        self.previous_country = country
        self.previous_timestamp = timestamp


def _score_user(user, login_stats: _LoginStats, non_compliant_device: bool) -> dict:
    """Identical scoring rules for individual API reads and the batched sync."""
    score = 0.0
    factors = []
    now = datetime.now(timezone.utc)
    if login_stats.travel:
        score += 30
        factors.append(login_stats.travel)
    if login_stats.count > 5 and len(login_stats.countries) > 3:
        score += 20
        factors.append(f"multiple_countries:{len(login_stats.countries)}")
    if non_compliant_device:
        score += 25
        factors.append("non_compliant_device")
    if not user.mfa_enabled:
        score += 15
        factors.append("no_mfa")
    if user.last_login:
        last_login = user.last_login
        if last_login.tzinfo is None:
            last_login = last_login.replace(tzinfo=timezone.utc)
        days_inactive = (now - last_login).days
        if days_inactive > 30:
            score += 10
            factors.append(f"inactive_{days_inactive}_days")
    score = min(score, 100)
    return {"score": score, "level": risk_level(score), "factors": factors}


async def user_risk_score(user_id: str, db: AsyncSession) -> dict:
    from app.models.user import User
    from app.models.activity import ActivityEvent
    from app.models.compliance import ComplianceExclusion, ComplianceStatus
    from app.models.endpoint import Endpoint

    user_id = UUID(user_id) if isinstance(user_id, str) else user_id
    user = (await db.execute(select(User).where(User.id == user_id))).scalar_one_or_none()
    if not user:
        return {"score": 0, "level": "low", "factors": []}
    login_stats = _LoginStats()
    for country, timestamp in (await db.execute(
        select(ActivityEvent.country, ActivityEvent.timestamp)
        .where(ActivityEvent.user_id == user_id, ActivityEvent.event_type == "login")
        .order_by(ActivityEvent.timestamp.asc())
    )).all():
        login_stats.observe(country, timestamp)
    non_compliant_device = bool(await db.scalar(
        select(Endpoint.id)
        .join(ComplianceStatus, ComplianceStatus.endpoint_id == Endpoint.id)
        .where(
            Endpoint.owner_user_id == user_id,
            ComplianceStatus.status == "non_compliant",
            ~exists().where(
                ComplianceExclusion.endpoint_id == Endpoint.id,
                ComplianceExclusion.agent_key == "*",
            ),
        ).limit(1)
    ))
    return _score_user(user, login_stats, non_compliant_device)


async def endpoint_risk_score(
    endpoint_id: str, db: AsyncSession, *, snapshot: PostureSnapshot | None = None,
) -> dict:
    from app.models.endpoint import Endpoint
    from app.models.compliance import ComplianceExclusion, ComplianceStatus
    from app.models.system_settings import SystemSettings
    from app.services.compliance_agents import load_required_compliance_agents

    endpoint_id = UUID(endpoint_id) if isinstance(endpoint_id, str) else endpoint_id
    if snapshot is not None:
        endpoint = snapshot.endpoints.get(endpoint_id)
    else:
        result = await db.execute(select(Endpoint).where(Endpoint.id == endpoint_id))
        endpoint = result.scalars().first()
    if not endpoint:
        return {"score": 0, "level": "low", "factors": []}

    if snapshot is not None:
        cs = snapshot.statuses.get(endpoint_id)
        cfg = snapshot.settings
        required_agents = snapshot.required_agents
        excluded_keys = snapshot.exclusions.get(endpoint_id, set())
    else:
        cs = (await db.execute(
            select(ComplianceStatus).where(ComplianceStatus.endpoint_id == endpoint_id)
        )).scalars().first()
        cfg = (await db.execute(select(SystemSettings).where(SystemSettings.id == 1))).scalars().first()
        required_agents = await load_required_compliance_agents(db)
        excluded_keys = set((await db.execute(
            select(ComplianceExclusion.agent_key).where(ComplianceExclusion.endpoint_id == endpoint.id)
        )).scalars().all())
    w_no_edr     = cfg.risk_weight_no_edr     if cfg else 30.0
    w_edr_ver    = cfg.risk_weight_edr_version if cfg else 20.0
    w_no_dlp     = cfg.risk_weight_no_dlp      if cfg else 25.0
    w_dlp_ver    = cfg.risk_weight_dlp_version if cfg else 15.0
    w_no_wss     = cfg.risk_weight_no_wss      if cfg else 15.0
    w_wss_ver    = cfg.risk_weight_wss_version if cfg else 10.0
    w_no_user    = cfg.risk_weight_no_user     if cfg else 10.0
    required_keys = {agent.key for agent in required_agents}

    score = 0.0
    factors = []

    if "*" in excluded_keys:
        if not endpoint.owner_user_id:
            score += w_no_user
            factors.append("no_user_assigned")
        return {"score": min(score, 100), "level": risk_level(score), "factors": factors}

    if not cs:
        score += 50
        factors.append("no_compliance_data")
        return {"score": min(score, 100), "level": risk_level(score), "factors": factors}

    if "sentinelone" in required_keys and "sentinelone" not in excluded_keys and not cs.edr_installed:
        score += w_no_edr
        factors.append("no_edr")

    elif "sentinelone" in required_keys and "sentinelone" not in excluded_keys and not cs.edr_version_ok:
        score += w_edr_ver
        factors.append("edr_outdated")

    if "symantec_dlp" in required_keys and "symantec_dlp" not in excluded_keys and not cs.dlp_installed:
        score += w_no_dlp
        factors.append("no_dlp")

    elif "symantec_dlp" in required_keys and "symantec_dlp" not in excluded_keys and not cs.dlp_version_ok:
        score += w_dlp_ver
        factors.append("dlp_outdated")

    if "symantec_wss" in required_keys and "symantec_wss" not in excluded_keys and not cs.wss_installed:
        score += w_no_wss
        factors.append("no_wss")
    elif "symantec_wss" in required_keys and "symantec_wss" not in excluded_keys and not cs.wss_version_ok:
        score += w_wss_ver
        factors.append("wss_outdated")

    for agent in required_agents:
        if agent.key in {"sentinelone", "symantec_dlp", "symantec_wss"}:
            continue
        if agent.key not in excluded_keys and not (cs.agent_presence or {}).get(agent.key, False):
            # Generic connected agents currently use the network-agent absence
            # weight; this keeps their coverage meaningful in risk without
            # inventing a hidden per-product setting.
            score += w_no_wss
            factors.append(f"missing_{agent.key}")

    if not endpoint.owner_user_id:
        score += w_no_user
        factors.append("no_user_assigned")

    score = min(score, 100)
    return {"score": score, "level": risk_level(score), "factors": factors}


async def update_all_risk_scores(db: AsyncSession) -> dict:
    from app.models.user import User
    from app.models.activity import ActivityEvent

    snapshot = await load_posture_snapshot(db)
    users = {user.id: user for user in (await db.execute(select(User))).scalars()}
    login_stats: dict[UUID, _LoginStats] = {}
    # Stream only the three needed columns; do not load all event ORM objects
    # or re-read each user's history in a separate round trip.
    events = await db.stream(
        select(ActivityEvent.user_id, ActivityEvent.country, ActivityEvent.timestamp)
        .where(ActivityEvent.event_type == "login", ActivityEvent.user_id.in_(select(User.id)))
        .order_by(ActivityEvent.user_id, ActivityEvent.timestamp)
        .execution_options(yield_per=1000)
    )
    try:
        async for user_id, country, timestamp in events:
            login_stats.setdefault(user_id, _LoginStats()).observe(country, timestamp)
    finally:
        await events.close()
    non_compliant_users = {
        endpoint.owner_user_id
        for endpoint_id, endpoint in snapshot.endpoints.items()
        if endpoint.owner_user_id
        and endpoint_id in snapshot.statuses
        and snapshot.statuses[endpoint_id].status == "non_compliant"
        and "*" not in snapshot.exclusions.get(endpoint_id, set())
    }
    for user_id, user in users.items():
        user.risk_score = _score_user(
            user, login_stats.get(user_id, _LoginStats()), user_id in non_compliant_users,
        )["score"]
    for endpoint_id, endpoint in snapshot.endpoints.items():
        endpoint.risk_score = (await endpoint_risk_score(endpoint_id, db, snapshot=snapshot))["score"]
    await db.flush()
    logger.info("Risk: Updated %d users and %d endpoints", len(users), len(snapshot.endpoints))
    return {"users_updated": len(users), "endpoints_updated": len(snapshot.endpoints)}
