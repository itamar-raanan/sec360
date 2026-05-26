import logging
from datetime import datetime, timezone, timedelta
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

logger = logging.getLogger(__name__)

# Rough km/h threshold: if two logins from different countries within N hours
IMPOSSIBLE_TRAVEL_HOURS = 6


async def detect_impossible_travel(user_id: str, db: AsyncSession) -> list[dict]:
    from app.models.activity import ActivityEvent

    result = await db.execute(
        select(ActivityEvent)
        .where(
            ActivityEvent.user_id == user_id,
            ActivityEvent.event_type == "login",
            ActivityEvent.country.isnot(None),
        )
        .order_by(ActivityEvent.timestamp.asc())
    )
    events = result.scalars().all()

    detections = []
    for i in range(1, len(events)):
        prev = events[i - 1]
        curr = events[i]
        if prev.country and curr.country and prev.country != curr.country:
            delta_hours = (curr.timestamp - prev.timestamp).total_seconds() / 3600
            if 0 < delta_hours < IMPOSSIBLE_TRAVEL_HOURS:
                detections.append({
                    "type": "impossible_travel",
                    "from_country": prev.country,
                    "to_country": curr.country,
                    "time_diff_hours": round(delta_hours, 2),
                    "event_1_id": str(prev.id),
                    "event_2_id": str(curr.id),
                    "timestamp": curr.timestamp.isoformat(),
                })
    return detections


async def detect_new_country(user_id: str, db: AsyncSession, lookback_days: int = 90) -> list[dict]:
    from app.models.activity import ActivityEvent

    since = datetime.now(timezone.utc) - timedelta(days=lookback_days)

    # Historical countries (before lookback window)
    historical_result = await db.execute(
        select(ActivityEvent.country)
        .where(
            ActivityEvent.user_id == user_id,
            ActivityEvent.event_type == "login",
            ActivityEvent.timestamp < since,
            ActivityEvent.country.isnot(None),
        )
    )
    historical_countries = {row[0] for row in historical_result.fetchall()}

    # Recent countries
    recent_result = await db.execute(
        select(ActivityEvent)
        .where(
            ActivityEvent.user_id == user_id,
            ActivityEvent.event_type == "login",
            ActivityEvent.timestamp >= since,
            ActivityEvent.country.isnot(None),
        )
        .order_by(ActivityEvent.timestamp.desc())
    )
    recent_events = recent_result.scalars().all()

    detections = []
    seen_new = set()
    for event in recent_events:
        if event.country and event.country not in historical_countries and event.country not in seen_new:
            seen_new.add(event.country)
            detections.append({
                "type": "new_country",
                "country": event.country,
                "event_id": str(event.id),
                "timestamp": event.timestamp.isoformat(),
            })

    return detections


async def detect_shadow_it(user_id: str, db: AsyncSession) -> list[dict]:
    from app.models.activity import ActivityEvent
    from app.models.application import Application

    result = await db.execute(
        select(ActivityEvent)
        .where(
            ActivityEvent.user_id == user_id,
            ActivityEvent.event_type == "app_usage",
        )
    )
    events = result.scalars().all()

    app_names_result = await db.execute(
        select(Application.name).where(Application.is_approved == True)  # noqa: E712
    )
    approved_apps = {row[0].lower() for row in app_names_result.fetchall()}

    shadow_it = []
    seen_apps = set()
    for event in events:
        app_name = (event.details or {}).get("app", "")
        if app_name and app_name.lower() not in approved_apps and app_name not in seen_apps:
            seen_apps.add(app_name)
            shadow_it.append({
                "type": "shadow_it",
                "app": app_name,
                "event_id": str(event.id),
                "timestamp": event.timestamp.isoformat(),
            })

    return shadow_it


async def build_user_timeline(user_id: str, db: AsyncSession, days: int = 7) -> list[dict]:
    from app.models.activity import ActivityEvent

    since = datetime.now(timezone.utc) - timedelta(days=days)

    result = await db.execute(
        select(ActivityEvent)
        .where(
            ActivityEvent.user_id == user_id,
            ActivityEvent.timestamp >= since,
        )
        .order_by(ActivityEvent.timestamp.desc())
    )
    events = result.scalars().all()

    timeline = []
    for event in events:
        timeline.append({
            "id": str(event.id),
            "type": event.event_type,
            "timestamp": event.timestamp.isoformat(),
            "location": event.location,
            "country": event.country,
            "ip_address": event.ip_address,
            "is_suspicious": event.is_suspicious,
            "details": event.details,
        })

    return timeline
