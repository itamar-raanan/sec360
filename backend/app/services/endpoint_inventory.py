from datetime import datetime, timedelta, timezone

from sqlalchemy import exists, or_


ENDPOINT_ACTIVITY_WINDOW_DAYS = 60


def current_endpoint_clause(*, now: datetime | None = None):
    """SQL predicate for endpoints that belong in current inventory metrics.

    An endpoint must still exist in its authoritative inventory and must have
    been observed either directly or by one of its product agents recently.
    """
    from app.models.agent import SecurityAgent
    from app.models.endpoint import Endpoint

    reference_time = now or datetime.now(timezone.utc)
    cutoff = reference_time - timedelta(days=ENDPOINT_ACTIVITY_WINDOW_DAYS)
    recent_agent = exists().where(
        SecurityAgent.endpoint_id == Endpoint.id,
        SecurityAgent.last_seen >= cutoff,
    )
    return (
        Endpoint.is_active.is_(True)
        & or_(Endpoint.last_seen >= cutoff, recent_agent)
    )
