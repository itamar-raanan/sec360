def current_endpoint_clause():
    """SQL predicate for every endpoint still available in inventory.

    Last-seen time is intentionally not considered: old devices must remain
    visible so analysts can identify and clean them up in source systems.
    """
    from app.models.endpoint import Endpoint

    return Endpoint.is_active.is_(True) & (Endpoint.lifecycle_state == "active")


def restore_endpoint_from_inventory(endpoint, source: str) -> bool:
    """Restore an automatically stale endpoint when a live source reports it.

    A canonical JumpCloud endpoint can disappear from JumpCloud while still
    being authoritatively present in SentinelOne or DLP. Product evidence must
    therefore restore the shared endpoint to the current inventory. Explicit
    analyst lifecycle choices remain untouched.
    """
    if endpoint.lifecycle_state in {"ignored", "decommissioned"}:
        return False
    if endpoint.is_active and endpoint.lifecycle_state == "active":
        return False

    endpoint.is_active = True
    endpoint.lifecycle_state = "active"
    endpoint.lifecycle_reason = None
    endpoint.lifecycle_changed_at = None
    endpoint.lifecycle_changed_by = None
    return True


async def retire_orphaned_source_endpoints(db, source: str, endpoint_ids: set) -> int:
    """Retire source-owned endpoints after their final inventory evidence is removed.

    Endpoints owned by another canonical source remain available. Analyst-set
    lifecycle states are never overwritten, and Puppet or another security
    product keeps the endpoint in inventory.
    """
    if not endpoint_ids:
        return 0

    from datetime import datetime, timezone

    from sqlalchemy import exists, select

    from app.models.agent import SecurityAgent
    from app.models.endpoint import Endpoint
    from app.models.puppet import PuppetNode

    candidates = list((await db.execute(
        select(Endpoint).where(
            Endpoint.id.in_(endpoint_ids),
            Endpoint.source == source,
            Endpoint.lifecycle_state.in_(("active", "stale")),
        )
    )).scalars())
    retired = 0
    for endpoint in candidates:
        has_agent = await db.scalar(select(exists().where(
            SecurityAgent.endpoint_id == endpoint.id,
        )))
        has_puppet = await db.scalar(select(exists().where(
            PuppetNode.endpoint_id == endpoint.id,
        )))
        if has_agent or has_puppet:
            continue
        endpoint.is_active = False
        endpoint.lifecycle_state = "stale"
        endpoint.lifecycle_reason = f"Removed from {source} inventory"
        endpoint.lifecycle_changed_at = datetime.now(timezone.utc)
        endpoint.lifecycle_changed_by = "system"
        retired += 1

    if retired:
        await db.flush()
    return retired
