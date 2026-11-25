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


def inventory_evidence_clause():
    """A retained security agent or Puppet node keeps a machine in inventory.

    Connectivity is deliberately not a presence check: an offline S1/DLP
    agent still exists in its authoritative product inventory.
    """
    from sqlalchemy import exists

    from app.models.agent import SecurityAgent
    from app.models.endpoint import Endpoint
    from app.models.puppet import PuppetNode

    return exists().where(SecurityAgent.endpoint_id == Endpoint.id) | exists().where(
        PuppetNode.endpoint_id == Endpoint.id
    )


async def reconcile_source_backed_endpoints(db) -> int:
    """Repair legacy hidden inventory before evaluating compliance.

    This also handles partial collection cycles where another source has
    hidden a machine and the security product cannot be collected this cycle.
    Explicit ignored/decommissioned records must stay outside inventory.
    """
    from sqlalchemy import select

    from app.models.endpoint import Endpoint

    await db.flush()
    endpoints = (await db.execute(
        select(Endpoint).where(
            Endpoint.lifecycle_state.in_(("active", "stale")),
            ~current_endpoint_clause(),
            inventory_evidence_clause(),
        )
    )).scalars().all()
    for endpoint in endpoints:
        restore_endpoint_from_inventory(endpoint, "retained_product_inventory")
    if endpoints:
        await db.flush()
    return len(endpoints)


async def retire_orphaned_source_endpoints(db, source: str, endpoint_ids: set) -> int:
    """Retire source-owned endpoints after their final inventory evidence is removed.

    Endpoints owned by another canonical source remain available. Analyst-set
    lifecycle states are never overwritten, and Puppet or another security
    product keeps the endpoint in inventory.
    """
    if not endpoint_ids:
        return 0

    from datetime import datetime, timezone

    from sqlalchemy import select

    from app.models.endpoint import Endpoint

    candidates = list((await db.execute(
        select(Endpoint).where(
            Endpoint.id.in_(endpoint_ids),
            Endpoint.source == source,
            Endpoint.lifecycle_state.in_(("active", "stale")),
            ~inventory_evidence_clause(),
        )
    )).scalars())
    retired = 0
    for endpoint in candidates:
        endpoint.is_active = False
        endpoint.lifecycle_state = "stale"
        endpoint.lifecycle_reason = f"Removed from {source} inventory"
        endpoint.lifecycle_changed_at = datetime.now(timezone.utc)
        endpoint.lifecycle_changed_by = "system"
        retired += 1

    if retired:
        await db.flush()
    return retired
