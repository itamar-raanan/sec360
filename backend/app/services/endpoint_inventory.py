def current_endpoint_clause():
    """SQL predicate for every endpoint still available in inventory.

    Last-seen time is intentionally not considered: old devices must remain
    visible so analysts can identify and clean them up in source systems.
    """
    from app.models.endpoint import Endpoint

    return Endpoint.is_active.is_(True) & (Endpoint.lifecycle_state == "active")
