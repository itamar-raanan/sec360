"""Explainable endpoint identity quality and duplicate-candidate analysis."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from app.engines.correlation import normalize_hostname, normalize_serial, normalize_username
from app.models.endpoint import Endpoint
from app.services.endpoint_inventory import ENDPOINT_ACTIVITY_WINDOW_DAYS


def _aware(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value


def endpoint_sources(endpoint: Endpoint) -> list[str]:
    labels = {
        "jumpcloud": "JumpCloud",
        "sentinelone": "SentinelOne",
        "symantec": "Symantec DLP",
        "symantec_wss": "Symantec WSS",
    }
    sources = {endpoint.source} if endpoint.source else set()
    sources.update(agent.product_name for agent in endpoint.agents)
    return sorted(labels.get(source, source.replace("_", " ").title()) for source in sources if source)


def freshest_observation(endpoint: Endpoint) -> datetime | None:
    values = [_aware(endpoint.last_seen)]
    values.extend(_aware(agent.last_seen) for agent in endpoint.agents)
    present = [value for value in values if value is not None]
    return max(present) if present else None


def is_current(endpoint: Endpoint, *, now: datetime | None = None) -> bool:
    reference = now or datetime.now(timezone.utc)
    freshest = freshest_observation(endpoint)
    return bool(
        endpoint.is_active
        and endpoint.lifecycle_state == "active"
        and freshest
        and freshest >= reference - timedelta(days=ENDPOINT_ACTIVITY_WINDOW_DAYS)
    )


def confidence_for(endpoint: Endpoint, *, now: datetime | None = None) -> dict[str, Any]:
    """Score identity quality from observable evidence, never hidden heuristics."""
    reference = now or datetime.now(timezone.utc)
    sources = endpoint_sources(endpoint)
    freshest = freshest_observation(endpoint)
    score = 20
    signals: list[str] = []

    serial = normalize_serial(endpoint.serial_number)
    if serial:
        score += 35
        signals.append("Validated hardware serial")

    owner = endpoint.owner
    owner_prefix = owner.email.split("@", 1)[0].lower() if owner and owner.email else ""
    username = normalize_username(endpoint.username or "")
    hostname = normalize_hostname(endpoint.hostname)
    if owner:
        score += 10
        signals.append("Directory owner assigned")
        if username and username == owner_prefix:
            score += 10
            signals.append("Endpoint username matches owner identity")
        elif owner_prefix and hostname.startswith(owner_prefix):
            score += 5
            signals.append("Hostname aligns with owner identity")

    if len(sources) >= 2:
        score += 15
        signals.append(f"Observed by {len(sources)} security sources")
    elif sources:
        signals.append("Observed by one security source")

    if freshest:
        age = reference - freshest
        if age <= timedelta(days=7):
            score += 10
            signals.append("Observed within 7 days")
        elif age <= timedelta(days=ENDPOINT_ACTIVITY_WINDOW_DAYS):
            score += 5
            signals.append(f"Observed within {ENDPOINT_ACTIVITY_WINDOW_DAYS} days")
        else:
            signals.append(f"No observation within {ENDPOINT_ACTIVITY_WINDOW_DAYS} days")
    else:
        signals.append("No source observation timestamp")

    score = min(score, 100)
    tier = "high" if score >= 80 else "medium" if score >= 55 else "low"

    if serial and len(sources) >= 2:
        method = "hardware_serial"
        explanation = "Cross-product identity anchored by a validated hardware serial."
    elif owner and username and username == owner_prefix:
        method = "directory_identity"
        explanation = "Endpoint username maps exactly to its directory owner."
    elif len(sources) >= 2:
        method = "normalized_hostname"
        explanation = "Multiple product records converge on the canonical hostname."
    else:
        method = "source_native"
        explanation = "Identity currently relies on a single source record."

    issues: list[str] = []
    if not serial:
        issues.append("missing_serial")
    if not owner:
        issues.append("unassigned")
    if tier == "low":
        issues.append("low_confidence")
    if not is_current(endpoint, now=reference):
        issues.append("not_in_compliance")

    return {
        "score": score,
        "tier": tier,
        "method": method,
        "explanation": explanation,
        "signals": signals,
        "issues": issues,
        "sources": sources,
        "freshest_observation": freshest,
    }


def duplicate_candidates(endpoints: list[Endpoint]) -> list[dict[str, Any]]:
    """Return review candidates only; this function never merges records."""
    active = [ep for ep in endpoints if ep.lifecycle_state not in {"ignored", "decommissioned"}]
    serial_buckets: dict[str, list[Endpoint]] = {}
    hostname_buckets: dict[str, list[Endpoint]] = {}
    for endpoint in active:
        serial = normalize_serial(endpoint.serial_number)
        hostname = normalize_hostname(endpoint.hostname)
        if serial:
            serial_buckets.setdefault(serial, []).append(endpoint)
        if hostname:
            hostname_buckets.setdefault(hostname, []).append(endpoint)

    pairs: dict[tuple[str, str], dict[str, Any]] = {}

    def add_pair(left: Endpoint, right: Endpoint, reason: str, score: int) -> None:
        ordered = sorted((left, right), key=lambda item: str(item.id))
        key = (str(ordered[0].id), str(ordered[1].id))
        existing = pairs.get(key)
        if existing:
            existing["reasons"].append(reason)
            existing["score"] = max(existing["score"], score)
            return
        pairs[key] = {
            "candidate_id": f"{key[0]}:{key[1]}",
            "score": score,
            "reasons": [reason],
            "left": ordered[0],
            "right": ordered[1],
        }

    for serial, members in serial_buckets.items():
        if len(members) > 1:
            for index, left in enumerate(members):
                for right in members[index + 1:]:
                    add_pair(left, right, f"Same hardware serial: {serial}", 99)

    for hostname, members in hostname_buckets.items():
        if len(members) > 1:
            for index, left in enumerate(members):
                for right in members[index + 1:]:
                    add_pair(left, right, f"Same normalized hostname: {hostname}", 84)

    return sorted(pairs.values(), key=lambda item: (-item["score"], item["candidate_id"]))
