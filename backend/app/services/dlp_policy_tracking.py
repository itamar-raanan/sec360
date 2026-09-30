from datetime import datetime, timezone
import re
from typing import Any

from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.change_event import EntityStateSnapshot
from app.services.change_tracking import record_change_event


MARKER_TYPE = "system"
MARKER_ID = "dlp-policy-pattern-tracking-v1"
SNAPSHOT_TYPE = "dlp_policy_pattern"

PATTERN_FIELDS = (
    "object_name",
    "object_description",
    "object_status",
    "rule_type",
    "user_patterns",
    "ip_addresses",
    "url_domains",
    "personal_email_breadth",
    "personal_email_excluded_domains",
    "personal_email_max_recipients",
)

AUDIT_FIELDS = (
    "modified_date",
    "modified_by_id",
    "modified_by_name",
)

LIST_FIELDS = {
    "user_patterns",
    "ip_addresses",
    "url_domains",
    "personal_email_excluded_domains",
}


def _pattern_key(row: dict[str, Any]) -> str | None:
    value = row.get("object_uuid") or row.get("object_id")
    return str(value) if value is not None else None


def _normalise_patterns(rows: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    """Collapse repeated policy-usage rows into one stable pattern document."""
    patterns: dict[str, dict[str, Any]] = {}
    policy_sets: dict[str, set[tuple[str, str, str, str]]] = {}
    for row in rows:
        key = _pattern_key(row)
        if not key:
            continue
        if key not in patterns:
            patterns[key] = {
                "object_id": row.get("object_id"),
                "object_uuid": row.get("object_uuid"),
                **{field: row.get(field) for field in (*PATTERN_FIELDS, *AUDIT_FIELDS)},
                "policies": [],
            }
            policy_sets[key] = set()
        if row.get("policy_id") is not None or row.get("policy_name"):
            policy_sets[key].add((
                str(row.get("policy_id") or ""),
                str(row.get("policy_name") or ""),
                str(row.get("used_as") or ""),
                str(row.get("policy_active_status") or ""),
            ))

    for key, values in policy_sets.items():
        patterns[key]["policies"] = [
            {
                "policy_id": policy_id,
                "policy_name": policy_name,
                "used_as": used_as,
                "active_status": active_status,
            }
            for policy_id, policy_name, used_as, active_status in sorted(values)
        ]
    return patterns


def _actor(state: dict[str, Any] | None) -> str | None:
    if not state:
        return None
    value = state.get("modified_by_name") or state.get("modified_by_id")
    return str(value) if value is not None else None


def _policy_names(state: dict[str, Any] | None) -> list[str]:
    if not state:
        return []
    return sorted({
        str(policy.get("policy_name"))
        for policy in state.get("policies", [])
        if policy.get("policy_name")
    })


def _split_values(value: Any) -> list[str]:
    if value is None:
        return []
    return sorted({
        item.strip()
        for item in re.split(r"[\r\n;,]+", str(value))
        if item.strip()
    })


def _policy_values(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return sorted({
        " · ".join(filter(None, (
            str(item.get("policy_name") or item.get("policy_id") or "Unknown policy"),
            str(item.get("used_as") or ""),
            f"status {item.get('active_status')}" if item.get("active_status") not in (None, "") else "",
        )))
        for item in value
        if isinstance(item, dict)
    })


def _exact_diff(old: dict[str, Any], new: dict[str, Any]) -> tuple[dict, dict, list[str]]:
    """Return only the values removed/added or the scalar fields truly changed."""
    before: dict[str, Any] = {}
    after: dict[str, Any] = {}
    changed_fields: list[str] = []
    for field in (*PATTERN_FIELDS, "policies"):
        previous = old.get(field)
        current = new.get(field)
        if previous == current:
            continue
        if field in LIST_FIELDS:
            previous_values = set(_split_values(previous))
            current_values = set(_split_values(current))
            removed = sorted(previous_values - current_values)
            added = sorted(current_values - previous_values)
            if not removed and not added:
                continue
            before[field] = removed
            after[field] = added
        elif field == "policies":
            previous_values = set(_policy_values(previous))
            current_values = set(_policy_values(current))
            removed = sorted(previous_values - current_values)
            added = sorted(current_values - previous_values)
            if not removed and not added:
                continue
            before[field] = removed
            after[field] = added
        else:
            before[field] = previous
            after[field] = current
        changed_fields.append(field)
    return before, after, changed_fields


async def capture_dlp_policy_changes(
    db: AsyncSession,
    rows: list[dict[str, Any]],
    *,
    complete: bool = True,
) -> int:
    """Snapshot Symantec DLP patterns and emit field-level changes after baseline."""
    now = datetime.now(timezone.utc)
    current = _normalise_patterns(rows)
    snapshots = (await db.execute(
        select(EntityStateSnapshot).where(or_(
            EntityStateSnapshot.entity_type == SNAPSHOT_TYPE,
            (EntityStateSnapshot.entity_type == MARKER_TYPE)
            & (EntityStateSnapshot.entity_id == MARKER_ID),
        ))
    )).scalars().all()
    marker = next((item for item in snapshots if item.entity_type == MARKER_TYPE), None)
    existing = {
        item.entity_id: item
        for item in snapshots
        if item.entity_type == SNAPSHOT_TYPE
    }
    emitted = 0

    for key, state in current.items():
        snapshot = existing.get(key)
        old = snapshot.state if snapshot else None
        if marker and old is None:
            await record_change_event(
                db,
                event_type="dlp.policy_pattern_added",
                entity_type="dlp_policy_pattern",
                entity_id=key,
                entity_name=state.get("object_name"),
                action="added",
                source="symantec_dlp",
                actor_email=_actor(state),
                before={"pattern_exists": False},
                after={"pattern_exists": True},
                details={
                    "changed_fields": ["pattern_exists"],
                    "policies": _policy_names(state),
                    "modified_by_id": state.get("modified_by_id"),
                    "modified_by_name": state.get("modified_by_name"),
                    "diff_only": True,
                },
            )
            emitted += 1
        elif marker and old != state:
            before, after, changed_fields = _exact_diff(old, state)
            # MODIFIED_DATE/editor changes are audit metadata, not a policy
            # content diff. Do not create noise when only those values move.
            if changed_fields:
                await record_change_event(
                    db,
                    event_type="dlp.policy_pattern_changed",
                    entity_type="dlp_policy_pattern",
                    entity_id=key,
                    entity_name=state.get("object_name") or old.get("object_name"),
                    action="changed",
                    source="symantec_dlp",
                    actor_email=_actor(state),
                    before=before,
                    after=after,
                    details={
                        "changed_fields": changed_fields,
                        "policies": _policy_names(state),
                        "modified_by_id": state.get("modified_by_id"),
                        "modified_by_name": state.get("modified_by_name"),
                        "modified_date": state.get("modified_date"),
                        "diff_only": True,
                    },
                )
                emitted += 1

        if snapshot:
            snapshot.state = state
            snapshot.updated_at = now
        else:
            db.add(EntityStateSnapshot(
                entity_type=SNAPSHOT_TYPE,
                entity_id=key,
                state=state,
                updated_at=now,
            ))

    if marker and complete:
        for key, snapshot in existing.items():
            if key in current:
                continue
            old = snapshot.state or {}
            await record_change_event(
                db,
                event_type="dlp.policy_pattern_removed",
                entity_type="dlp_policy_pattern",
                entity_id=key,
                entity_name=old.get("object_name"),
                action="removed",
                severity="warning",
                source="symantec_dlp",
                actor_email=_actor(old),
                before={"pattern_exists": True},
                after={"pattern_exists": False},
                details={
                    "changed_fields": ["pattern_exists"],
                    "policies": _policy_names(old),
                    "modified_by_id": old.get("modified_by_id"),
                    "modified_by_name": old.get("modified_by_name"),
                    "diff_only": True,
                },
            )
            await db.delete(snapshot)
            emitted += 1

    if not marker:
        db.add(EntityStateSnapshot(
            entity_type=MARKER_TYPE,
            entity_id=MARKER_ID,
            state={"initialized_at": now.isoformat()},
            updated_at=now,
        ))

    await db.flush()
    return emitted
