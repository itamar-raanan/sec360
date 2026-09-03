"""
Compliance-focused batch anomaly detection engine.

Return-dict schema for every detector:

    {
        "insight_type": str,
        "severity":     str,   # info | warning | high | critical
        "title":        str,   # ≤ 80 chars
        "user_id":      str | None,   # None for batch insights
        "evidence":     dict,
        "event_ids":    list[str],
    }

Batch compliance detectors emit ONE insight per issue type; user_id is None.
Evidence contains {"count": N, "affected": [{id, name, email, ...}, ...]}.

Behavioral detectors (per-user) emit one insight per affected user/event.

run_all_detections() runs compliance detectors first, then behavioral ones,
deduplicates, and returns the list sorted critical-first.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone, timedelta
from collections import defaultdict
from typing import Any

from sqlalchemy import select, func, and_, or_, text
from sqlalchemy.ext.asyncio import AsyncSession

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_SEVERITY_RANK = {"critical": 4, "high": 3, "warning": 2, "info": 1}

_EDR_PRODUCTS = {"sentinelone", "symantec edr", "symantec endpoint protection"}


def _higher_severity(a: str, b: str) -> str:
    return a if _SEVERITY_RANK.get(a, 0) >= _SEVERITY_RANK.get(b, 0) else b


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


# ---------------------------------------------------------------------------
# Compliance detector 1: Users without MFA
# ---------------------------------------------------------------------------


async def detect_users_no_mfa(db: AsyncSession) -> list[dict]:
    """
    Active users (not suspended, employment_status='active') who have
    mfa_enabled=False and have logged in within the last 30 days.
    Batch insight: one entry, user_id=None.
    """
    from app.models.user import User

    cutoff = _now_utc() - timedelta(days=30)

    result = await db.execute(
        select(
            User.id,
            User.full_name,
            User.email,
            User.last_login,
            User.department,
        )
        .where(
            and_(
                User.mfa_enabled == False,  # noqa: E712
                User.suspended == False,    # noqa: E712
                User.employment_status == "active",
                User.last_login.isnot(None),
                User.last_login > cutoff,
            )
        )
        .order_by(User.last_login.desc())
    )
    rows = result.fetchall()

    if not rows:
        return []

    affected = [
        {
            "id": str(r.id),
            "name": r.full_name,
            "email": r.email,
            "last_login": r.last_login.isoformat() if r.last_login else None,
            "department": r.department,
        }
        for r in rows
    ]
    n = len(affected)
    return [
        {
            "insight_type": "users_no_mfa",
            "severity": "high",
            "title": f"{n} active users without MFA"[:80],
            "user_id": None,
            "evidence": {"count": n, "affected": affected},
            "event_ids": [],
        }
    ]


# ---------------------------------------------------------------------------
# Compliance detector 2: Stale accounts
# ---------------------------------------------------------------------------


async def detect_stale_accounts(db: AsyncSession) -> list[dict]:
    """
    Active, non-suspended users whose last_login is NULL or older than 60 days.
    Batch insight sorted by last_login ASC (longest stale first). Capped at 30.
    """
    from app.models.user import User

    cutoff = _now_utc() - timedelta(days=60)

    result = await db.execute(
        select(
            User.id,
            User.full_name,
            User.email,
            User.last_login,
            User.department,
        )
        .where(
            and_(
                User.suspended == False,  # noqa: E712
                User.employment_status == "active",
                or_(
                    User.last_login.is_(None),
                    User.last_login < cutoff,
                ),
            )
        )
        .order_by(User.last_login.asc().nullsfirst())
    )
    rows = result.fetchall()

    if not rows:
        return []

    n = len(rows)
    affected = [
        {
            "id": str(r.id),
            "name": r.full_name,
            "email": r.email,
            "last_login": r.last_login.isoformat() if r.last_login else None,
            "department": r.department,
        }
        for r in rows[:30]
    ]
    return [
        {
            "insight_type": "stale_accounts",
            "severity": "warning",
            "title": f"{n} active accounts with no recent login"[:80],
            "user_id": None,
            "evidence": {"count": n, "affected": affected},
            "event_ids": [],
        }
    ]


# ---------------------------------------------------------------------------
# Compliance detector 3: Endpoints missing EDR
# ---------------------------------------------------------------------------


async def detect_endpoints_missing_edr(db: AsyncSession) -> list[dict]:
    """
    Endpoints joined with compliance_statuses where edr_installed=False.
    """
    from app.models.endpoint import Endpoint
    from app.models.compliance import ComplianceStatus
    from app.models.user import User

    result = await db.execute(
        select(
            Endpoint.id,
            Endpoint.hostname,
            Endpoint.last_seen,
            User.full_name.label("owner_name"),
        )
        .join(ComplianceStatus, ComplianceStatus.endpoint_id == Endpoint.id)
        .outerjoin(User, User.id == Endpoint.owner_user_id)
        .where(ComplianceStatus.edr_installed == False)  # noqa: E712
        .order_by(Endpoint.last_seen.desc().nullslast())
    )
    rows = result.fetchall()

    if not rows:
        return []

    n = len(rows)
    affected = [
        {
            "id": str(r.id),
            "hostname": r.hostname,
            "owner_name": r.owner_name,
            "last_seen": r.last_seen.isoformat() if r.last_seen else None,
        }
        for r in rows
    ]
    return [
        {
            "insight_type": "endpoints_missing_edr",
            "severity": "high",
            "title": f"{n} endpoints without EDR protection"[:80],
            "user_id": None,
            "evidence": {"count": n, "affected": affected},
            "event_ids": [],
        }
    ]


# ---------------------------------------------------------------------------
# Compliance detector 4: Endpoints missing disk encryption
# ---------------------------------------------------------------------------


async def detect_endpoints_missing_encryption(db: AsyncSession) -> list[dict]:
    """
    Endpoints where disk_encrypted=False or disk_encrypted IS NULL.
    """
    from app.models.endpoint import Endpoint
    from app.models.compliance import ComplianceStatus

    result = await db.execute(
        select(
            Endpoint.id,
            Endpoint.hostname,
            Endpoint.last_seen,
            ComplianceStatus.disk_encrypted,
        )
        .join(ComplianceStatus, ComplianceStatus.endpoint_id == Endpoint.id)
        .where(
            or_(
                ComplianceStatus.disk_encrypted == False,  # noqa: E712
                ComplianceStatus.disk_encrypted.is_(None),
            )
        )
        .order_by(Endpoint.last_seen.desc().nullslast())
    )
    rows = result.fetchall()

    if not rows:
        return []

    n = len(rows)
    affected = [
        {
            "id": str(r.id),
            "hostname": r.hostname,
            "last_seen": r.last_seen.isoformat() if r.last_seen else None,
            "disk_encrypted": r.disk_encrypted,
        }
        for r in rows
    ]
    return [
        {
            "insight_type": "endpoints_missing_encryption",
            "severity": "high",
            "title": f"{n} endpoints without disk encryption"[:80],
            "user_id": None,
            "evidence": {"count": n, "affected": affected},
            "event_ids": [],
        }
    ]


# ---------------------------------------------------------------------------
# Compliance detector 5: Endpoints missing DLP
# ---------------------------------------------------------------------------


async def detect_endpoints_missing_dlp(db: AsyncSession) -> list[dict]:
    """
    Endpoints where dlp_installed=False.
    """
    from app.models.endpoint import Endpoint
    from app.models.compliance import ComplianceStatus

    result = await db.execute(
        select(Endpoint.id, Endpoint.hostname, Endpoint.last_seen)
        .join(ComplianceStatus, ComplianceStatus.endpoint_id == Endpoint.id)
        .where(ComplianceStatus.dlp_installed == False)  # noqa: E712
        .order_by(Endpoint.last_seen.desc().nullslast())
    )
    rows = result.fetchall()

    if not rows:
        return []

    n = len(rows)
    affected = [
        {
            "id": str(r.id),
            "hostname": r.hostname,
            "last_seen": r.last_seen.isoformat() if r.last_seen else None,
        }
        for r in rows
    ]
    return [
        {
            "insight_type": "endpoints_missing_dlp",
            "severity": "warning",
            "title": f"{n} endpoints without DLP agent"[:80],
            "user_id": None,
            "evidence": {"count": n, "affected": affected},
            "event_ids": [],
        }
    ]


# ---------------------------------------------------------------------------
# Compliance detector 6: Inactive security agents (by product)
# ---------------------------------------------------------------------------


async def detect_inactive_agents(db: AsyncSession) -> list[dict]:
    """
    security_agents where status='inactive'. Grouped by product_name.
    One batch insight per product. EDR products → high; others → warning.
    """
    from app.models.agent import SecurityAgent
    from app.models.endpoint import Endpoint

    result = await db.execute(
        select(
            SecurityAgent.endpoint_id,
            SecurityAgent.product_name,
            SecurityAgent.status,
            SecurityAgent.version,
            SecurityAgent.last_seen,
            Endpoint.hostname,
        )
        .outerjoin(Endpoint, Endpoint.id == SecurityAgent.endpoint_id)
        .where(SecurityAgent.status == "inactive")
        .order_by(SecurityAgent.product_name, SecurityAgent.last_seen.desc().nullslast())
    )
    rows = result.fetchall()

    if not rows:
        return []

    # Group by product_name
    by_product: dict[str, list[dict]] = defaultdict(list)
    for r in rows:
        by_product[r.product_name or "Unknown"].append(
            {
                "endpoint_id": str(r.endpoint_id),
                "hostname": r.hostname,
                "last_seen": r.last_seen.isoformat() if r.last_seen else None,
                "version": r.version,
            }
        )

    detections: list[dict] = []
    for product, agents in by_product.items():
        n = len(agents)
        is_edr = product.lower() in _EDR_PRODUCTS
        severity = "high" if is_edr else "warning"
        detections.append(
            {
                "insight_type": "inactive_agents",
                "severity": severity,
                "title": f"{n} {product} agents offline"[:80],
                "user_id": None,
                "evidence": {"count": n, "product": product, "affected": agents},
                "event_ids": [],
            }
        )
    return detections


# ---------------------------------------------------------------------------
# Compliance detector 8: Non-compliant endpoints (status='non_compliant')
# ---------------------------------------------------------------------------


async def detect_non_compliant_endpoints(db: AsyncSession) -> list[dict]:
    """
    Endpoints with compliance status='non_compliant'. Includes what's missing.
    """
    from app.models.endpoint import Endpoint
    from app.models.compliance import ComplianceStatus

    result = await db.execute(
        select(
            Endpoint.id,
            Endpoint.hostname,
            Endpoint.last_seen,
            ComplianceStatus.edr_installed,
            ComplianceStatus.dlp_installed,
            ComplianceStatus.wss_installed,
            ComplianceStatus.disk_encrypted,
            ComplianceStatus.device_control_enabled,
            ComplianceStatus.last_evaluated,
        )
        .join(ComplianceStatus, ComplianceStatus.endpoint_id == Endpoint.id)
        .where(ComplianceStatus.status == "non_compliant")
        .order_by(Endpoint.hostname)
    )
    rows = result.fetchall()

    if not rows:
        return []

    _bool_field_label = {
        "edr_installed": "EDR",
        "dlp_installed": "DLP",
        "wss_installed": "WSS",
        "disk_encrypted": "Disk Encryption",
        "device_control_enabled": "Device Control",
    }

    n = len(rows)
    affected = []
    for r in rows:
        missing = [
            label
            for field, label in _bool_field_label.items()
            if not getattr(r, field, True)
        ]
        affected.append(
            {
                "id": str(r.id),
                "hostname": r.hostname,
                "last_seen": r.last_seen.isoformat() if r.last_seen else None,
                "missing_controls": missing,
                "last_evaluated": r.last_evaluated.isoformat() if r.last_evaluated else None,
            }
        )
    return [
        {
            "insight_type": "non_compliant_endpoints",
            "severity": "high",
            "title": f"{n} endpoints fully non-compliant"[:80],
            "user_id": None,
            "evidence": {"count": n, "affected": affected},
            "event_ids": [],
        }
    ]


# ---------------------------------------------------------------------------
# Compliance detector 9: Partial compliance endpoints
# ---------------------------------------------------------------------------


async def detect_partial_compliance_endpoints(db: AsyncSession) -> list[dict]:
    """
    Endpoints with compliance status='partial'. Only emits if count > 10.
    """
    from app.models.endpoint import Endpoint
    from app.models.compliance import ComplianceStatus

    result = await db.execute(
        select(
            Endpoint.id,
            Endpoint.hostname,
            Endpoint.last_seen,
            ComplianceStatus.edr_installed,
            ComplianceStatus.dlp_installed,
            ComplianceStatus.wss_installed,
            ComplianceStatus.disk_encrypted,
            ComplianceStatus.device_control_enabled,
            ComplianceStatus.last_evaluated,
        )
        .join(ComplianceStatus, ComplianceStatus.endpoint_id == Endpoint.id)
        .where(ComplianceStatus.status == "partial")
        .order_by(Endpoint.hostname)
    )
    rows = result.fetchall()

    n = len(rows)
    if n <= 10:
        return []

    _bool_field_label = {
        "edr_installed": "EDR",
        "dlp_installed": "DLP",
        "wss_installed": "WSS",
        "disk_encrypted": "Disk Encryption",
        "device_control_enabled": "Device Control",
    }

    affected = []
    for r in rows:
        missing = [
            label
            for field, label in _bool_field_label.items()
            if not getattr(r, field, True)
        ]
        affected.append(
            {
                "id": str(r.id),
                "hostname": r.hostname,
                "last_seen": r.last_seen.isoformat() if r.last_seen else None,
                "missing_controls": missing,
                "last_evaluated": r.last_evaluated.isoformat() if r.last_evaluated else None,
            }
        )
    return [
        {
            "insight_type": "partial_compliance_endpoints",
            "severity": "warning",
            "title": f"{n} endpoints with partial compliance gaps"[:80],
            "user_id": None,
            "evidence": {"count": n, "affected": affected},
            "event_ids": [],
        }
    ]


# ---------------------------------------------------------------------------
# Compliance detector 10: Unmanaged device access
# ---------------------------------------------------------------------------


async def detect_unmanaged_device_access(db: AsyncSession) -> list[dict]:
    """
    Users with activity_events in last 7 days but NO endpoint with
    owner_user_id = their id. Suggests access from unmanaged devices.
    """
    from app.models.activity import ActivityEvent
    from app.models.endpoint import Endpoint
    from app.models.user import User

    since = _now_utc() - timedelta(days=7)

    # Users who had activity in the last 7 days
    activity_result = await db.execute(
        select(
            ActivityEvent.user_id,
            func.count(ActivityEvent.id).label("event_count"),
            func.max(ActivityEvent.timestamp).label("last_seen"),
        )
        .where(
            and_(
                ActivityEvent.timestamp >= since,
                ActivityEvent.user_id.isnot(None),
            )
        )
        .group_by(ActivityEvent.user_id)
    )
    active_users = activity_result.fetchall()

    if not active_users:
        return []

    active_user_ids = [r.user_id for r in active_users]

    # Users who DO have a managed endpoint
    managed_result = await db.execute(
        select(Endpoint.owner_user_id)
        .where(Endpoint.owner_user_id.in_(active_user_ids))
        .distinct()
    )
    managed_ids = {str(r.owner_user_id) for r in managed_result.fetchall()}

    # Unmanaged = active but no endpoint
    unmanaged = [r for r in active_users if str(r.user_id) not in managed_ids]

    if not unmanaged:
        return []

    # Fetch names/emails
    user_ids_unmanaged = [r.user_id for r in unmanaged]
    user_result = await db.execute(
        select(User.id, User.full_name, User.email)
        .where(User.id.in_(user_ids_unmanaged))
    )
    user_info = {str(r.id): {"name": r.full_name, "email": r.email} for r in user_result.fetchall()}

    n = len(unmanaged)
    affected = [
        {
            "user_id": str(r.user_id),
            "name": user_info.get(str(r.user_id), {}).get("name"),
            "email": user_info.get(str(r.user_id), {}).get("email"),
            "event_count": r.event_count,
            "last_seen": r.last_seen.isoformat() if r.last_seen else None,
        }
        for r in unmanaged
    ]
    return [
        {
            "insight_type": "unmanaged_device_access",
            "severity": "high",
            "title": f"{n} users accessing systems from unmanaged devices"[:80],
            "user_id": None,
            "evidence": {"count": n, "affected": affected},
            "event_ids": [],
        }
    ]


# ---------------------------------------------------------------------------
# Behavioral detector 11: Suspended user active (per-user)
# ---------------------------------------------------------------------------


async def detect_suspended_user_active(
    db: AsyncSession, hours_back: int = 24
) -> list[dict]:
    """
    Detect any activity from users whose account is suspended=True.
    One insight per user found.
    """
    from app.models.activity import ActivityEvent
    from app.models.user import User

    since = _now_utc() - timedelta(hours=hours_back)

    result = await db.execute(
        select(
            ActivityEvent.id,
            ActivityEvent.user_id,
            ActivityEvent.event_type,
            ActivityEvent.timestamp,
            ActivityEvent.country,
            ActivityEvent.ip_address,
            User.full_name,
            User.email,
        )
        .join(User, ActivityEvent.user_id == User.id)
        .where(
            and_(
                User.suspended == True,  # noqa: E712
                ActivityEvent.timestamp >= since,
            )
        )
        .order_by(ActivityEvent.user_id, ActivityEvent.timestamp.desc())
    )
    rows = result.fetchall()

    by_user: dict[str, dict] = {}
    for row in rows:
        uid = str(row.user_id)
        if uid not in by_user:
            by_user[uid] = {
                "name": row.full_name,
                "email": row.email,
                "event_ids": [],
                "event_types": [],
                "last_seen": row.timestamp.isoformat(),
                "country": row.country,
                "ip_address": row.ip_address,
            }
        by_user[uid]["event_ids"].append(str(row.id))
        if row.event_type not in by_user[uid]["event_types"]:
            by_user[uid]["event_types"].append(row.event_type)

    detections: list[dict] = []
    for user_id, info in by_user.items():
        name = info["name"] or info["email"]
        detections.append(
            {
                "insight_type": "suspended_user_active",
                "severity": "critical",
                "title": f"Suspended user active: {name}"[:80],
                "user_id": user_id,
                "evidence": {
                    "user_name": info["name"],
                    "user_email": info["email"],
                    "event_count": len(info["event_ids"]),
                    "event_types": info["event_types"],
                    "last_seen": info["last_seen"],
                    "country": info["country"],
                    "ip_address": info["ip_address"],
                },
                "event_ids": info["event_ids"],
            }
        )
    return detections


# ---------------------------------------------------------------------------
# Behavioral detector 12: Risky OAuth grants (per-event)
# ---------------------------------------------------------------------------


async def detect_risky_oauth(
    db: AsyncSession, hours_back: int = 24
) -> list[dict]:
    """
    OAuth grant events with a non-empty risky_scopes array in details.
    One insight per event.
    """
    from app.models.activity import ActivityEvent

    since = _now_utc() - timedelta(hours=hours_back)

    result = await db.execute(
        select(
            ActivityEvent.id,
            ActivityEvent.user_id,
            ActivityEvent.timestamp,
            ActivityEvent.details,
        )
        .where(
            and_(
                ActivityEvent.event_type == "oauth_grant",
                ActivityEvent.timestamp >= since,
                ActivityEvent.user_id.isnot(None),
                ActivityEvent.details["risky_scopes"].as_string().isnot(None),
                ActivityEvent.details["risky_scopes"].as_string() != "null",
                ActivityEvent.details["risky_scopes"].as_string() != "[]",
            )
        )
    )
    rows = result.fetchall()

    detections: list[dict] = []
    for row in rows:
        details = row.details or {}
        risky_scopes = details.get("risky_scopes") or []
        if not risky_scopes:
            continue
        app_name = details.get("app_name") or details.get("app") or "Unknown app"
        detections.append(
            {
                "insight_type": "risky_oauth",
                "severity": "high",
                "title": f"Risky OAuth grant: {app_name}"[:80],
                "user_id": str(row.user_id),
                "evidence": {
                    "app_name": app_name,
                    "risky_scopes": risky_scopes,
                    "scopes": details.get("scopes"),
                    "timestamp": row.timestamp.isoformat(),
                },
                "event_ids": [str(row.id)],
            }
        )
    return detections


# ---------------------------------------------------------------------------
# Behavioral detector 13: Auth brute force (per-user)
# ---------------------------------------------------------------------------


async def detect_auth_brute_force(
    db: AsyncSession, hours_back: int = 24
) -> list[dict]:
    """
    3+ access_eval/saml failures within 30 min followed by a success.
    One insight per user.
    """
    from app.models.activity import ActivityEvent

    since = _now_utc() - timedelta(hours=hours_back)
    failure_outcomes = {"fail", "denied", "blocked"}

    result = await db.execute(
        select(
            ActivityEvent.id,
            ActivityEvent.user_id,
            ActivityEvent.event_type,
            ActivityEvent.timestamp,
            ActivityEvent.details,
        )
        .where(
            and_(
                ActivityEvent.event_type.in_(["access_eval", "saml"]),
                ActivityEvent.timestamp >= since,
                ActivityEvent.user_id.isnot(None),
            )
        )
        .order_by(ActivityEvent.user_id, ActivityEvent.timestamp.asc())
    )
    rows = result.fetchall()

    by_user: dict[str, list[Any]] = defaultdict(list)
    for row in rows:
        by_user[str(row.user_id)].append(row)

    detections: list[dict] = []
    for user_id, events in by_user.items():
        classified = []
        for ev in events:
            outcome = ((ev.details or {}).get("outcome") or "").lower()
            classified.append({"row": ev, "is_failure": outcome in failure_outcomes, "outcome": outcome})

        n = len(classified)
        for i in range(n):
            if not classified[i]["is_failure"]:
                continue
            window_end = classified[i]["row"].timestamp + timedelta(minutes=30)
            window_events = [classified[i]]
            for j in range(i + 1, n):
                if classified[j]["row"].timestamp > window_end:
                    break
                window_events.append(classified[j])

            failures = [e for e in window_events if e["is_failure"]]
            if len(failures) < 3:
                continue

            last_failure_ts = failures[-1]["row"].timestamp
            success_event = None
            for k in range(i, n):
                ev_ts = classified[k]["row"].timestamp
                if ev_ts <= last_failure_ts:
                    continue
                if not classified[k]["is_failure"]:
                    success_event = classified[k]
                    break

            if success_event is None:
                continue

            event_ids = [str(e["row"].id) for e in failures] + [str(success_event["row"].id)]
            window_minutes = round(
                (failures[-1]["row"].timestamp - failures[0]["row"].timestamp).total_seconds() / 60, 1
            )
            detections.append(
                {
                    "insight_type": "auth_brute_force",
                    "severity": "high",
                    "title": f"Brute-force success: {len(failures)} failures then access granted"[:80],
                    "user_id": user_id,
                    "evidence": {
                        "failure_count": len(failures),
                        "failure_window_minutes": window_minutes,
                        "final_outcome": success_event["outcome"] or "success",
                        "first_failure_ts": failures[0]["row"].timestamp.isoformat(),
                        "success_ts": success_event["row"].timestamp.isoformat(),
                    },
                    "event_ids": event_ids,
                }
            )
            break  # one finding per user

    return detections


# ---------------------------------------------------------------------------
# Behavioral detector 14: After-hours logins (batch)
# ---------------------------------------------------------------------------


async def detect_after_hours_logins(
    db: AsyncSession, hours_back: int = 24
) -> list[dict]:
    """
    login/saml events between 22:00-05:00 UTC. One batch insight total.
    Title: "{N} after-hours authentication events".
    Evidence: list of {user, event_type, hour, timestamp, ip}.
    """
    from app.models.activity import ActivityEvent
    from app.models.user import User

    since = _now_utc() - timedelta(hours=hours_back)

    result = await db.execute(
        select(
            ActivityEvent.id,
            ActivityEvent.user_id,
            ActivityEvent.timestamp,
            ActivityEvent.event_type,
            ActivityEvent.ip_address,
            User.full_name,
            User.email,
        )
        .outerjoin(User, User.id == ActivityEvent.user_id)
        .where(
            and_(
                ActivityEvent.event_type.in_(["login", "saml"]),
                ActivityEvent.timestamp >= since,
                ActivityEvent.user_id.isnot(None),
            )
        )
    )
    rows = result.fetchall()

    events = []
    event_ids = []
    for row in rows:
        hour = row.timestamp.hour
        if not (hour >= 22 or hour < 5):
            continue
        events.append(
            {
                "user": row.full_name or row.email,
                "event_type": row.event_type,
                "hour": hour,
                "timestamp": row.timestamp.isoformat(),
                "ip": row.ip_address,
            }
        )
        event_ids.append(str(row.id))

    if not events:
        return []

    n = len(events)
    return [
        {
            "insight_type": "after_hours_login",
            "severity": "warning",
            "title": f"{n} after-hours authentication events"[:80],
            "user_id": None,
            "evidence": {"count": n, "affected": events},
            "event_ids": event_ids,
        }
    ]


# ---------------------------------------------------------------------------
# Behavioral detector 15: MFA changes (per-event)
# ---------------------------------------------------------------------------

_MFA_CHANGE_KEYWORDS = {"2sv_disable", "mfa_disable"}


async def detect_mfa_changes(
    db: AsyncSession, hours_back: int = 24
) -> list[dict]:
    """
    user_account events where event_name contains '2sv_disable' or 'mfa_disable'.
    One insight per event.
    """
    from app.models.activity import ActivityEvent

    since = _now_utc() - timedelta(hours=hours_back)

    result = await db.execute(
        select(
            ActivityEvent.id,
            ActivityEvent.user_id,
            ActivityEvent.timestamp,
            ActivityEvent.details,
        )
        .where(
            and_(
                ActivityEvent.event_type == "user_account",
                ActivityEvent.timestamp >= since,
            )
        )
    )
    rows = result.fetchall()

    detections: list[dict] = []
    for row in rows:
        details = row.details or {}
        event_name = (details.get("event_name") or "").lower()
        if not any(kw in event_name for kw in _MFA_CHANGE_KEYWORDS):
            continue
        detections.append(
            {
                "insight_type": "mfa_disabled",
                "severity": "high",
                "title": f"MFA disabled: {details.get('event_name', event_name)}"[:80],
                "user_id": str(row.user_id) if row.user_id else None,
                "evidence": {
                    "event_name": details.get("event_name"),
                    "actor": details.get("actor") or details.get("performed_by"),
                    "target_user": details.get("target_user") or details.get("affected_email"),
                    "timestamp": row.timestamp.isoformat(),
                },
                "event_ids": [str(row.id)],
            }
        )
    return detections


# ---------------------------------------------------------------------------
# Behavioral detector 16: Bulk cloud access (batch)
# ---------------------------------------------------------------------------


async def detect_bulk_cloud_access(
    db: AsyncSession, hours_back: int = 24
) -> list[dict]:
    """
    Users with >200 cloud_access events in the window. One batch insight.
    Title: "{N} users with abnormal cloud data volume".
    """
    from app.models.activity import ActivityEvent
    from app.models.user import User

    since = _now_utc() - timedelta(hours=hours_back)

    count_result = await db.execute(
        select(
            ActivityEvent.user_id,
            func.count(ActivityEvent.id).label("event_count"),
            func.max(ActivityEvent.timestamp).label("last_seen"),
        )
        .where(
            and_(
                ActivityEvent.event_type == "cloud_access",
                ActivityEvent.timestamp >= since,
                ActivityEvent.user_id.isnot(None),
            )
        )
        .group_by(ActivityEvent.user_id)
        .having(func.count(ActivityEvent.id) > 200)
    )
    flagged = count_result.fetchall()

    if not flagged:
        return []

    flagged_user_ids = [r.user_id for r in flagged]
    count_by_uid = {str(r.user_id): {"event_count": r.event_count, "last_seen": r.last_seen} for r in flagged}

    # Gather event IDs for flagged users
    events_result = await db.execute(
        select(ActivityEvent.id, ActivityEvent.user_id)
        .where(
            and_(
                ActivityEvent.event_type == "cloud_access",
                ActivityEvent.timestamp >= since,
                ActivityEvent.user_id.in_(flagged_user_ids),
            )
        )
    )
    event_rows = events_result.fetchall()
    all_event_ids = [str(r.id) for r in event_rows]

    # Fetch user info
    user_result = await db.execute(
        select(User.id, User.full_name, User.email)
        .where(User.id.in_(flagged_user_ids))
    )
    user_info = {str(r.id): {"name": r.full_name, "email": r.email} for r in user_result.fetchall()}

    n = len(flagged)
    affected = [
        {
            "user_id": uid,
            "name": user_info.get(uid, {}).get("name"),
            "email": user_info.get(uid, {}).get("email"),
            "event_count": info["event_count"],
            "last_seen": info["last_seen"].isoformat() if info["last_seen"] else None,
        }
        for uid, info in count_by_uid.items()
    ]
    return [
        {
            "insight_type": "bulk_cloud_access",
            "severity": "high",
            "title": f"{n} users with abnormal cloud data volume"[:80],
            "user_id": None,
            "evidence": {"count": n, "affected": affected},
            "event_ids": all_event_ids,
        }
    ]


# ---------------------------------------------------------------------------
# run_all_detections
# ---------------------------------------------------------------------------


async def run_all_detections(
    db: AsyncSession, hours_back: int = 24
) -> list[dict]:
    """
    Run all compliance detectors first (no hours_back), then behavioral ones.
    Runs sequentially on the same DB session.

    Deduplication:
      - Batch insights (user_id=None): key = insight_type
      - Per-user insights: key = (insight_type, user_id)
      Keep highest severity when duplicate keys collide.

    Returns list sorted critical → high → warning → info.
    """
    compliance_detectors = [
        detect_users_no_mfa,
        detect_stale_accounts,
        detect_endpoints_missing_edr,
        detect_endpoints_missing_encryption,
        detect_endpoints_missing_dlp,
        detect_inactive_agents,
        detect_non_compliant_endpoints,
        detect_partial_compliance_endpoints,
        detect_unmanaged_device_access,
    ]

    behavioral_detectors = [
        detect_suspended_user_active,
        detect_risky_oauth,
        detect_auth_brute_force,
        detect_after_hours_logins,
        detect_mfa_changes,
        detect_bulk_cloud_access,
    ]

    all_findings: list[dict] = []

    # Run compliance detectors (no hours_back parameter)
    for detector in compliance_detectors:
        try:
            findings = await detector(db)
            all_findings.extend(findings)
        except Exception as exc:
            logger.warning("Compliance detector %s raised: %s", detector.__name__, exc, exc_info=True)

    # Run behavioral detectors (accept hours_back)
    for detector in behavioral_detectors:
        try:
            findings = await detector(db, hours_back)
            all_findings.extend(findings)
        except Exception as exc:
            logger.warning("Behavioral detector %s raised: %s", detector.__name__, exc, exc_info=True)

    # Deduplicate
    # Batch insights key on insight_type only; per-user key on (insight_type, user_id)
    dedup: dict[tuple[str, str | None], dict] = {}
    for finding in all_findings:
        user_id = finding.get("user_id")
        # Batch insights: user_id is None → key by type only
        # Per-user: key by (type, user_id) — but keep one per user
        key: tuple[str, str | None] = (finding["insight_type"], user_id)
        if key not in dedup:
            dedup[key] = finding
        else:
            existing = dedup[key]["severity"]
            incoming = finding["severity"]
            if _SEVERITY_RANK.get(incoming, 0) > _SEVERITY_RANK.get(existing, 0):
                dedup[key] = finding

    deduplicated = list(dedup.values())
    deduplicated.sort(key=lambda f: _SEVERITY_RANK.get(f["severity"], 0), reverse=True)
    return deduplicated
