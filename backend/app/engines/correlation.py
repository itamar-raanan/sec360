"""
Correlation engine — links endpoints and users across JumpCloud, SentinelOne,
and Symantec DLP.

Design principles
-----------------
* JumpCloud is the canonical source for both users and endpoints.
* SentinelOne and Symantec agents are attached to the matching JumpCloud
  endpoint (or a new endpoint if no JC record exists).
* Correlation priority for endpoint matching:
    0. Serial number match  (hardware-level — highest confidence)
    1. Normalised hostname equality
    2. Cross-match hostname ↔ username
    3. Same username + hostname prefix
* Hostnames are normalised to a common "slug" before comparison so that
  "itamarra's MacBook Air", "ITAMARRA-MACBOOK-AIR", and "itamarra-macbook-air.local"
  all resolve to "itamarra".
* Serial numbers are uppercased and validated (junk values are ignored).
"""

import logging
import re
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from sqlalchemy.orm import selectinload

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Known-bad serial number values to ignore
# ---------------------------------------------------------------------------

_INVALID_SERIALS = {
    "not specified",
    "system serial number",
    "to be filled by o.e.m.",
    "to be filled by o.e.m",
    "default string",
    "0000000000",
    "1234567890",
    "0",
    "na",
    "n/a",
    "none",
    "null",
    "serial number",
    "chassis serial number",
    "base board serial number",
    "invalid",
    "unknown",
}


# ---------------------------------------------------------------------------
# Normalisation helpers
# ---------------------------------------------------------------------------

def normalize_serial(serial: str | None) -> str | None:
    """
    Return an uppercase, stripped serial number suitable for comparison,
    or None if the value is empty, too short, or a known-bad placeholder.

    Examples
    --------
    "C02XJ0K1JGH5"            → "C02XJ0K1JGH5"
    "  not specified  "        → None
    "To Be Filled By O.E.M."   → None
    ""                         → None
    """
    if not serial:
        return None
    s = serial.strip().upper()
    if len(s) < 4:
        return None
    if s.lower() in _INVALID_SERIALS:
        return None
    return s


def normalize_hostname(hostname: str) -> str:
    """
    Convert any system-reported hostname into a lowercase username slug.

    Examples
    --------
    "itamarra's MacBook Air"   → "itamarra"
    "ITAMARRA-MACBOOK-AIR"     → "itamarra"
    "itamarra-macbook-air.local" → "itamarra"
    "ALONAV-PC.corp.local"     → "alonav"
    "eilamts-MacBook-Air"      → "eilamt"   (possessive 's stripped)
    "tomh-YWQYH"               → "tomh"     (Windows random suffix stripped)
    "lielm-75YKC"              → "lielm"    (Windows random suffix stripped)
    "jacobbs-Air"              → "jacobbs"  (-air device suffix)
    "DESKTOP-A7CGIM8"          → "desktop-a7cgim8"  (generic prefix → keep as-is)
    "iPad"                     → "ipad"
    """
    if not hostname:
        return ""

    h = hostname.lower().strip()

    # 1. Strip DNS suffixes
    for sfx in (".corp.local", ".local", ".internal", ".corp", ".domain", ".home", ".lan"):
        if h.endswith(sfx):
            h = h[: -len(sfx)]
            break

    # 2. Strip apostrophes — handle both "name's device" and bare "name's"
    #    "itamarra's macbook air"  → split on "'s" → take left side = "itamarra"
    #    "o'brien-laptop"          → remove apostrophe → "obrien-laptop" → then strip suffix
    if "'" in h:
        apos_idx = h.index("'")
        after = h[apos_idx + 1:]
        if after.startswith("s"):           # possessive: name's …
            h = h[:apos_idx]               # take only the name part
        else:
            h = h.replace("'", "")         # bare apostrophe → just remove it

    # 3. Normalise separators: spaces and underscores → hyphens
    h = re.sub(r"[\s_]+", "-", h).strip("-")

    # 4. Strip device-type suffixes.
    #
    #    IMPORTANT ordering: plain suffixes ("-macbook-air") must be tried BEFORE
    #    possessive suffixes ("s-macbook-air").  Both match "bens-macbook-air" because
    #    h[-13:] == "s-macbook-air", but stripping "s-macbook-air" would give "ben"
    #    (wrong) while stripping "-macbook-air" gives "bens" (correct).  We only fall
    #    back to the possessive variants when the plain suffix does not match, which
    #    handles the genuinely-possessive case "eilamts-macbook-air" → "eilamts"
    #    (consistent; the trailing 's' is kept so it can match via username cross-match).
    DEVICE_SUFFIXES_PLAIN = [
        "-macbook-air", "-macbook-pro", "-macbook",
        "-laptop", "-pc", "-desktop", "-nb", "-workstation",
        "-macbookair", "-macbookpro",
        "-air",                                           # short "jacobbs-Air"
        "-mac",                                           # "Bastian-MAC"
    ]
    DEVICE_SUFFIXES_POSSESSIVE = [
        "s-macbook-air", "s-macbook-pro", "s-macbook",   # "eilamts-macbook-air"
        "s-laptop", "s-pc", "s-desktop", "s-nb", "s-air",
    ]
    for sfx in DEVICE_SUFFIXES_PLAIN + DEVICE_SUFFIXES_POSSESSIVE:
        if h.endswith(sfx):
            h = h[: -len(sfx)]
            break

    # 5. Strip Windows-generated random hostname suffix.
    #    Pattern: "username-RANDOM" where RANDOM is 4-8 alphanumeric chars that look
    #    machine-generated (contains a digit, or has no vowels, or vowel ratio < 20%).
    #    Skip when the prefix itself is a generic computer-room name.
    _GENERIC_PREFIXES = {"desktop", "laptop", "server", "workstation", "ws", "win", "training"}
    parts = h.rsplit("-", 1)
    if len(parts) == 2:
        prefix, suffix = parts
        if (4 <= len(suffix) <= 8
                and suffix.isalnum()
                and len(prefix) >= 3
                and prefix.split("-")[0] not in _GENERIC_PREFIXES):
            vowel_ratio = sum(1 for c in suffix if c in "aeiou") / len(suffix)
            has_digit   = any(c.isdigit() for c in suffix)
            if has_digit or vowel_ratio < 0.2:
                h = prefix

    return h.strip("-").strip()


def normalize_username(username: str) -> str:
    """Lowercase, strip domain prefix (DOMAIN\\user) and @domain suffix."""
    if not username:
        return ""
    u = username.lower().strip()
    if "\\" in u:           # DOMAIN\user  →  user
        u = u.split("\\")[-1]
    if "@" in u:            # user@domain  →  user
        u = u.split("@")[0]
    return u.strip()


def email_prefix(email: str) -> str:
    return email.split("@")[0].lower().strip() if email else ""


# ---------------------------------------------------------------------------
# Shared lookup helpers (used by collectors)
# ---------------------------------------------------------------------------

async def find_endpoint_by_serial(db: AsyncSession, serial: str | None):
    """
    Return the best-matching Endpoint for the given hardware serial number.

    Serial numbers are normalised (uppercase, stripped, junk rejected) before
    comparison.  Returns None when the serial is invalid or no match is found.

    Priority: JumpCloud-sourced endpoint first, then any other.
    """
    from app.models.endpoint import Endpoint

    norm = normalize_serial(serial)
    if not norm:
        return None

    result = await db.execute(
        select(Endpoint).where(Endpoint.serial_number == norm)
    )
    candidates = result.scalars().all()

    if not candidates:
        # Case-insensitive fallback (shouldn't be needed after normalisation,
        # but covers any stale rows stored without uppercasing)
        result = await db.execute(
            select(Endpoint).where(Endpoint.serial_number.ilike(norm))
        )
        candidates = result.scalars().all()

    if not candidates:
        return None

    jc = [ep for ep in candidates if ep.source == "jumpcloud"]
    return jc[0] if jc else candidates[0]


async def find_endpoint_by_hostname(db: AsyncSession, hostname: str):
    """
    Return the best-matching Endpoint for *hostname*, using normalised
    comparison so that "itamarra's MacBook Air" matches "ITAMARRA-MACBOOK-AIR".

    Priority: JumpCloud-sourced endpoints first, then any other.
    Returns None if no match is found.
    """
    from app.models.endpoint import Endpoint

    if not hostname:
        return None

    norm_incoming = normalize_hostname(hostname)

    # 1. Try exact case-insensitive match first (fastest path)
    result = await db.execute(
        select(Endpoint).where(Endpoint.hostname.ilike(hostname))
    )
    candidates = result.scalars().all()

    # 2. If no exact match, load all endpoints and compare normalised forms
    if not candidates:
        result = await db.execute(select(Endpoint))
        all_eps = result.scalars().all()
        candidates = [ep for ep in all_eps
                      if normalize_hostname(ep.hostname) == norm_incoming]

    if not candidates:
        return None

    # Prefer JumpCloud-sourced endpoints; otherwise take the first
    jc = [ep for ep in candidates if ep.source == "jumpcloud"]
    return jc[0] if jc else candidates[0]


async def find_endpoint(db: AsyncSession, serial: str | None, hostname: str | None):
    """
    Combined lookup used by collectors: try serial number first (most
    reliable), fall back to hostname normalisation.

    Returns (endpoint, match_method) or (None, None).
    """
    if serial:
        ep = await find_endpoint_by_serial(db, serial)
        if ep:
            return ep, "serial"

    if hostname:
        ep = await find_endpoint_by_hostname(db, hostname)
        if ep:
            return ep, "hostname"

    return None, None


# ---------------------------------------------------------------------------
# Endpoint deduplication
# ---------------------------------------------------------------------------

async def deduplicate_endpoints(db: AsyncSession) -> int:
    """
    Merge endpoints that represent the same physical machine.

    Matching strategies (evaluated in priority order):
    0. Serial number match  — hardware certainty; overrides all name-based checks.
    1. Normalised hostnames are identical.
    2. Normalised hostname of A == normalised username of B (or vice-versa).
    3. Both share the same non-trivial username AND their normalised hostnames
       start with that username.
    3b. Same non-trivial username across JC ↔ S1/DLP boundary (lower confidence —
        only applied when exactly one of the two endpoints is JumpCloud-sourced).

    When merging, always keep the JumpCloud-sourced endpoint as the canonical
    record.  All agents and the compliance record are re-parented to it.
    """
    from app.models.endpoint import Endpoint
    from app.models.agent import SecurityAgent

    total_merged = 0

    # Run multiple passes until no further merges happen
    for _pass in range(5):
        result = await db.execute(
            select(Endpoint).options(
                selectinload(Endpoint.agents),
                selectinload(Endpoint.compliance_status),
            )
        )
        endpoints = result.scalars().all()

        merged_this_pass = 0
        visited: set[str] = set()

        # Build a list of (ep, norm_host, norm_user, norm_serial) tuples once
        ep_info = [
            (
                ep,
                normalize_hostname(ep.hostname),
                normalize_username(ep.username or ""),
                normalize_serial(ep.serial_number),
            )
            for ep in endpoints
        ]

        for i, (ep_a, norm_host_a, norm_user_a, norm_serial_a) in enumerate(ep_info):
            if str(ep_a.id) in visited:
                continue

            for ep_b, norm_host_b, norm_user_b, norm_serial_b in ep_info[i + 1:]:
                if str(ep_b.id) in visited:
                    continue

                match = False
                match_reason = ""

                # ── Hard exclusion: two endpoints with DIFFERENT valid serials ──
                # Serial numbers are hardware identifiers — if both endpoints have
                # distinct serials they are provably different physical machines.
                # A user can own multiple devices; we must not merge them.
                if (norm_serial_a and norm_serial_b
                        and norm_serial_a != norm_serial_b):
                    continue   # skip all strategies — definitely different machines

                # ── Strategy 0: serial number match (highest confidence) ──
                if (norm_serial_a and norm_serial_b
                        and norm_serial_a == norm_serial_b):
                    match = True
                    match_reason = f"serial={norm_serial_a}"

                # ── Strategy 1: identical normalised hostnames ──
                elif norm_host_a and norm_host_a == norm_host_b:
                    match = True
                    match_reason = f"hostname={norm_host_a}"

                # ── Strategy 1b: trailing possessive-s difference ──
                # "yarinms" (JC, from "yarinm's MacBook Air") vs "yarinm" (S1)
                # The 's' is an artefact of macOS possessive computer names; treat
                # as the same endpoint when one slug is exactly the other + 's'.
                # Guard: minimum 5-char base to avoid false positives ("bens"/"ben").
                elif (
                    norm_host_a and norm_host_b
                    and len(norm_host_a) >= 5 and len(norm_host_b) >= 5
                    and (
                        norm_host_a == norm_host_b + "s"
                        or norm_host_b == norm_host_a + "s"
                    )
                ):
                    match = True
                    shorter = norm_host_b if norm_host_a.endswith("s") else norm_host_a
                    match_reason = f"hostname_possessive_s={shorter}"

                # ── Strategy 2: cross-match hostname ↔ username ──
                elif norm_host_a and norm_user_b and norm_host_a == norm_user_b:
                    match = True
                    match_reason = f"host_a=user_b={norm_host_a}"
                elif norm_host_b and norm_user_a and norm_host_b == norm_user_a:
                    match = True
                    match_reason = f"host_b=user_a={norm_host_b}"

                # ── Strategy 3: same username, hostname starts with username ──
                elif (
                    norm_user_a
                    and norm_user_a == norm_user_b
                    and norm_user_a not in ("admin", "user", "guest", "root")
                    and len(norm_user_a) >= 4
                    and (norm_host_a.startswith(norm_user_a)
                         or norm_host_b.startswith(norm_user_a))
                ):
                    match = True
                    match_reason = f"username_prefix={norm_user_a}"

                # ── Strategy 3b: same non-trivial username across JC ↔ S1/DLP ──
                # Lower confidence than serial/hostname but catches cases where
                # hostnames diverge completely (renamed machines, different naming
                # conventions between systems).  Only apply when one endpoint is
                # JumpCloud-sourced and the other is not, to avoid false positives
                # between two S1-only or two DLP-only records.
                elif (
                    norm_user_a
                    and norm_user_a == norm_user_b
                    and norm_user_a not in (
                        "admin", "administrator", "user", "guest", "root",
                        "system", "service", "local",
                    )
                    and len(norm_user_a) >= 5
                    and (
                        (ep_a.source == "jumpcloud") != (ep_b.source == "jumpcloud")
                    )
                ):
                    match = True
                    match_reason = f"username_xsource={norm_user_a}"

                if not match:
                    continue

                # ── Decide which to keep (canonical = JumpCloud source) ──
                keep, drop = ep_a, ep_b
                if ep_b.source == "jumpcloud" and ep_a.source != "jumpcloud":
                    keep, drop = ep_b, ep_a

                # Inherit missing scalar fields onto keep
                for attr in ("username", "ip_address", "os_version",
                             "owner_user_id", "serial_number"):
                    if not getattr(keep, attr) and getattr(drop, attr):
                        setattr(keep, attr, getattr(drop, attr))

                # last_seen: take the most recent (JC owns its own last_seen)
                if drop.last_seen and (not keep.last_seen or drop.last_seen > keep.last_seen):
                    if keep.source != "jumpcloud":
                        keep.last_seen = drop.last_seen

                # Re-parent agents from drop → keep
                for agent in list(drop.agents):
                    drop.agents.remove(agent)
                    already = any(a.product_name == agent.product_name for a in keep.agents)
                    if not already:
                        agent.endpoint_id = keep.id
                        keep.agents.append(agent)
                        logger.info(
                            "Correlation: moved %s agent from %r → %r (%s)",
                            agent.product_name, drop.hostname, keep.hostname, match_reason,
                        )
                    else:
                        await db.delete(agent)

                # Re-parent compliance record
                if drop.compliance_status:
                    cs = drop.compliance_status
                    drop.compliance_status = None
                    if not keep.compliance_status:
                        cs.endpoint_id = keep.id
                        keep.compliance_status = cs
                    else:
                        await db.delete(cs)

                await db.flush()
                await db.delete(drop)
                await db.flush()

                visited.add(str(drop.id))
                merged_this_pass += 1
                logger.info(
                    "Correlation: merged %r → %r [%s]",
                    drop.hostname, keep.hostname, match_reason,
                )

                # ep_a might now be the drop — update outer loop reference
                if ep_a is drop:
                    break  # ep_a was dropped, move to next i

        total_merged += merged_this_pass
        if merged_this_pass == 0:
            break  # stable — stop

    logger.info("Correlation: deduplication merged %d endpoint pairs total", total_merged)
    return total_merged


# ---------------------------------------------------------------------------
# User ↔ Endpoint matching
# ---------------------------------------------------------------------------

async def match_user_to_endpoint(db: AsyncSession) -> int:
    """
    Link every endpoint to its JumpCloud owner by comparing:
    1. endpoint.username    (set by SentinelOne / Symantec collectors)
    2. Normalised hostname  (many Mac names embed the username)

    against the JumpCloud user email prefix.
    """
    from app.models.user import User
    from app.models.endpoint import Endpoint

    users_result = await db.execute(select(User))
    users = users_result.scalars().all()

    if not users:
        return 0

    # Build look-up structures
    by_prefix: dict[str, User] = {}          # email-prefix   → User
    by_firstname: dict[str, list[User]] = {} # first-name     → [User]

    for u in users:
        pfx = email_prefix(u.email)
        if pfx:
            by_prefix[pfx] = u
        first = (u.full_name or "").split()[0].lower() if u.full_name else ""
        if first and len(first) >= 3:
            by_firstname.setdefault(first, []).append(u)

    endpoints_result = await db.execute(select(Endpoint))
    endpoints = endpoints_result.scalars().all()

    matched = 0
    for ep in endpoints:
        # Collect candidate tokens: username field + hostname-derived token
        tokens: list[str] = []

        if ep.username:
            tokens.append(normalize_username(ep.username))

        nh = normalize_hostname(ep.hostname)
        if nh and nh not in tokens:
            tokens.append(nh)

        user = None
        for token in tokens:
            if not token or token in ("admin", "user", "guest", "root", "administrator"):
                continue

            # 1. Exact email-prefix match
            user = by_prefix.get(token)
            if user:
                break

            # 2. email prefix starts with token (token is shorter: "ben" → "benh")
            if not user and len(token) >= 4:
                for pfx, u in by_prefix.items():
                    if pfx.startswith(token):
                        user = u
                        break
            if user:
                break

            # 3. token starts with email prefix (token has extra chars: "eilamts" → "eilamt")
            if not user and len(token) >= 4:
                for pfx, u in by_prefix.items():
                    if len(pfx) >= 4 and token.startswith(pfx):
                        user = u
                        break
            if user:
                break

            # 4. First-name fallback (only when exactly one JC user has that first name)
            if not user:
                candidates = by_firstname.get(token, [])
                if len(candidates) == 1:
                    user = candidates[0]
            if user:
                break

        if user and ep.owner_user_id != user.id:
            ep.owner_user_id = user.id
            matched += 1

    await db.flush()
    logger.info("Correlation: linked %d endpoints to users", matched)
    return matched


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

async def run_full_correlation(db: AsyncSession) -> dict:
    """Run endpoint deduplication then user-endpoint linking."""
    logger.info("Correlation: starting full run")

    dedup = await deduplicate_endpoints(db)
    matched = await match_user_to_endpoint(db)

    await db.flush()
    logger.info("Correlation complete: %d merges, %d user-endpoint links", dedup, matched)
    return {"endpoint_merges": dedup, "user_endpoint_matches": matched}
