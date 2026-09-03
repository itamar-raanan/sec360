"""
AI Chat router  —  /ai/chat

Hybrid architecture:
  - LISTING queries  → fetch DB data → format as markdown directly (no LLM, instant, no truncation)
  - ANALYSIS queries → fetch DB context → pass to Ollama 3B for interpretation

Conversational intelligence:
  - Follow-up detection:  recognises "those", "them", "which of these", etc.
  - Intent merging:       layers new filters on top of the previous query's intent
  - Entity pivots:        "who owns them?" switches from endpoints→users; "their devices?" reverses
  - Filter inheritance:   short filter phrases (e.g. "without VPN?") inherit entity from context
  - Smart LLM context:    history summary injected so the model knows what was last shown

No external API keys required.
"""

from __future__ import annotations

import json
import logging
import re
from datetime import datetime, timezone, timedelta
from typing import Any, AsyncIterator

import httpx
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from sqlalchemy import select, func, and_, or_
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.api.deps import get_db, require_role
from app.models.user import AuthUser, User
from app.models.endpoint import Endpoint
from app.models.compliance import ComplianceStatus
from app.models.activity import ActivityEvent
from app.services.endpoint_inventory import current_endpoint_clause

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/ai", tags=["AI"])

OLLAMA_BASE  = "http://172.18.0.1:11434"
OLLAMA_MODEL = "llama3.2:3b"
KEEP_ALIVE   = "10m"

# ---------------------------------------------------------------------------
# Pydantic schemas
# ---------------------------------------------------------------------------

class ChatMessage(BaseModel):
    role: str
    content: str

class ChatRequest(BaseModel):
    message: str
    history: list[ChatMessage] = []

class ChatResponse(BaseModel):
    response: str

# ---------------------------------------------------------------------------
# Prompts (used only for analysis queries)
# ---------------------------------------------------------------------------

SYSTEM_PROMPT = """\
You are a corporate security analyst assistant inside Sec360.
Rules (follow strictly):
1. Use ONLY the numbers and names from the DATA block. Never invent or guess.
2. Be direct. No filler like "Based on the data…" or "It appears that…"
3. Format lists as markdown tables with clear column headers.
4. Always state the total count.
5. Keep the ENTIRE answer under 120 words.
6. If CONTEXT block is present, use it to understand what was discussed before — do not repeat it verbatim.\
"""

# ---------------------------------------------------------------------------
# Query-type classifier
# ---------------------------------------------------------------------------

# Signals that the user wants a raw listing of items
_LIST_SIGNALS = re.compile(
    r"\b(list|show|give me|get|fetch|display|find|what are|which|who|all|with|without)\b",
    re.IGNORECASE,
)
# Signals that the user wants analysis / summary
_ANALYSIS_SIGNALS = re.compile(
    r"\b(how many|summary|overview|status|count|percentage|compare|why|trend|average|total|breakdown)\b",
    re.IGNORECASE,
)

RISK_RANGES = {"low": (0, 25), "medium": (26, 50), "high": (51, 75), "critical": (76, 100)}


def _is_list_query(msg: str) -> bool:
    """True if the question is asking for a list of items rather than an analysis."""
    has_list   = bool(_LIST_SIGNALS.search(msg))
    has_analysis = bool(_ANALYSIS_SIGNALS.search(msg))
    # list wins unless it's clearly analytical
    return has_list and not has_analysis


# ---------------------------------------------------------------------------
# Conversation context helpers
# ---------------------------------------------------------------------------

# Words / phrases that indicate the message references a previous result
_FOLLOWUP_SIGNALS = re.compile(
    r"\b(those|them|these|the ones|the above|the results?|the list|"
    r"from those|of those|among them|within those|from the previous|in that list)\b"
    # Short imperative starting with a filter phrase → implies context
    r"|^(with(out)?\b|that have\b|that are\b|which have\b|who have\b|"
    r"now (show|list|filter|give|find)\b|and (show|list|find|filter|the|also)\b|"
    r"also\b|what about\b|no\b|"
    r"only the\b|only show\b|show only\b|filter(?: by)?\b|narrow\b|refine\b)",
    re.IGNORECASE | re.MULTILINE,
)

# "who owns them / show me the owners / list their owners" → pivot endpoints → users
_PIVOT_TO_OWNERS = re.compile(
    r"\b(who owns?|whose (device|endpoint|machine)|their owners?\b|"
    r"(show|list|get).{0,12}owners?\b|who (is|are) (the )?owner)",
    re.IGNORECASE,
)

# "show their devices / list their endpoints / what machines do they have" → pivot users → endpoints
_PIVOT_TO_DEVICES = re.compile(
    r"\b(their (devices?|endpoints?|machines?|computers?|laptops?)|"
    r"what (devices?|endpoints?|machines?) (do )?they|"
    r"(show|list|get).{0,12}their\s+(devices?|endpoints?|machines?))\b",
    re.IGNORECASE,
)

# "sort / order by X"
_SORT_SIGNAL = re.compile(
    r"\b(sort|order|rank).{0,12}by\b|\bby (risk|name|date|last.?seen|hostname|email)\b",
    re.IGNORECASE,
)

# Sort key mapping
_SORT_KEYS = {
    "risk":      "risk",
    "name":      "name",
    "hostname":  "hostname",
    "email":     "email",
    "last seen": "last_seen",
    "date":      "last_seen",
}


def _is_followup(msg: str, history: list) -> bool:
    """Return True if the message seems to reference a previous exchange."""
    if not history:
        return False
    m = msg.strip().lower()
    words = m.split()
    # Very short messages without an entity are almost always follow-ups
    if len(words) <= 4 and not re.search(
        r"\b(endpoints?|devices?|machines?|hosts?|users?|employees?|"
        r"activity|logins?|events?|compliance|saml|oauth|vpn|network|"
        r"cloud|file|app|access|sessions?|auth)\b", m
    ):
        return True
    # Sort / order requests always refine the previous result
    if _SORT_SIGNAL.search(msg):
        return True
    # Pivot signals (owner/device pivot) always reference previous results
    if _PIVOT_TO_OWNERS.search(msg) or _PIVOT_TO_DEVICES.search(msg):
        return True
    return bool(_FOLLOWUP_SIGNALS.search(msg))


def _extract_prev_intent(history: list) -> dict | None:
    """Reconstruct the intent from the most recent user message in history."""
    for msg in reversed(history):
        if msg.role == "user" and msg.content.strip():
            return _detect_intent(msg.content)
    return None


def _extract_context_summary(history: list) -> str:
    """
    Build a one-line summary of what was last shown, for injection into the
    LLM system context on follow-up turns.
    """
    if not history:
        return ""
    # Find the most recent assistant message that looks like a result
    for msg in reversed(history):
        if msg.role == "assistant":
            text = msg.content.strip()
            # Grab first bold header like "**High-risk users** — 36 found"
            m = re.search(r"\*\*(.{5,80}?)\*\*", text)
            if m:
                return f"Previously shown: {m.group(1).strip()}"
            # Fallback: first non-empty line
            first = next((l.strip() for l in text.splitlines() if l.strip()), "")
            if first:
                return f"Previously shown: {first[:120]}"
    return ""


def _extract_sort(msg: str) -> str | None:
    """Return the sort key if the message contains a sort request."""
    if not _SORT_SIGNAL.search(msg):
        return None
    m = msg.lower()
    for kw, key in _SORT_KEYS.items():
        if kw in m:
            return key
    return None


def _merge_intents(prev: dict, curr: dict, msg: str) -> dict:
    """
    Merge the current turn's intent with the previous turn's intent.

    Strategy:
      - If the current message pivots the entity (owners / devices), swap entity.
      - If the current message specifies the same entity as prev, layer new filters.
      - If the current message has no entity at all, inherit prev entity + layer filters.
      - Compliance / risk flags are ORed.
      - Cross-intent cleanup is re-applied.
    """
    m_lower = msg.lower()

    pivot_owners  = bool(_PIVOT_TO_OWNERS.search(msg))
    pivot_devices = bool(_PIVOT_TO_DEVICES.search(msg))
    curr_has_entity = curr["endpoints"] or curr["users"] or curr["activity"]

    # Base = copy of previous
    merged: dict[str, Any] = {
        "endpoints":    prev["endpoints"],
        "users":        prev["users"],
        "activity":     prev["activity"],
        "compliance":   prev["compliance"] or curr["compliance"],
        "risk":         prev["risk"] or curr["risk"],
        "ep_filters":   dict(prev.get("ep_filters") or {}),
        "user_filters": dict(prev.get("user_filters") or {}),
        "act_filters":  dict(prev.get("act_filters") or {}),
    }

    if pivot_owners:
        # "who owns these endpoints?" → show users; carry ep_filters for owner lookup
        merged["users"]        = True
        merged["endpoints"]    = False
        merged["user_filters"] = {**(prev.get("user_filters") or {}), **(curr.get("user_filters") or {})}
        # Keep ep_filters so caller can cross-reference owners of the filtered endpoints
        merged["ep_filters"]   = dict(prev.get("ep_filters") or {})
        merged["_owner_pivot"] = True   # signal for direct response formatter

    elif pivot_devices:
        # "show their devices" (after listing users) → show endpoints owned by those users
        merged["endpoints"]    = True
        merged["users"]        = False
        merged["ep_filters"]   = {**(prev.get("ep_filters") or {}), **(curr.get("ep_filters") or {})}
        merged["user_filters"] = dict(prev.get("user_filters") or {})
        merged["_device_pivot"] = True

    elif curr_has_entity:
        # Current message names an entity
        if curr["endpoints"] and prev["endpoints"]:
            # Same entity — layer filters
            merged["ep_filters"] = {**(prev.get("ep_filters") or {}), **(curr.get("ep_filters") or {})}
        elif curr["endpoints"]:
            merged["ep_filters"] = dict(curr.get("ep_filters") or {})

        if curr["users"] and prev["users"]:
            merged["user_filters"] = {**(prev.get("user_filters") or {}), **(curr.get("user_filters") or {})}
        elif curr["users"]:
            merged["user_filters"] = dict(curr.get("user_filters") or {})

        if curr["activity"]:
            merged["act_filters"] = {**(prev.get("act_filters") or {}), **(curr.get("act_filters") or {})}

        merged["endpoints"] = curr["endpoints"]
        merged["users"]     = curr["users"]
        merged["activity"]  = curr["activity"]

    else:
        # No entity in current message — inherit previous, add any new filters
        merged["ep_filters"]   = {**(prev.get("ep_filters") or {}), **(curr.get("ep_filters") or {})}
        merged["user_filters"] = {**(prev.get("user_filters") or {}), **(curr.get("user_filters") or {})}
        merged["act_filters"]  = {**(prev.get("act_filters") or {}), **(curr.get("act_filters") or {})}

    # Propagate risk/compliance flags from current
    if curr["compliance"]:
        merged["compliance"] = True
    if curr["risk"]:
        merged["risk"] = True

    # ── Risk level in entity context ─────────────────────────────────────────
    # If generic risk=True was set but we have an entity from the previous turn,
    # assign the risk level to that entity's filters (e.g. "high risk ones" → users)
    if merged.get("risk") and not merged.get("ep_filters", {}).get("risk_level") \
            and not merged.get("user_filters", {}).get("risk_level"):
        for level in ["critical", "high", "medium", "low"]:
            if re.search(rf"\b{level}\b", m_lower):
                if merged.get("users"):
                    merged["user_filters"]["risk_level"] = level
                    merged["risk"] = False
                elif merged.get("endpoints"):
                    merged["ep_filters"]["risk_level"] = level
                    merged["risk"] = False
                break

    # ── Re-apply cross-intent cleanup ────────────────────────────────────────
    if merged["ep_filters"].get("unassigned"):
        merged["users"] = False
        merged["user_filters"] = {}
    if merged["user_filters"].get("no_endpoint"):
        merged["endpoints"] = False
        merged["ep_filters"] = {}
    if merged["user_filters"] and merged["endpoints"] and not merged["ep_filters"]:
        merged["endpoints"] = False
    if merged["risk"] and (merged["ep_filters"].get("risk_level") or
                           merged["user_filters"].get("risk_level")):
        merged["risk"] = False
    if merged["ep_filters"] and merged["compliance"]:
        if not re.search(r"\bcompar\w+|\bvs\b|\bversus\b", m_lower):
            merged["compliance"] = False

    return merged


# ---------------------------------------------------------------------------
# Intent detection  — extracts filters from natural language
# ---------------------------------------------------------------------------

def _detect_intent(msg: str) -> dict:
    m = msg.lower()

    intent: dict[str, Any] = {
        "endpoints":    False,
        "users":        False,
        "activity":     False,
        "compliance":   False,
        "risk":         False,
        "ep_filters":   {},
        "user_filters": {},
        "act_filters":  {},
    }

    # ── Entity detection ──────────────────────────────────────────────────
    if re.search(r"\b(endpoints?|devices?|machines?|computers?|laptops?|hosts?|hostnames?|pcs?|workstations?)\b", m):
        intent["endpoints"] = True
    if re.search(r"\b(users?|employees?|people|persons?|staff|members?|accounts?|who|workers?|everyone|everybody)\b", m):
        intent["users"] = True
    if re.search(r"\b(activity|logins?|events?|access|sign.?ins?|signed.?in|logged|auth|saml|oauth|sessions?)\b"
                 r"|\b(country|geo|ip\s|location|from\s+[a-z]{3,})", m):
        intent["activity"] = True
    # Only set compliance intent if not a filtered endpoint query
    if re.search(r"\b(compliance|posture|policy)\b", m):
        intent["compliance"] = True
    elif re.search(r"\bcompliant\b", m) and not re.search(r"non.?compliant|not compliant|partially", m):
        intent["compliance"] = True
    elif re.search(r"\bcompar\w+.{0,20}complian|complian.{0,20}\bvs\b", m):
        intent["compliance"] = True
    if re.search(r"\b(risk score|risk distribution|risk overview|risk summary|risk posture|risk landscape|risk metrics|risk breakdown|risky)\b"
                 r"|\bhigh risk\b|\bcritical risk\b", m):
        intent["risk"] = True

    # ── Endpoint filters ──────────────────────────────────────────────────

    # ── Named owner lookup: "john's devices", "devices for alice", "what does bob have" ─────
    _OWNER_STOP = {
        "the", "a", "an", "all", "this", "that", "their", "my", "our",
        "your", "its", "his", "her", "any", "some", "new", "old",
    }
    _EP_WORDS = r"(?:devices?|endpoints?|machines?|computers?|laptops?|pcs?|workstations?|hosts?)"
    _name_re = r"([a-z][a-z0-9._+\-]{1,40}(?:@[a-z0-9._\-]+\.[a-z]{2,})?)"

    _owner_m = (
        re.search(rf"{_name_re}'s?\s+{_EP_WORDS}", m)
        or re.search(rf"{_EP_WORDS}\s+(?:for|by|of|owned by|belonging to|assigned to)\s+{_name_re}", m)
        or re.search(rf"what\s+{_EP_WORDS}\s+(?:does|do|is|are)\s+{_name_re}\s+(?:have|own|use)", m)
        or re.search(rf"show\s+(?:me\s+)?{_name_re}(?:'s?)?\s+{_EP_WORDS}", m)
    )
    if _owner_m:
        _candidate = (_owner_m.group(1) if _owner_m.lastindex and _owner_m.group(1)
                      else _owner_m.group(2) if _owner_m.lastindex and _owner_m.lastindex >= 2
                      else None)
        # For group(2) matches (for/by patterns), re-extract from the match
        _raw = _owner_m.group(_owner_m.lastindex) if _owner_m.lastindex else None
        if _raw and _raw.lower() not in _OWNER_STOP and len(_raw) > 1:
            intent["endpoints"] = True
            intent["ep_filters"]["owner_name"] = _raw

    # Unassigned / no owner  (must involve "owner" or "assign", not just "user")
    if re.search(
        r"(no|without|missing|not|don.?t have).{0,8}(owner)\b"
        r"|(no|without|missing|not).{0,6}assigned?\s+(?:owner|user)"
        r"|(no|without|missing|not).{0,6}owner.{0,6}assigned?"
        r"|\bunassigned\b"
        r"|\bwithout.{0,8}assignment\b"
        r"|without.{0,6}user.{0,6}assign"
        r"|not.{0,6}assign(ed)?.{0,12}(?:user|owner|anyone|any)"
        r"|not\s+assigned\b"
        r"|devices?\s+not\s+assigned"
        r"|(no|without|missing|not).{0,8}user.{0,8}assign",
        m,
    ):
        intent["endpoints"] = True
        intent["ep_filters"]["unassigned"] = True
        # Clear owner_name if we set it accidentally from "no owner" phrasing
        intent["ep_filters"].pop("owner_name", None)

    # Outdated S1/EDR
    if re.search(
        r"(outdated|old|not updated|out.?of.?date|needs? update|stale).{0,12}(s1|sentinelone|edr|agent)"
        r"|(s1|sentinelone|edr|agent).{0,25}(outdated|old|not updated|out.?of.?date|stale)"
        r"|need.{0,4}(edr|s1|sentinelone|agent).{0,8}update"
        r"|need.{0,4}update.{0,8}(edr|s1|sentinelone)",
        m,
    ):
        intent["endpoints"] = True
        intent["ep_filters"]["edr_outdated"] = True

    # Missing S1/EDR
    if re.search(
        r"(no|missing|without|not installed|lacking|lack\b|don.?t have).{0,8}(s1|sentinelone|edr)"
        r"|(s1|sentinelone|edr).{0,8}(not installed|missing|absent|not present)",
        m,
    ):
        intent["endpoints"] = True
        intent["ep_filters"]["edr_missing"] = True

    # Missing VPN
    if re.search(
        r"(no|missing|without|not installed|lacking|lack\b|don.?t have|doesn.?t have).{0,8}(vpn|globalprotect|gp\b|wss)"
        r"|(vpn|globalprotect).{0,8}(not installed|missing|absent|not present)",
        m,
    ):
        intent["endpoints"] = True
        intent["ep_filters"]["vpn_missing"] = True

    # Missing DLP
    if re.search(r"(no|missing|without|lacking|lack\b|don.?t have).{0,20}dlp|dlp.{0,8}(not installed|missing|absent)", m):
        intent["endpoints"] = True
        intent["ep_filters"]["dlp_missing"] = True

    # Not encrypted
    if re.search(r"(not|un)?.?encrypt|(no|without|missing).{0,6}(disk.{0,6}encrypt|bitlocker|filevault)", m):
        intent["endpoints"] = True
        intent["ep_filters"]["disk_not_encrypted"] = True

    # Compliance status
    if re.search(r"non.?compliant|not compliant|fail.*complian", m):
        intent["endpoints"] = True
        intent["ep_filters"]["compliance_status"] = "non_compliant"
    elif re.search(r"partial.*complian|partially complian", m):
        intent["endpoints"] = True
        intent["ep_filters"]["compliance_status"] = "partial"
    elif re.search(r"fully compliant|all compliant|compliant\s+(?:endpoints?|devices?|hosts?|machines?)|"
                   r"pass.{0,8}complian|^meet.{0,8}complian", m):
        intent["endpoints"] = True
        intent["ep_filters"]["compliance_status"] = "compliant"

    # "not meeting compliance" / "fail compliance" → non_compliant (separate if to not override above)
    if re.search(r"not\s+meet.{0,12}complian|fail.{0,8}complian", m) and \
            not intent["ep_filters"].get("compliance_status"):
        intent["endpoints"] = True
        intent["ep_filters"]["compliance_status"] = "non_compliant"

    # Inactive agents
    if re.search(r"(inactive|disabled|stopped).{0,10}agent|agent.{0,10}(inactive|disabled|stopped)", m):
        intent["endpoints"] = True
        intent["ep_filters"]["agent_inactive"] = True

    # OS filter
    if re.search(r"\bwindows\b", m):
        intent["endpoints"] = True
        intent["ep_filters"]["os"] = "windows"
    elif re.search(r"\bmacos?\b|mac os|\bmac\b", m):
        intent["endpoints"] = True
        intent["ep_filters"]["os"] = "macos"
    elif re.search(r"\blinux\b", m):
        intent["endpoints"] = True
        intent["ep_filters"]["os"] = "linux"

    # ── User filters ──────────────────────────────────────────────────────

    # No MFA
    if re.search(
        r"(no|without|missing|disabled?|not enabled?|lacking|don.?t have|doesn.?t have|do not have|don.?t use|lack).{0,8}(mfa|2fa|two.?factor)"
        r"|(mfa|2fa|two.?factor).{0,8}(disabled?|off|not enabled?|missing|not active|turned off)"
        r"|(mfa|2fa|two.?factor)\s+missing"
        r"|disabled?.{0,6}(mfa|2fa|two.?factor)",
        m,
    ):
        intent["users"] = True
        intent["user_filters"]["mfa_enabled"] = False

    # Has MFA — positive match; exclude negations: "with no", "without", "don't have"
    if re.search(r"\b(with|have)\b(?!\s+no\b|\s+out\b).{0,10}(mfa|2fa|two.?factor)"
                 r"|(mfa|2fa|two.?factor).{0,8}(enabled?|on|active)", m) \
       and not re.search(r"(don.?t|doesn.?t|do not|without|no|lack)\s.{0,8}(mfa|2fa|two.?factor)"
                         r"|(mfa|2fa|two.?factor).{0,10}(off|not|dis|missing|turned)"
                         r"|disabled?.{0,6}(mfa|2fa|two.?factor)", m) \
       and intent["user_filters"].get("mfa_enabled") is not False:
        intent["users"] = True
        intent["user_filters"]["mfa_enabled"] = True

    # Suspended
    if re.search(r"\b(suspended|disabled accounts?|locked out|locked accounts?|deactivated accounts?|blocked)\b", m):
        intent["users"] = True
        intent["user_filters"]["suspended"] = True

    # No endpoint
    if re.search(r"\b(users?|employees?|people|persons?|staff|accounts?|who|workers?|members?)\b", m) and \
       re.search(r"(no|without|missing|not have|lacking|not associated|zero|don.?t have|doesn.?t have).{0,16}(endpoints?|devices?|machines?|laptops?|computers?|pcs?)", m):
        intent["users"] = True
        intent["user_filters"]["no_endpoint"] = True

    # Inactive users
    if re.search(r"(inactive|not active).{0,20}(user|employee|account|staff|worker|member|people)", m):
        intent["users"] = True
        intent["user_filters"]["employment_status"] = "inactive"

    # Department — suffix includes time/activity stop-words so "russia this week" doesn't bleed in
    _USER_ENTITY_RE = r"\b(users?|employees?|people|persons?|staff|accounts?|workers?|members?)\b"
    _dept_from_m = None
    if re.search(_USER_ENTITY_RE, m):
        _dept_from_m = re.search(r"\bfrom\s+([a-z][a-z0-9]+)\b", m)
    dept_m = (
        # "<dept> department/dept users/staff/employees" — dept name before "department" keyword
        re.search(
            r"([a-z][a-z0-9]+)\s+(?:department|dept)\s+"
            r"(?:users?|employees?|staff|workers?|members?|people|accounts?)\b",
            m,
        )
        # "from the <dept> team/users/employees"
        or re.search(
            r"\bfrom the\s+([a-z][a-z0-9]+)\s+"
            r"(?:dept|department|team|users?|employees?|staff|workers?|members?)\b",
            m,
        )
        # "in the <dept> team/users/employees/dept", "in <dept> department"
        or re.search(
            r"(?:\bin the |\bin )"
            r"([a-z][a-z0-9 &/]+?)"
            r"(?:\s+dept|\s+department|\s+team|\s+users|\s+employees|\s+people"
            r"|\s+this|\s+last|\s+today|\s+login|\s+access|\s+event|\s+and\b|$)",
            m,
        )
        # "from <dept>" when a user entity word is present (e.g. "users from engineering")
        or _dept_from_m
        # "<dept> team/staff" — dept immediately before team/staff (with optional verb prefix)
        or re.search(
            r"(?:(?:show|list|find|get|display)\s+(?:me\s+)?(?:all\s+)?(?:\w+\s+){0,3})"
            r"([a-z][a-z0-9]+)\s+"
            r"(?:team|staff)\b",
            m,
        )
        # "<dept> users/employees/staff/team/members" preceded by show/list/find/get/display
        # Allow up to 3 adjective/modifier words between verb and dept word
        or re.search(
            r"(?:show|list|find|get|display)\s+(?:me\s+)?(?:all\s+)?(?:\w+\s+){0,3}"
            r"([a-z][a-z0-9]+)\s+"
            r"(?:users?|employees?|staff|workers?|members?|people|accounts?)\b",
            m,
        )
        # "<dept> staff/team/employees" at start of message
        or re.search(
            r"^([a-z][a-z0-9]+)\s+"
            r"(?:staff|team|members?|employees?|workers?)\b",
            m,
        )
    )
    _skip_dept = {
        "the", "a", "an", "all", "any", "our", "this", "last", "past",
        "active", "inactive", "suspended", "blocked",
        "high", "medium", "low", "critical",
        "me", "also", "only",
        # relative/demonstrative pronouns and articles
        "that", "which", "where", "whose", "those", "these", "what", "when",
        "with", "without", "not", "via", "per",
        # organizational scope words that should not be departments
        "company", "organization", "organisation", "fleet", "org", "corp",
        "network", "system", "database", "infrastructure",
        # verb / action words that could be matched
        "show", "list", "find", "get", "display", "fetch",
        # user entity words themselves
        "user", "users", "employee", "employees", "staff", "member", "members",
        "worker", "workers", "people", "persons", "accounts", "account",
        # risk / filter modifiers
        "risk", "no", "without", "missing",
        # country names that can appear after "from " or "in "
        "israel", "russia", "china", "iran", "north korea", "ukraine",
        "germany", "france", "united states", "usa", "united kingdom",
        "uk", "india", "brazil", "canada", "australia", "turkey",
        "pakistan", "nigeria", "romania", "vietnam",
        # noise
        "from china", "from russia", "from india", "from germany", "from france",
    }
    if dept_m:
        dept = dept_m.group(1).strip()
        # Allow 2-char dept names (e.g. "hr", "it")
        if len(dept) >= 2 and dept not in _skip_dept and not intent["act_filters"].get("country"):
            intent["users"] = True
            intent["user_filters"]["department"] = dept

    # ── Named user lookup for activity: "alice's logins", "activity for bob" ─────
    _ACT_WORDS = r"(?:activity|logins?|events?|access|history|sessions?|saml|oauth|apps?|sign.?ins?|usage|traffic|connections?)"
    _act_user_m = (
        re.search(rf"{_name_re}'s?\s+(?:\w+\s+){{0,2}}{_ACT_WORDS}", m)
        or re.search(rf"{_ACT_WORDS}\s+(?:for|by|of)\s+{_name_re}", m)
        or re.search(rf"what\s+(?:\w+\s+){{0,3}}did\s+{_name_re}\s+(?:login|access|visit|connect|do|use)", m)
        or re.search(rf"(?:what|which)\s+(?:apps?|sites?|services?|tools?)\s+(?:does|do|did|has|have)\s+{_name_re}", m)
        or re.search(rf"(?:show|list|get|display)\s+(?:me\s+)?{_name_re}(?:'s?)?\s+(?:\w+\s+){{0,2}}{_ACT_WORDS}", m)
    )
    # Keywords that must NOT be captured as a user name in activity queries
    _ACT_NAME_SKIP = _OWNER_STOP | {
        "saml", "oauth", "vpn", "login", "access", "activity", "app",
        "network", "file", "cloud", "all", "user", "users",
    }
    if _act_user_m:
        _act_raw = _act_user_m.group(_act_user_m.lastindex) if _act_user_m.lastindex else None
        if _act_raw and _act_raw.lower() not in _ACT_NAME_SKIP and len(_act_raw) > 1:
            intent["activity"] = True
            intent["act_filters"]["user_email"] = _act_raw

    # ── Activity event type ───────────────────────────────────────────────────
    _EVENT_TYPE_PATTERNS = [
        (re.compile(r"\bsaml\b", re.IGNORECASE), "saml"),
        (re.compile(r"\boauth(?:[\s_\-]?grant)?\b", re.IGNORECASE), "oauth_grant"),
        (re.compile(r"\bapp[\s_\-]?usage\b|\bapplication[\s_\-]?usage\b", re.IGNORECASE), "app_usage"),
        (re.compile(r"\bnetwork[\s_\-]?(?:events?|activity|traffic|access|connection)\b", re.IGNORECASE), "network"),
        (re.compile(r"\bfile[\s_\-]?(?:access|events?)\b", re.IGNORECASE), "file_access"),
        (re.compile(r"\bcloud[\s_\-]?(?:access|events?|service\s+access)\b", re.IGNORECASE), "cloud_access"),
        (re.compile(r"\bvpn[\s_\-]?(?:events?|activity|connect(?:ion)?s?|logins?|logs?|sessions?)\b", re.IGNORECASE), "vpn"),
        (re.compile(r"\bapp[\s_\-]?logins?\b|\bapplication[\s_\-]?logins?\b|\blogins?.{0,6}via\s+app\b", re.IGNORECASE), "app_usage"),
    ]
    for _et_pat, _et_val in _EVENT_TYPE_PATTERNS:
        if _et_pat.search(msg):   # use original case for patterns
            intent["activity"] = True
            intent["act_filters"]["event_type"] = _et_val
            break

    # ── Activity filters ──────────────────────────────────────────────────
    if re.search(r"\b(suspicious|anomalous?|unusual|flagged|threat|malicious)\b", m):
        intent["activity"] = True
        intent["act_filters"]["is_suspicious"] = True

    # Country
    _countries = {
        "israel": "Israel", "russia": "Russia", "china": "China",
        "iran": "Iran", "north korea": "North Korea", "ukraine": "Ukraine",
        "germany": "Germany", "france": "France",
        "united states": "United States", "usa": "United States",
        "united kingdom": "United Kingdom", "uk": "United Kingdom",
        "india": "India", "brazil": "Brazil", "canada": "Canada",
        "australia": "Australia", "turkey": "Turkey", "pakistan": "Pakistan",
        "nigeria": "Nigeria", "romania": "Romania", "vietnam": "Vietnam",
    }
    for kw, name in _countries.items():
        if re.search(rf"\b{re.escape(kw)}\b", m):
            intent["activity"] = True
            intent["act_filters"]["country"] = name
            break

    # Time range
    days_m = re.search(r"(?:last|past)\s+(\d+)\s*day", m)
    if days_m:
        intent["act_filters"]["days_back"] = int(days_m.group(1))
    elif re.search(r"\btoday\b|last 24|past 24", m):
        intent["act_filters"]["days_back"] = 1
    elif re.search(r"this week|last week|past week|\b7 day", m):
        intent["act_filters"]["days_back"] = 7
    elif re.search(r"this month|last month|past month|\b30 day", m):
        intent["act_filters"]["days_back"] = 30

    # Risk level
    for level in ["critical", "high", "medium", "low"]:
        if re.search(rf"\b{level}\b.{{0,8}}risk|risk.{{0,8}}\b{level}\b", m) \
                or re.search(rf"\b{level}\b.{{0,15}}\b(endpoints?|devices?|machines?|computers?|laptops?)\b", m) \
                or re.search(rf"\b{level}\b.{{0,15}}\b(users?|employees?|staff|accounts?)\b", m):
            if intent["endpoints"]:
                intent["ep_filters"]["risk_level"] = level
            if intent["users"]:
                intent["user_filters"]["risk_level"] = level
            # Even without an explicit entity, infer from context
            if not intent["endpoints"] and not intent["users"]:
                if re.search(r"\b(users?|employees?|people|staff)\b", m):
                    intent["users"] = True
                    intent["user_filters"]["risk_level"] = level
                elif re.search(r"\b(endpoints?|devices?|machines?|computers?|laptops?)\b", m):
                    intent["endpoints"] = True
                    intent["ep_filters"]["risk_level"] = level
                else:
                    intent["risk"] = True
            break

    # ── User profile lookup ───────────────────────────────────────────────
    # Detects: "tell me about alice", "who is liad", "show alice's profile",
    #          "user details for bob", "lookup john@company.com"
    _PROFILE_STOP = _OWNER_STOP | _ACT_NAME_SKIP | {
        "high", "low", "medium", "critical", "risk", "compliance", "mfa",
        "suspended", "inactive", "active", "engineering", "finance", "hr",
        # entity words that are NOT user names
        "endpoint", "endpoints", "device", "devices", "machine", "machines",
        "laptop", "laptops", "computer", "computers", "host", "hosts",
        "event", "events", "session", "sessions", "history", "report",
        # security domain words that can appear after "about/on"
        "security", "posture", "policy", "compliance", "risk", "threat",
        "data", "info", "information", "details", "overview", "summary",
    }
    _profile_m = (
        re.search(rf"(?:tell|inform|brief)\s+me\s+(?:about|on)\s+{_name_re}\b", m)
        or re.search(rf"\bwho\s+is\s+{_name_re}\b", m)
        or re.search(rf"(?:profile|details?|info(?:rmation)?|overview|summary)\s+(?:for|of|on|about)\s+{_name_re}\b", m)
        or re.search(rf"(?:show|get|fetch|display)\s+(?:me\s+)?{_name_re}(?:'s?)?\s+(?:profile|details?|info(?:rmation)?|overview|summary)\b", m)
        or re.search(rf"(?:show|get|find)\s+(?:me\s+)?(?:user\s+)?{_name_re}\s+(?:profile|details?|overview)\b", m)
        or re.search(rf"(?:everything|all\s+(?:info|details?))\s+(?:about|on)\s+{_name_re}\b", m)
        or re.search(rf"\b(?:look\s*up|lookup|search\s+(?:for\s+)?user)\s+{_name_re}\b", m)
    )
    if _profile_m:
        _p_raw = _profile_m.group(_profile_m.lastindex) if _profile_m.lastindex else None
        if _p_raw and _p_raw.lower() not in _PROFILE_STOP and len(_p_raw) >= 2:
            intent["users"] = True
            intent["user_filters"]["profile_search"] = _p_raw
            # Profile is self-contained — suppress other entities from fallback
            intent["endpoints"] = False
            intent["ep_filters"] = {}
            intent["compliance"] = False
            intent["risk"] = False

    # ── Cross-intent cleanup ──────────────────────────────────────────────
    # If we have a specific endpoint filter, don't also show compliance summary
    # (keep compliance for explicit comparison queries like "compare compliant vs non-compliant")
    if intent["ep_filters"] and intent["compliance"]:
        if not re.search(r"\bcompar\w+|\bvs\b|\bversus\b", m):
            intent["compliance"] = False

    # If risk is filtered on a specific entity, suppress the generic risk distribution
    if intent["risk"] and (intent["ep_filters"].get("risk_level") or intent["user_filters"].get("risk_level")):
        intent["risk"] = False

    # "endpoints without user/owner" → endpoint filter, not a users listing
    if intent["ep_filters"].get("unassigned"):
        intent["users"] = False
        intent["user_filters"] = {}

    # "users without endpoint" → user filter, not an endpoint listing
    if intent["user_filters"].get("no_endpoint"):
        intent["endpoints"] = False
        intent["ep_filters"] = {}

    # If we have a user filter, don't also list endpoints
    if intent["user_filters"] and intent["endpoints"] and not intent["ep_filters"]:
        intent["endpoints"] = False

    # If activity has specific filters and "user" was generic in the query, suppress users
    # e.g. "list apps that user login to via saml" — "user" is generic, not a users filter
    if (intent["activity"] and intent["act_filters"].get("event_type")
            and intent["users"] and not intent["user_filters"]):
        intent["users"] = False

    # ── Fallback ──────────────────────────────────────────────────────────
    if not any([intent["endpoints"], intent["users"], intent["activity"],
                intent["compliance"], intent["risk"]]):
        intent["compliance"] = True
        intent["risk"] = True

    return intent


# ---------------------------------------------------------------------------
# DB fetch functions  (no row limit — caller decides)
# ---------------------------------------------------------------------------

async def _fetch_endpoints(params: dict, db: AsyncSession, limit: int = 200) -> dict:
    q = (
        select(Endpoint)
        .options(
            selectinload(Endpoint.agents),
            selectinload(Endpoint.compliance_status),
            selectinload(Endpoint.owner),
        )
        .where(Endpoint.is_active == True)  # noqa: E712
    )

    if params.get("search"):
        s = f"%{params['search']}%"
        q = q.where(or_(Endpoint.hostname.ilike(s), Endpoint.ip_address.ilike(s)))

    if params.get("os"):
        mapping = {
            "windows": ["Windows"],
            "macos":   ["macOS", "Mac OS", "Darwin"],
            "linux":   ["Linux", "Ubuntu", "CentOS", "Debian", "Fedora"],
        }
        kws = mapping.get(params["os"].lower(), [params["os"]])
        q = q.where(or_(*[Endpoint.os_version.ilike(f"%{k}%") for k in kws]))

    if params.get("risk_level") and params["risk_level"] in RISK_RANGES:
        lo, hi = RISK_RANGES[params["risk_level"]]
        q = q.where(Endpoint.risk_score >= lo, Endpoint.risk_score <= hi)

    if params.get("owner_name"):
        q = q.join(User, User.id == Endpoint.owner_user_id).where(
            or_(
                User.email.ilike(f"%{params['owner_name']}%"),
                User.full_name.ilike(f"%{params['owner_name']}%"),
            )
        )

    if params.get("unassigned"):
        q = q.where(Endpoint.owner_user_id == None)  # noqa: E711

    needs_cs = any(params.get(k) for k in ["compliance_status", "edr_outdated", "edr_missing",
                                             "dlp_missing", "disk_not_encrypted"])
    if needs_cs:
        q = q.join(ComplianceStatus, ComplianceStatus.endpoint_id == Endpoint.id)
        if params.get("compliance_status"):
            q = q.where(ComplianceStatus.status == params["compliance_status"])
        if params.get("edr_outdated"):
            q = q.where(ComplianceStatus.edr_installed == True,          # noqa: E712
                        ComplianceStatus.edr_version_ok.isnot(True))
        if params.get("edr_missing"):
            q = q.where(ComplianceStatus.edr_installed.isnot(True))
        if params.get("dlp_missing"):
            q = q.where(ComplianceStatus.dlp_installed.isnot(True))
        if params.get("disk_not_encrypted"):
            q = q.where(ComplianceStatus.disk_encrypted.isnot(True))

    result = await db.execute(q.limit(limit))
    endpoints = list(result.scalars().unique().all())

    if params.get("vpn_missing"):
        endpoints = [ep for ep in endpoints
                     if not any(a.product_name in ("globalprotect", "symantec_wss") for a in ep.agents)]
    if params.get("agent_inactive"):
        endpoints = [ep for ep in endpoints if any(a.status == "inactive" for a in ep.agents)]

    rows = []
    for ep in endpoints:
        s1  = next((a for a in ep.agents if a.product_name == "sentinelone"),   None)
        dlp = next((a for a in ep.agents if a.product_name == "symantec"),      None)
        gp  = next((a for a in ep.agents if a.product_name == "globalprotect"), None)
        wss = next((a for a in ep.agents if a.product_name == "symantec_wss"),  None)
        cs  = ep.compliance_status
        rows.append({
            "hostname":    ep.hostname,
            "owner":       ep.owner.email.split("@")[0] if ep.owner else "—",
            "os":          _short_os(ep.os_version),
            "risk":        int(ep.risk_score or 0),
            "compliance":  cs.status if cs else "unknown",
            "s1":          "ok" if (s1 and s1.status == "active" and cs and cs.edr_version_ok)
                           else ("outdated" if (s1 and cs and not cs.edr_version_ok)
                           else ("inactive" if s1 else "missing")),
            "dlp":         "ok" if (dlp and dlp.status == "active") else ("inactive" if dlp else "missing"),
            "vpn":         "GP" if gp else ("WSS" if wss else "none"),
            "encrypted":   "yes" if (cs and cs.disk_encrypted) else "no",
            "last_seen":   ep.last_seen.strftime("%Y-%m-%d") if ep.last_seen else "—",
        })
    return {"count": len(rows), "rows": rows}


def _short_os(v: str | None) -> str:
    if not v:
        return "—"
    if "Windows" in v:
        m = re.search(r"(\d+)", v.split("Windows")[-1])
        return f"Win {m.group(1)}" if m else "Windows"
    if "macOS" in v or "Mac OS" in v or "Darwin" in v:
        m = re.search(r"(\d+\.\d+)", v)
        return f"macOS {m.group(1)}" if m else "macOS"
    if "Linux" in v or "Ubuntu" in v:
        return "Linux"
    return v[:18]


async def _fetch_users(params: dict, db: AsyncSession, limit: int = 200) -> dict:
    q = select(User)

    if params.get("search"):
        s = f"%{params['search']}%"
        q = q.where(or_(User.full_name.ilike(s), User.email.ilike(s)))
    if params.get("department"):
        q = q.where(User.department.ilike(f"%{params['department']}%"))
    if "mfa_enabled" in params and params["mfa_enabled"] is not None:
        q = q.where(User.mfa_enabled == params["mfa_enabled"])
    if params.get("employment_status"):
        q = q.where(User.employment_status == params["employment_status"])
    if params.get("suspended") is not None:
        q = q.where(User.suspended == params["suspended"])
    if params.get("risk_level") and params["risk_level"] in RISK_RANGES:
        lo, hi = RISK_RANGES[params["risk_level"]]
        q = q.where(User.risk_score >= lo, User.risk_score <= hi)

    result = await db.execute(q.limit(limit))
    users = list(result.scalars().all())

    ep_counts: dict = {}
    if users:
        ids = [u.id for u in users]
        cr = await db.execute(
            select(Endpoint.owner_user_id, func.count(Endpoint.id).label("cnt"))
            .where(Endpoint.owner_user_id.in_(ids), Endpoint.is_active == True)  # noqa: E712
            .group_by(Endpoint.owner_user_id)
        )
        ep_counts = {row.owner_user_id: row.cnt for row in cr}

    if params.get("no_endpoint"):
        users = [u for u in users if ep_counts.get(u.id, 0) == 0]

    rows = []
    for u in users:
        rows.append({
            "name":       (u.full_name or u.email.split("@")[0])[:28],
            "email":      u.email,
            "dept":       (u.department or "—")[:20],
            "title":      (u.job_title or "—")[:24],
            "status":     "suspended" if u.suspended else (u.employment_status or "active"),
            "mfa":        "yes" if u.mfa_enabled else "NO",
            "risk":       int(u.risk_score or 0),
            "devices":    ep_counts.get(u.id, 0),
            "last_login": u.last_login.strftime("%Y-%m-%d") if u.last_login else "never",
        })
    return {"count": len(rows), "rows": rows}


async def _fetch_activity(params: dict, db: AsyncSession, limit: int = 200) -> dict:
    q = select(ActivityEvent).options(selectinload(ActivityEvent.user))

    if params.get("event_type"):
        q = q.where(ActivityEvent.event_type.in_(params["event_type"].split(",")))
    if params.get("country"):
        q = q.where(ActivityEvent.country.ilike(f"%{params['country']}%"))
    if params.get("ip_address"):
        q = q.where(ActivityEvent.ip_address.ilike(f"%{params['ip_address']}%"))
    if params.get("is_suspicious") is not None:
        q = q.where(ActivityEvent.is_suspicious == params["is_suspicious"])
    if params.get("user_email"):
        q = q.join(User, User.id == ActivityEvent.user_id).where(
            User.email.ilike(f"%{params['user_email']}%"))

    days = int(params.get("days_back", 30))
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    q = q.where(ActivityEvent.timestamp >= cutoff)

    result = await db.execute(q.order_by(ActivityEvent.timestamp.desc()).limit(limit))
    events = list(result.scalars().unique().all())

    rows = []
    for ev in events:
        d = ev.details or {}
        rows.append({
            "user":    (ev.user.full_name if ev.user else d.get("actor") or "?")[:24],
            "email":   ev.user.email if ev.user else "—",
            "type":    ev.event_type,
            "time":    ev.timestamp.strftime("%Y-%m-%d %H:%M"),
            "country": ev.country or "—",
            "ip":      ev.ip_address or "—",
            "susp":    "⚠ YES" if ev.is_suspicious else "no",
            "app":     (d.get("app_name") or d.get("application_name") or "—")[:20],
        })
    return {"count": len(rows), "days": days, "rows": rows}


async def _fetch_user_profile(search: str, db: AsyncSession) -> dict | None:
    """
    Load a single user's full profile: identity, devices, and recent activity.
    Searches by email prefix/name fragment (case-insensitive).
    Returns None if no user is found.
    """
    # Find all matching users so we can warn when ambiguous
    q = select(User).where(
        or_(
            User.email.ilike(f"%{search}%"),
            User.full_name.ilike(f"%{search}%"),
        )
    ).limit(5)
    result = await db.execute(q)
    users = list(result.scalars().all())

    if not users:
        return None

    user = users[0]

    # Load their endpoints with agents + compliance
    ep_q = (
        select(Endpoint)
        .options(
            selectinload(Endpoint.agents),
            selectinload(Endpoint.compliance_status),
        )
        .where(Endpoint.owner_user_id == user.id, Endpoint.is_active == True)  # noqa: E712
    )
    ep_result = await db.execute(ep_q)
    endpoints = list(ep_result.scalars().unique().all())

    # Format endpoint rows
    ep_rows = []
    for ep in endpoints:
        s1  = next((a for a in ep.agents if a.product_name == "sentinelone"),   None)
        gp  = next((a for a in ep.agents if a.product_name == "globalprotect"), None)
        wss = next((a for a in ep.agents if a.product_name == "symantec_wss"),  None)
        cs  = ep.compliance_status
        s1_status = (
            "ok" if (s1 and s1.status == "active" and cs and cs.edr_version_ok)
            else "outdated" if (s1 and cs and not cs.edr_version_ok)
            else "inactive" if s1 else "missing"
        )
        ep_rows.append({
            "hostname":   ep.hostname,
            "os":         _short_os(ep.os_version),
            "risk":       int(ep.risk_score or 0),
            "s1":         s1_status,
            "vpn":        "GP" if gp else ("WSS" if wss else "none"),
            "encrypted":  "yes" if (cs and cs.disk_encrypted) else "no",
            "compliance": cs.status if cs else "unknown",
            "last_seen":  ep.last_seen.strftime("%Y-%m-%d") if ep.last_seen else "—",
        })

    # Load recent activity (last 60 days, up to 15 events)
    cutoff = datetime.now(timezone.utc) - timedelta(days=60)
    act_q = (
        select(ActivityEvent)
        .where(ActivityEvent.user_id == user.id, ActivityEvent.timestamp >= cutoff)
        .order_by(ActivityEvent.timestamp.desc())
        .limit(15)
    )
    act_result = await db.execute(act_q)
    events = list(act_result.scalars().unique().all())

    act_rows = []
    for ev in events:
        d = ev.details or {}
        act_rows.append({
            "type":    ev.event_type,
            "time":    ev.timestamp.strftime("%Y-%m-%d %H:%M"),
            "country": ev.country or "—",
            "ip":      ev.ip_address or "—",
            "app":     (d.get("app_name") or d.get("application_name") or "—")[:28],
            "susp":    "⚠" if ev.is_suspicious else "—",
        })

    return {
        "user":        user,
        "total_matches": len(users),
        "other_matches": [u.email for u in users[1:4]],
        "ep_rows":     ep_rows,
        "act_rows":    act_rows,
    }


async def _fetch_compliance_summary(db: AsyncSession) -> dict:
    status_r = await db.execute(
        select(ComplianceStatus.status, func.count(ComplianceStatus.id).label("cnt"))
        .join(Endpoint, ComplianceStatus.endpoint_id == Endpoint.id)
        .where(current_endpoint_clause())
        .group_by(ComplianceStatus.status)
    )
    sc = {row.status: row.cnt for row in status_r}

    async def _cnt(cond) -> int:
        r = await db.execute(
            select(func.count(ComplianceStatus.id))
            .join(Endpoint, ComplianceStatus.endpoint_id == Endpoint.id)
            .where(current_endpoint_clause(), cond)
        )
        return r.scalar_one()

    total_r = await db.execute(
        select(func.count(Endpoint.id)).where(current_endpoint_clause())
    )

    return {
        "total":         total_r.scalar_one(),
        "compliant":     sc.get("compliant", 0),
        "partial":       sc.get("partial", 0),
        "non_compliant": sc.get("non_compliant", 0),
        "no_edr":        await _cnt(ComplianceStatus.edr_installed.isnot(True)),
        "edr_outdated":  await _cnt(and_(ComplianceStatus.edr_installed == True,  # noqa: E712
                                         ComplianceStatus.edr_version_ok.isnot(True))),
        "no_dlp":        await _cnt(ComplianceStatus.dlp_installed.isnot(True)),
        "no_vpn":        await _cnt(and_(ComplianceStatus.gp_installed.isnot(True),
                                         ComplianceStatus.wss_installed.isnot(True))),
        "no_encrypt":    await _cnt(ComplianceStatus.disk_encrypted.isnot(True)),
        "no_devctrl":    await _cnt(ComplianceStatus.device_control_enabled.isnot(True)),
    }


async def _fetch_risk_summary(db: AsyncSession) -> dict:
    async def _risk(model, col):
        out = {}
        for level, (lo, hi) in RISK_RANGES.items():
            r = await db.execute(select(func.count(model.id)).where(col >= lo, col <= hi))
            out[level] = r.scalar_one()
        return out
    return {
        "users":     await _risk(User, User.risk_score),
        "endpoints": await _risk(Endpoint, Endpoint.risk_score),
    }


# ---------------------------------------------------------------------------
# Direct formatter  (no LLM — used for listing queries)
# ---------------------------------------------------------------------------

def _ep_filter_desc(ep_f: dict) -> str:
    """Return a short human-readable description of the active endpoint filters."""
    parts = []
    if ep_f.get("owner_name"):     parts.append(f"endpoints owned by {ep_f['owner_name']}")
    if ep_f.get("unassigned"):     parts.append("unassigned endpoints")
    if ep_f.get("edr_missing"):    parts.append("endpoints missing EDR")
    if ep_f.get("edr_outdated"):   parts.append("endpoints with outdated S1")
    if ep_f.get("vpn_missing"):    parts.append("endpoints without VPN")
    if ep_f.get("dlp_missing"):    parts.append("endpoints without DLP")
    if ep_f.get("disk_not_encrypted"): parts.append("unencrypted endpoints")
    if ep_f.get("risk_level"):     parts.append(f"{ep_f['risk_level']}-risk endpoints")
    if ep_f.get("compliance_status"): parts.append(f"{ep_f['compliance_status'].replace('_',' ')} endpoints")
    if ep_f.get("os"):             parts.append(f"{ep_f['os']} endpoints")
    return ", ".join(parts) if parts else "endpoints"


def _md_table(rows: list[dict], cols: list[str]) -> str:
    if not rows:
        return "*(no results found)*"
    cols = [c for c in cols if c in rows[0]]
    header = " | ".join(f"**{c}**" for c in cols)
    sep    = " | ".join("---" for _ in cols)
    lines  = [header, sep]
    for r in rows:
        lines.append(" | ".join(str(r.get(c, "—")) for c in cols))
    return "\n".join(lines)


def _sort_rows(rows: list[dict], key: str | None) -> list[dict]:
    """Sort rows by the given key (descending for numeric, ascending for strings)."""
    if not key or not rows or key not in rows[0]:
        return rows
    sample = rows[0][key]
    reverse = isinstance(sample, (int, float))
    try:
        return sorted(rows, key=lambda r: (r[key] is None, r[key]), reverse=reverse)
    except TypeError:
        return rows


async def _direct_response(intent: dict, db: AsyncSession, sort_key: str | None = None) -> str:
    """Build a complete formatted response without using the LLM."""
    parts: list[str] = []

    if intent["compliance"]:
        d = await _fetch_compliance_summary(db)
        parts.append(
            f"**Compliance Summary** — {d['total']} active endpoints\n\n"
            f"| Status | Count |\n|---|---|\n"
            f"| ✅ Compliant | {d['compliant']} |\n"
            f"| 🟡 Partial | {d['partial']} |\n"
            f"| ❌ Non-compliant | {d['non_compliant']} |\n\n"
            f"**Gaps:** No EDR: {d['no_edr']} · Outdated EDR: {d['edr_outdated']} · "
            f"No DLP: {d['no_dlp']} · No VPN: {d['no_vpn']} · "
            f"No disk encryption: {d['no_encrypt']} · No device control: {d['no_devctrl']}"
        )

    if intent["risk"]:
        d = await _fetch_risk_summary(db)
        u, e = d["users"], d["endpoints"]
        parts.append(
            f"**Risk Distribution**\n\n"
            f"| | 🔴 Critical | 🟠 High | 🟡 Medium | 🟢 Low |\n|---|---|---|---|---|\n"
            f"| Users | {u['critical']} | {u['high']} | {u['medium']} | {u['low']} |\n"
            f"| Endpoints | {e['critical']} | {e['high']} | {e['medium']} | {e['low']} |"
        )

    if intent["endpoints"]:
        r = await _fetch_endpoints(intent["ep_filters"], db, limit=500)
        ep_f = intent["ep_filters"]

        # ── Build a combined description that reflects ALL active filters ────
        ep_desc_parts: list[str] = []
        if ep_f.get("risk_level"):           ep_desc_parts.append(f"{ep_f['risk_level']}-risk")
        if ep_f.get("os"):                   ep_desc_parts.append(ep_f["os"])
        if ep_f.get("compliance_status") == "non_compliant": ep_desc_parts.append("non-compliant")
        if ep_f.get("compliance_status") == "partial":       ep_desc_parts.append("partially-compliant")
        if ep_f.get("compliance_status") == "compliant":     ep_desc_parts.append("fully-compliant")
        if ep_f.get("owner_name"):            ep_desc_parts.append(f"owned by {ep_f['owner_name']}")
        if ep_f.get("unassigned"):           ep_desc_parts.append("unassigned")
        ep_desc_parts.append("endpoints")
        if ep_f.get("edr_outdated"):         ep_desc_parts.append("with outdated S1")
        if ep_f.get("edr_missing"):          ep_desc_parts.append("missing EDR")
        if ep_f.get("vpn_missing"):          ep_desc_parts.append("without VPN")
        if ep_f.get("dlp_missing"):          ep_desc_parts.append("without DLP")
        if ep_f.get("disk_not_encrypted"):   ep_desc_parts.append("without disk encryption")
        if ep_f.get("agent_inactive"):       ep_desc_parts.append("with inactive agents")
        # Build header — capitalise first word but preserve acronyms (VPN, EDR, DLP, S1)
        ep_label = " ".join(ep_desc_parts)
        ep_first = ep_label[:1].upper() + ep_label[1:]  # only first char
        header = f"**{ep_first}** — {r['count']} found"

        # Columns: show most informative set given the active filters
        if ep_f.get("unassigned"):
            cols = ["hostname", "os", "risk", "compliance", "last_seen"]
        elif ep_f.get("edr_outdated"):
            cols = ["hostname", "owner", "os", "s1"]
        elif ep_f.get("edr_missing"):
            cols = ["hostname", "owner", "os", "compliance"]
        elif ep_f.get("vpn_missing"):
            cols = ["hostname", "owner", "os", "vpn"]
        elif ep_f.get("dlp_missing"):
            cols = ["hostname", "owner", "os", "dlp"]
        elif ep_f.get("disk_not_encrypted"):
            cols = ["hostname", "owner", "os", "encrypted"]
        elif ep_f.get("agent_inactive"):
            cols = ["hostname", "owner", "os", "s1", "dlp"]
        elif ep_f.get("compliance_status"):
            cols = ["hostname", "owner", "os", "s1", "dlp", "vpn", "encrypted"]
        elif ep_f.get("risk_level"):
            cols = ["hostname", "owner", "os", "risk", "compliance"]
        else:
            cols = ["hostname", "owner", "os", "risk", "compliance", "s1", "vpn"]

        ep_rows = _sort_rows(r["rows"], sort_key)
        parts.append(f"{header}\n\n{_md_table(ep_rows, cols)}")

    # ── Owner pivot: show owners of the filtered endpoint set ─────────────────
    if intent.get("_owner_pivot") and intent["ep_filters"]:
        ep_r = await _fetch_endpoints(intent["ep_filters"], db, limit=500)
        owner_names = {row["owner"] for row in ep_r["rows"] if row["owner"] != "—"}
        if owner_names:
            # Fetch those specific users
            from sqlalchemy import or_
            q = select(User).where(
                or_(*[User.email.ilike(f"{name}@%") for name in owner_names])
            )
            result = await db.execute(q.limit(500))
            users = list(result.scalars().all())
            ep_counts: dict = {}
            if users:
                ids = [u.id for u in users]
                cr = await db.execute(
                    select(Endpoint.owner_user_id, func.count(Endpoint.id).label("cnt"))
                    .where(Endpoint.owner_user_id.in_(ids), Endpoint.is_active == True)  # noqa: E712
                    .group_by(Endpoint.owner_user_id)
                )
                ep_counts = {row.owner_user_id: row.cnt for row in cr}
            rows = [{
                "name":       (u.full_name or u.email.split("@")[0])[:28],
                "email":      u.email,
                "dept":       (u.department or "—")[:20],
                "mfa":        "yes" if u.mfa_enabled else "NO",
                "risk":       int(u.risk_score or 0),
                "devices":    ep_counts.get(u.id, 0),
            } for u in users]
            rows = _sort_rows(rows, sort_key)
            ep_desc = _ep_filter_desc(intent["ep_filters"])
            header = f"**Owners of {ep_desc}** — {len(rows)} found"
            parts.append(f"{header}\n\n{_md_table(rows, ['name','email','dept','mfa','risk','devices'])}")
        else:
            parts.append("*None of those endpoints have an assigned owner.*")

    # ── User profile (single-person deep-dive) ───────────────────────────────
    if intent["users"] and intent["user_filters"].get("profile_search"):
        search = intent["user_filters"]["profile_search"]
        profile = await _fetch_user_profile(search, db)
        if profile is None:
            parts.append(f"*No user found matching **{search}**.*")
        else:
            u = profile["user"]
            # Risk label
            risk_score = int(u.risk_score or 0)
            if risk_score >= 76:   risk_label = "🔴 Critical"
            elif risk_score >= 51: risk_label = "🟠 High"
            elif risk_score >= 26: risk_label = "🟡 Medium"
            else:                  risk_label = "🟢 Low"

            mfa_label    = "✅ Enabled" if u.mfa_enabled else "❌ Disabled"
            status_label = ("🔒 Suspended" if u.suspended
                            else "💤 Inactive" if u.employment_status == "inactive"
                            else "✅ Active")

            # Identity card
            card_rows = [
                ["Department", u.department or "—"],
                ["Title",      u.job_title or "—"],
                ["Manager",    u.manager or "—"],
                ["Status",     status_label],
                ["MFA",        mfa_label],
                ["Risk",       f"{risk_score} — {risk_label}"],
                ["Last Login", u.last_login.strftime("%Y-%m-%d %H:%M") if u.last_login else "never"],
            ]
            card_md = "**Field** | **Value**\n--- | ---\n"
            card_md += "\n".join(f"{r[0]} | {r[1]}" for r in card_rows)

            name_display = u.full_name or u.email.split("@")[0]
            header_line = f"**{name_display}** — {u.email}"
            if profile["total_matches"] > 1:
                others = ", ".join(profile["other_matches"])
                header_line += f"\n\n*Also matched: {others} — showing first result.*"

            # Devices section
            if profile["ep_rows"]:
                ep_md = _md_table(profile["ep_rows"],
                                  ["hostname", "os", "risk", "s1", "vpn", "encrypted", "compliance"])
                devices_section = f"**Devices** — {len(profile['ep_rows'])} found\n\n{ep_md}"
            else:
                devices_section = "**Devices** — none assigned"

            # Activity section
            if profile["act_rows"]:
                act_md = _md_table(profile["act_rows"],
                                   ["type", "time", "country", "ip", "app", "susp"])
                activity_section = f"**Recent Activity** — last 60 days — {len(profile['act_rows'])} events\n\n{act_md}"
            else:
                activity_section = "**Recent Activity** — no events in the last 60 days"

            parts.append(
                f"{header_line}\n\n{card_md}\n\n---\n\n"
                f"{devices_section}\n\n---\n\n{activity_section}"
            )
        # Profile is a complete response on its own — stop here
        return "\n\n---\n\n".join(parts) if parts else "No data found for this query."

    if intent["users"] and not intent.get("_owner_pivot"):
        r = await _fetch_users(intent["user_filters"], db, limit=500)
        uf = intent["user_filters"]

        # Build a combined description that reflects ALL active filters
        desc_parts: list[str] = []
        if uf.get("risk_level"):       desc_parts.append(f"{uf['risk_level']}-risk")
        if uf.get("suspended"):        desc_parts.append("suspended")
        if uf.get("employment_status") == "inactive": desc_parts.append("inactive")
        if "mfa_enabled" in uf:        desc_parts.append("with MFA" if uf["mfa_enabled"] else "without MFA")
        if uf.get("no_endpoint"):      desc_parts.append("with no endpoint")
        if uf.get("department"):       desc_parts.append(f"in {uf['department']}")

        entity_desc = " ".join(desc_parts) + " users" if desc_parts else "users"
        header = f"**{entity_desc.capitalize()}** — {r['count']} found"

        # Columns: show most relevant set based on primary filter
        if uf.get("no_endpoint"):
            cols = ["name", "email", "dept", "status", "last_login"]
        elif uf.get("risk_level") or uf.get("suspended"):
            cols = ["name", "email", "dept", "risk", "mfa", "status"]
        elif "mfa_enabled" in uf:
            cols = ["name", "email", "dept", "risk", "last_login"]
        elif uf.get("department"):
            cols = ["name", "email", "title", "mfa", "risk", "devices"]
        else:
            cols = ["name", "email", "dept", "mfa", "risk", "devices"]

        rows = _sort_rows(r["rows"], sort_key)
        parts.append(f"{header}\n\n{_md_table(rows, cols)}")

    if intent["activity"]:
        r = await _fetch_activity(intent["act_filters"], db, limit=200)
        af = intent["act_filters"]
        days = r["days"]

        # Build header from active filters
        _EVENT_LABELS = {
            "saml": "SAML", "oauth_grant": "OAuth", "app_usage": "App usage",
            "network": "Network", "file_access": "File access",
            "cloud_access": "Cloud access", "vpn": "VPN", "login": "Login",
        }
        _type_label = _EVENT_LABELS.get(af.get("event_type", ""), "Activity")
        _hdr_adj: list[str] = []
        if af.get("is_suspicious"):
            _hdr_adj.append("suspicious")
        _hdr_noun = ((" ".join(_hdr_adj) + " " if _hdr_adj else "") + _type_label + " events").strip()
        _hdr_detail: list[str] = []
        if af.get("country"):
            _hdr_detail.append(f"from {af['country']}")
        if af.get("user_email"):
            _hdr_detail.append(f"for {af['user_email']}")
        _hdr_label = _hdr_noun + (" " + " ".join(_hdr_detail) if _hdr_detail else "")
        header = f"**{_hdr_label[:1].upper() + _hdr_label[1:]}** — last {days} days — {r['count']} events"

        if af.get("is_suspicious") or af.get("event_type") in ("saml", "oauth_grant", "app_usage", "cloud_access"):
            cols = ["user", "email", "type", "time", "country", "ip", "app"]
        elif af.get("country"):
            cols = ["user", "email", "type", "time", "country", "ip", "susp"]
        elif af.get("user_email"):
            cols = ["type", "time", "country", "ip", "app", "susp"]
        else:
            cols = ["user", "type", "time", "country", "ip", "susp"]

        parts.append(f"{header}\n\n{_md_table(r['rows'], cols)}")

    return "\n\n---\n\n".join(parts) if parts else "No data found for this query."


# ---------------------------------------------------------------------------
# LLM context builder  (used only for analysis queries)
# ---------------------------------------------------------------------------

async def _build_llm_context(intent: dict, db: AsyncSession) -> str:
    parts: list[str] = []

    if intent["compliance"]:
        d = await _fetch_compliance_summary(db)
        parts.append(
            f"COMPLIANCE (total={d['total']}): compliant={d['compliant']} "
            f"partial={d['partial']} non_compliant={d['non_compliant']} | "
            f"no_edr={d['no_edr']} edr_outdated={d['edr_outdated']} no_dlp={d['no_dlp']} "
            f"no_vpn={d['no_vpn']} no_encryption={d['no_encrypt']} no_devctrl={d['no_devctrl']}"
        )

    if intent["risk"]:
        d = await _fetch_risk_summary(db)
        u, e = d["users"], d["endpoints"]
        parts.append(
            f"RISK: users(crit={u['critical']} high={u['high']} med={u['medium']} low={u['low']}) "
            f"endpoints(crit={e['critical']} high={e['high']} med={e['medium']} low={e['low']})"
        )

    if intent["endpoints"]:
        r = await _fetch_endpoints(intent["ep_filters"], db, limit=10)
        ep_f = intent["ep_filters"]
        if ep_f.get("unassigned"):
            cols = ["hostname", "os", "compliance"]
        elif ep_f.get("edr_outdated"):
            cols = ["hostname", "owner", "s1"]
        elif ep_f.get("vpn_missing"):
            cols = ["hostname", "owner", "vpn"]
        elif ep_f.get("compliance_status"):
            cols = ["hostname", "owner", "s1", "dlp", "vpn"]
        else:
            cols = ["hostname", "owner", "compliance", "risk"]
        rows_str = " | ".join(",".join(str(row.get(c,"—")) for c in cols) for row in r["rows"][:8])
        parts.append(f"ENDPOINTS({r['count']} total): [{rows_str}]")

    if intent["users"]:
        r = await _fetch_users(intent["user_filters"], db, limit=10)
        uf = intent["user_filters"]
        if "mfa_enabled" in uf:
            cols = ["name", "email"]
        elif uf.get("no_endpoint"):
            cols = ["name", "email"]
        else:
            cols = ["name", "email", "risk"]
        rows_str = " | ".join(",".join(str(row.get(c,"—")) for c in cols) for row in r["rows"][:8])
        parts.append(f"USERS({r['count']} total): [{rows_str}]")

    if intent["activity"]:
        r = await _fetch_activity(intent["act_filters"], db, limit=10)
        rows_str = " | ".join(
            f"{row['user']},{row['type']},{row['country']},{row['susp']}"
            for row in r["rows"][:8]
        )
        parts.append(f"ACTIVITY({r['count']} events, last {r['days']}d): [{rows_str}]")

    return "\n".join(parts)


# ---------------------------------------------------------------------------
# Conversational handler  (greetings, thanks, help — no DB needed)
# ---------------------------------------------------------------------------

_GREETING_RE = re.compile(
    r"^\s*(hi|hello|hey|howdy|good\s+(morning|afternoon|evening|day))(\s+(there|all|everyone))?[!,.\s]*$",
    re.IGNORECASE,
)
_THANKS_RE = re.compile(
    r"^\s*(thanks?\s*(a\s*(lot|bunch|ton))?|thank\s+you(\s+so\s+much)?|thx|ty|cheers|great|perfect|awesome|nice|cool)[!,.\s]*$",
    re.IGNORECASE,
)
_HELP_RE = re.compile(
    r"\b(what can you (do|help)|help me|how (do i|can i) (use|get started)|"
    r"what (do|can) you (do|know|show)|who are you|what are you|capabilities|features|"
    r"get started|what can i (ask|do|query)|what queries can i|"
    r"what can i (ask|say|use|do))\b",
    re.IGNORECASE,
)


def _handle_conversational(msg: str) -> str | None:
    """Return a canned response for purely conversational messages, or None."""
    m = msg.strip()
    if _GREETING_RE.match(m):
        return (
            "Hi! I'm your Security Assistant. I can help you query your security posture.\n\n"
            "Try asking:\n"
            "- *List endpoints without VPN*\n"
            "- *Show users without MFA*\n"
            "- *Suspicious login events this week*\n"
            "- *Non-compliant endpoints*"
        )
    if _THANKS_RE.match(m):
        return "Happy to help! Let me know if you need anything else."
    if _HELP_RE.search(m):
        return (
            "Here's what I can help you with:\n\n"
            "**Endpoints** — list by OS, risk, VPN / EDR / DLP status, compliance, encryption\n"
            "**Users** — filter by MFA, risk score, department, activity status\n"
            "**Login activity** — suspicious events, by country, time range\n"
            "**Compliance** — summary, non-compliant devices, gap analysis\n"
            "**Risk** — distribution across users and endpoints\n\n"
            "You can chain questions too — ask a list query, then follow up with "
            "*\"which of those are Windows?\"* or *\"who owns them?\"*"
        )
    return None


# ---------------------------------------------------------------------------
# Follow-up suggestion generator
# ---------------------------------------------------------------------------

def _suggest_followups(intent: dict) -> list[str]:
    """Generate up to 3 contextual follow-up questions based on the active intent."""
    suggestions: list[str] = []
    ep_f = intent.get("ep_filters") or {}
    uf   = intent.get("user_filters") or {}
    af   = intent.get("act_filters") or {}

    if intent.get("endpoints") or ep_f:
        if not ep_f.get("os"):
            suggestions.append("Which of those are Windows?")
        if not ep_f.get("edr_missing"):
            suggestions.append("Which of those are also missing EDR?")
        if not intent.get("_owner_pivot"):
            suggestions.append("Who owns them?")
        if not ep_f.get("risk_level"):
            suggestions.append("Show me the high-risk ones")

    elif uf.get("profile_search"):
        name = uf["profile_search"]
        suggestions = [
            f"Show {name}'s login activity",
            f"Show {name}'s devices",
            f"What SAML apps did {name} use?",
        ]

    elif intent.get("users") or uf:
        if "mfa_enabled" not in uf or uf.get("mfa_enabled") is not False:
            suggestions.append("Which of those are missing MFA?")
        if not uf.get("risk_level"):
            suggestions.append("Show me the high-risk ones")
        suggestions.append("What devices do they have?")

    elif intent.get("activity") or af:
        if not af.get("is_suspicious"):
            suggestions.append("Show me only the suspicious ones")
        if not af.get("country"):
            suggestions.append("Which of those are from Russia?")
        suggestions.append("Show login activity from Israel")

    elif intent.get("compliance"):
        suggestions = [
            "List non-compliant endpoints",
            "Show endpoints missing disk encryption",
            "Which endpoints are missing EDR?",
        ]

    elif intent.get("risk"):
        suggestions = [
            "Show high-risk users",
            "List critical-risk endpoints",
            "Show non-compliant endpoints",
        ]

    return suggestions[:3]


# ---------------------------------------------------------------------------
# Ollama streaming
# ---------------------------------------------------------------------------

async def _stream_ollama(messages: list[dict]) -> AsyncIterator[str]:
    try:
        async with httpx.AsyncClient(timeout=180.0) as client:
            async with client.stream(
                "POST",
                f"{OLLAMA_BASE}/api/chat",
                json={
                    "model":      OLLAMA_MODEL,
                    "messages":   messages,
                    "stream":     True,
                    "keep_alive": KEEP_ALIVE,
                    "options": {
                        "temperature":    0.05,
                        "num_ctx":        2048,
                        "num_thread":     4,
                        "num_predict":    220,
                        "repeat_penalty": 1.1,
                    },
                },
            ) as resp:
                resp.raise_for_status()
                async for line in resp.aiter_lines():
                    if not line.strip():
                        continue
                    try:
                        chunk = json.loads(line)
                        token = chunk.get("message", {}).get("content", "")
                        if token:
                            yield token
                        if chunk.get("done"):
                            break
                    except json.JSONDecodeError:
                        continue
    except httpx.ConnectError:
        yield "\n\n*Error: Ollama is not running.*"
    except Exception as exc:
        logger.error("Ollama stream error: %s", exc, exc_info=True)
        yield f"\n\n*Error: {exc}*"


async def _stream_direct(text: str, suggestions: list[str] | None = None) -> AsyncIterator[str]:
    """Yield a pre-built string, optionally followed by a suggestions marker."""
    yield text
    if suggestions:
        marker = "|".join(s.replace("|", "") for s in suggestions)
        yield f"\n<!--SUGGESTIONS:{marker}-->"


def _build_messages(
    question: str,
    history: list[ChatMessage],
    context: str,
    conv_context: str = "",
) -> list[dict]:
    msgs: list[dict] = [{"role": "system", "content": SYSTEM_PROMPT}]

    # Include up to 6 history messages (3 full exchanges), trim long assistant replies
    for m in history[-6:]:
        content = m.content
        if m.role == "assistant" and len(content) > 500:
            # Keep first 500 chars so the LLM knows what was shown without blowing the context
            content = content[:500] + "\n…[result truncated for context]"
        msgs.append({"role": m.role, "content": content})

    # Build the user turn: inject conversation context + DB data + question
    parts = []
    if conv_context:
        parts.append(f"CONTEXT: {conv_context}")
    if context:
        parts.append(f"DATA: {context}")
    parts.append(f"QUESTION: {question}")
    msgs.append({"role": "user", "content": "\n\n".join(parts)})
    return msgs


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

async def _handle(body: ChatRequest, db: AsyncSession) -> AsyncIterator[str]:
    # ── Conversational short-circuit ─────────────────────────────────────────
    conv_resp = _handle_conversational(body.message)
    if conv_resp:
        return _stream_direct(conv_resp)

    intent = _detect_intent(body.message)

    # ── Conversational context resolution ────────────────────────────────────
    is_followup = _is_followup(body.message, body.history)
    if is_followup:
        prev_intent = _extract_prev_intent(body.history)
        if prev_intent:
            intent = _merge_intents(prev_intent, intent, body.message)
            logger.debug("Follow-up detected — merged intent: %s", intent)

    # ── Sort key ─────────────────────────────────────────────────────────────
    sort_key = _extract_sort(body.message)

    # ── Routing decision ─────────────────────────────────────────────────────
    # Direct (no-LLM) path:
    #   a) explicit list signal in the message, OR
    #   b) query has specific entity filters and no analysis signal
    # Activity with specific filters (event_type, user_email, country, is_suspicious) routes direct
    _act_f = intent.get("act_filters") or {}
    _act_is_filtered = bool(_act_f.get("event_type") or _act_f.get("user_email")
                            or _act_f.get("country") or _act_f.get("is_suspicious"))
    has_entity_filter = bool(intent["ep_filters"] or intent["user_filters"]
                             or _act_is_filtered
                             or intent.get("_owner_pivot") or intent.get("_device_pivot"))
    has_analysis      = bool(_ANALYSIS_SIGNALS.search(body.message))

    if _is_list_query(body.message) or (has_entity_filter and not has_analysis):
        response = await _direct_response(intent, db, sort_key=sort_key)
        return _stream_direct(response, _suggest_followups(intent))
    else:
        # LLM path — inject conversation context so the model knows the prior topic
        conv_context = _extract_context_summary(body.history) if is_followup else ""
        context      = await _build_llm_context(intent, db)
        messages     = _build_messages(body.message, body.history, context, conv_context)
        return _stream_ollama(messages)


@router.post("/chat/stream")
async def chat_stream(
    body: ChatRequest,
    db: AsyncSession = Depends(get_db),
    _: AuthUser = Depends(require_role("viewer")),
):
    stream = await _handle(body, db)
    return StreamingResponse(
        stream,
        media_type="text/plain",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@router.post("/chat", response_model=ChatResponse)
async def chat(
    body: ChatRequest,
    db: AsyncSession = Depends(get_db),
    _: AuthUser = Depends(require_role("viewer")),
):
    stream = await _handle(body, db)
    chunks: list[str] = []
    async for token in stream:
        chunks.append(token)
    return ChatResponse(response="".join(chunks))


@router.get("/chat/health")
async def chat_health():
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            r = await client.get(f"{OLLAMA_BASE}/api/tags")
            models = [m["name"] for m in r.json().get("models", [])]
            ok = any(OLLAMA_MODEL.split(":")[0] in m for m in models)
        return {"status": "ok" if ok else "model_missing", "model": OLLAMA_MODEL,
                "backend": "ollama", "mode": "cpu"}
    except Exception:
        return {"status": "unavailable", "model": OLLAMA_MODEL, "backend": "ollama", "mode": "cpu"}
