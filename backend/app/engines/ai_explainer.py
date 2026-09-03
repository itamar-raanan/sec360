"""
AI-powered explanation engine for security insights and events.

Uses Anthropic Claude when an API key is configured; falls back to rich
template-based descriptions when no key is available or the API call fails.

All public functions are async.  Claude API calls are made via the
synchronous anthropic.Anthropic() client wrapped in run_in_executor so
that they don't block the event loop.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Optional Anthropic import
# ---------------------------------------------------------------------------
try:
    import anthropic as _anthropic_module

    _ANTHROPIC_AVAILABLE = True
except ImportError:
    _anthropic_module = None  # type: ignore[assignment]
    _ANTHROPIC_AVAILABLE = False


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _get_client():
    """Return a configured anthropic.Anthropic() client or None."""
    if not _ANTHROPIC_AVAILABLE:
        return None
    from app.core.config import settings

    key = getattr(settings, "ANTHROPIC_API_KEY", None)
    if not key:
        return None
    return _anthropic_module.Anthropic(api_key=key)


def _call_claude_sync(
    client: Any,
    model: str,
    system: str,
    user_message: str,
    max_tokens: int = 512,
) -> str:
    """Synchronous Claude call — run inside an executor."""
    response = client.messages.create(
        model=model,
        max_tokens=max_tokens,
        system=system,
        messages=[{"role": "user", "content": user_message}],
    )
    return response.content[0].text.strip()


async def _call_claude(
    client: Any,
    model: str,
    system: str,
    user_message: str,
    max_tokens: int = 512,
) -> str:
    """Async wrapper around _call_claude_sync."""
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(
        None,
        _call_claude_sync,
        client,
        model,
        system,
        user_message,
        max_tokens,
    )


# ---------------------------------------------------------------------------
# Template fallbacks
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Batch compliance insight templates (no user context)
# ---------------------------------------------------------------------------

_BATCH_INSIGHT_TEMPLATES: dict[str, str] = {
    "users_no_mfa": (
        "{count} active users have no multi-factor authentication configured. "
        "Accounts without MFA are significantly more vulnerable to credential-based attacks "
        "including phishing, password spraying, and credential stuffing. "
        "Enforce MFA immediately via your identity provider policy and set a compliance deadline for enrollment."
    ),
    "stale_accounts": (
        "{count} active accounts have not logged in for 60 or more days. "
        "Dormant accounts are a common attack vector — they may retain full access privileges "
        "while going unnoticed. Disable or remove these accounts to reduce your attack surface, "
        "or verify with HR that they belong to active employees."
    ),
    "endpoints_missing_edr": (
        "{count} managed endpoints have no EDR agent installed or reporting. "
        "Without endpoint detection and response coverage, threats such as ransomware, "
        "lateral movement, and credential theft may go undetected. "
        "Deploy the EDR agent immediately via MDM policy to all unprotected devices."
    ),
    "endpoints_missing_encryption": (
        "{count} endpoints do not have full-disk encryption enabled. "
        "Unencrypted devices expose sensitive corporate data if lost or stolen. "
        "This is a common compliance requirement under SOC 2, ISO 27001, and GDPR. "
        "Enable FileVault (macOS) or BitLocker (Windows) via MDM policy as a priority."
    ),
    "endpoints_missing_dlp": (
        "{count} endpoints are missing a DLP (Data Loss Prevention) agent. "
        "Without DLP, sensitive data such as PII, financial records, and IP can be exfiltrated "
        "without detection or blocking. Deploy the DLP agent to all managed endpoints "
        "and verify policy enforcement is active."
    ),
    "inactive_agents": (
        "{count} {product} security agents are reporting as inactive or offline. "
        "An offline agent provides no protection — the endpoint is effectively unmonitored. "
        "Investigate each affected device to determine if the agent was uninstalled, "
        "if the endpoint is decommissioned, or if there is a connectivity or configuration issue."
    ),
    "non_compliant_endpoints": (
        "{count} endpoints are fully non-compliant with the required security baseline. "
        "These devices are missing multiple critical security controls including EDR, DLP, "
        "encryption, and/or web security coverage. Consider quarantining these endpoints from corporate "
        "resources until they are remediated and compliant."
    ),
    "partial_compliance_endpoints": (
        "{count} endpoints have partial compliance gaps — they meet some but not all required "
        "security controls. While less critical than fully non-compliant devices, these endpoints "
        "represent an incomplete security posture. Create remediation tickets for each gap "
        "and track resolution to achieve full compliance."
    ),
    "unmanaged_device_access": (
        "{count} users have accessed corporate systems from devices with no enrolled MDM endpoint. "
        "Access from unmanaged devices bypasses endpoint security controls (EDR, DLP, encryption) "
        "and represents a significant data security risk. Enforce managed device requirements "
        "through Conditional Access policies to block or restrict unmanaged device access."
    ),
    "after_hours_login": (
        "{count} authentication events occurred outside normal business hours (22:00–05:00 UTC). "
        "While some after-hours access may be legitimate (remote workers, different time zones), "
        "this pattern can also indicate account compromise or insider threat activity. "
        "Review each event, verify with the affected users, and consider Conditional Access "
        "policies to flag or restrict off-hours logins."
    ),
}

_INSIGHT_TEMPLATES: dict[str, str] = {
    "impossible_travel": (
        "User {user_name} ({user_email}) authenticated from {from_country} and then from "
        "{to_country} only {time_diff_hours:.1f} hour(s) later — physically impossible without "
        "simultaneous access from two locations. This is a strong indicator of credential "
        "compromise or account sharing. Investigate both sessions immediately and consider "
        "suspending the account pending review."
    ),
    "suspended_user_active": (
        "User {user_name} ({user_email}) has a suspended account but generated {event_count} "
        "activity event(s) in the detection window. Event types observed: {event_types}. "
        "A suspended user producing activity suggests either a system configuration error or that "
        "the user bypassed suspension controls. Verify the suspension status and audit all recent "
        "events for this account."
    ),
    "risky_oauth": (
        "User {user_name} ({user_email}) granted OAuth access to '{app_name}' with high-risk "
        "permission scopes: {risky_scopes}. These scopes provide broad access to corporate data. "
        "Verify whether this application is approved for use and whether the permission grant was "
        "intentional. Consider revoking the grant if the application is unauthorized."
    ),
    "bulk_cloud_access": (
        "User {user_name} ({user_email}) generated {event_count} cloud access events in the "
        "detection window — far above the expected threshold of 200. The most frequently accessed "
        "service was '{most_used_service}'. High-volume cloud access can indicate automated "
        "data exfiltration, a runaway script, or compromised credentials being used for bulk "
        "data collection. Review the specific resources accessed and correlate with any recent "
        "data-loss-prevention alerts."
    ),
    "auth_brute_force": (
        "User {user_name} ({user_email}) experienced {failure_count} authentication failures "
        "within a {failure_window_minutes}-minute window, followed by a successful login "
        "(outcome: '{final_outcome}'). This pattern is consistent with a brute-force or "
        "credential-stuffing attack that ultimately succeeded. Immediately reset the user's "
        "credentials, review all post-authentication activity, and consider enforcing MFA."
    ),
    "privilege_change": (
        "A privilege or account configuration change was detected for user {user_name} "
        "({user_email}). The recorded event was '{event_name}'. Unauthorised privilege "
        "escalation is a key indicator of insider threat or post-exploitation activity. "
        "Confirm the change was authorised by the appropriate administrator and review the "
        "actor's identity in the event details."
    ),
    "new_country_login": (
        "User {user_name} ({user_email}) logged in from {new_country}, a country with no "
        "login history in the past 30 days (historical countries: {historical_countries}). "
        "Logins from new geographic regions can indicate credential theft or account takeover. "
        "Verify whether the user is travelling and, if not, treat this as a potential compromise."
    ),
    "cloud_threat_incident": (
        "User {user_name} ({user_email}) was involved in {incident_count} suspicious cloud "
        "access event(s). Services involved: {services}. Sample threat descriptions: "
        "{descriptions_sample}. Clustered suspicious cloud activity often signals malware, "
        "a compromised device, or an attacker using stolen cloud credentials. Isolate the "
        "affected account and review all accessed resources."
    ),
    "mfa_disabled": (
        "MFA was disabled for user {user_name} ({user_email}) via event '{event_name}'. "
        "Disabling multi-factor authentication significantly weakens account security and is "
        "a common attacker technique to maintain persistent access after an initial compromise. "
        "Re-enable MFA immediately, verify the action was authorised, and audit recent logins "
        "for signs of unauthorised access."
    ),
    "off_hours_cloud_bulk": (
        "User {user_name} ({user_email}) generated {event_count} cloud access events between "
        "22:00 and 05:00 UTC on the night of {night_date}. The most-accessed service was "
        "'{most_used_service}'. Large-volume off-hours cloud activity is a strong indicator of "
        "automated data exfiltration. Investigate the specific files or data accessed and "
        "determine whether a DLP policy violation occurred."
    ),
}

_EVENT_TEMPLATES: dict[str, str] = {
    "login": (
        "User {user_name} ({user_email}) signed in at {timestamp}{country_str}. "
        "The login originated from IP {ip_str}.{suspicious_str}"
    ),
    "logout": (
        "User {user_name} ({user_email}) signed out at {timestamp}. "
        "The session ended from IP {ip_str}."
    ),
    "saml": (
        "A SAML single-sign-on authentication event was recorded for {user_name} "
        "({user_email}) at {timestamp}{country_str}. SAML is used for federated identity — "
        "this event represents a login via an identity provider.{suspicious_str}"
    ),
    "oauth_grant": (
        "User {user_name} ({user_email}) granted OAuth permissions to a third-party "
        "application at {timestamp}. OAuth grants allow external apps to access corporate "
        "resources on the user's behalf.{suspicious_str}"
    ),
    "user_account": (
        "An account management action was performed at {timestamp} involving user "
        "{user_name} ({user_email}). This event type covers changes such as password resets, "
        "MFA modifications, role assignments, and group membership updates.{suspicious_str}"
    ),
    "access_eval": (
        "An access policy evaluation was triggered for {user_name} ({user_email}) at "
        "{timestamp}. This event records whether a resource access request was approved or "
        "denied by a policy engine.{suspicious_str}"
    ),
    "cloud_access": (
        "User {user_name} ({user_email}) accessed a cloud service at {timestamp}{country_str}. "
        "Cloud access events capture interactions with SaaS or IaaS platforms.{suspicious_str}"
    ),
    "file_access": (
        "User {user_name} ({user_email}) accessed or modified a file at {timestamp}. "
        "File access events help track data handling and potential data-loss incidents."
        "{suspicious_str}"
    ),
    "network": (
        "A network activity event was recorded for {user_name} ({user_email}) at {timestamp} "
        "from IP {ip_str}. This may represent DNS lookups, firewall traversals, or proxy "
        "connections.{suspicious_str}"
    ),
    "vpn": (
        "User {user_name} ({user_email}) connected to or disconnected from the VPN at "
        "{timestamp} from IP {ip_str}{country_str}. VPN events are important for tracking "
        "remote access.{suspicious_str}"
    ),
    "app_usage": (
        "User {user_name} ({user_email}) used an application at {timestamp}. App usage events "
        "capture interactions with sanctioned or unsanctioned SaaS applications.{suspicious_str}"
    ),
}


def _build_insight_template(
    insight_type: str,
    evidence: dict,
    user_name: str,
    user_email: str,
) -> str:
    # Batch/compliance insights (no user) use dedicated templates
    if insight_type in _BATCH_INSIGHT_TEMPLATES:
        template = _BATCH_INSIGHT_TEMPLATES[insight_type]
        ctx: dict[str, Any] = {"insight_type": insight_type, **evidence}
        # Flatten lists to a readable string for template substitution
        for k, v in list(ctx.items()):
            if isinstance(v, list):
                ctx[k] = ", ".join(str(x) for x in v) if v else "none"
        try:
            return template.format_map(ctx)
        except (KeyError, ValueError):
            count = evidence.get("count", "")
            count_str = f" ({count} affected)" if count else ""
            return (
                f"Compliance finding: {insight_type.replace('_', ' ').title()}{count_str}. "
                "Review the evidence details for the full list of affected resources."
            )

    # Per-user behavioral insight templates
    template = _INSIGHT_TEMPLATES.get(
        insight_type,
        (
            "Security anomaly detected for user {user_name} ({user_email}). "
            "Insight type: {insight_type}. Please review the raw evidence for details."
        ),
    )
    # Safely format — unknown keys are left as-is
    ctx = {
        "user_name": user_name or "Unknown",
        "user_email": user_email or "unknown@unknown",
        "insight_type": insight_type,
        **evidence,
    }
    # Some evidence values might be lists; convert for readable formatting
    for k, v in list(ctx.items()):
        if isinstance(v, list):
            ctx[k] = ", ".join(str(x) for x in v) if v else "none"
    try:
        return template.format_map(ctx)
    except (KeyError, ValueError):
        return (
            f"Security anomaly of type '{insight_type}' detected for {user_name} "
            f"({user_email}). Evidence: {evidence}"
        )


def _build_event_template(
    event_type: str,
    details: dict,
    user_name: str,
    user_email: str,
    timestamp: str,
    country: str | None,
    ip_address: str | None,
    is_suspicious: bool,
) -> str:
    country_str = f" from {country}" if country else ""
    ip_str = ip_address or "unknown"
    suspicious_str = (
        " This event has been flagged as suspicious and warrants investigation."
        if is_suspicious
        else ""
    )
    template = _EVENT_TEMPLATES.get(
        event_type,
        (
            "A '{event_type}' event was recorded for {user_name} ({user_email}) at "
            "{timestamp}.{suspicious_str}"
        ),
    )
    try:
        return template.format(
            user_name=user_name or "Unknown",
            user_email=user_email or "unknown@unknown",
            timestamp=timestamp,
            country_str=country_str,
            ip_str=ip_str,
            suspicious_str=suspicious_str,
            event_type=event_type,
        )
    except (KeyError, ValueError):
        return (
            f"A '{event_type}' event was recorded for {user_name} ({user_email}) at "
            f"{timestamp}.{suspicious_str}"
        )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


async def generate_insight_description(
    insight_type: str,
    title: str,
    evidence: dict,
    user_name: str,
    user_email: str,
    user_dept: str | None,
) -> str:
    """
    Generate a human-readable description for an AI insight.

    Uses Claude claude-3-5-haiku-20241022 when an API key is available;
    returns a rich template string otherwise.
    """
    client = _get_client()
    if client is not None:
        system_prompt = (
            "You are a senior security analyst writing concise threat summaries. "
            "Be direct, specific, and actionable. 2-3 sentences max."
        )
        user_message = (
            f"Anomaly type: {insight_type}\n"
            f"Title: {title}\n"
            f"User: {user_name} <{user_email}>"
            + (f", Department: {user_dept}" if user_dept else "")
            + f"\nEvidence: {evidence}\n\n"
            "Explain: (1) what happened, (2) why it is suspicious, "
            "(3) what the analyst should investigate next."
        )
        try:
            return await _call_claude(
                client,
                model="claude-3-5-haiku-20241022",
                system=system_prompt,
                user_message=user_message,
                max_tokens=256,
            )
        except Exception as exc:
            logger.warning(
                "Claude API call failed for generate_insight_description (%s): %s",
                insight_type,
                exc,
            )

    return _build_insight_template(insight_type, evidence, user_name, user_email)


async def explain_event(
    event_type: str,
    details: dict,
    user_name: str,
    user_email: str,
    timestamp: str,
    country: str | None,
    ip_address: str | None,
    is_suspicious: bool,
) -> str:
    """
    Generate a plain-English explanation for a single security event.

    Uses Claude claude-3-5-haiku-20241022 when an API key is available;
    returns a rich template string otherwise.
    """
    client = _get_client()
    if client is not None:
        system_prompt = (
            "You are a security analyst. Explain what this security event means in "
            "2-3 plain-English sentences. Focus on: what action was taken, by whom, "
            "what system/service was involved, and whether anything looks unusual."
        )
        suspicious_note = " This event is flagged as suspicious." if is_suspicious else ""
        user_message = (
            f"Event type: {event_type}\n"
            f"User: {user_name} <{user_email}>\n"
            f"Timestamp: {timestamp}\n"
            f"Country: {country or 'unknown'}\n"
            f"IP address: {ip_address or 'unknown'}\n"
            f"Details: {details}\n"
            f"{suspicious_note}"
        )
        try:
            return await _call_claude(
                client,
                model="claude-3-5-haiku-20241022",
                system=system_prompt,
                user_message=user_message,
                max_tokens=256,
            )
        except Exception as exc:
            logger.warning(
                "Claude API call failed for explain_event (%s): %s",
                event_type,
                exc,
            )

    return _build_event_template(
        event_type, details, user_name, user_email, timestamp, country, ip_address, is_suspicious
    )


async def generate_user_threat_summary(
    user_name: str,
    user_email: str,
    risk_score: int,
    insights: list[dict],
) -> str:
    """
    Generate a multi-sentence threat narrative for a user based on all of
    their active insights.

    Uses Claude claude-3-5-sonnet-20241022 when an API key is available;
    returns a template-based summary otherwise.
    """
    if not insights:
        return (
            f"{user_name} ({user_email}) currently has no active security insights. "
            f"Their risk score is {risk_score}/100."
        )

    severity_counts: dict[str, int] = {"critical": 0, "high": 0, "warning": 0, "info": 0}
    insight_summaries: list[str] = []
    for ins in insights:
        sev = ins.get("severity", "info")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1
        insight_summaries.append(f"[{sev.upper()}] {ins.get('title', ins.get('insight_type', ''))}")

    client = _get_client()
    if client is not None:
        system_prompt = (
            "You are a senior security operations analyst. Write a concise, actionable "
            "threat narrative for a user based on the provided security insights. "
            "Be specific about the risks and recommend clear next steps. "
            "3-5 sentences."
        )
        user_message = (
            f"User: {user_name} <{user_email}>\n"
            f"Risk score: {risk_score}/100\n"
            f"Active security insights ({len(insights)} total):\n"
            + "\n".join(f"  - {s}" for s in insight_summaries)
            + "\n\nWrite a threat narrative for this user."
        )
        try:
            return await _call_claude(
                client,
                model="claude-3-5-sonnet-20241022",
                system=system_prompt,
                user_message=user_message,
                max_tokens=512,
            )
        except Exception as exc:
            logger.warning(
                "Claude API call failed for generate_user_threat_summary (%s): %s",
                user_email,
                exc,
            )

    # Template fallback
    parts: list[str] = [
        f"{user_name} ({user_email}) has a risk score of {risk_score}/100 "
        f"and {len(insights)} active security insight(s)."
    ]

    if severity_counts["critical"] > 0:
        parts.append(
            f"There are {severity_counts['critical']} CRITICAL finding(s) that require "
            "immediate investigation, including possible credential compromise or policy bypass."
        )
    if severity_counts["high"] > 0:
        parts.append(
            f"{severity_counts['high']} HIGH severity finding(s) indicate elevated risk "
            "and should be reviewed within 24 hours."
        )
    if severity_counts["warning"] > 0:
        parts.append(
            f"{severity_counts['warning']} WARNING(s) suggest abnormal behaviour that "
            "may warrant follow-up."
        )

    parts.append(
        "Recommended actions: review all flagged events, verify account integrity, "
        "and consider enforcing additional authentication controls."
    )

    return " ".join(parts)
