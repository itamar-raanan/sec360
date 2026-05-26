import asyncio
import json
import logging
from typing import Any
from datetime import datetime, timezone, timedelta

import httpx
from sqlalchemy.ext.asyncio import AsyncSession

from app.collectors.base import BaseCollector
from app.core.config import settings

logger = logging.getLogger(__name__)

_SCOPES = [
    "https://www.googleapis.com/auth/admin.reports.audit.readonly",
    "https://www.googleapis.com/auth/admin.directory.user.readonly",
    "https://www.googleapis.com/auth/admin.directory.user.security",
]

_SETUP_HINT = (
    "To fix: (1) In Google Admin Console → Security → API Controls → Domain-wide Delegation, "
    "add the service account Client ID with scopes: "
    "https://www.googleapis.com/auth/admin.reports.audit.readonly, "
    "https://www.googleapis.com/auth/admin.directory.user.readonly, "
    "https://www.googleapis.com/auth/admin.directory.user.security  "
    "(2) The Admin Email must be a Super Admin account in your domain."
)

# OAuth scopes considered high-risk (broad access to user data)
_RISKY_SCOPES = {
    "https://mail.google.com/",
    "https://www.googleapis.com/auth/gmail.modify",
    "https://www.googleapis.com/auth/gmail.readonly",
    "https://www.googleapis.com/auth/drive",
    "https://www.googleapis.com/auth/drive.readonly",
    "https://www.googleapis.com/auth/admin.directory.user",
    "https://www.googleapis.com/auth/admin.directory.group",
    "https://www.googleapis.com/auth/calendar",
    "https://www.googleapis.com/auth/contacts",
}

# ── Human-readable descriptions per log application / event name ──────────────

def _describe_saml(event_name: str, params: dict) -> str:
    sp = (
        params.get("application_name")
        or params.get("saml_service_provider_initiated_login")
        or params.get("service_provider")
        or ""
    )
    sp_str = f" to {sp}" if sp else ""
    names = {
        "login_success":          f"Authenticated via SAML{sp_str}",
        "login_failure":          f"SAML authentication failed{sp_str}",
        "authn_only":             f"SAML authentication only (no session){sp_str}",
        "sp_initiated_logout":    f"Logged out via SAML (SP-initiated){sp_str}",
        "idp_initiated_logout":   f"Logged out via SAML (IdP-initiated){sp_str}",
        "response_sent":          f"SAML response sent{sp_str}",
    }
    return names.get(event_name, f"SAML event: {event_name}{sp_str}")


def _normalize_scopes(scope_raw) -> list[str]:
    if isinstance(scope_raw, list):
        return [s.strip() for s in scope_raw if s.strip()]
    if isinstance(scope_raw, str):
        return [s.strip() for s in scope_raw.split() if s.strip()]
    return []

def _describe_token(event_name: str, params: dict) -> str:
    app = params.get("app_name") or params.get("client_id") or "unknown app"
    scopes = _normalize_scopes(params.get("scope") or [])
    readable_scopes = _human_scopes(scopes)
    scope_str = f" ({readable_scopes})" if readable_scopes else ""
    names = {
        "authorize":   f"Authorized {app} to access account{scope_str}",
        "revoke":      f"Revoked access for {app}",
        "activity":    f"OAuth activity for {app}{scope_str}",
    }
    return names.get(event_name, f"OAuth event '{event_name}' for {app}")


def _describe_user_account(event_name: str, params: dict) -> str:
    names = {
        "change_password":            "Password changed",
        "recovery_phone_add":         "Recovery phone number added",
        "recovery_phone_edit":        "Recovery phone number changed",
        "recovery_phone_delete":      "Recovery phone number removed",
        "recovery_email_add":         "Recovery email added",
        "recovery_email_edit":        "Recovery email changed",
        "recovery_email_delete":      "Recovery email removed",
        "2sv_enroll":                 "Two-step verification enrolled",
        "2sv_disable":                "Two-step verification disabled",
        "2sv_unenroll":               "Two-step verification unenrolled",
        "account_disabled_password_leak": "Account disabled — password found in data breach",
        "account_disabled_spamming":  "Account disabled — spam detected",
        "gov_attack_warning":         "Government-backed attack warning sent",
        "email_forwarding_out_of_domain": "Email forwarding set to external address",
        "titan_unenroll":             "Titan security key unenrolled",
        "suspend_user":               "User account suspended",
        "unsuspend_user":             "User account unsuspended",
    }
    return names.get(event_name, f"Account event: {event_name.replace('_', ' ')}")


def _describe_access_eval(event_name: str, params: dict) -> str:
    policy = params.get("policy_name") or ""
    device = params.get("device_id") or ""
    result = params.get("access_level_result") or params.get("result") or ""
    parts = []
    if policy:
        parts.append(f"policy '{policy}'")
    if result:
        parts.append(f"result: {result}")
    if device:
        parts.append(f"device {device}")
    suffix = " — " + ", ".join(parts) if parts else ""
    names = {
        "CONTEXT_AWARE_ACCESS_EVALUATION": f"Context-aware access evaluated{suffix}",
        "context_aware_access_disabled":   f"Context-aware access disabled{suffix}",
    }
    return names.get(event_name, f"Access evaluation: {event_name}{suffix}")


def _human_scopes(scopes: list[str]) -> str:
    """Convert OAuth scope URLs into short readable labels."""
    mapping = {
        "https://mail.google.com/":                          "Gmail (full)",
        "https://www.googleapis.com/auth/gmail.modify":     "Gmail (modify)",
        "https://www.googleapis.com/auth/gmail.readonly":   "Gmail (read)",
        "https://www.googleapis.com/auth/drive":            "Drive (full)",
        "https://www.googleapis.com/auth/drive.readonly":   "Drive (read)",
        "https://www.googleapis.com/auth/calendar":         "Calendar (full)",
        "https://www.googleapis.com/auth/calendar.events":  "Calendar (events)",
        "https://www.googleapis.com/auth/contacts":         "Contacts",
        "https://www.googleapis.com/auth/admin.directory.user": "Admin: Users",
        "https://www.googleapis.com/auth/admin.directory.group": "Admin: Groups",
        "https://www.googleapis.com/auth/userinfo.email":   "Email address",
        "https://www.googleapis.com/auth/userinfo.profile": "Profile",
        "openid":                                           "OpenID",
    }
    labels = [mapping.get(s, s.split("/")[-1]) for s in scopes]
    # deduplicate, cap length
    seen, out = set(), []
    for l in labels:
        if l not in seen:
            seen.add(l)
            out.append(l)
    return ", ".join(out[:5]) + ("…" if len(out) > 5 else "")


def _refresh_credentials_sync(service_account_json: str, admin_email: str) -> str:
    """Blocking — run via asyncio.to_thread."""
    from google.oauth2 import service_account
    import google.auth.transport.requests

    creds_info = json.loads(service_account_json)
    credentials = service_account.Credentials.from_service_account_info(
        creds_info,
        scopes=_SCOPES,
        subject=admin_email,
    )
    request = google.auth.transport.requests.Request()
    credentials.refresh(request)
    return credentials.token


class GoogleWorkspaceCollector(BaseCollector):
    name = "google_workspace"

    def __init__(self, credentials: dict = None, db: AsyncSession = None):
        super().__init__()
        if credentials:
            self.service_account_json = credentials.get("service_account_json", "")
            self.admin_email = credentials.get("admin_email", "")
            self.domain = self.admin_email.split("@", 1)[1] if "@" in (self.admin_email or "") else ""
        else:
            self.domain = settings.GOOGLE_WORKSPACE_DOMAIN or ""
            self.service_account_json = settings.GOOGLE_SERVICE_ACCOUNT_JSON or ""
            self.admin_email = f"admin@{self.domain}" if self.domain else ""
        self.db = db

    # ── BaseCollector abstract stubs ─────────────────────────────────────
    async def fetch_data(self) -> list[dict]:
        return []

    async def normalize(self, raw_items: list[dict]) -> list[dict]:
        return raw_items

    # ── Auth ─────────────────────────────────────────────────────────────
    async def _get_access_token(self) -> str:
        try:
            return await asyncio.to_thread(
                _refresh_credentials_sync,
                self.service_account_json,
                self.admin_email,
            )
        except ImportError:
            raise RuntimeError(
                "google-auth package not installed. Run: pip install google-auth google-auth-httplib2"
            )
        except json.JSONDecodeError:
            raise RuntimeError(
                "Invalid service account JSON — paste the full contents of the key file "
                "downloaded from Google Cloud Console → IAM → Service Accounts → Keys."
            )
        except Exception as e:
            msg = str(e)
            if "missing fields" in msg or "not in the expected format" in msg:
                raise RuntimeError(
                    f"Malformed service account JSON — {msg}. "
                    "Download a fresh key from Google Cloud Console → IAM → Service Accounts → Keys."
                )
            raise RuntimeError(f"Failed to obtain access token: {msg}")

    @staticmethod
    def _google_error_message(resp: httpx.Response) -> str:
        try:
            body = resp.json()
            err = body.get("error", {})
            if isinstance(err, dict):
                return err.get("message", "")
            return str(err)
        except Exception:
            return resp.text[:200]

    # ── Test connection ──────────────────────────────────────────────────
    async def test_connection(self) -> dict:
        if not self.service_account_json:
            return {"success": False, "message": "Service account JSON is required"}
        if not self.admin_email:
            return {"success": False, "message": "Admin Email is required (a Super Admin account in your domain)"}

        try:
            token = await self._get_access_token()
        except RuntimeError as e:
            return {"success": False, "message": str(e)}

        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                resp = await client.get(
                    "https://admin.googleapis.com/admin/directory/v1/users",
                    headers={"Authorization": f"Bearer {token}"},
                    params={"domain": self.domain or "my_customer", "maxResults": 1, "viewType": "admin_view"},
                )
                google_msg = self._google_error_message(resp)

                if resp.status_code == 401:
                    return {"success": False, "message": f"Google rejected the token (401{': ' + google_msg if google_msg else ''}). {_SETUP_HINT}"}
                if resp.status_code == 403:
                    return {"success": False, "message": f"Access denied (403{': ' + google_msg if google_msg else ''}). {_SETUP_HINT}"}
                if not resp.is_success:
                    return {"success": False, "message": f"Unexpected response {resp.status_code}: {google_msg or resp.text[:120]}"}

                return {
                    "success": True,
                    "message": "Connected to Google Workspace — Directory API accessible",
                }
        except httpx.ConnectError as e:
            return {"success": False, "message": f"Network error: {e}"}
        except Exception as e:
            return {"success": False, "message": f"Error: {e}"}

    # ── Collect ──────────────────────────────────────────────────────────
    async def collect(self) -> dict:
        if not self.service_account_json or not self.admin_email:
            return {"records_synced": 0, "error": "Not configured"}
        try:
            token = await self._get_access_token()
            users_synced  = await self._sync_user_directory(token)
            saml_synced   = await self._sync_report_log(token, "saml",         "saml",         _describe_saml)
            oauth_synced  = await self._sync_report_log(token, "token",        "oauth_grant",  _describe_token)
            user_synced   = await self._sync_report_log(token, "user_accounts","user_account", _describe_user_account)
            access_synced = await self._sync_report_log(token, "context_aware_access", "access_eval", _describe_access_eval)
            total = users_synced + saml_synced + oauth_synced + user_synced + access_synced
            return {
                "records_synced": total,
                "detail": {
                    "users_synced":       users_synced,
                    "saml_events":        saml_synced,
                    "oauth_log_events":   oauth_synced,
                    "user_account_events":user_synced,
                    "access_eval_events": access_synced,
                },
            }
        except Exception as e:
            logger.error(f"Google Workspace collect failed: {e}", exc_info=True)
            return {"records_synced": 0, "error": str(e)}

    # ── User directory ───────────────────────────────────────────────────
    async def _fetch_all_users(self, token: str) -> list[dict]:
        users: list[dict] = []
        page_token = None

        async with httpx.AsyncClient(timeout=30.0) as client:
            while True:
                params: dict[str, Any] = {
                    "customer": "my_customer",
                    "maxResults": 500,
                    "orderBy": "email",
                    "projection": "full",
                    "viewType": "admin_view",
                }
                if page_token:
                    params["pageToken"] = page_token

                resp = await client.get(
                    "https://admin.googleapis.com/admin/directory/v1/users",
                    headers={"Authorization": f"Bearer {token}"},
                    params=params,
                )
                resp.raise_for_status()
                data = resp.json()
                users.extend(data.get("users", []))
                page_token = data.get("nextPageToken")
                if not page_token:
                    break

        return users

    async def _sync_user_directory(self, token: str) -> int:
        from sqlalchemy import select
        from app.models.user import User

        raw_users = await self._fetch_all_users(token)
        logger.info(f"Google Workspace: fetched {len(raw_users)} directory users")

        count = 0
        for gu in raw_users:
            try:
                email = gu.get("primaryEmail", "")
                if not email:
                    continue

                orgs = gu.get("organizations", [{}])
                org = orgs[0] if orgs else {}
                department = org.get("department") or gu.get("department")
                job_title  = org.get("title")
                phones = gu.get("phones") or []
                phone = phones[0].get("value") if phones else None

                manager_email = None
                for rel in gu.get("relations", []):
                    if rel.get("type") == "manager":
                        manager_email = rel.get("value")
                        break

                mfa_enrolled = gu.get("isEnrolledIn2Sv", False)

                last_login = None
                raw_last = gu.get("lastLoginTime")
                if raw_last and raw_last != "1970-01-01T00:00:00.000Z":
                    try:
                        last_login = datetime.fromisoformat(raw_last.replace("Z", "+00:00"))
                    except Exception:
                        pass

                suspended = gu.get("suspended", False)
                status = "inactive" if suspended else "active"
                full_name = gu.get("name", {}).get("fullName") or email.split("@")[0]

                google_source = {
                    "active":    not suspended,
                    "suspended": suspended,
                    "mfa":       mfa_enrolled,
                    "last_login": gu.get("lastLoginTime"),
                    "org_unit":  gu.get("orgUnitPath"),
                }

                result = await self.db.execute(select(User).where(User.email == email))
                user = result.scalars().first()

                if user:
                    user.full_name         = full_name
                    user.department        = department or user.department
                    user.manager           = manager_email or user.manager
                    user.mfa_enabled       = mfa_enrolled
                    user.suspended         = suspended
                    user.employment_status = status
                    if last_login:
                        user.last_login    = last_login
                    if job_title:
                        user.job_title     = job_title
                    if phone:
                        user.phone         = phone
                    existing = dict(user.sources) if user.sources else {}
                    existing["google"] = google_source
                    user.sources = existing
                else:
                    self.db.add(User(
                        full_name         = full_name,
                        email             = email,
                        department        = department,
                        manager           = manager_email,
                        job_title         = job_title,
                        phone             = phone,
                        mfa_enabled       = mfa_enrolled,
                        suspended         = suspended,
                        employment_status = status,
                        last_login        = last_login,
                        sources           = {"google": google_source},
                    ))
                count += 1
            except Exception as e:
                logger.warning(f"Google Workspace: failed to upsert user {gu.get('primaryEmail')}: {e}")

        await self.db.flush()
        logger.info(f"Google Workspace: synced {count} users")
        return count

    # ── GeoIP enrichment (ip-api.com batch, free tier) ───────────────────
    @staticmethod
    async def _geoip_lookup(ips: list[str]) -> dict[str, dict]:
        """Return {ip: {country, city}} for a list of IPs using ip-api.com batch."""
        if not ips:
            return {}
        unique = list({ip for ip in ips if ip})
        results: dict[str, dict] = {}
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                # batch endpoint: up to 100 IPs, no auth required
                for i in range(0, len(unique), 100):
                    batch = unique[i:i + 100]
                    resp = await client.post(
                        "http://ip-api.com/batch",
                        json=[{"query": ip, "fields": "query,country,countryCode,city,status"} for ip in batch],
                    )
                    if resp.status_code == 200:
                        for item in resp.json():
                            if item.get("status") == "success":
                                results[item["query"]] = {
                                    "country": item.get("countryCode") or item.get("country"),
                                    "city": item.get("city"),
                                }
        except Exception as e:
            logger.debug("GeoIP lookup failed: %s", e)
        return results

    # ── Generic Reports API log fetcher ──────────────────────────────────
    async def _sync_report_log(
        self,
        token: str,
        application_name: str,
        event_type_value: str,
        describe_fn,
    ) -> int:
        """
        Fetch last-7-days audit log for `application_name` from the Reports API,
        upsert into ActivityEvent with the given event_type.
        `describe_fn(event_name, params_dict)` returns a human-readable description.
        """
        import uuid as _uuid
        from sqlalchemy import select, delete, text as _text
        from sqlalchemy.dialects.postgresql import insert as pg_insert
        from app.models.user import User
        from app.models.activity import ActivityEvent
        _ext_id_where = _text("external_id IS NOT NULL")

        # Delete existing events of this type before re-syncing the 7-day window.
        # These event types (saml, user_account, access_eval, oauth_grant) are only
        # ever created by this collector, so deleting by event_type is safe.
        cutoff = datetime.now(timezone.utc) - timedelta(days=7)
        await self.db.execute(
            delete(ActivityEvent).where(
                ActivityEvent.event_type == event_type_value,
                ActivityEvent.timestamp >= cutoff,
            )
        )

        start_time = cutoff.strftime("%Y-%m-%dT%H:%M:%SZ")
        items: list[dict] = []
        page_token = None

        async with httpx.AsyncClient(timeout=30.0) as client:
            while True:
                params: dict[str, Any] = {"maxResults": 1000, "startTime": start_time}
                if page_token:
                    params["pageToken"] = page_token

                resp = await client.get(
                    f"https://admin.googleapis.com/admin/reports/v1/activity/users/all/applications/{application_name}",
                    headers={"Authorization": f"Bearer {token}"},
                    params=params,
                )

                # 400 = application not available for this domain (e.g. context_aware_access without BeyondCorp)
                if resp.status_code == 400:
                    logger.info(f"Google Workspace: {application_name} log not available for this domain, skipping")
                    return 0
                if resp.status_code == 403:
                    logger.warning(f"Google Workspace: no permission for {application_name} log")
                    return 0

                resp.raise_for_status()
                data = resp.json()
                items.extend(data.get("items", []))
                page_token = data.get("nextPageToken")
                if not page_token:
                    break

        count = 0
        user_cache: dict[str, Any] = {}
        saml_seen: set[tuple] = set()
        token_seen: set[tuple] = set()  # dedup oauth_grant: (user_email, app_name, event_name)

        # Enrich with geo data for event types where Google doesn't supply location
        geo_cache: dict[str, dict] = {}
        if application_name == "token":
            ips = list({item.get("ipAddress") for item in items if item.get("ipAddress")})
            geo_cache = await self._geoip_lookup(ips)

        for item in items:
            try:
                actor = item.get("actor", {})
                email = actor.get("email") or ""
                ip_address = item.get("ipAddress")
                unique_qualifier = item.get("id", {}).get("uniqueQualifier", "")

                # Parse timestamp
                raw_time = item.get("id", {}).get("time")
                timestamp = datetime.now(timezone.utc)
                if raw_time:
                    try:
                        timestamp = datetime.fromisoformat(raw_time.replace("Z", "+00:00"))
                    except Exception:
                        pass

                # Resolve user_id (cached)
                user_id = None
                if email:
                    if email not in user_cache:
                        result = await self.db.execute(select(User).where(User.email == email))
                        user_cache[email] = result.scalars().first()
                    u = user_cache[email]
                    if u:
                        user_id = u.id

                for event_idx, event in enumerate(item.get("events", [])):
                    event_name = event.get("name", "")
                    params_list = event.get("parameters", [])
                    # Build params dict — handle both value and multiValue
                    params_dict: dict[str, Any] = {}
                    for p in params_list:
                        key = p.get("name", "")
                        if "value" in p:
                            params_dict[key] = p["value"]
                        elif "multiValue" in p:
                            params_dict[key] = p["multiValue"]
                        elif "boolValue" in p:
                            params_dict[key] = p["boolValue"]
                        elif "intValue" in p:
                            params_dict[key] = p["intValue"]

                    description = describe_fn(event_name, params_dict)

                    # Determine if suspicious
                    is_suspicious = (
                        params_dict.get("is_suspicious") in (True, "true", "TRUE")
                        or event_name in (
                            "login_failure", "account_disabled_password_leak",
                            "account_disabled_spamming", "gov_attack_warning",
                            "email_forwarding_out_of_domain",
                        )
                        or (event_type_value == "oauth_grant" and bool(
                            _RISKY_SCOPES & set(
                                _normalize_scopes(params_dict.get("scope") or [])
                            )
                        ))
                    )

                    # Build clean details — only include non-empty fields
                    details: dict[str, Any] = {
                        "app":         "google_workspace",
                        "source":      application_name,
                        "description": description,
                        "event_name":  event_name,
                    }

                    # Per-application extra fields
                    if application_name == "saml":
                        for k in ("saml_service_provider_initiated_login", "initiated_by", "application_name"):
                            if params_dict.get(k):
                                details[k] = params_dict[k]

                    elif application_name == "token":
                        # Only record explicit grants/revocations — skip background activity events
                        if event_name not in ("authorize", "revoke"):
                            continue
                        # Skip admin-pushed grants (no IP = not user-initiated)
                        if not ip_address:
                            continue
                        app_name = params_dict.get("app_name") or params_dict.get("client_id", "")
                        # One entry per user+app+action in the 7-day window
                        tok_key = (email, app_name, event_name)
                        if tok_key in token_seen:
                            continue
                        token_seen.add(tok_key)
                        scopes = _normalize_scopes(params_dict.get("scope") or [])
                        risky = list(_RISKY_SCOPES & set(scopes))
                        if app_name:
                            details["app_name"] = app_name
                        if scopes:
                            details["scopes"] = scopes
                        if risky:
                            details["risky_scopes"] = risky

                    elif application_name == "user_accounts":
                        for k in ("user_email", "affected_email_address"):
                            if params_dict.get(k):
                                details[k] = params_dict[k]

                    elif application_name == "context_aware_access":
                        for k in ("policy_name", "access_level_result", "device_id", "resource"):
                            if params_dict.get(k):
                                details[k] = params_dict[k]

                    # For SAML successes: deduplicate — skip if same user
                    # already has a success for the same app+IP today.
                    if (
                        application_name == "saml"
                        and event_name == "login_success"
                        and user_id is not None
                    ):
                        app_name_key = details.get("application_name") or ""
                        day_start = timestamp.replace(hour=0, minute=0, second=0, microsecond=0)
                        dup_key = (user_id, app_name_key, ip_address, day_start.date())
                        if dup_key in saml_seen:
                            continue
                        saml_seen.add(dup_key)

                    geo = geo_cache.get(ip_address or "") or {}
                    ext_id = (
                        f"google_{application_name}_{unique_qualifier}_{event_idx}"
                        if unique_qualifier else None
                    )
                    stmt = pg_insert(ActivityEvent).values(
                        id            = _uuid.uuid4(),
                        user_id       = user_id,
                        event_type    = event_type_value,
                        timestamp     = timestamp,
                        ip_address    = ip_address,
                        country       = geo.get("country") or None,
                        is_suspicious = is_suspicious,
                        external_id   = ext_id,
                        details       = {**details, **({
                            "city": geo["city"]
                        } if geo.get("city") else {})},
                    ).on_conflict_do_nothing(index_elements=["external_id"], index_where=_ext_id_where)
                    await self.db.execute(stmt)
                    count += 1

            except Exception as e:
                logger.warning(f"Google Workspace: failed to process {application_name} event: {e}")

        if count:
            await self.db.flush()
        logger.info(f"Google Workspace: synced {count} {application_name} events")
        return count
