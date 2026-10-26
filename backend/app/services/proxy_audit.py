"""Symantec Management Center policy revision collection and diffing."""

import difflib
import hashlib
import json
import logging
from datetime import datetime, timezone
from typing import Any
from urllib.parse import quote

import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import AsyncSessionLocal
from app.core.outbound import validate_outbound_url
from app.models.proxy_audit import ProxyAuditConnection, ProxyAuditEvent
from app.models.system_settings import SystemSettings


logger = logging.getLogger(__name__)
MAX_POLICIES = 5_000
MAX_VERSIONS_PER_POLICY = 5_000
MAX_CONTENT_BYTES = 20 * 1024 * 1024
MAX_DIFF_CHARS = 2_000_000


def _items(payload: Any, *keys: str) -> list[dict[str, Any]]:
    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, dict)]
    if isinstance(payload, dict):
        for key in (*keys, "data", "items"):
            value = payload.get(key)
            if isinstance(value, list):
                return [item for item in value if isinstance(item, dict)]
    raise ValueError("Management Center returned an unsupported response format")


def _first(data: dict[str, Any], *keys: str, default: Any = None) -> Any:
    for key in keys:
        value = data.get(key)
        if value is not None and value != "":
            return value
    return default


def _bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    return str(value or "").strip().lower() in {"1", "true", "yes", "shared", "shared_object"}


def _revision_date(value: Any) -> datetime:
    if isinstance(value, (int, float)):
        seconds = value / 1000 if value > 10_000_000_000 else value
        return datetime.fromtimestamp(seconds, timezone.utc)
    text = str(value or "").strip()
    if not text:
        return datetime.now(timezone.utc)
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"Unsupported Management Center revision date: {text[:80]}") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _content_of(raw: Any) -> str:
    if isinstance(raw, dict) and "content" in raw:
        raw = raw["content"]
    if isinstance(raw, dict):
        for key in ("urlList", "xml", "cpl", "content"):
            if key in raw:
                return str(raw[key] or "")
        return json.dumps(raw, indent=2, sort_keys=True, ensure_ascii=False)
    if isinstance(raw, (list, tuple)):
        return json.dumps(raw, indent=2, sort_keys=True, ensure_ascii=False)
    return str(raw or "")


def _revision_sort_key(item: dict[str, Any]) -> tuple[datetime, int, str]:
    raw_number = str(_first(item, "revisionNumber", "version", "revision", default="0"))
    try:
        number = int(raw_number)
    except ValueError:
        number = 0
    return (
        _revision_date(_first(item, "revisionDate", "date", "createdAt")),
        number,
        raw_number,
    )


def build_policy_diff(previous: str | None, current: str) -> tuple[str, str, int, int]:
    current_lines = current.splitlines()
    if previous is None:
        additions = len(current_lines)
        return "Initial policy version", "", additions, 0
    diff_lines = list(difflib.unified_diff(
        previous.splitlines(),
        current_lines,
        fromfile="previous",
        tofile="current",
        lineterm="",
        n=2,
    ))
    additions = sum(1 for line in diff_lines if line.startswith("+") and not line.startswith("+++"))
    deletions = sum(1 for line in diff_lines if line.startswith("-") and not line.startswith("---"))
    if not additions and not deletions:
        return "No content changes", "", 0, 0
    parts = []
    if additions:
        parts.append(f"{additions} line{'s' if additions != 1 else ''} added")
    if deletions:
        parts.append(f"{deletions} line{'s' if deletions != 1 else ''} removed")
    diff_text = "\n".join(diff_lines)
    if len(diff_text) > MAX_DIFF_CHARS:
        diff_text = diff_text[:MAX_DIFF_CHARS] + "\n… diff truncated by SEC360 …"
    return " · ".join(parts), diff_text, additions, deletions


class ManagementCenterClient:
    def __init__(self, config: dict[str, Any]):
        base_url = str(config.get("base_url") or "").strip().rstrip("/")
        if base_url.endswith("/api"):
            base_url = base_url[:-4]
        self.base_url = base_url
        self.username = str(config.get("username") or "").strip()
        self.password = str(config.get("password") or "")
        self.verify_ssl = config.get("verify_ssl", True) not in (False, "false", "0", 0)
        self.timeout_seconds = min(120, max(5, int(config.get("timeout_seconds") or 60)))
        self.client: httpx.AsyncClient | None = None

    def validate(self) -> None:
        if not self.base_url:
            raise ValueError("Management Center URL is required")
        if not self.username or not self.password:
            raise ValueError("Management Center username and password are required")

    async def open(self) -> None:
        self.validate()
        await validate_outbound_url(self.base_url)
        self.client = httpx.AsyncClient(
            timeout=self.timeout_seconds,
            verify=self.verify_ssl,
            trust_env=False,
            follow_redirects=False,
            auth=httpx.BasicAuth(self.username, self.password),
        )

    async def close(self) -> None:
        if self.client:
            await self.client.aclose()
            self.client = None

    async def _get(self, path: str) -> Any:
        temporary_client = self.client is None
        if temporary_client:
            await self.open()
        try:
            response = await self.client.get(  # type: ignore[union-attr]
                f"{self.base_url}/api{path}",
                headers={"Accept": "application/json"},
            )
        finally:
            if temporary_client:
                await self.close()
        if response.is_redirect:
            raise ValueError("Management Center API URL must be the final endpoint")
        if response.status_code == 401:
            raise ValueError("Management Center rejected the username or password")
        if response.status_code == 403:
            raise ValueError("The Management Center account cannot read policies")
        response.raise_for_status()
        if len(response.content) > MAX_CONTENT_BYTES:
            raise ValueError("Management Center returned an object larger than 20 MB")
        try:
            return response.json()
        except ValueError as exc:
            raise ValueError("Management Center returned invalid JSON") from exc

    async def policies(self) -> list[dict[str, Any]]:
        rows = _items(await self._get("/policies"), "policies")
        if len(rows) > MAX_POLICIES:
            raise ValueError(f"Management Center returned more than {MAX_POLICIES:,} policies")
        return rows

    async def versions(self, policy_uuid: str) -> list[dict[str, Any]]:
        rows = _items(
            await self._get(f"/policies/{quote(policy_uuid, safe='')}/versions"),
            "versions",
        )
        if len(rows) > MAX_VERSIONS_PER_POLICY:
            raise ValueError("A policy contains too many revisions to import safely")
        return sorted(rows, key=_revision_sort_key)

    async def content(self, policy_uuid: str, revision: str) -> str:
        raw = await self._get(
            f"/policies/{quote(policy_uuid, safe='')}/content/{quote(revision, safe='')}"
        )
        content = _content_of(raw)
        if len(content.encode("utf-8")) > MAX_CONTENT_BYTES:
            raise ValueError("A policy revision is larger than 20 MB")
        return content

    async def test_connection(self) -> dict[str, Any]:
        await self.open()
        try:
            policies = await self.policies()
            shared = sum(1 for item in policies if _bool(_first(item, "shared", "isShared")))
            return {
                "success": True,
                "message": f"Connected successfully. {len(policies):,} objects found ({shared:,} shared).",
                "policies": len(policies) - shared,
                "shared_objects": shared,
            }
        finally:
            await self.close()


async def collect_proxy_audit(db: AsyncSession, config: dict[str, Any]) -> dict[str, int]:
    client = ManagementCenterClient(config)
    await client.open()
    try:
        policies = await client.policies()
        imported = 0
        scanned = 0
        for policy in policies:
            policy_uuid = str(_first(policy, "uuid", "policyUUID", "policyUuid", "id", "policyId", default="")).strip()
            if not policy_uuid:
                logger.warning("Proxy Audit: skipping policy without a UUID")
                continue
            policy_name = str(_first(policy, "name", "policyName", "displayName", default=policy_uuid)).strip()[:500]
            object_type = "shared_object" if _bool(_first(policy, "shared", "isShared")) else "policy"
            versions = await client.versions(policy_uuid)
            scanned += len(versions)
            existing_revisions = set((await db.execute(
                select(ProxyAuditEvent.revision_number).where(
                    ProxyAuditEvent.policy_uuid == policy_uuid
                )
            )).scalars().all())
            missing_indexes = [
                index for index, item in enumerate(versions)
                if str(_first(item, "revisionNumber", "version", "revision", default="")).strip()
                not in existing_revisions
            ]
            if not missing_indexes:
                continue
            first_missing = missing_indexes[0]
            start_index = max(0, first_missing - 1)
            previous_content: str | None = None
            for index, revision in enumerate(versions[start_index:], start=start_index):
                revision_number = str(_first(
                    revision, "revisionNumber", "version", "revision", default=""
                )).strip()
                if not revision_number:
                    logger.warning("Proxy Audit: skipping revision without a number for %s", policy_uuid)
                    continue
                content = await client.content(policy_uuid, revision_number)
                if index >= first_missing and revision_number not in existing_revisions:
                    summary, diff_text, additions, deletions = build_policy_diff(previous_content, content)
                    db.add(ProxyAuditEvent(
                        policy_uuid=policy_uuid,
                        policy_name=policy_name,
                        object_type=object_type,
                        author=str(_first(revision, "author", "createdBy", "modifiedBy", default="")).strip()[:255] or None,
                        revision_date=_revision_date(_first(revision, "revisionDate", "date", "createdAt")),
                        revision_number=revision_number[:100],
                        comment=str(_first(
                            revision, "revisionDescription", "comment", "description", default=""
                        )).strip() or None,
                        change_summary=summary,
                        diff_text=diff_text,
                        additions=additions,
                        deletions=deletions,
                        content_hash=hashlib.sha256(content.encode("utf-8")).hexdigest(),
                    ))
                    imported += 1
                previous_content = content
            await db.flush()
        return {"imported": imported, "scanned": scanned, "objects": len(policies)}
    finally:
        await client.close()


async def run_proxy_audit_sync() -> None:
    """Background/scheduled sync with isolated transaction and durable status."""
    async with AsyncSessionLocal() as db:
        connection = await db.get(ProxyAuditConnection, 1)
        if not connection or not connection.config:
            return
        connection.sync_in_progress = True
        await db.commit()
        try:
            result = await collect_proxy_audit(db, connection.config)
            connection.status = "connected"
            connection.last_error = None
            connection.last_sync = datetime.now(timezone.utc)
            connection.records_synced = result["scanned"]
            connection.sync_in_progress = False
            await db.commit()
            logger.info(
                "Proxy Audit: scanned %d revisions across %d objects; imported %d",
                result["scanned"], result["objects"], result["imported"],
            )
        except Exception as exc:
            await db.rollback()
            connection = await db.get(ProxyAuditConnection, 1)
            if connection:
                connection.status = "error"
                connection.last_error = str(exc)[:4000]
                connection.last_sync = datetime.now(timezone.utc)
                connection.sync_in_progress = False
                await db.commit()
            logger.error("Proxy Audit sync failed: %s", exc, exc_info=True)


async def scheduled_proxy_audit_sync() -> None:
    async with AsyncSessionLocal() as db:
        enabled = await db.scalar(
            select(SystemSettings.proxy_audit_enabled).where(SystemSettings.id == 1)
        )
        connection = await db.get(ProxyAuditConnection, 1)
        if not enabled or not connection or not connection.config or connection.sync_in_progress:
            return
    await run_proxy_audit_sync()
