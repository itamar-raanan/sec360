import base64
import logging
from typing import Any

import httpx
from sqlalchemy.ext.asyncio import AsyncSession

from app.collectors.base import BaseCollector
from app.core.config import settings

logger = logging.getLogger(__name__)


class HiBobCollector(BaseCollector):
    name = "hibob"

    def __init__(self, credentials: dict = None, db: AsyncSession = None):
        super().__init__()
        if credentials:
            self.service_user_id = credentials.get("service_user_id", "")
            self.service_token = credentials.get("service_user_token", "")
        else:
            self.service_user_id = settings.HIBOB_SERVICE_USER_ID or ""
            self.service_token = settings.HIBOB_SERVICE_TOKEN or ""
        self.base_url = "https://api.hibob.com/v1"
        self.db = db

    def _auth_header(self) -> str:
        creds = base64.b64encode(f"{self.service_user_id}:{self.service_token}".encode()).decode()
        return f"Basic {creds}"

    async def test_connection(self) -> dict:
        if not self.service_user_id or not self.service_token:
            return {"success": False, "message": "Service user ID and token are required"}
        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                resp = await client.get(
                    f"{self.base_url}/people",
                    headers={
                        "Authorization": self._auth_header(),
                        "Accept": "application/json",
                    },
                    params={"includeHumanReadable": "true"},
                )
                if resp.status_code == 401:
                    return {"success": False, "message": "Invalid credentials (401 Unauthorized)"}
                if resp.status_code == 403:
                    return {"success": False, "message": "Access denied (403 Forbidden)"}
                resp.raise_for_status()
                data = resp.json()
                total = len(data.get("employees", []))
                return {"success": True, "message": f"Connected successfully. {total} employees in first page."}
        except httpx.ConnectError as e:
            return {"success": False, "message": f"Connection error: {str(e)}"}
        except httpx.TimeoutException:
            return {"success": False, "message": "Connection timed out"}
        except Exception as e:
            return {"success": False, "message": f"Error: {str(e)}"}

    async def collect(self) -> dict:
        if not self.service_user_id or not self.service_token:
            return {"records_synced": 0, "error": "Not configured"}
        try:
            employees = await self._fetch_people()
            count = await self._upsert_users(employees)
            return {"records_synced": count}
        except Exception as e:
            logger.error(f"HiBob: collect failed: {e}", exc_info=True)
            return {"records_synced": 0, "error": str(e)}

    async def _fetch_people(self) -> list:
        all_employees = []
        max_people = 10_000
        next_page = None
        async with httpx.AsyncClient(timeout=30.0) as client:
            while True:
                params: dict = {"includeHumanReadable": "true"}
                if next_page:
                    params["nextPage"] = next_page
                resp = await client.get(
                    f"{self.base_url}/people",
                    headers={
                        "Authorization": self._auth_header(),
                        "Accept": "application/json",
                    },
                    params=params,
                )
                resp.raise_for_status()
                data = resp.json()
                all_employees.extend(data.get("employees", []))
                next_page = data.get("nextPage")
                if not next_page or len(all_employees) >= max_people:
                    break
        return all_employees[:max_people]

    async def _upsert_users(self, employees: list) -> int:
        import uuid as _uuid
        from sqlalchemy import select
        from app.models.user import User

        count = 0
        touched_ids: set[_uuid.UUID] = set()

        for item in employees:
            try:
                work = item.get("work", {}) or {}
                personal = item.get("personal", {}) or {}

                email = work.get("email") or personal.get("privateEmail", "")
                if not email:
                    continue

                first_name = item.get("firstName", "")
                last_name = item.get("lastName", item.get("surname", ""))
                full_name = f"{first_name} {last_name}".strip()

                department = work.get("department")
                manager_info = work.get("manager") or work.get("reportsTo")
                manager = None
                if isinstance(manager_info, dict):
                    manager = manager_info.get("displayName") or manager_info.get("email")
                elif isinstance(manager_info, str):
                    manager = manager_info

                start_date = work.get("startDate")
                employment_status = "active" if work.get("activeEffectiveDate") or start_date else "inactive"

                # Build HiBob source entry (used for prune detection below)
                bob_source = {
                    "external_id": item.get("id"),
                    "active": employment_status == "active",
                }

                result = await self.db.execute(select(User).where(User.email == email))
                user = result.scalars().first()

                if not user:
                    user = User(
                        full_name=full_name or email,
                        email=email,
                        department=department,
                        manager=manager,
                        employment_status=employment_status,
                        sources={"hibob": bob_source},
                    )
                    self.db.add(user)
                    await self.db.flush()  # populate user.id before tracking
                else:
                    if full_name:
                        user.full_name = full_name
                    if department:
                        user.department = department
                    if manager:
                        user.manager = manager
                    user.employment_status = employment_status
                    # Merge sources: preserve existing keys (e.g. jumpcloud), update hibob
                    existing_sources = dict(user.sources) if user.sources else {}
                    existing_sources["hibob"] = bob_source
                    user.sources = existing_sources

                if user.id:
                    touched_ids.add(user.id)
                count += 1

            except Exception as e:
                logger.warning(f"HiBob: Failed to process employee: {e}")

        await self.db.flush()

        # Prune: users with a HiBob source entry not returned this sync were
        # removed from HiBob — mark them inactive unless JumpCloud still has them.
        bob_users = (
            await self.db.execute(
                select(User).where(
                    User.sources["hibob"].isnot(None),
                    User.employment_status != "inactive",
                )
            )
        ).scalars().all()
        pruned = 0
        for u in bob_users:
            if u.id not in touched_ids:
                # Only deactivate if JumpCloud also doesn't have them active
                jc_active = (
                    u.sources
                    and u.sources.get("jumpcloud", {}).get("active", False)
                )
                if not jc_active:
                    updated_sources = dict(u.sources) if u.sources else {}
                    updated_sources.pop("hibob", None)
                    u.sources = updated_sources
                    u.employment_status = "inactive"
                    pruned += 1
        if pruned:
            logger.info("HiBob: marked %d removed employees as inactive", pruned)
            await self.db.flush()

        return count

    # Legacy support
    async def fetch_data(self) -> list[dict[str, Any]]:
        if not self.service_user_id or not self.service_token:
            logger.warning("HiBob: No credentials configured, skipping")
            return []
        return await self._fetch_people()

    async def normalize(self, raw_items: list[dict[str, Any]]) -> list[dict[str, Any]]:
        normalized = []
        for item in raw_items:
            try:
                work = item.get("work", {})
                personal = item.get("personal", {})
                normalized.append({
                    "type": "user",
                    "full_name": f"{item.get('firstName', '')} {item.get('surname', '')}".strip(),
                    "email": work.get("email", personal.get("privateEmail", "")),
                    "department": work.get("department"),
                    "manager": work.get("reportsTo", {}).get("displayName") if work.get("reportsTo") else None,
                    "employment_status": "active" if work.get("activeEffectiveDate") else "inactive",
                    "external_id": item.get("id"),
                })
            except Exception as e:
                logger.warning(f"HiBob: Failed to normalize item: {e}")
        return normalized

    async def upsert_to_db(self, normalized: list[dict[str, Any]], db) -> None:
        from sqlalchemy import select
        from app.models.user import User

        for item in normalized:
            if not item.get("email"):
                continue
            result = await db.execute(select(User).where(User.email == item["email"]))
            user = result.scalars().first()
            if not user:
                user = User(
                    full_name=item["full_name"],
                    email=item["email"],
                    department=item.get("department"),
                    manager=item.get("manager"),
                    employment_status=item.get("employment_status", "active"),
                )
                db.add(user)
            else:
                user.full_name = item["full_name"] or user.full_name
                user.department = item.get("department") or user.department
                user.manager = item.get("manager") or user.manager
                user.employment_status = item.get("employment_status", user.employment_status)
