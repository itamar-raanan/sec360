from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import select

from app.models.api_key import PersonalApiKey
from app.models.audit import AuditLog


pytestmark = pytest.mark.asyncio


async def _login(client, email: str, password: str) -> str:
    response = await client.post("/api/auth/login", json={"email": email, "password": password})
    assert response.status_code == 200
    return response.json()["access_token"]


async def test_user_can_create_use_list_and_revoke_read_only_api_key(
    client, db_session, admin_user
):
    access_token = await _login(client, admin_user.email, "Admin123!")
    created = await client.post(
        "/api/settings/me/api-keys",
        json={"name": "Reporting export", "expires_in_days": 30},
    )
    assert created.status_code == 201
    payload = created.json()
    raw_key = payload["key"]
    assert raw_key.startswith(f"{payload['prefix']}_")
    assert payload["status"] == "active"

    stored = await db_session.scalar(select(PersonalApiKey))
    assert stored is not None
    assert stored.name == "Reporting export"
    assert stored.key_hash != raw_key
    assert raw_key not in stored.key_hash

    # Machine requests do not carry browser cookies. The key can fetch data,
    # but every mutating method is rejected before route logic runs.
    client.cookies.clear()
    api_headers = {"Authorization": f"Bearer {raw_key}"}
    me = await client.get("/api/auth/me", headers=api_headers)
    assert me.status_code == 200
    assert me.json()["email"] == admin_user.email
    denied = await client.post("/api/auth/logout", headers=api_headers)
    assert denied.status_code == 403
    assert "read-only" in denied.json()["detail"]

    await db_session.refresh(stored)
    assert stored.last_used_at is not None

    # Key-management endpoints require an interactive session, even though
    # listing is itself a GET request.
    managed_by_key = await client.get("/api/settings/me/api-keys", headers=api_headers)
    assert managed_by_key.status_code == 403
    mfa_setup_by_key = await client.get("/api/settings/me/mfa/setup", headers=api_headers)
    assert mfa_setup_by_key.status_code == 403

    interactive_headers = {"Authorization": f"Bearer {access_token}"}
    listing = await client.get("/api/settings/me/api-keys", headers=interactive_headers)
    assert listing.status_code == 200
    assert listing.json()[0]["prefix"] == payload["prefix"]
    assert "key" not in listing.json()[0]
    assert "key_hash" not in listing.json()[0]

    revoked = await client.delete(
        f"/api/settings/me/api-keys/{payload['id']}", headers=interactive_headers
    )
    assert revoked.status_code == 200
    assert (await client.get("/api/auth/me", headers=api_headers)).status_code == 401

    actions = set((await db_session.execute(
        select(AuditLog.action).where(AuditLog.resource_type == "personal_api_key")
    )).scalars().all())
    assert actions == {"create_personal_api_key", "revoke_personal_api_key"}


async def test_api_key_inherits_user_role_and_expiration(
    client, db_session, viewer_user
):
    await _login(client, viewer_user.email, "Viewer123!")
    created = await client.post(
        "/api/settings/me/api-keys",
        json={"name": "Viewer automation", "expires_in_days": 90},
    )
    assert created.status_code == 201
    raw_key = created.json()["key"]
    client.cookies.clear()
    headers = {"Authorization": f"Bearer {raw_key}"}

    assert (await client.get("/api/auth/me", headers=headers)).status_code == 200
    assert (await client.get("/api/settings/system", headers=headers)).status_code == 403

    stored = await db_session.scalar(select(PersonalApiKey))
    stored.expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
    await db_session.commit()
    assert (await client.get("/api/auth/me", headers=headers)).status_code == 401


async def test_invalid_api_key_is_rejected(client):
    response = await client.get(
        "/api/auth/me",
        headers={"Authorization": "Bearer sec360_0000000000000000_not-a-real-key"},
    )
    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid or expired API key"
