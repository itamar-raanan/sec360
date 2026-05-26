"""Tests for role-based access control across key routes."""
import pytest
from httpx import AsyncClient

pytestmark = pytest.mark.asyncio


async def _token(client: AsyncClient, email: str, password: str) -> str:
    res = await client.post("/api/auth/login", json={"email": email, "password": password})
    return res.json()["access_token"]


async def test_viewer_can_read_users(client: AsyncClient, viewer_user):
    tok = await _token(client, "viewer@test.local", "Viewer123!")
    res = await client.get("/api/users", headers={"Authorization": f"Bearer {tok}"})
    assert res.status_code == 200


async def test_viewer_can_read_endpoints(client: AsyncClient, viewer_user):
    tok = await _token(client, "viewer@test.local", "Viewer123!")
    res = await client.get("/api/endpoints", headers={"Authorization": f"Bearer {tok}"})
    assert res.status_code == 200


async def test_viewer_can_read_compliance(client: AsyncClient, viewer_user):
    tok = await _token(client, "viewer@test.local", "Viewer123!")
    res = await client.get("/api/compliance/summary", headers={"Authorization": f"Bearer {tok}"})
    assert res.status_code == 200


async def test_viewer_cannot_trigger_evaluation(client: AsyncClient, viewer_user):
    tok = await _token(client, "viewer@test.local", "Viewer123!")
    res = await client.post("/api/compliance/evaluate", headers={"Authorization": f"Bearer {tok}"})
    assert res.status_code == 403


async def test_analyst_can_trigger_evaluation(client: AsyncClient, analyst_user):
    tok = await _token(client, "analyst@test.local", "Analyst123!")
    res = await client.post("/api/compliance/evaluate", headers={"Authorization": f"Bearer {tok}"})
    # 200 (background task queued) — not 403
    assert res.status_code == 200


async def test_viewer_cannot_access_settings_users(client: AsyncClient, viewer_user):
    tok = await _token(client, "viewer@test.local", "Viewer123!")
    res = await client.get("/api/settings/users", headers={"Authorization": f"Bearer {tok}"})
    assert res.status_code == 403


async def test_admin_can_access_settings_users(client: AsyncClient, admin_user):
    tok = await _token(client, "admin@test.local", "Admin123!")
    res = await client.get("/api/settings/users", headers={"Authorization": f"Bearer {tok}"})
    assert res.status_code == 200


async def test_unauthenticated_blocked_everywhere(client: AsyncClient):
    for path in ["/api/users", "/api/endpoints", "/api/compliance/summary", "/api/risk/summary"]:
        res = await client.get(path)
        assert res.status_code == 401, f"Expected 401 for {path}, got {res.status_code}"
