"""Tests for authentication endpoints."""
import pytest
from httpx import AsyncClient

pytestmark = pytest.mark.asyncio


async def test_login_success(client: AsyncClient, admin_user):
    res = await client.post("/api/auth/login", json={"email": "admin@test.local", "password": "Admin123!"})
    assert res.status_code == 200
    data = res.json()
    assert "access_token" in data
    assert data["user"]["email"] == "admin@test.local"
    assert data["user"]["role"] == "admin"
    # Cookie should be set
    assert "sec360_token" in res.cookies


async def test_login_wrong_password(client: AsyncClient, admin_user):
    res = await client.post("/api/auth/login", json={"email": "admin@test.local", "password": "wrong"})
    assert res.status_code == 401
    assert "Invalid" in res.json()["detail"]


async def test_login_unknown_email(client: AsyncClient):
    res = await client.post("/api/auth/login", json={"email": "nobody@test.local", "password": "pass"})
    assert res.status_code == 401


async def test_login_inactive_user(client: AsyncClient, db_session, admin_user):
    from app.models.user import AuthUser
    from sqlalchemy import select
    result = await db_session.execute(select(AuthUser).where(AuthUser.email == "admin@test.local"))
    user = result.scalar_one()
    user.is_active = False
    await db_session.commit()

    res = await client.post("/api/auth/login", json={"email": "admin@test.local", "password": "Admin123!"})
    assert res.status_code == 403


async def test_brute_force_lockout(client: AsyncClient, admin_user):
    """After 10 failed attempts the endpoint returns 429."""
    for _ in range(10):
        await client.post("/api/auth/login", json={"email": "admin@test.local", "password": "bad"})
    res = await client.post("/api/auth/login", json={"email": "admin@test.local", "password": "bad"})
    assert res.status_code == 429


async def test_get_me_authenticated(client: AsyncClient, admin_user):
    login = await client.post("/api/auth/login", json={"email": "admin@test.local", "password": "Admin123!"})
    token = login.json()["access_token"]
    res = await client.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert res.status_code == 200
    assert res.json()["email"] == "admin@test.local"


async def test_get_me_unauthenticated(client: AsyncClient):
    res = await client.get("/api/auth/me")
    assert res.status_code == 401


async def test_logout(client: AsyncClient, admin_user):
    login = await client.post("/api/auth/login", json={"email": "admin@test.local", "password": "Admin123!"})
    token = login.json()["access_token"]
    res = await client.post("/api/auth/logout", headers={"Authorization": f"Bearer {token}"})
    assert res.status_code == 200
    assert res.json()["message"] == "Logged out"


async def test_refresh_token(client: AsyncClient, admin_user):
    login = await client.post("/api/auth/login", json={"email": "admin@test.local", "password": "Admin123!"})
    assert login.status_code == 200
    # Refresh cookie should be present
    assert "sec360_refresh" in login.cookies
    res = await client.post("/api/auth/refresh")
    assert res.status_code == 200
    assert "access_token" in res.json()
