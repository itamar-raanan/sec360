import logging
from types import SimpleNamespace

import pytest
from fastapi import HTTPException
from httpx import AsyncClient
from starlette.requests import Request


pytestmark = pytest.mark.asyncio


async def _login(client: AsyncClient, email: str, password: str) -> dict[str, str]:
    response = await client.post("/api/auth/login", json={"email": email, "password": password})
    assert response.status_code == 200
    return {"Authorization": f"Bearer {response.json()['access_token']}"}


async def test_rate_limit_normalizes_email_identity():
    from app.core.rate_limit import check_rate_limit, record_failure

    for index in range(10):
        email = " Admin@Test.Local " if index % 2 else "admin@test.local"
        await record_failure(email, "192.0.2.10")

    with pytest.raises(HTTPException) as exc:
        await check_rate_limit("ADMIN@TEST.LOCAL", "192.0.2.10")
    assert exc.value.status_code == 429


async def test_client_ip_ignores_proxy_headers_unless_trusted(monkeypatch):
    from app.core import request as request_security

    scope = {
        "type": "http",
        "method": "GET",
        "path": "/",
        "headers": [
            (b"x-real-ip", b"198.51.100.50"),
            (b"x-forwarded-for", b"203.0.113.99"),
        ],
        "client": ("192.0.2.25", 12345),
        "server": ("test", 443),
        "scheme": "https",
        "query_string": b"",
    }
    request = Request(scope)

    monkeypatch.setattr(request_security.settings, "TRUST_PROXY_HEADERS", False)
    assert request_security.get_client_ip(request) == "192.0.2.25"
    monkeypatch.setattr(request_security.settings, "TRUST_PROXY_HEADERS", True)
    assert request_security.get_client_ip(request) == "198.51.100.50"


async def test_bootstrap_user_is_restricted_until_password_change(client, db_session):
    from app.core.security import hash_password
    from app.models.user import AuthUser

    user = AuthUser(
        email="bootstrap@test.local",
        hashed_password=hash_password("TemporaryPassword123!"),
        role="admin",
        is_active=True,
        must_change_password=True,
    )
    db_session.add(user)
    await db_session.commit()

    headers = await _login(client, user.email, "TemporaryPassword123!")
    blocked = await client.get("/api/endpoints", headers=headers)
    assert blocked.status_code == 403
    assert blocked.json()["detail"] == "Password change required before continuing"

    changed = await client.post(
        "/api/settings/me/password",
        headers=headers,
        json={"current_password": "TemporaryPassword123!", "new_password": "ReplacementPassword123!"},
    )
    assert changed.status_code == 200
    assert user.must_change_password is False

    allowed = await client.get("/api/endpoints", headers=headers)
    assert allowed.status_code == 200


async def test_system_settings_response_never_contains_secrets(client, db_session, admin_user):
    from app.models.system_settings import SystemSettings

    db_session.add(SystemSettings(
        id=1,
        saml_sp_key="private-saml-key",
        radius_config={"host": "radius.internal", "shared_secret": "radius-secret"},
        siem_config={"url": "https://siem.internal", "secret": "siem-secret"},
    ))
    await db_session.commit()
    headers = await _login(client, "admin@test.local", "Admin123!")

    response = await client.get("/api/settings/system", headers=headers)
    assert response.status_code == 200
    payload = response.json()
    assert "saml_sp_key" not in payload
    assert "radius_config" not in payload
    assert "siem_config" not in payload
    assert "private-saml-key" not in response.text
    assert "radius-secret" not in response.text
    assert "siem-secret" not in response.text


async def test_invitation_token_is_not_logged(caplog):
    from app.services.email import send_invitation_email

    token = "super-secret-invitation-token"
    with caplog.at_level(logging.INFO):
        send_invitation_email("invitee@example.com", "viewer", token, "admin@example.com")
    assert token not in caplog.text


async def test_production_configuration_fails_closed():
    from app.core.config import validate_runtime_security

    unsafe = SimpleNamespace(
        ENVIRONMENT="production",
        JWT_SECRET="changeme-super-secret-key-for-jwt-signing-at-least-32-chars",
        COOKIE_SECURE=False,
        CREDENTIALS_ENCRYPTION_KEY=None,
        REQUIRE_REDIS_RATE_LIMIT=True,
        REDIS_URL=None,
    )
    with pytest.raises(RuntimeError) as exc:
        validate_runtime_security(unsafe)
    message = str(exc.value)
    assert "JWT_SECRET" in message
    assert "COOKIE_SECURE" in message
    assert "CREDENTIALS_ENCRYPTION_KEY" in message
    assert "REDIS_URL" in message
