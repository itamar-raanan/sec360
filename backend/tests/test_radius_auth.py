"""RADIUS configuration, login, and packet-validation tests."""

import hashlib
import struct

import pytest
from httpx import AsyncClient

from app.services.radius_auth import (
    ACCESS_ACCEPT,
    RadiusError,
    _build_request,
    _validate_response,
)

pytestmark = pytest.mark.asyncio


async def _admin_headers(client: AsyncClient) -> dict[str, str]:
    login = await client.post(
        "/api/auth/login",
        json={"email": "admin@test.local", "password": "Admin123!"},
    )
    return {"Authorization": f"Bearer {login.json()['access_token']}"}


async def test_radius_settings_hide_secret_and_publish_availability(
    client: AsyncClient,
    admin_user,
):
    headers = await _admin_headers(client)
    update = await client.put(
        "/api/settings/saml",
        headers=headers,
        json={
            "radius_enabled": True,
            "radius_host": "radius.internal.example",
            "radius_port": 1812,
            "radius_shared_secret": "not-returned-to-browser",
            "radius_nas_identifier": "SEC360-ONPREM",
            "radius_username_format": "local_part",
        },
    )
    assert update.status_code == 200

    saved = await client.get("/api/settings/saml", headers=headers)
    assert saved.status_code == 200
    assert saved.json()["has_radius_shared_secret"] is True
    assert saved.json()["radius_host"] == "radius.internal.example"
    assert "radius_shared_secret" not in saved.json()

    status = await client.get("/api/auth/radius/status")
    assert status.json() == {"enabled": True, "provider_label": "RADIUS"}


async def test_radius_user_is_active_without_invitation_and_uses_regular_login(
    client: AsyncClient,
    admin_user,
    monkeypatch,
):
    headers = await _admin_headers(client)
    await client.put(
        "/api/settings/saml",
        headers=headers,
        json={
            "radius_enabled": True,
            "radius_host": "radius.internal.example",
            "radius_shared_secret": "shared-secret",
            "radius_username_format": "local_part",
        },
    )
    provision = await client.post(
        "/api/settings/users/provision",
        headers=headers,
        json={
            "email": "radius.user@test.local",
            "role": "analyst",
            "auth_method": "radius",
        },
    )
    assert provision.status_code == 201
    assert provision.json()["email_sent"] is False

    users = (await client.get("/api/settings/users", headers=headers)).json()
    radius_user = next(user for user in users if user["email"] == "radius.user@test.local")
    assert radius_user["auth_method"] == "radius"
    assert radius_user["is_active"] is True
    assert radius_user["invitation_pending"] is False

    calls: list[str] = []

    def accept(**kwargs):
        calls.append(kwargs["username"])
        return True, "Access-Accept"

    monkeypatch.setattr("app.services.radius_auth.authenticate_radius", accept)
    response = await client.post(
        "/api/auth/login",
        json={"email": "RADIUS.USER@test.local", "password": "radius-password"},
    )
    assert response.status_code == 200
    assert response.json()["user"]["email"] == "radius.user@test.local"
    assert response.json()["user"]["auth_method"] == "radius"
    assert calls == ["RADIUS.USER"]

    unknown = await client.post(
        "/api/auth/radius/login",
        json={"email": "unknown@test.local", "password": "radius-password"},
    )
    assert unknown.status_code == 401

    local_user = await client.post(
        "/api/auth/radius/login",
        json={"email": "admin@test.local", "password": "radius-password"},
    )
    assert local_user.status_code == 401
    assert calls == ["RADIUS.USER"]


async def test_user_provisioning_applies_auth_specific_invitation_rules(
    client: AsyncClient,
    admin_user,
    monkeypatch,
):
    headers = await _admin_headers(client)
    sent_to: list[str] = []
    monkeypatch.setattr(
        "app.services.email.send_invitation_email",
        lambda email, *_args: sent_to.append(email) or True,
    )

    local = await client.post(
        "/api/settings/users/provision",
        headers=headers,
        json={"email": "local@test.local", "role": "viewer", "auth_method": "local"},
    )
    sso = await client.post(
        "/api/settings/users/provision",
        headers=headers,
        json={"email": "sso@test.local", "role": "viewer", "auth_method": "sso"},
    )

    assert local.status_code == 201
    assert local.json()["email_sent"] is True
    assert sso.status_code == 201
    assert sso.json()["email_sent"] is False
    assert sent_to == ["local@test.local"]

    users = (await client.get("/api/settings/users", headers=headers)).json()
    by_email = {user["email"]: user for user in users}
    assert by_email["local@test.local"]["invitation_pending"] is True
    assert by_email["local@test.local"]["is_active"] is False
    assert by_email["sso@test.local"]["auth_method"] == "sso"
    assert by_email["sso@test.local"]["invitation_pending"] is False
    assert by_email["sso@test.local"]["is_active"] is True


async def test_radius_packet_encrypts_password_and_validates_response():
    secret = b"test-shared-secret"
    request = _build_request(
        7,
        b"0123456789abcdef",
        "analyst@example.com",
        "unique-clear-password",
        secret,
        "SEC360",
    )
    assert b"unique-clear-password" not in request

    response_head = struct.pack("!BBH", ACCESS_ACCEPT, 7, 20)
    authenticator = hashlib.md5(response_head + request[4:20] + secret).digest()  # noqa: S324
    response = response_head + authenticator
    assert _validate_response(response, request, secret) == ACCESS_ACCEPT

    tampered = response[:4] + bytes([response[4] ^ 1]) + response[5:]
    with pytest.raises(RadiusError, match="authenticator validation failed"):
        _validate_response(tampered, request, secret)
