import pytest
from sqlalchemy import select

from app.collectors.active_directory import ActiveDirectoryCollector
from app.collectors.custom_db import validate_read_only_query
from app.core.outbound import OutboundTargetError, validate_outbound_url
from app.models.system_settings import SystemSettings
from app.models.user import AuthSession


@pytest.mark.asyncio
async def test_logout_revokes_server_side_session(client, db_session, admin_user):
    login = await client.post(
        "/api/auth/login",
        json={"email": admin_user.email, "password": "Admin123!"},
    )
    token = login.json()["access_token"]
    assert await db_session.scalar(select(AuthSession)) is not None

    assert (await client.post("/api/auth/logout")).status_code == 200
    denied = await client.get(
        "/api/auth/me", headers={"Authorization": f"Bearer {token}"}
    )
    assert denied.status_code == 401


@pytest.mark.asyncio
async def test_refresh_token_is_one_time_use(client, admin_user):
    login = await client.post(
        "/api/auth/login",
        json={"email": admin_user.email, "password": "Admin123!"},
    )
    original_refresh = login.cookies["sec360_refresh"]
    assert (await client.post("/api/auth/refresh")).status_code == 200

    client.cookies.clear()
    client.cookies.set(
        "sec360_refresh",
        original_refresh,
        path="/api/auth/refresh",
    )
    replay = await client.post("/api/auth/refresh")
    assert replay.status_code == 401


@pytest.mark.asyncio
async def test_global_mfa_policy_restricts_account_until_enrollment(
    client, db_session, admin_user
):
    db_session.add(SystemSettings(id=1, enforce_mfa=True))
    await db_session.commit()
    login = await client.post(
        "/api/auth/login",
        json={"email": admin_user.email, "password": "Admin123!"},
    )
    assert login.status_code == 200
    assert login.json()["user"]["mfa_setup_required"] is True
    assert (await client.get("/api/settings/endpoint-product-tags")).status_code == 403
    assert (await client.get("/api/settings/me/mfa/setup")).status_code == 200


@pytest.mark.parametrize(
    "query",
    [
        "SELECT * FROM endpoints; DELETE FROM endpoints",
        "UPDATE endpoints SET hostname = 'bad'",
        "SELECT 1 -- hidden mutation",
        "WITH changed AS (DELETE FROM endpoints RETURNING *) SELECT * FROM changed",
    ],
)
def test_custom_database_rejects_non_read_only_queries(query):
    with pytest.raises(ValueError):
        validate_read_only_query(query)


def test_custom_database_accepts_one_select():
    assert validate_read_only_query(" SELECT id FROM endpoints; ") == "SELECT id FROM endpoints"


@pytest.mark.asyncio
async def test_outbound_validator_blocks_metadata_and_loopback():
    with pytest.raises(OutboundTargetError):
        await validate_outbound_url("https://169.254.169.254/latest/meta-data")
    with pytest.raises(OutboundTargetError):
        await validate_outbound_url("https://127.0.0.1/admin")


@pytest.mark.asyncio
async def test_active_directory_rejects_plaintext_ldap(db_session):
    collector = ActiveDirectoryCollector(
        {
            "ldap_host": "dc.example.test",
            "ldap_port": 389,
            "base_dn": "DC=example,DC=test",
            "bind_dn": "CN=svc,DC=example,DC=test",
            "bind_password": "secret",
            "use_ssl": "false",
        },
        db_session,
    )
    result = await collector.test_connection()
    assert result["success"] is False
    assert "Unencrypted LDAP" in result["message"]
