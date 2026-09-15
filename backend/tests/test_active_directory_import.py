"""Offline Active Directory CSV import tests."""

import pytest
from httpx import AsyncClient
from sqlalchemy import select

from app.models.endpoint import Endpoint
from app.models.integration import IntegrationConfig
from app.models.user import User

pytestmark = pytest.mark.asyncio


async def _admin_headers(client: AsyncClient) -> dict[str, str]:
    login = await client.post(
        "/api/auth/login",
        json={"email": "admin@test.local", "password": "Admin123!"},
    )
    return {"Authorization": f"Bearer {login.json()['access_token']}"}


async def test_admin_can_import_minimal_ad_users_and_link_endpoints(
    client: AsyncClient,
    db_session,
    admin_user,
):
    headers = await _admin_headers(client)
    endpoint = Endpoint(hostname="WS-014", username="asmith", source="sentinelone")
    db_session.add(endpoint)
    await db_session.commit()
    csv_data = """First Name,Last Name,E-mail,Enabled
Alice,Smith,asmith@example.com,True
Bob,Jones,bjones@example.com,False
"""
    response = await client.post(
        "/api/integrations/active_directory/import",
        headers=headers,
        files={"file": ("sec360-ad-export.csv", csv_data, "text/csv")},
    )
    assert response.status_code == 200
    assert response.json()["users"] == 2
    assert response.json()["enabled_users"] == 1
    assert response.json()["disabled_users"] == 1
    assert response.json()["linked_endpoints"] == 1

    user = (await db_session.execute(
        select(User).where(User.email == "asmith@example.com")
    )).scalar_one()
    assert user.full_name == "Alice Smith"
    assert user.employment_status == "active"
    assert user.sources == {"active_directory": {"sAMAccountName": "asmith", "enabled": True}}

    disabled_user = (await db_session.execute(
        select(User).where(User.email == "bjones@example.com")
    )).scalar_one()
    assert disabled_user.full_name == "Bob Jones"
    assert disabled_user.employment_status == "inactive"
    assert disabled_user.sources == {"active_directory": {"sAMAccountName": "bjones", "enabled": False}}

    imported_endpoint = (await db_session.execute(
        select(Endpoint).where(Endpoint.hostname == "WS-014")
    )).scalar_one()
    assert imported_endpoint.source == "sentinelone"
    assert imported_endpoint.owner_user_id == user.id

    config = (await db_session.execute(
        select(IntegrationConfig).where(IntegrationConfig.integration_type == "active_directory")
    )).scalar_one()
    assert config.status == "connected"
    assert config.credentials["import_mode"] == "manual"
    assert config.records_synced == "2"


async def test_ad_import_rejects_missing_required_columns(
    client: AsyncClient,
    admin_user,
):
    response = await client.post(
        "/api/integrations/active_directory/import",
        headers=await _admin_headers(client),
        files={"file": ("bad.csv", "mail,name\na@example.com,Alice\n", "text/csv")},
    )
    assert response.status_code == 400
    assert "first name" in response.json()["detail"]
