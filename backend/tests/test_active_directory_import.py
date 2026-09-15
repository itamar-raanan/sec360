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


async def test_admin_can_import_combined_ad_snapshot(
    client: AsyncClient,
    db_session,
    admin_user,
):
    headers = await _admin_headers(client)
    csv_data = """object_type,sAMAccountName,mail,displayName,department,title,userAccountControl,name,operatingSystem,operatingSystemVersion,dNSHostName,lastLogonTimestamp
user,asmith,asmith@example.com,Alice Smith,Security,Analyst,512,,,,,
computer,,,,,,,WS-014,Windows 11 Enterprise,10.0,WS-014.example.com,133700000000000000
"""
    response = await client.post(
        "/api/integrations/active_directory/import",
        headers=headers,
        files={"file": ("sec360-ad-export.csv", csv_data, "text/csv")},
    )
    assert response.status_code == 200
    assert response.json()["users"] == 1
    assert response.json()["endpoints"] == 1

    user = (await db_session.execute(
        select(User).where(User.email == "asmith@example.com")
    )).scalar_one()
    assert user.full_name == "Alice Smith"
    assert user.department == "Security"
    assert user.job_title == "Analyst"
    assert user.sources == {"active_directory": {"sAMAccountName": "asmith"}}

    endpoint = (await db_session.execute(
        select(Endpoint).where(Endpoint.hostname == "WS-014")
    )).scalar_one()
    assert endpoint.source == "active_directory"
    assert endpoint.os_version == "Windows 11 Enterprise 10.0"

    config = (await db_session.execute(
        select(IntegrationConfig).where(IntegrationConfig.integration_type == "active_directory")
    )).scalar_one()
    assert config.status == "connected"
    assert config.credentials["import_mode"] == "manual"
    assert config.records_synced == "2"


async def test_ad_import_rejects_missing_object_type(
    client: AsyncClient,
    admin_user,
):
    response = await client.post(
        "/api/integrations/active_directory/import",
        headers=await _admin_headers(client),
        files={"file": ("bad.csv", "mail,name\na@example.com,Alice\n", "text/csv")},
    )
    assert response.status_code == 400
    assert "object_type" in response.json()["detail"]
