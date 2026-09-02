from unittest.mock import AsyncMock

import pytest
from httpx import AsyncClient

from app.models.integration import IntegrationConfig

pytestmark = pytest.mark.asyncio


async def _token(client: AsyncClient, email: str, password: str) -> str:
    response = await client.post("/api/auth/login", json={"email": email, "password": password})
    return response.json()["access_token"]


async def test_viewer_cannot_search_dlp_policies(client: AsyncClient, viewer_user):
    token = await _token(client, "viewer@test.local", "Viewer123!")
    response = await client.get(
        "/api/dlp-policy-search",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 403


async def test_search_requires_configured_symantec_integration(client: AsyncClient, analyst_user):
    token = await _token(client, "analyst@test.local", "Analyst123!")
    response = await client.get(
        "/api/dlp-policy-search",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 409
    assert "credentials" in response.json()["detail"].lower()


async def test_analyst_can_search_with_existing_oracle_credentials(
    client: AsyncClient,
    db_session,
    analyst_user,
    monkeypatch,
):
    db_session.add(IntegrationConfig(
        integration_type="symantec_dlp",
        display_name="Symantec DLP",
        credentials={
            "db_type": "oracle",
            "db_host": "dlp-db.internal",
            "db_port": 1521,
            "db_name": "protect",
            "db_user": "readonly",
            "db_password": "secret",
        },
        status="connected",
        is_enabled=True,
    ))
    await db_session.commit()

    query_mock = AsyncMock(return_value=([{
        "object_id": 42,
        "object_name": "Executive exclusions",
        "object_description": "Approved exception list",
        "object_status": "ACTIVE",
        "rule_type": 1,
        "used_as": "SENDER",
        "policy_id": 7,
        "policy_name": "Outbound source code",
        "policy_active_status": 1,
        "policy_record_status": "ACTIVE",
        "user_patterns": "alice@example.com",
        "ip_addresses": None,
        "url_domains": None,
        "personal_email_breadth": None,
        "personal_email_excluded_domains": None,
        "personal_email_max_recipients": None,
        "modified_date": "2026-08-31T12:00:00",
        "modified_by_id": 3,
        "object_uuid": "test-uuid",
    }], False))
    monkeypatch.setattr(
        "app.api.routes.dlp_policy_search.query_dlp_policy_exclusions",
        query_mock,
    )

    token = await _token(client, "analyst@test.local", "Analyst123!")
    response = await client.get(
        "/api/dlp-policy-search",
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 200
    body = response.json()
    assert body["row_count"] == 1
    assert body["truncated"] is False
    assert body["items"][0]["policy_name"] == "Outbound source code"
    assert body["items"][0]["user_patterns"] == "alice@example.com"
    assert "db_password" not in response.text
    query_mock.assert_awaited_once()
