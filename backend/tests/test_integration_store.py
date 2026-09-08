from unittest.mock import AsyncMock

import pytest
from httpx import AsyncClient
from sqlalchemy import select

from app.models.integration import IntegrationConfig


pytestmark = pytest.mark.asyncio


async def _admin_headers(client: AsyncClient) -> dict[str, str]:
    response = await client.post(
        "/api/auth/login",
        json={"email": "admin@test.local", "password": "Admin123!"},
    )
    assert response.status_code == 200
    return {"Authorization": f"Bearer {response.json()['access_token']}"}


async def test_catalog_contains_only_the_default_store_products(
    client: AsyncClient, admin_user
):
    response = await client.get(
        "/api/integrations/catalog",
        headers=await _admin_headers(client),
    )

    assert response.status_code == 200
    assert [product["integration_type"] for product in response.json()] == [
        "jumpcloud",
        "puppet",
        "sentinelone",
        "symantec_dlp",
        "google_workspace",
        "adfs",
        "active_directory",
    ]
    products = {product["integration_type"]: product for product in response.json()}
    assert products["sentinelone"]["features"] == ["application_vulnerabilities"]
    assert products["symantec_dlp"]["features"] == ["dlp_policy_search"]
    for integration_type in ("adfs", "active_directory", "google_workspace"):
        assert products[integration_type]["features"] == ["activity"]


async def test_listing_retires_removed_products_and_seeds_the_store(
    client: AsyncClient, db_session, admin_user
):
    db_session.add_all([
        IntegrationConfig(integration_type="hibob", display_name="HiBob"),
        IntegrationConfig(integration_type="cloudsoc", display_name="CloudSOC"),
    ])
    await db_session.commit()

    response = await client.get(
        "/api/integrations",
        headers=await _admin_headers(client),
    )

    assert response.status_code == 200
    types = {item["integration_type"] for item in response.json()}
    assert types == {
        "jumpcloud", "puppet", "sentinelone", "symantec_dlp",
        "google_workspace", "adfs", "active_directory",
    }
    retired = (await db_session.execute(
        select(IntegrationConfig).where(
            IntegrationConfig.integration_type.in_(("hibob", "cloudsoc"))
        )
    )).scalars().all()
    assert retired == []


async def test_successful_connection_test_unlocks_product_features(
    client: AsyncClient, db_session, admin_user, monkeypatch
):
    config = IntegrationConfig(
        integration_type="sentinelone",
        display_name="SentinelOne",
        credentials={"api_key": "test"},
        status="unconfigured",
        is_enabled=True,
    )
    db_session.add(config)
    await db_session.commit()
    monkeypatch.setattr(
        "app.api.routes.integrations._run_test",
        AsyncMock(return_value={"success": True, "message": "Connected"}),
    )

    response = await client.post(
        "/api/integrations/sentinelone/test",
        headers=await _admin_headers(client),
    )

    assert response.status_code == 200
    await db_session.refresh(config)
    assert config.status == "connected"


async def test_feature_api_is_unavailable_until_its_product_is_connected(
    client: AsyncClient, admin_user
):
    response = await client.get(
        "/api/application-vulnerabilities/summary",
        headers=await _admin_headers(client),
    )

    assert response.status_code == 409
    assert "sentinelone" in response.json()["detail"].lower()


async def test_activity_accepts_any_connected_identity_product(
    client: AsyncClient, db_session, admin_user
):
    headers = await _admin_headers(client)
    locked = await client.get("/api/activity", headers=headers)
    assert locked.status_code == 409

    db_session.add(IntegrationConfig(
        integration_type="adfs",
        display_name="ADFS",
        credentials={"service_url": "https://adfs.test/adfs"},
        status="connected",
        is_enabled=True,
    ))
    await db_session.commit()

    unlocked = await client.get("/api/activity", headers=headers)
    assert unlocked.status_code == 200
