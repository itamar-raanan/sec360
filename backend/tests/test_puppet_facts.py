from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock

import pytest
from httpx import AsyncClient
from sqlalchemy import func, select

from app.collectors.puppet import PuppetCollector
from app.models.endpoint import Endpoint
from app.models.integration import IntegrationConfig
from app.models.puppet import PuppetFact, PuppetNode


pytestmark = pytest.mark.asyncio


async def _admin_headers(client: AsyncClient) -> dict[str, str]:
    response = await client.post(
        "/api/auth/login",
        json={"email": "admin@test.local", "password": "Admin123!"},
    )
    assert response.status_code == 200
    return {"Authorization": f"Bearer {response.json()['access_token']}"}


async def test_puppet_sync_preserves_canonical_source_and_stores_all_facts(
    db_session, monkeypatch
):
    endpoint = Endpoint(
        hostname="finance-01.example.test",
        source="jumpcloud",
        last_seen=datetime.now(timezone.utc),
    )
    db_session.add(endpoint)
    await db_session.commit()

    nodes = [{
        "certname": "finance-01.example.test",
        "report_environment": "production",
        "latest_report_status": "changed",
        "report_timestamp": "2026-09-14T10:00:00Z",
    }]
    facts = [
        {"certname": "finance-01.example.test", "name": "operatingsystem", "value": "Ubuntu", "environment": "production"},
        {"certname": "finance-01.example.test", "name": "processors", "value": {"count": 8}, "environment": "production"},
        {"certname": "finance-01.example.test", "name": "is_virtual", "value": True, "environment": "production"},
    ]
    collector = PuppetCollector({"base_url": "https://puppetdb.test"}, db_session)
    monkeypatch.setattr(collector, "_fetch_nodes", AsyncMock(return_value=nodes))
    monkeypatch.setattr(collector, "_fetch_facts", AsyncMock(return_value=facts))

    result = await collector.collect()
    await db_session.commit()

    await db_session.refresh(endpoint)
    assert endpoint.source == "jumpcloud"
    assert endpoint.os_version == "Ubuntu"
    assert result == {"records_synced": 4, "nodes_synced": 1, "facts_synced": 3}
    node = await db_session.get(PuppetNode, "finance-01.example.test")
    assert node is not None
    assert node.endpoint_id == endpoint.id
    assert await db_session.scalar(select(func.count()).select_from(PuppetFact)) == 3
    processors = (await db_session.execute(
        select(PuppetFact).where(PuppetFact.name == "processors")
    )).scalar_one()
    assert processors.value == {"count": 8}
    assert processors.value_type == "object"
    is_virtual = (await db_session.execute(
        select(PuppetFact).where(PuppetFact.name == "is_virtual")
    )).scalar_one()
    assert is_virtual.value_type == "boolean"


async def test_puppet_facts_api_is_gated_searchable_and_marks_endpoints(
    client: AsyncClient, db_session, admin_user
):
    headers = await _admin_headers(client)
    locked = await client.get("/api/puppet-facts/summary", headers=headers)
    assert locked.status_code == 409

    endpoint = Endpoint(
        hostname="build-01",
        source="active_directory",
        last_seen=datetime.now(timezone.utc) - timedelta(days=90),
    )
    db_session.add(endpoint)
    await db_session.flush()
    db_session.add(IntegrationConfig(
        integration_type="puppet",
        display_name="Puppet",
        credentials={"base_url": "https://puppetdb.test"},
        status="connected",
        is_enabled=True,
    ))
    db_session.add(PuppetNode(
        certname="build-01",
        endpoint_id=endpoint.id,
        environment="production",
        facts_timestamp=datetime.now(timezone.utc),
        synced_at=datetime.now(timezone.utc),
    ))
    db_session.add(PuppetFact(
        certname="build-01",
        name="kernel",
        value="Linux",
        environment="production",
        synced_at=datetime.now(timezone.utc),
    ))
    await db_session.commit()

    summary = await client.get("/api/puppet-facts/summary", headers=headers)
    assert summary.status_code == 200
    assert summary.json()["facts"] == 1
    assert summary.json()["nodes"] == 1

    facts = await client.get("/api/puppet-facts?search=linux", headers=headers)
    assert facts.status_code == 200
    assert facts.headers["x-total-count"] == "1"
    assert facts.json()[0]["name"] == "kernel"

    favorite = await client.post(
        "/api/puppet-facts/favorites",
        headers=headers,
        json={"fact_name": "kernel"},
    )
    assert favorite.status_code == 201
    favorites = await client.get("/api/puppet-facts/favorites", headers=headers)
    assert favorites.status_code == 200
    assert [item["fact_name"] for item in favorites.json()] == ["kernel"]

    favorite_facts = await client.get(
        "/api/puppet-facts?favorites_only=true&value_types=string&names=kernel,uptime",
        headers=headers,
    )
    assert favorite_facts.status_code == 200
    assert favorite_facts.headers["x-total-count"] == "1"
    filtered_summary = await client.get(
        "/api/puppet-facts/summary?favorites_only=true&names=kernel",
        headers=headers,
    )
    assert filtered_summary.status_code == 200
    assert filtered_summary.json()["facts"] == 1

    view_payload = {
        "name": "Linux production",
        "is_default": True,
        "definition": {
            "search": "linux",
            "certname": "build",
            "names": ["kernel"],
            "environment": "production",
            "value_types": ["string"],
            "favorites_only": True,
            "page_size": 25,
            "sort": "name",
            "order": "desc",
        },
    }
    created_view = await client.post(
        "/api/puppet-facts/saved-views", headers=headers, json=view_payload
    )
    assert created_view.status_code == 201
    assert created_view.json()["definition"] == view_payload["definition"]
    views = await client.get("/api/puppet-facts/saved-views", headers=headers)
    assert views.status_code == 200
    assert views.json()[0]["is_default"] is True

    deleted_view = await client.delete(
        f"/api/puppet-facts/saved-views/{created_view.json()['id']}", headers=headers
    )
    assert deleted_view.status_code == 204
    deleted_favorite = await client.delete(
        f"/api/puppet-facts/favorites/{favorite.json()['id']}", headers=headers
    )
    assert deleted_favorite.status_code == 204

    endpoints = await client.get(
        "/api/endpoints",
        headers=headers,
    )
    assert endpoints.status_code == 200
    assert endpoints.json()[0]["puppet_managed"] is True
    assert endpoints.json()[0]["puppet_last_seen"] is not None
