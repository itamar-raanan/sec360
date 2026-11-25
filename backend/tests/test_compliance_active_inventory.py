from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock

import pytest
from httpx import AsyncClient
from sqlalchemy import func, select

from app.engines.compliance import run_full_compliance
from app.models.agent import SecurityAgent
from app.models.compliance import ComplianceStatus
from app.models.endpoint import Endpoint
from app.models.integration import IntegrationConfig
from app.models.compliance import ComplianceExclusion


pytestmark = pytest.mark.asyncio


async def _seed_inventory(db_session):
    now = datetime.now(timezone.utc)
    current = Endpoint(
        hostname="current-device",
        os_version="Windows 11 Enterprise",
        last_seen=now - timedelta(days=1),
        is_active=True,
        source="jumpcloud",
    )
    removed = Endpoint(
        hostname="removed-device",
        last_seen=now - timedelta(days=1),
        is_active=False,
        source="jumpcloud",
    )
    old_available = Endpoint(
        hostname="old-available-device",
        last_seen=now - timedelta(days=90),
        is_active=True,
        source="sentinelone",
    )
    agent_current = Endpoint(
        hostname="agent-current-device",
        os_version="Ubuntu Linux 24.04",
        last_seen=now - timedelta(days=90),
        is_active=True,
        source="jumpcloud",
    )
    db_session.add_all([current, removed, old_available, agent_current])
    await db_session.flush()

    db_session.add(SecurityAgent(
        endpoint_id=agent_current.id,
        product_name="sentinelone",
        status="active",
        version="1.0",
        last_seen=now - timedelta(days=2),
    ))
    db_session.add_all([
        IntegrationConfig(
            integration_type="sentinelone", display_name="SentinelOne",
            credentials={}, is_enabled=True, status="connected",
        ),
        IntegrationConfig(
            integration_type="symantec_dlp", display_name="Symantec DLP",
            credentials={}, is_enabled=True, status="connected",
        ),
        ComplianceStatus(endpoint_id=current.id, status="compliant", edr_installed=True, dlp_installed=True),
        ComplianceStatus(endpoint_id=removed.id, status="non_compliant"),
        ComplianceStatus(endpoint_id=old_available.id, status="non_compliant"),
        ComplianceStatus(endpoint_id=agent_current.id, status="partial", edr_installed=True),
    ])
    await db_session.commit()
    return current, removed, old_available, agent_current


async def _login(client: AsyncClient) -> dict[str, str]:
    response = await client.post(
        "/api/auth/login",
        json={"email": "admin@test.local", "password": "Admin123!"},
    )
    assert response.status_code == 200
    return {"Authorization": f"Bearer {response.json()['access_token']}"}


async def test_compliance_dashboard_counts_all_available_inventory(
    client: AsyncClient, db_session, admin_user
):
    await _seed_inventory(db_session)
    headers = await _login(client)

    dashboard = await client.get("/api/compliance/dashboard", headers=headers)
    assert dashboard.status_code == 200
    assert dashboard.json()["inventory_total"] == 3
    assert dashboard.json()["summary"] == {
        "total": 3,
        "compliant": 1,
        "partial": 1,
        "non_compliant": 1,
        "compliant_pct": 33.3,
    }

    inventory = await client.get("/api/endpoints?limit=100", headers=headers)
    assert inventory.status_code == 200
    assert {row["hostname"] for row in inventory.json()} == {
        "current-device",
        "old-available-device",
        "agent-current-device",
    }

    endpoints = await client.get("/api/compliance/endpoints", headers=headers)
    assert endpoints.status_code == 200
    assert endpoints.headers["x-total-count"] == "3"
    assert {row["hostname"] for row in endpoints.json()} == {
        "current-device",
        "old-available-device",
        "agent-current-device",
    }

    multiple_statuses = await client.get(
        "/api/compliance/endpoints?statuses=compliant,partial", headers=headers
    )
    assert multiple_statuses.status_code == 200
    assert {row["hostname"] for row in multiple_statuses.json()} == {
        "current-device",
        "agent-current-device",
    }

    combined_facets = await client.get(
        "/api/compliance/endpoints"
        "?statuses=partial,non_compliant"
        "&issues=no_dlp,edr_outdated"
        "&oses=Linux,Android",
        headers=headers,
    )
    assert combined_facets.status_code == 200
    assert [row["hostname"] for row in combined_facets.json()] == [
        "agent-current-device"
    ]


async def test_full_evaluation_keeps_old_available_records(db_session):
    await _seed_inventory(db_session)

    result = await run_full_compliance(db_session)
    await db_session.commit()

    assert result == {
        "evaluated": 3,
        "total": 3,
        "stale_records_removed": 1,
    }
    remaining = await db_session.scalar(
        select(func.count()).select_from(ComplianceStatus)
    )
    assert remaining == 3


async def test_security_inventory_and_compliance_counts_survive_source_removal(
    client: AsyncClient, db_session, admin_user
):
    """Compare the actual APIs after a later JumpCloud sync and a legacy repair."""
    from app.collectors.jumpcloud import JumpCloudCollector

    products = ("sentinelone", "symantec", "symantec_wss")
    endpoints = []
    for product in products:
        for state in ("active", "stale", "ignored", "decommissioned"):
            endpoint = Endpoint(
                hostname=f"{product}-{state}", source="jumpcloud",
                is_active=state == "active", lifecycle_state=state,
            )
            db_session.add(endpoint)
            await db_session.flush()
            db_session.add(SecurityAgent(
                endpoint_id=endpoint.id, product_name=product,
                status="inactive", source_id=f"{product}-{state}",
            ))
            endpoints.append(endpoint)
    excluded = Endpoint(hostname="compliance-exception", source="jumpcloud")
    db_session.add(excluded)
    await db_session.flush()
    db_session.add_all([
        SecurityAgent(endpoint_id=excluded.id, product_name="sentinelone", status="active"),
        ComplianceExclusion(
            endpoint_id=excluded.id, agent_key="*",
            reason="Approved exception", created_by="analyst@example.test",
        ),
        IntegrationConfig(
            integration_type="sentinelone", display_name="SentinelOne",
            credentials={"api_key": "test"}, is_enabled=True, status="connected",
        ),
        IntegrationConfig(
            integration_type="symantec_dlp", display_name="Symantec DLP",
            credentials={"db_host": "test"}, is_enabled=True, status="connected",
        ),
    ])
    await db_session.flush()
    collector = JumpCloudCollector(credentials={"api_key": "test"}, db=db_session)
    await collector._upsert_systems([])
    result = await run_full_compliance(db_session)
    await db_session.commit()
    assert result["total"] == result["evaluated"] == 7

    headers = await _login(client)
    inventory = await client.get("/api/endpoints?limit=100", headers=headers)
    dashboard = await client.get("/api/compliance/dashboard", headers=headers)
    compliance = await client.get("/api/compliance/endpoints", headers=headers)
    assert inventory.status_code == dashboard.status_code == compliance.status_code == 200
    assert int(inventory.headers["x-total-count"]) == dashboard.json()["inventory_total"] == 7
    assert int(compliance.headers["x-total-count"]) == dashboard.json()["summary"]["total"] == 6
    coverage = {item["key"]: item for item in dashboard.json()["agent_coverage"]}
    for product, key in zip(products, ("sentinelone", "symantec_dlp", "symantec_wss")):
        visible = sum(
            any(agent["product_name"] == product for agent in endpoint["agents"])
            for endpoint in inventory.json()
        )
        # The full exception is intentionally visible in Endpoints while not
        # counting towards Compliance. Connectivity does not reduce coverage.
        assert visible == (3 if product == "sentinelone" else 2)
        assert dashboard.json()["inventory_agent_counts"][key] == visible
        assert coverage[key]["has"] == 2
    assert dashboard.json()["excluded_total"] == 1
    for endpoint in endpoints:
        if endpoint.hostname.endswith(("-ignored", "-decommissioned")):
            assert endpoint.is_active is False


async def test_dashboard_deployment_count_does_not_require_a_compliance_snapshot(
    client: AsyncClient, db_session, admin_user
):
    endpoint = Endpoint(hostname="new-s1-device", source="sentinelone")
    db_session.add(endpoint)
    await db_session.flush()
    db_session.add(SecurityAgent(
        endpoint_id=endpoint.id, product_name="sentinelone", status="inactive",
    ))
    await db_session.commit()

    response = await client.get("/api/compliance/dashboard", headers=await _login(client))
    assert response.status_code == 200
    assert response.json()["summary"]["total"] == 0
    assert response.json()["inventory_total"] == 1
    assert response.json()["inventory_agent_counts"] == {
        "sentinelone": 1, "symantec_dlp": 0, "symantec_wss": 0,
    }


@pytest.mark.parametrize("integration_type", ["jumpcloud", "active_directory"])
async def test_manual_directory_sync_refreshes_security_coverage(
    client: AsyncClient, db_session, admin_user, monkeypatch, integration_type
):
    endpoint = Endpoint(
        hostname="retained-security-device", source="jumpcloud",
        is_active=False, lifecycle_state="stale",
    )
    db_session.add(endpoint)
    await db_session.flush()
    db_session.add_all([
        SecurityAgent(endpoint_id=endpoint.id, product_name="sentinelone", status="inactive"),
        IntegrationConfig(
            integration_type=integration_type, display_name=integration_type,
            credentials={"test": "configured"}, is_enabled=True, status="connected",
        ),
        IntegrationConfig(
            integration_type="sentinelone", display_name="SentinelOne",
            credentials={"api_key": "test"}, is_enabled=True, status="connected",
        ),
    ])
    await db_session.commit()
    # External collection is outside the regression; exercise real inventory
    # restoration, Compliance rebuilding, transaction commit, and API reads.
    monkeypatch.setattr(
        "app.api.routes.integrations._run_collect",
        AsyncMock(return_value={"records_synced": 0}),
    )
    monkeypatch.setattr("app.engines.risk.update_all_risk_scores", AsyncMock())
    headers = await _login(client)
    response = await client.post(f"/api/integrations/{integration_type}/sync", headers=headers)
    assert response.status_code == 200
    assert response.json()["success"] is True

    inventory = await client.get("/api/endpoints?has_s1=true", headers=headers)
    dashboard = await client.get("/api/compliance/dashboard", headers=headers)
    assert inventory.status_code == dashboard.status_code == 200
    assert int(inventory.headers["x-total-count"]) == 1
    coverage = {item["key"]: item for item in dashboard.json()["agent_coverage"]}
    assert coverage["sentinelone"]["has"] == 1
