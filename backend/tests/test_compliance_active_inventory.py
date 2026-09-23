from datetime import datetime, timedelta, timezone

import pytest
from httpx import AsyncClient
from sqlalchemy import func, select

from app.engines.compliance import run_full_compliance
from app.models.agent import SecurityAgent
from app.models.compliance import ComplianceStatus
from app.models.endpoint import Endpoint
from app.models.integration import IntegrationConfig


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
