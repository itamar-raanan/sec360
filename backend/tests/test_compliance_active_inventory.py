from datetime import datetime, timedelta, timezone

import pytest
from httpx import AsyncClient
from sqlalchemy import func, select

from app.engines.compliance import run_full_compliance
from app.models.agent import SecurityAgent
from app.models.compliance import ComplianceStatus
from app.models.endpoint import Endpoint


pytestmark = pytest.mark.asyncio


async def _seed_inventory(db_session):
    now = datetime.now(timezone.utc)
    current = Endpoint(
        hostname="current-device",
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
    stale = Endpoint(
        hostname="stale-device",
        last_seen=now - timedelta(days=90),
        is_active=True,
        source="sentinelone",
    )
    agent_current = Endpoint(
        hostname="agent-current-device",
        last_seen=now - timedelta(days=90),
        is_active=True,
        source="jumpcloud",
    )
    db_session.add_all([current, removed, stale, agent_current])
    await db_session.flush()

    db_session.add(SecurityAgent(
        endpoint_id=agent_current.id,
        product_name="sentinelone",
        status="active",
        version="1.0",
        last_seen=now - timedelta(days=2),
    ))
    db_session.add_all([
        ComplianceStatus(endpoint_id=current.id, status="compliant", edr_installed=True, dlp_installed=True),
        ComplianceStatus(endpoint_id=removed.id, status="non_compliant"),
        ComplianceStatus(endpoint_id=stale.id, status="non_compliant"),
        ComplianceStatus(endpoint_id=agent_current.id, status="partial", edr_installed=True),
    ])
    await db_session.commit()
    return current, removed, stale, agent_current


async def _login(client: AsyncClient) -> dict[str, str]:
    response = await client.post(
        "/api/auth/login",
        json={"email": "admin@test.local", "password": "Admin123!"},
    )
    assert response.status_code == 200
    return {"Authorization": f"Bearer {response.json()['access_token']}"}


async def test_compliance_dashboard_only_counts_current_inventory(
    client: AsyncClient, db_session, admin_user
):
    await _seed_inventory(db_session)
    headers = await _login(client)

    dashboard = await client.get("/api/compliance/dashboard", headers=headers)
    assert dashboard.status_code == 200
    assert dashboard.json()["summary"] == {
        "total": 2,
        "compliant": 1,
        "partial": 1,
        "non_compliant": 0,
        "compliant_pct": 50.0,
    }

    endpoints = await client.get("/api/compliance/endpoints", headers=headers)
    assert endpoints.status_code == 200
    assert endpoints.headers["x-total-count"] == "2"
    assert {row["hostname"] for row in endpoints.json()} == {
        "current-device",
        "agent-current-device",
    }


async def test_full_evaluation_removes_stale_derived_records(db_session):
    await _seed_inventory(db_session)

    result = await run_full_compliance(db_session)
    await db_session.commit()

    assert result == {
        "evaluated": 2,
        "total": 2,
        "stale_records_removed": 2,
    }
    remaining = await db_session.scalar(
        select(func.count()).select_from(ComplianceStatus)
    )
    assert remaining == 2
