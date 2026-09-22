from datetime import datetime, timezone

import pytest
from httpx import AsyncClient
from sqlalchemy import select

from app.engines.compliance import run_full_compliance
from app.models.compliance import ComplianceExclusion, ComplianceStatus
from app.models.endpoint import Endpoint
from app.models.integration import IntegrationConfig
from app.models.puppet import PuppetNode


pytestmark = pytest.mark.asyncio


async def _login(client: AsyncClient) -> dict[str, str]:
    response = await client.post(
        "/api/auth/login",
        json={"email": "admin@test.local", "password": "Admin123!"},
    )
    assert response.status_code == 200
    return {"Authorization": f"Bearer {response.json()['access_token']}"}


async def _seed_puppet_compliance(db_session):
    now = datetime.now(timezone.utc)
    managed = Endpoint(hostname="puppet-managed", last_seen=now, source="jumpcloud")
    missing = Endpoint(hostname="puppet-missing", last_seen=now, source="jumpcloud")
    db_session.add_all([managed, missing])
    await db_session.flush()
    db_session.add_all([
        IntegrationConfig(
            integration_type="puppet",
            display_name="Puppet",
            credentials={"base_url": "https://puppet.test"},
            is_enabled=True,
            status="connected",
        ),
        PuppetNode(certname="puppet-managed", endpoint_id=managed.id, synced_at=now),
    ])
    await db_session.commit()
    await run_full_compliance(db_session)
    await db_session.commit()
    return managed, missing


async def test_connected_puppet_becomes_compliance_requirement(db_session):
    managed, missing = await _seed_puppet_compliance(db_session)

    statuses = {
        row.endpoint_id: row
        for row in (await db_session.execute(select(ComplianceStatus))).scalars().all()
    }
    assert statuses[managed.id].agent_presence == {"puppet": True}
    assert statuses[managed.id].status == "compliant"
    assert statuses[missing.id].agent_presence == {"puppet": False}
    assert statuses[missing.id].status == "non_compliant"


async def test_agent_filter_and_exclusions_update_coverage(
    client: AsyncClient, db_session, admin_user
):
    managed, missing = await _seed_puppet_compliance(db_session)
    headers = await _login(client)

    dashboard = await client.get("/api/compliance/dashboard", headers=headers)
    assert dashboard.status_code == 200
    assert dashboard.json()["agent_coverage"] == [{
        "key": "puppet",
        "label": "Puppet",
        "description": "Puppet-managed endpoint",
        "has": 1,
        "missing": 1,
        "excluded": 0,
        "in_scope": 2,
        "coverage_pct": 50.0,
    }]

    filtered = await client.get(
        "/api/compliance/endpoints?agents=puppet:missing", headers=headers
    )
    assert filtered.status_code == 200
    assert [row["endpoint_id"] for row in filtered.json()] == [str(missing.id)]

    agent_exclusion = await client.put(
        f"/api/compliance/endpoints/{missing.id}/exclusions",
        headers=headers,
        json={
            "exclude_all": False,
            "excluded_agents": ["puppet"],
            "reason": "Temporary Puppet migration",
        },
    )
    assert agent_exclusion.status_code == 200
    assert agent_exclusion.json()["excluded_agents"] == ["puppet"]
    missing_status = await db_session.scalar(
        select(ComplianceStatus).where(ComplianceStatus.endpoint_id == missing.id)
    )
    assert missing_status.status == "compliant"

    filtered = await client.get(
        "/api/compliance/endpoints?agents=puppet:missing", headers=headers
    )
    assert filtered.status_code == 200
    assert filtered.json() == []

    endpoint_detail = await client.get(f"/api/endpoints/{missing.id}", headers=headers)
    assert endpoint_detail.status_code == 200
    assert endpoint_detail.json()["excluded_agents"] == ["puppet"]
    assert endpoint_detail.json()["compliance_exclusion_reason"] == "Temporary Puppet migration"

    endpoint_list = await client.get("/api/endpoints?limit=100", headers=headers)
    listed_missing = next(
        row for row in endpoint_list.json() if row["id"] == str(missing.id)
    )
    assert listed_missing["compliance_excluded"] is False
    assert listed_missing["excluded_agents"] == ["puppet"]
    assert listed_missing["compliance_exclusion_reason"] == "Temporary Puppet migration"

    dashboard = await client.get("/api/compliance/dashboard", headers=headers)
    puppet = dashboard.json()["agent_coverage"][0]
    assert puppet["missing"] == 0
    assert puppet["excluded"] == 1
    assert puppet["in_scope"] == 1

    full_exclusion = await client.put(
        f"/api/compliance/endpoints/{missing.id}/exclusions",
        headers=headers,
        json={
            "exclude_all": True,
            "excluded_agents": [],
            "reason": "Lab device",
        },
    )
    assert full_exclusion.status_code == 200

    dashboard = await client.get("/api/compliance/dashboard", headers=headers)
    assert dashboard.json()["summary"]["total"] == 1
    assert dashboard.json()["excluded_total"] == 1

    included = await client.get("/api/compliance/endpoints", headers=headers)
    assert {row["endpoint_id"] for row in included.json()} == {str(managed.id)}
    excluded = await client.get(
        "/api/compliance/endpoints?scope=excluded", headers=headers
    )
    assert [row["endpoint_id"] for row in excluded.json()] == [str(missing.id)]
    assert excluded.json()[0]["compliance_excluded"] is True
    assert await db_session.scalar(
        select(ComplianceExclusion.reason).where(
            ComplianceExclusion.endpoint_id == missing.id,
            ComplianceExclusion.agent_key == "*",
        )
    ) == "Lab device"


async def test_configured_product_remains_required_during_connection_error(
    client: AsyncClient, db_session, admin_user
):
    now = datetime.now(timezone.utc)
    endpoint = Endpoint(hostname="missing-dlp", last_seen=now, source="jumpcloud")
    db_session.add_all([
        endpoint,
        IntegrationConfig(
            integration_type="symantec_dlp",
            display_name="Symantec DLP",
            credentials={"api_url": "https://dlp.example.test", "api_key": "test"},
            is_enabled=True,
            status="error",
        ),
    ])
    await db_session.commit()
    await run_full_compliance(db_session)
    await db_session.commit()

    compliance = await db_session.scalar(
        select(ComplianceStatus).where(ComplianceStatus.endpoint_id == endpoint.id)
    )
    assert compliance.agent_presence == {"symantec_dlp": False}

    dashboard = await client.get(
        "/api/compliance/dashboard", headers=await _login(client)
    )
    assert dashboard.status_code == 200
    coverage = dashboard.json()["agent_coverage"]
    assert coverage == [{
        "key": "symantec_dlp",
        "label": "Symantec DLP",
        "description": "Data loss prevention endpoint agent",
        "has": 0,
        "missing": 1,
        "excluded": 0,
        "in_scope": 1,
        "coverage_pct": 0.0,
    }]

    inventory = (await client.get(
        "/api/endpoints?limit=100", headers=await _login(client)
    )).json()
    endpoint_missing = sum(
        not row["compliance_excluded"]
        and "symantec_dlp" not in row["excluded_agents"]
        and not row["compliance_status"]["agent_presence"].get("symantec_dlp", False)
        for row in inventory
    )
    assert endpoint_missing == coverage[0]["missing"]


async def test_exclusion_requires_reason(client: AsyncClient, db_session, admin_user):
    _, missing = await _seed_puppet_compliance(db_session)
    headers = await _login(client)
    response = await client.put(
        f"/api/compliance/endpoints/{missing.id}/exclusions",
        headers=headers,
        json={"exclude_all": True, "excluded_agents": []},
    )
    assert response.status_code == 422
