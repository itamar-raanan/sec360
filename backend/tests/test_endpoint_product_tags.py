from datetime import datetime, timezone

import pytest
from httpx import AsyncClient
from sqlalchemy import select

from app.models.agent import SecurityAgent
from app.models.compliance import ComplianceStatus
from app.models.endpoint import Endpoint
from app.models.system_settings import SystemSettings


pytestmark = pytest.mark.asyncio


async def _headers(client: AsyncClient, email: str, password: str) -> dict[str, str]:
    response = await client.post("/api/auth/login", json={"email": email, "password": password})
    assert response.status_code == 200
    return {"Authorization": f"Bearer {response.json()['access_token']}"}


async def test_endpoint_product_tags_default_to_all_products(client: AsyncClient, viewer_user):
    response = await client.get(
        "/api/settings/endpoint-product-tags",
        headers=await _headers(client, "viewer@test.local", "Viewer123!"),
    )

    assert response.status_code == 200
    assert response.json() == {"tags": ["S1", "DLP", "WSS"]}


async def test_admin_can_choose_endpoint_product_tags(
    client: AsyncClient,
    admin_user,
    viewer_user,
):
    admin_headers = await _headers(client, "admin@test.local", "Admin123!")
    update = await client.put(
        "/api/settings/system",
        headers=admin_headers,
        json={"endpoint_product_tags": ["S1", "DLP"]},
    )
    assert update.status_code == 200

    visible = await client.get(
        "/api/settings/endpoint-product-tags",
        headers=await _headers(client, "viewer@test.local", "Viewer123!"),
    )
    assert visible.status_code == 200
    assert visible.json() == {"tags": ["S1", "DLP"]}


async def test_product_scope_recalculates_compliance_and_dashboard(
    client: AsyncClient,
    db_session,
    admin_user,
):
    now = datetime.now(timezone.utc)
    endpoint = Endpoint(hostname="s1-only", is_active=True, source="jumpcloud", last_seen=now)
    db_session.add(endpoint)
    await db_session.flush()
    db_session.add(SecurityAgent(
        endpoint_id=endpoint.id,
        product_name="sentinelone",
        status="active",
        version="24.1.0",
        last_seen=now,
    ))
    await db_session.commit()

    headers = await _headers(client, "admin@test.local", "Admin123!")
    update = await client.put(
        "/api/settings/system",
        headers=headers,
        json={"endpoint_product_tags": ["S1"]},
    )
    assert update.status_code == 200

    compliance = (await db_session.execute(
        select(ComplianceStatus).where(ComplianceStatus.endpoint_id == endpoint.id)
    )).scalar_one()
    assert compliance.status == "compliant"

    dashboard = await client.get("/api/compliance/dashboard", headers=headers)
    assert dashboard.status_code == 200
    assert dashboard.json()["active_product_tags"] == ["S1"]
    assert dashboard.json()["issues"]["no_dlp"] == 0
    assert dashboard.json()["issues"]["no_wss"] == 0


async def test_unknown_endpoint_product_tag_is_rejected(client: AsyncClient, admin_user):
    response = await client.put(
        "/api/settings/system",
        headers=await _headers(client, "admin@test.local", "Admin123!"),
        json={"endpoint_product_tags": ["S1", "UNKNOWN"]},
    )

    assert response.status_code == 422


async def test_wss_scope_contributes_to_endpoint_risk_without_double_counting(
    db_session,
):
    from app.engines.risk import endpoint_risk_score

    endpoint = Endpoint(hostname="wss-risk", is_active=True, source="jumpcloud")
    db_session.add(endpoint)
    await db_session.flush()
    db_session.add(SystemSettings(
        id=1,
        endpoint_product_tags=["WSS"],
        risk_weight_no_wss=15,
        risk_weight_wss_version=10,
        risk_weight_no_user=10,
    ))
    compliance = ComplianceStatus(
        endpoint_id=endpoint.id,
        wss_installed=False,
        wss_version_ok=False,
    )
    db_session.add(compliance)
    await db_session.commit()

    missing = await endpoint_risk_score(str(endpoint.id), db_session)
    assert missing["score"] == 25
    assert missing["factors"] == ["no_wss", "no_user_assigned"]

    compliance.wss_installed = True
    await db_session.commit()
    outdated = await endpoint_risk_score(str(endpoint.id), db_session)
    assert outdated["score"] == 20
    assert outdated["factors"] == ["wss_outdated", "no_user_assigned"]
