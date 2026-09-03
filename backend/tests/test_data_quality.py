from datetime import datetime, timedelta, timezone

import pytest
from httpx import AsyncClient

from app.models.agent import SecurityAgent
from app.models.endpoint import Endpoint


pytestmark = pytest.mark.asyncio


async def _login(client: AsyncClient, email: str, password: str) -> dict[str, str]:
    response = await client.post("/api/auth/login", json={"email": email, "password": password})
    assert response.status_code == 200
    return {"Authorization": f"Bearer {response.json()['access_token']}"}


async def _seed(db_session):
    now = datetime.now(timezone.utc)
    trusted = Endpoint(
        hostname="finance-laptop",
        serial_number="SERIAL-100",
        username="finance.user",
        source="jumpcloud",
        last_seen=now - timedelta(hours=2),
        is_active=True,
    )
    duplicate = Endpoint(
        hostname="FINANCE-LAPTOP",
        serial_number="SERIAL-100",
        source="sentinelone",
        last_seen=now - timedelta(days=2),
        is_active=True,
    )
    stale = Endpoint(
        hostname="retired-laptop",
        source="jumpcloud",
        last_seen=now - timedelta(days=90),
        is_active=False,
        lifecycle_state="stale",
    )
    db_session.add_all([trusted, duplicate, stale])
    await db_session.flush()
    db_session.add(SecurityAgent(
        endpoint_id=trusted.id,
        product_name="sentinelone",
        status="active",
        last_seen=now - timedelta(hours=3),
    ))
    await db_session.commit()
    return trusted, duplicate, stale


async def test_summary_and_duplicate_candidates_are_explainable(
    client: AsyncClient, db_session, admin_user
):
    await _seed(db_session)
    headers = await _login(client, "admin@test.local", "Admin123!")

    summary = await client.get("/api/data-quality/summary", headers=headers)
    assert summary.status_code == 200
    body = summary.json()
    assert body["total"] == 3
    assert body["current_inventory"] == 2
    assert body["lifecycle"]["stale"] == 1
    assert body["duplicate_candidates"] == 1

    duplicates = await client.get("/api/data-quality/duplicates", headers=headers)
    assert duplicates.status_code == 200
    candidate = duplicates.json()["items"][0]
    assert candidate["score"] == 99
    assert any("hardware serial" in reason for reason in candidate["reasons"])
    assert any("normalized hostname" in reason for reason in candidate["reasons"])

    endpoints = await client.get("/api/data-quality/endpoints?confidence=high", headers=headers)
    assert endpoints.status_code == 200
    trusted_row = next(item for item in endpoints.json() if item["hostname"] == "finance-laptop")
    assert trusted_row["confidence"]["method"] == "hardware_serial"
    assert trusted_row["included_in_compliance"] is True
    assert "Validated hardware serial" in trusted_row["confidence"]["signals"]


async def test_lifecycle_decisions_require_reason_and_analyst_role(
    client: AsyncClient, db_session, analyst_user, viewer_user
):
    trusted, _, _ = await _seed(db_session)
    analyst_headers = await _login(client, "analyst@test.local", "Analyst123!")

    missing_reason = await client.patch(
        f"/api/data-quality/endpoints/{trusted.id}/lifecycle",
        headers=analyst_headers,
        json={"state": "ignored"},
    )
    assert missing_reason.status_code == 422

    updated = await client.patch(
        f"/api/data-quality/endpoints/{trusted.id}/lifecycle",
        headers=analyst_headers,
        json={"state": "ignored", "reason": "Approved lab test device"},
    )
    assert updated.status_code == 200
    assert updated.json()["lifecycle_state"] == "ignored"
    assert updated.json()["included_in_compliance"] is False
    assert updated.json()["lifecycle_changed_by"] == "analyst@test.local"

    viewer_headers = await _login(client, "viewer@test.local", "Viewer123!")
    forbidden = await client.patch(
        f"/api/data-quality/endpoints/{trusted.id}/lifecycle",
        headers=viewer_headers,
        json={"state": "active"},
    )
    assert forbidden.status_code == 403
