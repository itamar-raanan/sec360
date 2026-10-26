from datetime import datetime, timezone

import pytest
from httpx import AsyncClient
from sqlalchemy import select

from app.models.proxy_audit import ProxyAuditConnection, ProxyAuditEvent
from app.models.system_settings import SystemSettings
from app.services.proxy_audit import ManagementCenterClient, build_policy_diff, collect_proxy_audit


pytestmark = pytest.mark.asyncio


async def _headers(client: AsyncClient, email: str, password: str) -> dict[str, str]:
    response = await client.post("/api/auth/login", json={"email": email, "password": password})
    assert response.status_code == 200
    return {"Authorization": f"Bearer {response.json()['access_token']}"}


async def test_proxy_policy_diff_counts_real_changes():
    summary, diff, additions, deletions = build_policy_diff(
        "allow condition=old\ndeny category=risk\n",
        "allow condition=new\ndeny category=risk\nallow group=analysts\n",
    )
    assert summary == "2 lines added · 1 line removed"
    assert additions == 2
    assert deletions == 1
    assert "-allow condition=old" in diff
    assert "+allow condition=new" in diff


async def test_proxy_audit_connection_is_feature_gated_and_secret_is_not_returned(
    client: AsyncClient, db_session, admin_user
):
    headers = await _headers(client, "admin@test.local", "Admin123!")
    assert (await client.get("/api/proxy-audit/status", headers=headers)).json() == {"enabled": False}
    assert (await client.get("/api/proxy-audit", headers=headers)).status_code == 409

    db_session.add(SystemSettings(id=1, proxy_audit_enabled=True))
    await db_session.commit()
    saved = await client.put(
        "/api/proxy-audit/connection",
        headers=headers,
        json={
            "base_url": "https://10.20.30.100:8082",
            "username": "proxy-audit-reader",
            "password": "private-test-value",
            "verify_ssl": False,
            "timeout_seconds": 60,
        },
    )
    assert saved.status_code == 200, saved.text
    assert saved.json()["configured"] is True
    assert saved.json()["base_url"] == "https://10.20.30.100:8082"
    assert "password" not in saved.json()
    connection = await db_session.get(ProxyAuditConnection, 1)
    assert connection.config["password"] == "private-test-value"

    kept_password = await client.put(
        "/api/proxy-audit/connection",
        headers=headers,
        json={
            "base_url": "https://10.20.30.100:8082",
            "username": "proxy-audit-reader",
            "password": "",
            "verify_ssl": True,
            "timeout_seconds": 30,
        },
    )
    assert kept_password.status_code == 200
    assert connection.config["password"] == "private-test-value"


async def test_proxy_audit_collects_policy_and_shared_object_revisions(
    client: AsyncClient, db_session, admin_user, monkeypatch
):
    db_session.add(SystemSettings(id=1, proxy_audit_enabled=True))
    await db_session.commit()

    async def open_client(self):
        return None

    async def close_client(self):
        return None

    async def policies(self):
        return [
            {"uuid": "policy-1", "name": "Forwarding policy", "shared": False},
            {"uuid": "shared-1", "name": "Trusted destinations", "shared": True},
        ]

    async def versions(self, policy_uuid):
        if policy_uuid == "policy-1":
            return [
                {"revisionNumber": 1, "revisionDate": "2026-10-24T08:00:00Z", "author": "mc-admin", "revisionDescription": "Initial"},
                {"revisionNumber": 2, "revisionDate": "2026-10-25T09:30:00Z", "author": "security-ops", "revisionDescription": "Allow analysts"},
            ]
        return [
            {"revisionNumber": "7", "revisionDate": "2026-10-25T10:00:00Z", "author": "mc-admin", "revisionDescription": "Refresh domains"},
        ]

    contents = {
        ("policy-1", "1"): "deny category=risk\n",
        ("policy-1", "2"): "deny category=risk\nallow group=analysts\n",
        ("shared-1", "7"): "example.org\ninternal.example\n",
    }

    async def content(self, policy_uuid, revision):
        return contents[(policy_uuid, revision)]

    monkeypatch.setattr(ManagementCenterClient, "open", open_client)
    monkeypatch.setattr(ManagementCenterClient, "close", close_client)
    monkeypatch.setattr(ManagementCenterClient, "policies", policies)
    monkeypatch.setattr(ManagementCenterClient, "versions", versions)
    monkeypatch.setattr(ManagementCenterClient, "content", content)

    result = await collect_proxy_audit(db_session, {
        "base_url": "https://management-center.test:8082",
        "username": "reader",
        "password": "secret",
    })
    assert result == {"imported": 3, "scanned": 3, "objects": 2}
    await db_session.commit()

    rows = (await db_session.execute(
        select(ProxyAuditEvent).order_by(ProxyAuditEvent.revision_date)
    )).scalars().all()
    assert len(rows) == 3
    assert rows[1].policy_name == "Forwarding policy"
    assert rows[1].change_summary == "1 line added"
    assert rows[1].additions == 1
    assert rows[1].deletions == 0
    assert rows[2].object_type == "shared_object"

    # A repeated scheduled collection reads version metadata but does not fetch
    # or re-import content that SEC360 already has.
    second = await collect_proxy_audit(db_session, {
        "base_url": "https://management-center.test:8082",
        "username": "reader",
        "password": "secret",
    })
    assert second == {"imported": 0, "scanned": 3, "objects": 2}

    headers = await _headers(client, "admin@test.local", "Admin123!")
    listing = await client.get("/api/proxy-audit?object_type=shared_object", headers=headers)
    assert listing.status_code == 200
    assert listing.headers["x-total-count"] == "1"
    assert listing.json()[0]["policy_name"] == "Trusted destinations"
    assert "diff_text" not in listing.json()[0]

    detail = await client.get(f"/api/proxy-audit/{rows[1].id}", headers=headers)
    assert detail.status_code == 200
    assert "+allow group=analysts" in detail.json()["diff_text"]

    summary = await client.get("/api/proxy-audit/summary", headers=headers)
    assert summary.status_code == 200
    assert summary.json()["revisions"] == 3
    assert summary.json()["objects"] == 2
    assert summary.json()["authors"] == 2


async def test_proxy_audit_connection_changes_require_admin(
    client: AsyncClient, db_session, viewer_user
):
    db_session.add(SystemSettings(id=1, proxy_audit_enabled=True))
    db_session.add(ProxyAuditEvent(
        policy_uuid="policy-view",
        policy_name="Viewer policy",
        object_type="policy",
        author="auditor",
        revision_date=datetime.now(timezone.utc),
        revision_number="1",
        comment=None,
        change_summary="Initial policy version",
        additions=1,
        deletions=0,
        content_hash="a" * 64,
    ))
    await db_session.commit()
    headers = await _headers(client, "viewer@test.local", "Viewer123!")
    assert (await client.get("/api/proxy-audit", headers=headers)).status_code == 200
    forbidden = await client.put(
        "/api/proxy-audit/connection",
        headers=headers,
        json={
            "base_url": "https://10.20.30.100:8082",
            "username": "reader",
            "password": "secret",
            "verify_ssl": True,
            "timeout_seconds": 60,
        },
    )
    assert forbidden.status_code == 403
