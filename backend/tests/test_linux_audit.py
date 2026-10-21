from datetime import datetime, timezone
import json

import pytest
from httpx import AsyncClient

from app.models.endpoint import Endpoint
from app.models.system_settings import SystemSettings


pytestmark = pytest.mark.asyncio


async def _headers(client: AsyncClient, email: str, password: str) -> dict[str, str]:
    response = await client.post("/api/auth/login", json={"email": email, "password": password})
    assert response.status_code == 200
    return {"Authorization": f"Bearer {response.json()['access_token']}"}


def _report() -> dict:
    return {
        "benchmark": {
            "name": "CIS Debian Linux 13 Benchmark",
            "version": "1.0.0",
            "target_distribution": "Debian",
            "target_major_version": "13",
        },
        "schema_version": "1.1",
        "host": "web-01.example.test",
        "fqdn": "web-01.example.test",
        "ip_address": "10.20.30.40",
        "ip_addresses": ["10.20.30.40", "172.17.0.1"],
        "system": {
            "distribution": "Debian",
            "distribution_version": "13.1",
            "kernel": "6.12.0-amd64",
            "architecture": "x86_64",
            "virtualization_type": "kvm",
            "machine_id_hash": "a" * 64,
        },
        "audit_tool": {"version": "1.1.0", "git_commit": "abc1234"},
        "profile": "level1_server",
        "generated_at": "2026-10-20T14:25:00Z",
        "summary": {"total": "4", "pass": "2", "fail": "1", "review": "1", "excluded": "0", "error": "0"},
        "results": [
            {"id": "1.1.1", "title": "Disable unused filesystem", "status": "PASS", "actual": "disabled"},
            {"id": "1.2.1", "title": "Configure repositories", "status": "PASS", "actual": "configured"},
            {"id": "2.1.1", "title": "Remove legacy service", "status": "FAIL", "actual": "installed", "remediation": "Remove the package."},
            {"id": "3.1.1", "title": "Review network policy", "status": "REVIEW", "actual": "manual review"},
        ],
    }


async def test_linux_audit_is_feature_gated_and_imports_exact_report(
    client: AsyncClient, db_session, admin_user
):
    headers = await _headers(client, "admin@test.local", "Admin123!")

    status_response = await client.get("/api/linux-audits/status", headers=headers)
    assert status_response.status_code == 200
    assert status_response.json() == {"enabled": False}
    assert (await client.get("/api/linux-audits", headers=headers)).status_code == 409

    db_session.add(SystemSettings(id=1, linux_audit_enabled=True))
    db_session.add(Endpoint(
        hostname="inventory-web-01",
        ip_address="10.20.30.40",
        os_version="Debian GNU/Linux 13",
        last_seen=datetime.now(timezone.utc),
    ))
    await db_session.commit()

    invalid = await client.post(
        "/api/linux-audits/upload",
        headers=headers,
        files={"file": ("broken.json", b"not-json", "application/json")},
    )
    assert invalid.status_code == 422

    report_bytes = json.dumps(_report()).encode()
    uploaded = await client.post(
        "/api/linux-audits/upload",
        headers=headers,
        files={"file": ("cis_report_web-01.json", report_bytes, "application/json")},
    )
    assert uploaded.status_code == 201, uploaded.text
    body = uploaded.json()
    assert body["hostname"] == "web-01.example.test"
    assert body["fqdn"] == "web-01.example.test"
    assert body["ip_address"] == "10.20.30.40"
    assert body["ip_addresses"] == ["10.20.30.40", "172.17.0.1"]
    assert body["os_name"] == "Debian 13.1"
    assert body["kernel"] == "6.12.0-amd64"
    assert body["architecture"] == "x86_64"
    assert body["virtualization_type"] == "kvm"
    assert body["machine_id_hash"] == "a" * 64
    assert body["audit_tool_version"] == "1.1.0"
    assert body["audit_tool_git_commit"] == "abc1234"
    assert body["endpoint_id"] is not None
    assert body["fail_count"] == 1
    assert body["pass_rate"] == pytest.approx(66.7)

    listing = await client.get("/api/linux-audits?search=10.20.30.40&result=attention", headers=headers)
    assert listing.status_code == 200
    assert listing.headers["x-total-count"] == "1"
    assert listing.json()[0]["filename"] == "cis_report_web-01.json"

    detail = await client.get(f"/api/linux-audits/{body['id']}", headers=headers)
    assert detail.status_code == 200
    assert len(detail.json()["results"]) == 4
    assert detail.json()["results"][2]["status"] == "FAIL"

    summary = await client.get("/api/linux-audits/summary", headers=headers)
    assert summary.status_code == 200
    assert summary.json()["servers"] == 1
    assert summary.json()["failed_controls"] == 1

    duplicate = await client.post(
        "/api/linux-audits/upload",
        headers=headers,
        files={"file": ("copy.json", report_bytes, "application/json")},
    )
    assert duplicate.status_code == 409

    legacy = _report()
    for field in ("schema_version", "fqdn", "ip_address", "ip_addresses", "system", "audit_tool"):
        legacy.pop(field)
    legacy["host"] = "legacy-01"
    legacy["generated_at"] = "2026-10-19T14:25:00Z"
    legacy_upload = await client.post(
        "/api/linux-audits/upload",
        headers=headers,
        files={"file": ("legacy.json", json.dumps(legacy).encode(), "application/json")},
    )
    assert legacy_upload.status_code == 201
    assert legacy_upload.json()["os_name"] == "Debian 13"
    assert legacy_upload.json()["schema_version"] is None


async def test_linux_audit_upload_requires_analyst(
    client: AsyncClient, db_session, viewer_user
):
    db_session.add(SystemSettings(id=1, linux_audit_enabled=True))
    await db_session.commit()
    headers = await _headers(client, "viewer@test.local", "Viewer123!")

    forbidden = await client.post(
        "/api/linux-audits/upload",
        headers=headers,
        files={"file": ("report.json", b"{}", "application/json")},
    )
    assert forbidden.status_code == 403

    listing = await client.get("/api/linux-audits", headers=headers)
    assert listing.status_code == 200


async def test_linux_audit_automated_ingest_tokens_are_revocable_and_idempotent(
    client: AsyncClient, db_session, admin_user
):
    db_session.add(SystemSettings(id=1, linux_audit_enabled=True))
    await db_session.commit()
    headers = await _headers(client, "admin@test.local", "Admin123!")

    created = await client.post(
        "/api/linux-audits/ingest-tokens",
        headers=headers,
        json={"name": "Debian CIS production"},
    )
    assert created.status_code == 201, created.text
    token = created.json()["token"]
    assert token.startswith("lai_")

    listing = await client.get("/api/linux-audits/ingest-tokens", headers=headers)
    assert listing.status_code == 200
    assert listing.json()[0]["name"] == "Debian CIS production"
    assert "token" not in listing.json()[0]
    assert "token_hash" not in listing.json()[0]

    report_bytes = json.dumps(_report()).encode()
    unauthenticated = await client.post(
        "/api/linux-audits/ingest",
        content=report_bytes,
        headers={"Content-Type": "application/json"},
    )
    assert unauthenticated.status_code == 401

    ingest_headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
        "X-Report-Filename": "cis_report_web-01.json",
    }
    uploaded = await client.post(
        "/api/linux-audits/ingest",
        content=report_bytes,
        headers=ingest_headers,
    )
    assert uploaded.status_code == 201, uploaded.text
    assert uploaded.json()["duplicate"] is False
    assert uploaded.json()["uploaded_by_email"] == "automation:Debian CIS production"

    retried = await client.post(
        "/api/linux-audits/ingest",
        content=report_bytes,
        headers=ingest_headers,
    )
    assert retried.status_code == 200
    assert retried.json()["duplicate"] is True
    assert retried.json()["id"] == uploaded.json()["id"]

    refreshed = await client.get("/api/linux-audits/ingest-tokens", headers=headers)
    assert refreshed.json()[0]["last_used_at"] is not None
    assert refreshed.json()[0]["last_used_ip"] == "127.0.0.1"

    revoked = await client.delete(
        f"/api/linux-audits/ingest-tokens/{created.json()['id']}",
        headers=headers,
    )
    assert revoked.status_code == 200
    rejected = await client.post(
        "/api/linux-audits/ingest",
        content=report_bytes,
        headers=ingest_headers,
    )
    assert rejected.status_code == 401


async def test_linux_audit_ingest_token_management_requires_admin(
    client: AsyncClient, db_session, analyst_user
):
    db_session.add(SystemSettings(id=1, linux_audit_enabled=True))
    await db_session.commit()
    headers = await _headers(client, "analyst@test.local", "Analyst123!")

    assert (await client.get("/api/linux-audits/ingest-tokens", headers=headers)).status_code == 403
    assert (await client.post(
        "/api/linux-audits/ingest-tokens",
        headers=headers,
        json={"name": "Unauthorized"},
    )).status_code == 403
