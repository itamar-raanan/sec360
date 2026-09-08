from datetime import datetime, timezone

import pytest
import httpx
from httpx import AsyncClient
from sqlalchemy import func, select

from app.collectors.sentinelone import SentinelOneCollector
from app.models.application import ApplicationVulnerability
from app.models.endpoint import Endpoint
from app.models.integration import IntegrationConfig


pytestmark = pytest.mark.asyncio


async def _login(client: AsyncClient) -> dict[str, str]:
    response = await client.post(
        "/api/auth/login",
        json={"email": "admin@test.local", "password": "Admin123!"},
    )
    assert response.status_code == 200
    return {"Authorization": f"Bearer {response.json()['access_token']}"}


def _risk(s1_id: str, *, severity: str = "HIGH", endpoint_id: str = "s1-agent-1") -> dict:
    return {
        "application": "7-Zip 19.00",
        "applicationName": "7-Zip",
        "applicationVendor": "Igor Pavlov",
        "applicationVersion": "19.00",
        "cveId": "CVE-2025-11001",
        "cvssVersion": "3.1",
        "daysDetected": 20,
        "detectionDate": "2026-04-10T06:09:01.882869Z",
        "endpointId": endpoint_id,
        "endpointName": "finance-laptop",
        "endpointType": "laptop",
        "exploitCodeMaturity": "Proof of Concept",
        "id": s1_id,
        "lastScanDate": "2026-04-15T10:24:22Z",
        "lastScanResult": "Succeeded",
        "markType": "",
        "markedBy": None,
        "markedDate": None,
        "mitigationStatus": "Not mitigated",
        "mitigationStatusChangeTime": None,
        "mitigationStatusChangedBy": None,
        "mitigationStatusReason": None,
        "nvdBaseScore": "8.80",
        "nvdCvssVersion": "3.1",
        "osType": "windows",
        "publishedDate": "2025-10-08T04:39:35Z",
        "reason": None,
        "remediationLevel": "Official Fix",
        "reportConfidence": "Confirmed",
        "riskScore": "7.20",
        "severity": severity,
        "status": "Detected",
    }


async def test_collector_paginates_the_current_application_risk_api():
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        cursor = request.url.params.get("cursor")
        if not cursor:
            return httpx.Response(200, json={"data": [_risk("risk-1")], "pagination": {"nextCursor": "page-2"}})
        return httpx.Response(200, json={"data": [_risk("risk-2")], "pagination": {"nextCursor": None}})

    collector = SentinelOneCollector(credentials={"api_key": "test"})
    await collector.client.aclose()
    collector.client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    try:
        findings = await collector._fetch_application_vulnerabilities()
    finally:
        await collector.client.aclose()

    assert [item["id"] for item in findings] == ["risk-1", "risk-2"]
    assert requests[0].url.path == "/web/api/v2.1/application-management/risks"
    assert requests[0].url.params["limit"] == "1000"
    assert requests[1].url.params["cursor"] == "page-2"


async def test_collector_preserves_exact_risk_data_and_full_refreshes(db_session):
    endpoint = Endpoint(
        hostname="finance-laptop",
        source="sentinelone",
        last_seen=datetime.now(timezone.utc),
    )
    db_session.add(endpoint)
    await db_session.flush()
    collector = SentinelOneCollector(
        credentials={"api_key": "test", "console_url": "https://tenant.sentinelone.net"},
        db=db_session,
    )
    try:
        count = await collector._upsert_application_vulnerabilities(
            [_risk("risk-1")], {"s1-agent-1": str(endpoint.id)}
        )
        await db_session.commit()
        assert count == 1
        finding = (await db_session.execute(select(ApplicationVulnerability))).scalar_one()
        assert finding.endpoint_id == endpoint.id
        assert finding.application_vendor == "Igor Pavlov"
        assert finding.nvd_base_score == 8.8
        assert finding.exploit_code_maturity == "Proof of Concept"
        assert finding.raw_json["cveId"] == "CVE-2025-11001"

        await collector._upsert_application_vulnerabilities([], {})
        await db_session.commit()
        assert await db_session.scalar(select(func.count()).select_from(ApplicationVulnerability)) == 0
    finally:
        await collector.client.aclose()


async def test_collector_bulk_upserts_multiple_batches_and_removes_stale_rows(db_session):
    collector = SentinelOneCollector(credentials={"api_key": "test"}, db=db_session)
    try:
        findings = [_risk(f"risk-{index}") for index in range(1005)]
        assert await collector._upsert_application_vulnerabilities(findings, {}) == 1005
        await db_session.commit()
        assert await db_session.scalar(
            select(func.count()).select_from(ApplicationVulnerability)
        ) == 1005

        replacement = _risk("risk-0", severity="CRITICAL")
        assert await collector._upsert_application_vulnerabilities([replacement], {}) == 1
        await db_session.commit()

        remaining = (await db_session.execute(select(ApplicationVulnerability))).scalar_one()
        assert remaining.sentinelone_id == "risk-0"
        assert remaining.severity == "CRITICAL"
    finally:
        await collector.client.aclose()


async def test_vulnerability_api_summary_filters_detail_and_csv(
    client: AsyncClient, db_session, admin_user
):
    db_session.add(IntegrationConfig(
        integration_type="sentinelone",
        display_name="SentinelOne",
        credentials={"api_key": "test"},
        status="connected",
        is_enabled=True,
    ))
    collector = SentinelOneCollector(credentials={"api_key": "test"}, db=db_session)
    try:
        await collector._upsert_application_vulnerabilities([
            _risk("risk-high", severity="HIGH"),
            {**_risk("risk-low", severity="LOW", endpoint_id="s1-agent-2"),
             "application": "OpenSSL 3.0", "applicationName": "OpenSSL",
             "cveId": "CVE-2026-20002", "endpointName": "linux-build-02",
             "exploitCodeMaturity": "Unknown", "nvdBaseScore": "3.10"},
        ], {})
        await db_session.commit()
    finally:
        await collector.client.aclose()

    headers = await _login(client)
    summary = await client.get("/api/application-vulnerabilities/summary", headers=headers)
    assert summary.status_code == 200
    assert summary.json()["total"] == 2
    assert summary.json()["unique_cves"] == 2
    assert summary.json()["severity"]["high"] == 1
    assert summary.json()["exploit_available"] == 1

    filtered = await client.get(
        "/api/application-vulnerabilities?severity=high&exploit=true", headers=headers
    )
    assert filtered.status_code == 200
    assert filtered.headers["x-total-count"] == "1"
    finding = filtered.json()[0]
    assert finding["application_name"] == "7-Zip"

    detail = await client.get(
        f"/api/application-vulnerabilities/{finding['id']}", headers=headers
    )
    assert detail.status_code == 200
    assert detail.json()["raw_json"]["applicationVersion"] == "19.00"

    export = await client.get(
        "/api/application-vulnerabilities/export.csv?severity=HIGH", headers=headers
    )
    assert export.status_code == 200
    assert "CVE-2025-11001" in export.text
    assert "CVE-2026-20002" not in export.text
