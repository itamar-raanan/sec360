from datetime import datetime, timezone

import pytest

from app.investigations.indicators import _registrable_domain, normalize_indicator
from app.investigations.providers.adapters import AbuseIPDBAdapter, CloudflareUrlScannerAdapter, SiteShotAdapter
from app.investigations.providers.base import ProviderError
from app.investigations.scoring import score_results


pytestmark = pytest.mark.asyncio


async def _public_dns(_hostname: str):
    return ["93.184.216.34", "2606:2800:220:1:248:1893:25c8:1946"], 12


async def _headers(client, email: str, password: str) -> dict[str, str]:
    response = await client.post("/api/auth/login", json={"email": email, "password": password})
    assert response.status_code == 200
    return {"Authorization": f"Bearer {response.json()['access_token']}"}


async def test_registrable_domain_supports_pinned_tldextract_api(monkeypatch):
    class ExtractResult:
        registered_domain = "example.co.uk"

    class Extractor:
        def __call__(self, _hostname: str):
            return ExtractResult()

    monkeypatch.setattr("tldextract.TLDExtract", lambda **_kwargs: Extractor())
    assert _registrable_domain("login.example.co.uk") == "example.co.uk"


async def test_normalizes_defanged_url_without_losing_path_case_or_query(monkeypatch):
    monkeypatch.setattr("app.investigations.indicators._resolve_public", _public_dns)
    result = await normalize_indicator("hxxps://Exämple[.]com/Case/Path?a=One&a=Two")
    assert result.hostname == "xn--exmple-cua.com"
    assert result.exact_url == "https://xn--exmple-cua.com/Case/Path?a=One&a=Two"
    assert result.preview == result.exact_url
    assert result.indicator_type == "url"


async def test_sensitive_query_is_preserved_but_masked_in_preview(monkeypatch):
    monkeypatch.setattr("app.investigations.indicators._resolve_public", _public_dns)
    result = await normalize_indicator("https://example.com/reset?token=secret&next=%2FHome")
    assert result.exact_url == "https://example.com/reset?token=secret&next=%2FHome"
    assert "secret" not in result.preview
    assert "REDACTED" in result.preview
    assert result.is_sensitive is True


@pytest.mark.parametrize("value", [
    "ftp://example.com/file",
    "https://user:password@example.com/",
    "https://127.0.0.1/",
    "https://[::1]/",
    "https://169.254.169.254/latest/meta-data",
])
async def test_rejects_unsupported_or_non_public_targets(value):
    with pytest.raises(ValueError):
        await normalize_indicator(value)


async def test_site_shot_only_does_not_create_safe_score():
    score = score_results([{
        "provider": "site_shot",
        "status": "completed",
        "queried_scope": "exact_url",
        "assessment": {"verdict": "not_scored"},
    }])
    assert score["risk_score"] is None
    assert score["coverage"]["usable"] == 0
    assert score["risk_level"] == "unknown"


async def test_ip_reputation_alone_is_capped_below_high():
    score = score_results([{
        "provider": "abuseipdb",
        "status": "completed",
        "queried_scope": "resolved_ip",
        "native_metrics": {"max_abuse_confidence": 100},
        "assessment": {"scope": "resolved_ip", "verdict": "infrastructure_warning", "fresh_days": 90},
        "observed_at": datetime.now(timezone.utc).isoformat(),
    }])
    assert score["risk_score"] == 24
    assert score["risk_level"] == "low"
    assert any("infrastructure" in reason.lower() for reason in score["reasons"])


async def test_one_direct_malicious_source_is_not_averaged_away():
    score = score_results([{
        "provider": "virustotal",
        "status": "completed",
        "queried_scope": "exact_url",
        "native_metrics": {"malicious": 4, "suspicious": 1},
        "assessment": {"scope": "exact_url", "verdict": "malicious", "fresh_days": 30},
        "observed_at": datetime.now(timezone.utc).isoformat(),
    }, {
        "provider": "cloudflare_url_scanner",
        "status": "not_configured",
        "queried_scope": "exact_url",
    }])
    assert score["risk_score"] >= 75
    assert score["risk_level"] == "critical"
    assert score["evidence_confidence"] == "low"


async def test_malformed_or_missing_verdict_is_not_benign():
    score = score_results([{
        "provider": "cloudflare_url_scanner",
        "status": "completed",
        "queried_scope": "exact_url",
        "native_metrics": {},
        "assessment": {},
    }])
    assert score["risk_score"] is None
    assert score["coverage"]["usable"] == 0


async def test_explicit_no_detections_is_low_observed_risk_not_guaranteed_safe():
    score = score_results([{
        "provider": "virustotal",
        "status": "completed",
        "queried_scope": "exact_url",
        "native_metrics": {"malicious": 0, "suspicious": 0, "harmless": 15, "undetected": 40},
        "assessment": {"scope": "exact_url", "verdict": "no_threats_detected", "fresh_days": 30},
        "observed_at": datetime.now(timezone.utc).isoformat(),
    }])
    assert score["risk_score"] == 10
    assert score["risk_level"] == "low"
    assert "does not guarantee" in score["reasons"][0]


async def test_abuseipdb_reports_multiple_ips_and_partial_failure(monkeypatch):
    adapter = AbuseIPDBAdapter({"api_key": "secret", "max_ips": 3})

    async def request(_method, _url, **kwargs):
        address = kwargs["params"]["ipAddress"]
        if address == "203.0.113.2":
            raise ProviderError("temporary")
        return {"data": {
            "abuseConfidenceScore": 75 if address.endswith("1") else 5,
            "totalReports": 4,
            "lastReportedAt": "2026-10-10T10:00:00+00:00",
            "isp": "Example ISP",
            "usageType": "Data Center/Web Hosting/Transit",
            "countryCode": "US",
        }}

    monkeypatch.setattr(adapter, "request", request)
    outcome = await adapter.lookup({
        "resolved_ips": ["203.0.113.1", "203.0.113.2", "203.0.113.3", "203.0.113.4"],
        "hostname": "example.com",
        "resolution_ms": 8,
    })
    assert outcome.status == "completed"
    assert outcome.native_metrics["ips_checked"] == 2
    assert outcome.evidence["truncated"] is True
    assert outcome.evidence["failed_ips"] == ["203.0.113.2"]


async def test_cloudflare_missing_report_is_no_data(monkeypatch):
    adapter = CloudflareUrlScannerAdapter({"api_token": "secret", "account_id": "account"})

    async def request(*_args, **_kwargs):
        return {"success": True, "result": {"results": []}}

    monkeypatch.setattr(adapter, "request", request)
    outcome = await adapter.lookup({
        "indicator_type": "url", "exact_url": "https://example.com/", "preview": "https://example.com/", "hostname": "example.com",
    })
    assert outcome.status == "no_data"
    assert outcome.native_verdict is None


async def test_siteshot_failure_never_leaks_key(monkeypatch):
    adapter = SiteShotAdapter({"api_key": "super-secret-key"})

    async def request(*_args, **_kwargs):
        raise ProviderError("https://api.site-shot.com/?userkey=super-secret-key")

    monkeypatch.setattr(adapter, "request", request)
    with pytest.raises(ProviderError) as error:
        await adapter.active({"scan_target": "https://example.com/"}, "screenshot")
    assert "super-secret-key" not in str(error.value)


async def test_viewer_cannot_preview_investigation(client, viewer_user, monkeypatch):
    monkeypatch.setattr("app.investigations.indicators._resolve_public", _public_dns)
    response = await client.post(
        "/api/url-investigations/preview",
        json={"indicator": "example.com"},
        headers=await _headers(client, "viewer@test.local", "Viewer123!"),
    )
    assert response.status_code == 403


async def test_investigation_requires_disclosure_and_persists_all_provider_rows(
    client, db_session, analyst_user, monkeypatch
):
    monkeypatch.setattr("app.investigations.indicators._resolve_public", _public_dns)
    monkeypatch.setattr("app.api.routes.url_investigations.dispatch_investigation", lambda _id: None)
    headers = await _headers(client, "analyst@test.local", "Analyst123!")
    denied = await client.post(
        "/api/url-investigations",
        json={"indicator": "example.com", "acknowledge_disclosure": False},
        headers=headers,
    )
    assert denied.status_code == 400
    created = await client.post(
        "/api/url-investigations",
        json={"indicator": "example.com", "acknowledge_disclosure": True},
        headers=headers,
    )
    assert created.status_code == 202
    detail = await client.get(
        f"/api/url-investigations/detail/{created.json()['id']}", headers=headers
    )
    assert detail.status_code == 200
    body = detail.json()
    assert body["indicator"]["scan_target"] == "https://example.com/"
    assert {row["provider"] for row in body["providers"]} == {
        "virustotal", "abuseipdb", "cloudflare_url_scanner", "site_shot", "cisco_talos"
    }
    assert all(row["raw_response"] is None for row in body["providers"])


async def test_sensitive_url_requires_admin_for_creation(client, analyst_user, monkeypatch):
    monkeypatch.setattr("app.investigations.indicators._resolve_public", _public_dns)
    headers = await _headers(client, "analyst@test.local", "Analyst123!")
    response = await client.post(
        "/api/url-investigations",
        json={"indicator": "https://example.com/reset?token=secret", "acknowledge_disclosure": True},
        headers=headers,
    )
    assert response.status_code == 403
    assert "administrator" in response.json()["detail"].lower()
