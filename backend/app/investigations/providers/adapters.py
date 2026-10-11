import asyncio
import base64
from datetime import datetime, timezone
from typing import Any
from urllib.parse import quote_plus

from app.investigations.providers.base import (
    AuthenticationError,
    ProviderAdapter,
    ProviderCapabilities,
    ProviderError,
    ProviderOutcome,
    RateLimitedError,
    parse_timestamp,
    sanitize_raw,
    unwrap_cloud_response,
)


def _stats(attributes: dict[str, Any]) -> dict[str, int]:
    raw = attributes.get("last_analysis_stats") or {}
    return {name: int(raw.get(name) or 0) for name in ("malicious", "suspicious", "harmless", "undetected", "timeout")}


class VirusTotalAdapter(ProviderAdapter):
    name = "virustotal"
    capabilities = ProviderCapabilities(("url", "domain"), True, new_scan_submission=True, authentication=("api_key",))
    api = "https://www.virustotal.com/api/v3"

    @property
    def headers(self) -> dict[str, str]:
        key = str(self.credentials.get("api_key", "")).strip()
        if not key:
            raise AuthenticationError("VirusTotal API key is not configured")
        return {"x-apikey": key, "Accept": "application/json"}

    async def _object(self, kind: str, identifier: str) -> dict[str, Any] | None:
        return await self.request("GET", f"{self.api}/{kind}/{identifier}", headers=self.headers)

    def _parse(self, payload: dict[str, Any] | None, scope: str, checked: str) -> ProviderOutcome | None:
        if not payload or not isinstance(payload.get("data"), dict):
            return None
        data = payload["data"]
        attributes = data.get("attributes") if isinstance(data.get("attributes"), dict) else {}
        has_stats = isinstance(attributes.get("last_analysis_stats"), dict) and bool(attributes["last_analysis_stats"])
        stats = _stats(attributes) if has_stats else {}
        engine_results = attributes.get("last_analysis_results") or {}
        findings = []
        if isinstance(engine_results, dict):
            for name, item in engine_results.items():
                if isinstance(item, dict) and item.get("category") in {"malicious", "suspicious"}:
                    findings.append({"engine": str(name), "category": item.get("category"), "result": item.get("result")})
        verdict = (
            "malicious" if stats.get("malicious", 0)
            else "suspicious" if stats.get("suspicious", 0)
            else "no_threats_detected" if has_stats
            else "unknown"
        )
        object_id = str(data.get("id", ""))
        gui_kind = "url" if scope == "exact_url" else "domain"
        return ProviderOutcome(
            status="completed",
            queried_scope=scope,
            queried_indicator_preview=checked,
            native_verdict=verdict,
            native_metrics=stats,
            assessment={"scope": scope, "verdict": verdict, "fresh_days": int(self.credentials.get("fresh_days", 30))},
            findings=findings[:100],
            evidence={
                "categories": attributes.get("categories") if isinstance(attributes.get("categories"), dict) else {},
                "redirection_chain": (attributes.get("redirection_chain") or [])[:50],
                "last_final_url": attributes.get("last_final_url"),
            },
            report_url=f"https://www.virustotal.com/gui/{gui_kind}/{object_id}" if object_id else None,
            observed_at=parse_timestamp(attributes.get("last_analysis_date")),
            raw_response=sanitize_raw(payload),
        )

    async def lookup(self, indicator: dict[str, Any]) -> ProviderOutcome:
        hostname = indicator["hostname"]
        if indicator["indicator_type"] == "url":
            exact = indicator["exact_url"]
            url_id = base64.urlsafe_b64encode(exact.encode()).decode().rstrip("=")
            url_payload, domain_payload = await asyncio.gather(
                self._object("urls", url_id), self._object("domains", hostname)
            )
            direct = self._parse(url_payload, "exact_url", indicator["preview"])
            related = self._parse(domain_payload, "related_domain", hostname)
            if direct:
                if related:
                    direct.evidence["related_domain"] = {
                        "verdict": related.native_verdict,
                        "metrics": related.native_metrics,
                        "observed_at": related.observed_at.isoformat() if related.observed_at else None,
                        "report_url": related.report_url,
                    }
                return direct
            if related:
                related.findings.insert(0, {"summary": "No exact-URL report was available; this result is related-domain context."})
                return related
            return ProviderOutcome("no_data", "exact_url", indicator["preview"], error_message="No existing VirusTotal URL or domain report")
        payload = await self._object("domains", hostname)
        return self._parse(payload, "hostname", hostname) or ProviderOutcome(
            "no_data", "hostname", hostname, error_message="No existing VirusTotal domain report"
        )

    async def active(self, indicator: dict[str, Any], operation: str) -> ProviderOutcome:
        if operation != "scan":
            raise ProviderError("VirusTotal supports only URL scan submission")
        target = indicator["scan_target"]
        submitted = await self.request("POST", f"{self.api}/urls", headers=self.headers, data={"url": target})
        analysis_id = str(((submitted or {}).get("data") or {}).get("id") or "")
        if analysis_id:
            for attempt in range(5):
                analysis = await self.request("GET", f"{self.api}/analyses/{analysis_id}", headers=self.headers)
                status = str((((analysis or {}).get("data") or {}).get("attributes") or {}).get("status") or "")
                if status == "completed":
                    return await self.lookup({**indicator, "indicator_type": "url", "exact_url": target, "preview": target})
                await asyncio.sleep(min(2 ** attempt, 10))
        return ProviderOutcome(
            "timeout", "exact_url", target, native_verdict="pending",
            findings=[{"summary": "VirusTotal accepted the scan; analysis is still pending."}],
            error_code="pending", error_message="The scan was accepted but did not finish within the polling deadline",
            evidence={"analysis_id": analysis_id},
            raw_response=sanitize_raw(submitted),
        )

    async def test_connection(self) -> dict[str, Any]:
        await self._object("domains", "example.com")
        return {"success": True, "message": "VirusTotal API key accepted. This used one standard domain lookup."}


class AbuseIPDBAdapter(ProviderAdapter):
    name = "abuseipdb"
    capabilities = ProviderCapabilities(("url", "domain"), True, authentication=("api_key",))
    endpoint = "https://api.abuseipdb.com/api/v2/check"

    @property
    def headers(self) -> dict[str, str]:
        key = str(self.credentials.get("api_key", "")).strip()
        if not key:
            raise AuthenticationError("AbuseIPDB API key is not configured")
        return {"Key": key, "Accept": "application/json"}

    async def lookup(self, indicator: dict[str, Any]) -> ProviderOutcome:
        addresses = list(dict.fromkeys(indicator.get("resolved_ips") or []))
        maximum = max(1, min(int(self.credentials.get("max_ips", 5)), 20))
        selected = addresses[:maximum]
        checked: list[dict[str, Any]] = []
        failures: list[str] = []

        async def check(address: str):
            try:
                payload = await self.request("GET", self.endpoint, headers=self.headers, params={
                    "ipAddress": address,
                    "maxAgeInDays": max(1, min(int(self.credentials.get("max_age_days", 90)), 365)),
                })
                data = (payload or {}).get("data") if isinstance(payload, dict) else None
                if not isinstance(data, dict) or not isinstance(data.get("abuseConfidenceScore"), (int, float)):
                    failures.append(address)
                    return
                checked.append({
                    "ip": address,
                    "abuse_confidence_score": int(data.get("abuseConfidenceScore") or 0),
                    "total_reports": int(data.get("totalReports") or 0),
                    "last_reported_at": data.get("lastReportedAt"),
                    "isp": data.get("isp"),
                    "organization": data.get("domain"),
                    "usage_type": data.get("usageType"),
                    "country": data.get("countryCode"),
                })
            except (AuthenticationError, RateLimitedError):
                raise
            except ProviderError:
                failures.append(address)

        await asyncio.gather(*(check(address) for address in selected))
        if not checked:
            if failures:
                raise ProviderError("AbuseIPDB returned no usable IP results")
            return ProviderOutcome("no_data", "resolved_ip", indicator["hostname"], error_message="No public resolved IPs were available")
        highest = max(item["abuse_confidence_score"] for item in checked)
        total_reports = sum(item["total_reports"] for item in checked)
        verdict = "infrastructure_warning" if highest >= 40 else "no_significant_abuse_observed"
        observed_values = [parse_timestamp(item.get("last_reported_at")) for item in checked]
        observed = max((item for item in observed_values if item), default=None)
        return ProviderOutcome(
            "completed", "resolved_ip", indicator["hostname"],
            native_verdict=verdict,
            native_metrics={"max_abuse_confidence": highest, "total_reports": total_reports, "ips_checked": len(checked)},
            assessment={"scope": "resolved_ip", "verdict": verdict, "fresh_days": int(self.credentials.get("fresh_days", 90))},
            findings=[{"summary": "IP reputation / infrastructure context. Shared hosting and CDN addresses may serve many domains."}],
            evidence={
                "ips": checked,
                "dns_resolution_ms": indicator.get("resolution_ms", 0),
                "truncated": len(addresses) > maximum,
                "failed_ips": failures,
            },
            observed_at=observed,
            raw_response={"ips": checked},
        )

    async def test_connection(self) -> dict[str, Any]:
        await self.request("GET", self.endpoint, headers=self.headers, params={"ipAddress": "8.8.8.8", "maxAgeInDays": 1})
        return {"success": True, "message": "AbuseIPDB API key accepted. This used one IP check from the account quota."}


class CloudflareUrlScannerAdapter(ProviderAdapter):
    name = "cloudflare_url_scanner"
    capabilities = ProviderCapabilities(("url", "domain"), True, new_scan_submission=True, screenshot_capture=True, authentication=("api_token", "account_id"))
    api = "https://api.cloudflare.com/client/v4/accounts"

    @property
    def headers(self) -> dict[str, str]:
        token = str(self.credentials.get("api_token", "")).strip()
        if not token:
            raise AuthenticationError("Cloudflare API token is not configured")
        return {"Authorization": f"Bearer {token}", "Accept": "application/json"}

    @property
    def base(self) -> str:
        account = str(self.credentials.get("account_id", "")).strip()
        if not account:
            raise AuthenticationError("Cloudflare account ID is not configured")
        return f"{self.api}/{account}/urlscanner/v2"

    def _parse_result(
        self,
        result: dict[str, Any],
        row: dict[str, Any],
        indicator: dict[str, Any],
        scan_id: str,
    ) -> ProviderOutcome:
        task = result.get("task") or row.get("task") or {}
        verdicts = result.get("verdicts") or row.get("verdicts") or {}
        explicit_malicious = verdicts.get("malicious") if isinstance(verdicts, dict) else None
        overall = str(verdicts.get("overall", "")).lower() if isinstance(verdicts, dict) else ""
        has_verdict = isinstance(explicit_malicious, bool) or overall in {"malicious", "benign", "clean", "safe"}
        malicious = explicit_malicious is True or overall == "malicious"
        verdict = "malicious" if malicious else "no_threats_detected" if has_verdict else "unknown"
        scope = "exact_url" if indicator["indicator_type"] == "url" else "hostname"
        requests = ((result.get("data") or {}).get("requests") or []) if isinstance(result.get("data"), dict) else []
        contacted_domains = sorted({
            str((((item or {}).get("request") or {}).get("initiator") or {}).get("host"))
            for item in requests if isinstance(item, dict) and (((item.get("request") or {}).get("initiator") or {}).get("host"))
        })[:100]
        stats = result.get("stats") if isinstance(result.get("stats"), dict) else {}
        return ProviderOutcome(
            "completed", scope, indicator["preview"], native_verdict=verdict,
            native_metrics={"malicious": malicious, "requests": len(requests)} if has_verdict else {"requests": len(requests)},
            assessment={"scope": scope, "verdict": verdict, "fresh_days": int(self.credentials.get("fresh_days", 30))},
            findings=[{"summary": "Cloudflare scan verdict matched the submitted indicator scope."}],
            evidence={
                "categories": result.get("urlCategories") or {},
                "redirects": (task.get("redirects") or [])[:50] if isinstance(task.get("redirects"), list) else [],
                "contacted_domains": contacted_domains,
                "contacted_ips": [item.get("ip") for item in (stats.get("ipStats") or []) if isinstance(item, dict) and item.get("ip")][:100],
                "scan_id": scan_id,
                "visibility": task.get("visibility") or (row.get("task") or {}).get("visibility"),
                "screenshot_available": isinstance(result.get("screenshot"), dict) or bool(scan_id),
            },
            report_url=f"https://radar.cloudflare.com/scan/{scan_id}" if scan_id else None,
            observed_at=parse_timestamp(task.get("time")),
            raw_response=sanitize_raw(result),
        )

    async def lookup(self, indicator: dict[str, Any]) -> ProviderOutcome:
        target = indicator["exact_url"] if indicator["indicator_type"] == "url" else indicator["hostname"]
        query = f'page.url:"{target}"' if indicator["indicator_type"] == "url" else f'page.domain:"{target}"'
        payload = await self.request("GET", f"{self.base}/search", headers=self.headers, params={"q": query, "size": 10})
        search = unwrap_cloud_response(payload) or {}
        rows = search.get("results", []) if isinstance(search, dict) else []
        exact = []
        for row in rows if isinstance(rows, list) else []:
            if not isinstance(row, dict):
                continue
            task = row.get("task") or {}
            page = row.get("page") or {}
            candidate = task.get("url") or page.get("url")
            domain = page.get("domain")
            if (indicator["indicator_type"] == "url" and candidate == target) or (
                indicator["indicator_type"] == "domain" and domain == target
            ):
                exact.append(row)
        if not exact:
            return ProviderOutcome("no_data", "exact_url" if indicator["indicator_type"] == "url" else "hostname", indicator["preview"], error_message="No matching existing Cloudflare scan")
        row = sorted(exact, key=lambda item: str((item.get("task") or {}).get("time") or ""), reverse=True)[0]
        scan_id = str((row.get("task") or {}).get("uuid") or row.get("_id") or "")
        result_payload = await self.request("GET", f"{self.base}/result/{scan_id}", headers=self.headers)
        result = unwrap_cloud_response(result_payload) or {}
        return self._parse_result(result, row, indicator, scan_id)

    async def active(self, indicator: dict[str, Any], operation: str) -> ProviderOutcome:
        if operation != "scan":
            raise ProviderError("Cloudflare supports explicit URL scan submission")
        target = indicator["scan_target"]
        payload = await self.request("POST", f"{self.base}/scan", headers={**self.headers, "Content-Type": "application/json"}, json={
            "url": target, "visibility": "Unlisted", "screenshotsResolutions": ["desktop"],
        })
        submitted = unwrap_cloud_response(payload) or {}
        visibility = str(submitted.get("visibility") or "").lower()
        if visibility != "unlisted":
            raise ProviderError("Cloudflare did not confirm Unlisted visibility; the scan was not accepted by Sec360")
        scan_id = str(submitted.get("uuid") or "")
        for attempt in range(6):
            await asyncio.sleep(min(2 ** attempt, 10))
            try:
                result = await self.request("GET", f"{self.base}/result/{scan_id}", headers=self.headers)
                if result:
                    parsed = unwrap_cloud_response(result) or {}
                    return self._parse_result(
                        parsed,
                        {"task": {"url": target, "uuid": scan_id, "visibility": visibility}},
                        {**indicator, "indicator_type": "url", "exact_url": target, "preview": target},
                        scan_id,
                    )
            except ProviderError:
                if attempt == 5:
                    raise
        return ProviderOutcome(
            "timeout", "exact_url", target, native_verdict="pending",
            evidence={"scan_id": scan_id, "visibility": "unlisted"},
            report_url=f"https://radar.cloudflare.com/scan/{scan_id}" if scan_id else None,
            error_code="pending",
            error_message="The unlisted scan was accepted but did not finish within the polling deadline",
        )

    async def fetch_screenshot(self, scan_id: str) -> tuple[bytes, str]:
        payload = await self.request("GET", f"{self.base}/screenshots/{scan_id}.png", headers=self.headers, expect_json=False)
        content, content_type = payload
        if not content_type.lower().startswith("image/"):
            raise ProviderError("Cloudflare returned a non-image screenshot response")
        return content, content_type.split(";", 1)[0]

    async def test_connection(self) -> dict[str, Any]:
        await self.request("GET", f"{self.base}/search", headers=self.headers, params={"q": "apikey:me", "size": 1})
        return {"success": True, "message": "Cloudflare URL Scanner read access confirmed; no scan was submitted."}


class SiteShotAdapter(ProviderAdapter):
    name = "site_shot"
    capabilities = ProviderCapabilities(("url", "domain"), False, screenshot_capture=True, authentication=("api_key",))
    endpoint = "https://api.site-shot.com/"

    async def lookup(self, indicator: dict[str, Any]) -> ProviderOutcome:
        return ProviderOutcome(
            "awaiting_consent", "exact_url", indicator["scan_target"],
            findings=[{"summary": "Screenshot capture is active browsing and requires explicit confirmation."}],
            assessment={"scope": "exact_url", "verdict": "not_scored"},
        )

    async def active(self, indicator: dict[str, Any], operation: str) -> ProviderOutcome:
        if operation != "screenshot":
            raise ProviderError("Site-Shot supports screenshot capture only")
        key = str(self.credentials.get("api_key", "")).strip()
        if not key:
            raise AuthenticationError("Site-Shot API key is not configured")
        try:
            content, content_type = await self.request(
                "GET", self.endpoint,
                params={"url": indicator["scan_target"], "userkey": key, "format": "PNG", "width": 1440, "height": 900},
                expect_json=False,
            )
        except ProviderError:
            # Never include the credential-bearing request URL in propagated errors.
            raise ProviderError("Site-Shot capture failed; verify the API key, quota, and target") from None
        if not content_type.lower().startswith("image/"):
            raise ProviderError("Site-Shot returned a non-image response")
        return ProviderOutcome(
            "completed", "exact_url", indicator["scan_target"], native_verdict="visual_evidence_only",
            assessment={"scope": "exact_url", "verdict": "not_scored"},
            findings=[{"summary": "Screenshot captured as visual evidence. Sec360 does not infer reputation from appearance."}],
            artifact=content, artifact_content_type=content_type.split(";", 1)[0],
        )

    async def test_connection(self) -> dict[str, Any]:
        if not str(self.credentials.get("api_key", "")).strip():
            return {"success": False, "message": "Site-Shot API key is required"}
        return {
            "success": True,
            "status": "unverified",
            "message": "Key saved but not tested: Site-Shot has no documented zero-capture credential check. Use an explicit screenshot capture to verify it.",
        }


class TalosManualAdapter(ProviderAdapter):
    name = "cisco_talos"
    capabilities = ProviderCapabilities(("url", "domain"), False)

    async def lookup(self, indicator: dict[str, Any]) -> ProviderOutcome:
        target = indicator["hostname"]
        return ProviderOutcome(
            "unsupported", "hostname", target,
            native_verdict="manual_lookup",
            assessment={"scope": "hostname", "verdict": "not_scored"},
            findings=[{"summary": "Manual lookup — supported API access not configured."}],
            report_url=f"https://talosintelligence.com/reputation_center/lookup?search={quote_plus(target)}",
        )

    async def test_connection(self) -> dict[str, Any]:
        return {"success": True, "status": "connected", "message": "Manual Cisco Talos lookup enabled; no API credentials are used."}


PROVIDER_ADAPTERS: dict[str, type[ProviderAdapter]] = {
    adapter.name: adapter
    for adapter in (VirusTotalAdapter, AbuseIPDBAdapter, CloudflareUrlScannerAdapter, SiteShotAdapter, TalosManualAdapter)
}
