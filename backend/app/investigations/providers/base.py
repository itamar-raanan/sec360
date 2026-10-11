import asyncio
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, ClassVar

import httpx


class ProviderError(RuntimeError):
    code = "failed"


class AuthenticationError(ProviderError):
    code = "authentication_error"


class RateLimitedError(ProviderError):
    code = "rate_limited"

    def __init__(self, message: str, retry_after: int | None = None):
        super().__init__(message)
        self.retry_after = retry_after


class ProviderTimeoutError(ProviderError):
    code = "timeout"


@dataclass(frozen=True)
class ProviderCapabilities:
    indicator_types: tuple[str, ...]
    existing_report_lookup: bool
    new_scan_submission: bool = False
    screenshot_capture: bool = False
    authentication: tuple[str, ...] = ()


@dataclass
class ProviderOutcome:
    status: str
    queried_scope: str
    queried_indicator_preview: str
    native_verdict: str | None = None
    native_metrics: dict[str, Any] = field(default_factory=dict)
    assessment: dict[str, Any] = field(default_factory=dict)
    findings: list[dict[str, Any]] = field(default_factory=list)
    evidence: dict[str, Any] = field(default_factory=dict)
    report_url: str | None = None
    observed_at: datetime | None = None
    fetched_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    raw_response: dict[str, Any] | list[Any] | None = None
    error_code: str | None = None
    error_message: str | None = None
    artifact: bytes | None = None
    artifact_content_type: str | None = None


def sanitize_raw(value: Any) -> Any:
    """Bound and remove credential-bearing or browser-secret fields."""
    secret_markers = ("authorization", "api_key", "apikey", "token", "password", "secret", "cookie", "userkey")
    if isinstance(value, dict):
        clean: dict[str, Any] = {}
        for key, item in list(value.items())[:250]:
            if any(marker in str(key).lower() for marker in secret_markers):
                clean[str(key)] = "[REDACTED]"
            else:
                clean[str(key)] = sanitize_raw(item)
        return clean
    if isinstance(value, list):
        return [sanitize_raw(item) for item in value[:250]]
    if isinstance(value, str):
        return value[:4000]
    return value


def unwrap_cloud_response(payload: Any) -> Any:
    if isinstance(payload, dict) and "result" in payload and isinstance(payload.get("success"), bool):
        return payload.get("result")
    return payload


class ProviderAdapter:
    name: ClassVar[str]
    capabilities: ClassVar[ProviderCapabilities]

    def __init__(self, credentials: dict[str, Any]):
        self.credentials = credentials
        self.timeout = max(2, min(int(credentials.get("timeout_seconds", 15)), 60))

    async def lookup(self, indicator: dict[str, Any]) -> ProviderOutcome:
        raise NotImplementedError

    async def active(self, indicator: dict[str, Any], operation: str) -> ProviderOutcome:
        raise ProviderError(f"{self.name} does not support {operation}")

    async def test_connection(self) -> dict[str, Any]:
        return {"success": False, "message": "Connection testing is not supported"}

    async def request(
        self,
        method: str,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        params: dict[str, Any] | None = None,
        data: Any = None,
        json: Any = None,
        expect_json: bool = True,
        max_bytes: int = 5 * 1024 * 1024,
    ) -> Any:
        last_error: Exception | None = None
        for attempt in range(3):
            try:
                async with httpx.AsyncClient(timeout=self.timeout, follow_redirects=False) as client:
                    response = await client.request(method, url, headers=headers, params=params, data=data, json=json)
                if response.status_code in {401, 403}:
                    raise AuthenticationError("Provider rejected the configured credentials")
                if response.status_code == 429:
                    retry_value = response.headers.get("Retry-After", "")
                    retry_after = int(retry_value) if retry_value.isdigit() else None
                    raise RateLimitedError("Provider quota or rate limit was reached", retry_after)
                if response.status_code == 404:
                    return None
                if response.status_code >= 500 and attempt < 2:
                    await asyncio.sleep(0.5 * (2 ** attempt))
                    continue
                response.raise_for_status()
                if len(response.content) > max_bytes:
                    raise ProviderError("Provider response exceeded the allowed size")
                return response.json() if expect_json else (response.content, response.headers.get("content-type", ""))
            except (AuthenticationError, RateLimitedError, ProviderError):
                raise
            except httpx.TimeoutException as exc:
                last_error = exc
                if attempt < 2:
                    await asyncio.sleep(0.5 * (2 ** attempt))
                    continue
                raise ProviderTimeoutError("Provider request timed out") from exc
            except (httpx.HTTPError, ValueError) as exc:
                last_error = exc
                if attempt < 2 and isinstance(exc, httpx.TransportError):
                    await asyncio.sleep(0.5 * (2 ** attempt))
                    continue
                raise ProviderError("Provider returned an invalid or unsuccessful response") from exc
        raise ProviderError("Provider request failed") from last_error


def parse_timestamp(value: Any) -> datetime | None:
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(value, tz=timezone.utc)
    if isinstance(value, str):
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None
    return None

