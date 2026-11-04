"""Minimal, read-only client for the SEC360 REST API."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

import httpx

from sec360_mcp.config import Settings


class Sec360APIError(RuntimeError):
    """A safe error suitable for returning through an MCP tool result."""

    def __init__(self, status_code: int, message: str, request_id: str | None = None):
        self.status_code = status_code
        self.request_id = request_id
        suffix = f" (request ID: {request_id})" if request_id else ""
        super().__init__(f"SEC360 returned HTTP {status_code}: {message}{suffix}")


@dataclass(frozen=True)
class Sec360Result:
    data: Any
    total_count: int | None = None
    request_id: str | None = None

    def as_tool_result(self) -> Any:
        if self.total_count is None:
            return self.data
        return {"items": self.data, "total_count": self.total_count, "request_id": self.request_id}


def clean_params(values: Mapping[str, Any]) -> dict[str, Any]:
    """Remove unset values and encode lists using SEC360's CSV query convention."""
    result: dict[str, Any] = {}
    for key, value in values.items():
        if value is None or value == "":
            continue
        if isinstance(value, (list, tuple, set)):
            if value:
                result[key] = ",".join(str(item) for item in value)
        else:
            result[key] = value
    return result


class Sec360Client:
    """HTTP client that deliberately implements only GET requests."""

    def __init__(self, settings: Settings, *, transport: httpx.AsyncBaseTransport | None = None) -> None:
        self._client = httpx.AsyncClient(
            base_url=f"{settings.sec360_url}/",
            headers={
                "Authorization": f"Bearer {settings.api_key}",
                "Accept": "application/json",
                "User-Agent": "sec360-mcp/0.1.0",
            },
            timeout=httpx.Timeout(settings.timeout_seconds),
            verify=settings.verify_ssl,
            follow_redirects=False,
            transport=transport,
        )

    async def __aenter__(self) -> "Sec360Client":
        return self

    async def __aexit__(self, *_: object) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        await self._client.aclose()

    @staticmethod
    def _validate_path(path: str) -> str:
        if not path.startswith("/") or path.startswith("//"):
            raise ValueError("SEC360 API paths must start with one slash")
        if path != "/health" and not path.startswith("/api/"):
            raise ValueError("Only SEC360 /api resources and /health may be queried")
        return path

    async def get(self, path: str, params: Mapping[str, Any] | None = None) -> Sec360Result:
        safe_path = self._validate_path(path)
        try:
            response = await self._client.get(safe_path, params=clean_params(params or {}))
        except httpx.TimeoutException as exc:
            raise Sec360APIError(504, "request timed out") from exc
        except httpx.RequestError as exc:
            raise Sec360APIError(503, f"connection failed: {exc.__class__.__name__}") from exc

        request_id = response.headers.get("X-Request-ID")
        if response.is_error:
            message = response.reason_phrase or "request failed"
            try:
                payload = response.json()
                if isinstance(payload, dict) and isinstance(payload.get("detail"), str):
                    message = payload["detail"]
            except ValueError:
                pass
            raise Sec360APIError(response.status_code, message[:500], request_id)

        if "json" not in response.headers.get("content-type", "").lower():
            raise Sec360APIError(502, "SEC360 returned a non-JSON response", request_id)
        try:
            data = response.json()
        except ValueError as exc:
            raise Sec360APIError(502, "SEC360 returned invalid JSON", request_id) from exc

        total_raw = response.headers.get("X-Total-Count")
        try:
            total = int(total_raw) if total_raw is not None else None
        except ValueError:
            total = None
        return Sec360Result(data=data, total_count=total, request_id=request_id)
