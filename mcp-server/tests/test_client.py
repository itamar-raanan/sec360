import json

import httpx
import pytest

from sec360_mcp.client import Sec360APIError, Sec360Client, clean_params
from sec360_mcp.config import Settings


def settings() -> Settings:
    return Settings(
        sec360_url="https://sec360.example.com",
        api_key="sec360_public_secret",
        verify_ssl=True,
        timeout_seconds=30,
        transport="stdio",
        host="127.0.0.1",
        port=9000,
    )


def test_clean_params_removes_empty_values_and_encodes_lists():
    assert clean_params({
        "search": "server",
        "statuses": ["partial", "non_compliant"],
        "empty": None,
        "blank": "",
        "false": False,
    }) == {
        "search": "server",
        "statuses": "partial,non_compliant",
        "false": False,
    }


@pytest.mark.asyncio
async def test_get_sends_bearer_key_and_returns_total_count():
    async def handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "GET"
        assert request.headers["Authorization"] == "Bearer sec360_public_secret"
        assert request.url.params["limit"] == "25"
        return httpx.Response(
            200,
            headers={
                "Content-Type": "application/json",
                "X-Total-Count": "81",
                "X-Request-ID": "abc123",
            },
            content=json.dumps([{"id": "endpoint-1"}]),
        )

    async with Sec360Client(settings(), transport=httpx.MockTransport(handler)) as client:
        result = await client.get("/api/endpoints", {"limit": 25})

    assert result.data == [{"id": "endpoint-1"}]
    assert result.total_count == 81
    assert result.request_id == "abc123"


@pytest.mark.asyncio
async def test_api_error_exposes_safe_detail_and_request_id():
    async def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(
            403,
            headers={"Content-Type": "application/json", "X-Request-ID": "denied1"},
            json={"detail": "Requires role: analyst"},
        )

    async with Sec360Client(settings(), transport=httpx.MockTransport(handler)) as client:
        with pytest.raises(Sec360APIError) as caught:
            await client.get("/api/dlp-policy-search")

    assert caught.value.status_code == 403
    assert "Requires role: analyst" in str(caught.value)
    assert "denied1" in str(caught.value)


@pytest.mark.asyncio
async def test_non_api_paths_are_rejected_before_request():
    async def handler(_: httpx.Request) -> httpx.Response:
        raise AssertionError("request must not be sent")

    async with Sec360Client(settings(), transport=httpx.MockTransport(handler)) as client:
        with pytest.raises(ValueError, match="Only SEC360"):
            await client.get("/internal/secrets")
