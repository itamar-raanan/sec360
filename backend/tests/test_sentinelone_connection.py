import httpx
import pytest

from app.collectors.sentinelone import SentinelOneCollector


pytestmark = pytest.mark.asyncio


async def test_dns_failure_names_host_and_explains_container_fix():
    collector = SentinelOneCollector(
        credentials={
            "api_key": "test-token",
            "console_url": "https://tenant.sentinelone.net",
            "deployment_type": "cloud",
        }
    )
    try:
        error = httpx.ConnectError(
            "[Errno -3] Temporary failure in name resolution",
            request=httpx.Request("GET", "https://tenant.sentinelone.net"),
        )

        message = collector._connection_error_message(error)

        assert "tenant.sentinelone.net" in message
        assert "HOST_DNS" in message
        assert "Docker" in message
    finally:
        await collector.client.aclose()


async def test_example_console_url_is_rejected_before_network_call():
    collector = SentinelOneCollector(
        credentials={
            "api_key": "test-token",
            "console_url": "https://your-tenant.sentinelone.net",
            "deployment_type": "cloud",
        }
    )
    try:
        result = await collector.test_connection()

        assert result == {
            "success": False,
            "message": "Replace the example Console URL with your actual SentinelOne management-console URL",
        }
    finally:
        await collector.client.aclose()
