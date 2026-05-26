"""Tests for the health check endpoint."""
import pytest
from httpx import AsyncClient

pytestmark = pytest.mark.asyncio


async def test_health_returns_status(client: AsyncClient):
    res = await client.get("/health")
    assert res.status_code == 200
    data = res.json()
    assert "status" in data
    assert "checks" in data
    assert "database" in data["checks"]
    assert "scheduler" in data["checks"]


async def test_health_no_auth_required(client: AsyncClient):
    """Health endpoint must be publicly accessible."""
    res = await client.get("/health")
    assert res.status_code == 200
