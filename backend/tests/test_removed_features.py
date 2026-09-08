import pytest


pytestmark = pytest.mark.asyncio


async def test_retired_feature_routes_are_not_exposed(client):
    for path in (
        "/api/data-quality/summary",
        "/api/ai/insights",
        "/api/ai/chat",
    ):
        response = await client.get(path)
        assert response.status_code == 404


async def test_shared_search_and_compliance_routes_remain_registered():
    from app.main import app

    paths = app.openapi()["paths"]
    assert "/api/search" in paths
    assert "/api/compliance/dashboard" in paths

