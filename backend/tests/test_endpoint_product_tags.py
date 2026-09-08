import pytest
from httpx import AsyncClient


pytestmark = pytest.mark.asyncio


async def _headers(client: AsyncClient, email: str, password: str) -> dict[str, str]:
    response = await client.post("/api/auth/login", json={"email": email, "password": password})
    assert response.status_code == 200
    return {"Authorization": f"Bearer {response.json()['access_token']}"}


async def test_endpoint_product_tags_default_to_all_products(client: AsyncClient, viewer_user):
    response = await client.get(
        "/api/settings/endpoint-product-tags",
        headers=await _headers(client, "viewer@test.local", "Viewer123!"),
    )

    assert response.status_code == 200
    assert response.json() == {"tags": ["S1", "DLP", "WSS"]}


async def test_admin_can_choose_endpoint_product_tags(
    client: AsyncClient,
    admin_user,
    viewer_user,
):
    admin_headers = await _headers(client, "admin@test.local", "Admin123!")
    update = await client.put(
        "/api/settings/system",
        headers=admin_headers,
        json={"endpoint_product_tags": ["S1", "DLP"]},
    )
    assert update.status_code == 200

    visible = await client.get(
        "/api/settings/endpoint-product-tags",
        headers=await _headers(client, "viewer@test.local", "Viewer123!"),
    )
    assert visible.status_code == 200
    assert visible.json() == {"tags": ["S1", "DLP"]}


async def test_unknown_endpoint_product_tag_is_rejected(client: AsyncClient, admin_user):
    response = await client.put(
        "/api/settings/system",
        headers=await _headers(client, "admin@test.local", "Admin123!"),
        json={"endpoint_product_tags": ["S1", "UNKNOWN"]},
    )

    assert response.status_code == 422
