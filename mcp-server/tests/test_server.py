from typing import Any

import pytest

from sec360_mcp import server


pytestmark = pytest.mark.asyncio


async def test_integration_details_combines_safe_state_and_catalog(monkeypatch):
    async def fake_get_many(_: list[tuple[str, dict[str, Any]]]):
        return [
            [{
                "integration_type": "sentinelone",
                "display_name": "SentinelOne",
                "is_enabled": True,
                "status": "connected",
                "credentials_configured": True,
                "available_features": ["application_vulnerabilities"],
            }],
            [{
                "integration_type": "sentinelone",
                "capabilities": ["endpoints", "edr_agents", "application_risks"],
                "features": ["application_vulnerabilities"],
            }],
        ]

    monkeypatch.setattr(server, "_get_many", fake_get_many)

    result = await server.get_integration_details("sentinelone")

    assert result["found"] is True
    assert result["connected"] is True
    assert result["credentials"] == "configured"
    assert result["secret_values_exposed"] is False
    assert result["catalog"]["capabilities"] == [
        "endpoints", "edr_agents", "application_risks",
    ]


async def test_feature_inventory_respects_connection_and_deployment_features(monkeypatch):
    async def fake_get_many(_: list[tuple[str, dict[str, Any]]]):
        return [
            [
                {
                    "integration_type": "sentinelone",
                    "is_enabled": True,
                    "status": "connected",
                    "available_features": [],
                },
                {
                    "integration_type": "google_workspace",
                    "is_enabled": True,
                    "status": "connected",
                    "available_features": ["activity"],
                },
            ],
            [
                {
                    "integration_type": "sentinelone",
                    "features": ["application_vulnerabilities"],
                },
                {"integration_type": "google_workspace", "features": ["activity"]},
            ],
            {"enabled": True},
            {"enabled": False},
            {"enabled": True},
            {"tags": ["S1", "DLP"]},
        ]

    monkeypatch.setattr(server, "_get_many", fake_get_many)

    result = await server.get_feature_inventory()
    features = {item["name"]: item for item in result["features"]}

    assert features["activity"]["enabled"] is True
    assert features["activity"]["provided_by"] == ["google_workspace"]
    assert features["application_vulnerabilities"]["enabled"] is False
    assert features["network_map"]["enabled"] is True
    assert features["linux_audit"]["enabled"] is False
    assert features["proxy_audit"]["enabled"] is True
    assert result["endpoint_product_tags"] == ["S1", "DLP"]


async def test_endpoint_detail_includes_notes(monkeypatch):
    async def fake_get_many(requests: list[tuple[str, dict[str, Any]]]):
        assert requests[-1] == (
            "/api/notes",
            {"entity_type": "endpoint", "entity_id": "endpoint-1"},
        )
        return [
            {"id": "endpoint-1", "hostname": "server-1"},
            [{"product_name": "sentinelone"}],
            [{"content": "Investigating"}],
        ]

    monkeypatch.setattr(server, "_get_many", fake_get_many)

    result = await server.get_endpoint("endpoint-1")

    assert result["endpoint"]["hostname"] == "server-1"
    assert result["notes"] == [{"content": "Investigating"}]


async def test_user_detail_requests_full_timeline_and_notes(monkeypatch):
    async def fake_get_many(requests: list[tuple[str, dict[str, Any]]]):
        assert requests[3] == (
            "/api/users/user-1/timeline",
            {"days": 90, "limit": 1000},
        )
        assert requests[4] == (
            "/api/notes",
            {"entity_type": "user", "entity_id": "user-1"},
        )
        return [{"id": "user-1"}, {}, [], [], [{"content": "VIP"}]]

    monkeypatch.setattr(server, "_get_many", fake_get_many)

    result = await server.get_user("user-1", timeline_days=500, timeline_limit=5000)

    assert result["notes"] == [{"content": "VIP"}]
