from datetime import datetime, timezone
from unittest.mock import AsyncMock
import uuid

import pytest
from httpx import AsyncClient

from app.models.endpoint import Endpoint
from app.models.network_map import (
    NetworkMapCollectionRun,
    NetworkMapConnection,
    NetworkMapEquipment,
    NetworkMapFloor,
    NetworkMapObservation,
)
from app.models.puppet import PuppetFact, PuppetNode
from app.models.system_settings import SystemSettings
from app.network_map.collectors import (
    normalize_mac,
    parse_fortigate_leases,
    parse_wlc_aps,
    parse_wlc_clients,
    parse_wlc_wlans,
)


pytestmark = pytest.mark.asyncio


async def _admin_headers(client: AsyncClient) -> dict[str, str]:
    response = await client.post(
        "/api/auth/login",
        json={"email": "admin@test.local", "password": "Admin123!"},
    )
    assert response.status_code == 200
    return {"Authorization": f"Bearer {response.json()['access_token']}"}


async def test_network_collector_parsers_normalize_supported_shapes():
    assert normalize_mac("AABB.CCDD.EEFF") == "aa:bb:cc:dd:ee:ff"
    clients = parse_wlc_clients("aa:bb:cc:dd:ee:ff AP-25 7 Associated")
    assert clients == [{"mac": "aa:bb:cc:dd:ee:ff", "ap": "AP-25", "wlan": "7", "state": "Associated"}]
    assert parse_wlc_wlans("7 enabled Corp-WiFi open") == {"7": "Corp-WiFi"}
    aps = parse_wlc_aps("AP-25 AIR-AP3802 aa:bb:cc:00:11:22 10.20.1.25")
    assert aps[0]["name"] == "AP-25"
    assert aps[0]["ip"] == "10.20.1.25"
    leases = parse_fortigate_leases({"results": {"root": [{"mac": "AA-BB-CC-DD-EE-FF", "ip": "10.0.0.8"}]}})
    assert leases[0]["mac"] == "aa:bb:cc:dd:ee:ff"
    assert leases[0]["vdom"] == "root"


async def test_connections_are_admin_owned_cardinality_limited_and_never_return_secrets(
    client: AsyncClient, db_session, admin_user, monkeypatch
):
    headers = await _admin_headers(client)
    payload = {
        "connection_type": "cisco_wlc",
        "display_name": "Campus WLC",
        "config": {"host": "wlc.example.test", "username": "collector", "password": "very-secret"},
    }
    created = await client.post("/api/network-map/connections", headers=headers, json=payload)
    assert created.status_code == 201
    assert created.json()["credentials_configured"] is True
    assert "password" not in created.json()["config"]
    connection_id = created.json()["id"]

    updated = await client.put(f"/api/network-map/connections/{connection_id}", headers=headers, json={
        "config": {"host": "saved-wlc.example.test", "password": ""},
    })
    assert updated.status_code == 200
    stored = await db_session.get(NetworkMapConnection, uuid.UUID(connection_id))
    assert stored.config["password"] == "very-secret"

    test_call = AsyncMock(return_value={"ok": True, "counts": {"access_points": 1}})
    monkeypatch.setattr("app.api.routes.network_map._test", test_call)
    tested = await client.post(f"/api/network-map/connections/{connection_id}/test", headers=headers, json={
        "config": {"host": "temporary-wlc.example.test", "password": ""},
    })
    assert tested.status_code == 200
    tested_config = test_call.await_args.args[1]
    assert tested_config["host"] == "temporary-wlc.example.test"
    assert tested_config["password"] == "very-secret"
    await db_session.refresh(stored)
    assert stored.config["host"] == "saved-wlc.example.test"

    duplicate = await client.post("/api/network-map/connections", headers=headers, json=payload)
    assert duplicate.status_code == 409

    for name in ("Closet A", "Closet B"):
        response = await client.post("/api/network-map/connections", headers=headers, json={
            "connection_type": "mikrotik",
            "display_name": name,
            "config": {"base_url": f"http://{name[-1].lower()}.example.test", "username": "admin", "password": "secret"},
        })
        assert response.status_code == 201

    floors = await client.get("/api/network-map/floors", headers=headers)
    assert floors.status_code == 200
    assert len(floors.json()) == 8


async def test_operational_map_is_gated_and_correlates_only_by_puppet_mac(
    client: AsyncClient, db_session, admin_user
):
    headers = await _admin_headers(client)
    locked = await client.get("/api/network-map", headers=headers)
    assert locked.status_code == 409

    settings = SystemSettings(id=1, network_map_enabled=True)
    endpoint = Endpoint(hostname="managed-laptop", ip_address="10.0.0.8")
    connection = NetworkMapConnection(
        connection_type="mikrotik",
        display_name="Closet A",
        config={"base_url": "http://switch.test", "username": "admin", "password": "secret"},
    )
    floor = NetworkMapFloor(ordinal=1, label="First floor")
    db_session.add_all([settings, endpoint, connection, floor])
    await db_session.flush()
    db_session.add(PuppetNode(
        certname="managed-laptop",
        endpoint_id=endpoint.id,
        synced_at=datetime.now(timezone.utc),
    ))
    await db_session.flush()
    db_session.add(PuppetFact(
        certname="managed-laptop",
        name="networking",
        value={"interfaces": {"en0": {"mac": "AA-BB-CC-DD-EE-FF"}}},
        value_type="object",
        synced_at=datetime.now(timezone.utc),
    ))
    equipment = NetworkMapEquipment(
        connection_id=connection.id,
        source_key="switch",
        kind="switch",
        display_name="Closet A",
        floor_id=floor.id,
    )
    db_session.add(equipment)
    await db_session.flush()
    run = NetworkMapCollectionRun(connection_id=connection.id, status="success", complete_snapshot=True)
    db_session.add(run)
    await db_session.flush()
    db_session.add(NetworkMapObservation(
        run_id=run.id,
        connection_id=connection.id,
        equipment_id=equipment.id,
        observation_type="wired",
        mac_address="aa:bb:cc:dd:ee:ff",
        hostname="different-hostname",
        ip_address="192.0.2.10",
        port="3",
        is_current=True,
    ))
    await db_session.commit()

    response = await client.get("/api/network-map", headers=headers)
    assert response.status_code == 200
    body = response.json()
    assert len(body["floors"]) == 8
    assert body["attachments"][0]["match_state"] == "matched"
    assert body["attachments"][0]["endpoint"]["hostname"] == "managed-laptop"
