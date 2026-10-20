from datetime import datetime, timezone
import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy import select

from app.models.endpoint import Endpoint
from app.models.network_map import (
    NetworkMapCollector,
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


async def test_direct_connections_are_retired_and_floor_management_remains_available(
    client: AsyncClient, db_session, admin_user
):
    headers = await _admin_headers(client)
    payload = {
        "connection_type": "cisco_wlc",
        "display_name": "Campus WLC",
        "config": {"host": "wlc.example.test", "username": "collector", "password": "very-secret"},
    }
    created = await client.post("/api/network-map/connections", headers=headers, json=payload)
    assert created.status_code == 410
    assert "collector" in created.json()["detail"].lower()

    floors = await client.get("/api/network-map/floors", headers=headers)
    assert floors.status_code == 200
    assert len(floors.json()) == 31
    assert all(item["managed"] is False for item in floors.json())

    configured = await client.put(
        f"/api/network-map/floors/{floors.json()[24]['id']}",
        headers=headers,
        json={"managed": True, "label": "Security Operations"},
    )
    assert configured.status_code == 200
    assert configured.json()["managed"] is True
    assert configured.json()["label"] == "Security Operations"


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
    floor = NetworkMapFloor(ordinal=1, label="First floor", managed=True)
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
    assert len(body["floors"]) == 31
    assert body["summary"]["building_floors"] == 31
    assert body["summary"]["floors"] == 1
    assert body["attachments"][0]["match_state"] == "matched"
    assert body["attachments"][0]["endpoint"]["hostname"] == "managed-laptop"
    assert body["table_entities"][0]["mac_address"] == "aa:bb:cc:dd:ee:ff"


async def test_on_prem_collector_enrollment_and_idempotent_snapshot_ingestion(
    client: AsyncClient, db_session, admin_user
):
    headers = await _admin_headers(client)
    created = await client.post(
        "/api/network-map/collectors", headers=headers, json={"name": "Tel Aviv collector"}
    )
    assert created.status_code == 201
    collector_id = created.json()["id"]
    token = created.json()["token"]
    assert token.startswith(f"nmc_{collector_id}_")

    listed = await client.get("/api/network-map/collectors", headers=headers)
    assert listed.status_code == 200
    assert listed.json()[0]["name"] == "Tel Aviv collector"
    assert "token" not in listed.json()[0]

    snapshot_id = str(uuid.uuid4())
    snapshot = {
        "schema_version": "1.0",
        "collector_id": collector_id,
        "source_id": "campus-wlc",
        "source_name": "Campus WLC",
        "source_type": "cisco_wlc",
        "snapshot_id": snapshot_id,
        "sequence": 1,
        "collected_at": datetime.now(timezone.utc).isoformat(),
        "complete": True,
        "records": {
            "access_points": [{"name": "AP-25", "mac": "00:11:22:33:44:55", "ip": "10.0.0.25"}],
            "clients": [{"mac": "AA-BB-CC-DD-EE-FF", "ap": "AP-25", "wlan": "7", "state": "Associated"}],
            "wlans": {"7": "Corporate-WiFi"},
        },
    }
    collector_headers = {"Authorization": f"Collector {token}"}
    ingested = await client.post("/api/network-map/collector/ingest", headers=collector_headers, json=snapshot)
    assert ingested.status_code == 200
    assert ingested.json()["disposition"] == "accepted"
    assert ingested.json()["records_synced"] == 1

    duplicate = await client.post("/api/network-map/collector/ingest", headers=collector_headers, json=snapshot)
    assert duplicate.status_code == 200
    assert duplicate.json()["disposition"] == "duplicate"
    assert len((await db_session.execute(select(NetworkMapObservation))).scalars().all()) == 1

    stale_snapshot = {**snapshot, "snapshot_id": str(uuid.uuid4())}
    stale = await client.post("/api/network-map/collector/ingest", headers=collector_headers, json=stale_snapshot)
    assert stale.status_code == 200
    assert stale.json()["disposition"] == "stale"

    incomplete_snapshot = {**snapshot, "snapshot_id": str(uuid.uuid4()), "sequence": 2, "complete": False}
    incomplete = await client.post("/api/network-map/collector/ingest", headers=collector_headers, json=incomplete_snapshot)
    assert incomplete.status_code == 422
    assert len((await db_session.execute(select(NetworkMapObservation))).scalars().all()) == 1

    connection = (await db_session.execute(select(NetworkMapConnection).where(
        NetworkMapConnection.collector_id == uuid.UUID(collector_id)
    ))).scalar_one()
    assert connection.config == {}
    assert connection.source_identifier == "campus-wlc"
    assert connection.records_synced == 1
    observation = (await db_session.execute(select(NetworkMapObservation))).scalar_one()
    assert observation.mac_address == "aa:bb:cc:dd:ee:ff"
    assert observation.ssid == "Corporate-WiFi"

    heartbeat = await client.post("/api/network-map/collector/heartbeat", headers=collector_headers, json={
        "version": "1.0.0", "queue_depth": 0,
        "sources": {"campus-wlc": {"status": "ok"}},
    })
    assert heartbeat.status_code == 200
    collector = await db_session.get(NetworkMapCollector, uuid.UUID(collector_id))
    assert collector.version == "1.0.0"

    rejected = await client.post(
        "/api/network-map/collector/ingest",
        headers={"Authorization": "Collector nmc_00000000-0000-0000-0000-000000000000_invalid"},
        json=snapshot,
    )
    assert rejected.status_code == 401
