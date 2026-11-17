from datetime import datetime, timezone

import pytest
from sqlalchemy import select

from app.collectors.sentinelone import SentinelOneCollector
from app.collectors.symantec import SymantecCollector
from app.engines.correlation import deduplicate_endpoints
from app.models.agent import SecurityAgent
from app.models.endpoint import Endpoint


pytestmark = pytest.mark.asyncio


async def test_sentinelone_sync_removes_agents_missing_from_source(db_session):
    current = Endpoint(hostname="current-s1", source="jumpcloud")
    removed = Endpoint(hostname="removed-s1", source="sentinelone")
    db_session.add_all([current, removed])
    await db_session.flush()
    db_session.add(SecurityAgent(
        endpoint_id=removed.id,
        product_name="sentinelone",
        status="active",
    ))
    await db_session.flush()

    collector = SentinelOneCollector(credentials={"api_key": "test"}, db=db_session)
    try:
        count, mapping = await collector._upsert_agents([{
            "id": "s1-current",
            "computerName": "current-s1",
            "isActive": True,
            "agentVersion": "24.1",
        }])
    finally:
        await collector.client.aclose()

    agents = list((await db_session.execute(
        select(SecurityAgent).where(SecurityAgent.product_name == "sentinelone")
    )).scalars())
    assert count == 1
    assert mapping == {"s1-current": str(current.id)}
    assert [agent.endpoint_id for agent in agents] == [current.id]
    assert removed.is_active is False
    assert removed.lifecycle_state == "stale"


async def test_sentinelone_source_ids_preserve_normalized_hostname_collisions(db_session):
    records = [
        {"id": "s1-alice-laptop", "computerName": "alice-laptop", "isActive": True},
        {"id": "s1-alice-desktop", "computerName": "alice-desktop", "isActive": True},
    ]
    collector = SentinelOneCollector(credentials={"api_key": "test"}, db=db_session)
    try:
        first_count, _ = await collector._upsert_agents(records)
        second_count, _ = await collector._upsert_agents(records)
    finally:
        await collector.client.aclose()

    agents = list((await db_session.execute(
        select(SecurityAgent).where(SecurityAgent.product_name == "sentinelone")
    )).scalars())
    assert first_count == second_count == 2
    assert {agent.source_id for agent in agents} == {
        "s1-alice-laptop", "s1-alice-desktop",
    }
    assert len({agent.endpoint_id for agent in agents}) == 2


async def test_sentinelone_restores_stale_canonical_endpoint(db_session):
    endpoint = Endpoint(
        hostname="still-in-s1",
        source="jumpcloud",
        is_active=False,
        lifecycle_state="stale",
        lifecycle_reason="Removed from jumpcloud inventory",
    )
    db_session.add(endpoint)
    await db_session.flush()

    collector = SentinelOneCollector(credentials={"api_key": "test"}, db=db_session)
    try:
        await collector._upsert_agents([{
            "id": "s1-still-present",
            "computerName": "still-in-s1",
            "isActive": False,
        }])
    finally:
        await collector.client.aclose()

    assert endpoint.is_active is True
    assert endpoint.lifecycle_state == "active"
    assert endpoint.lifecycle_reason is None


async def test_wss_sync_removes_only_authoritatively_stale_rows(db_session, monkeypatch):
    installed = Endpoint(hostname="wss-installed", source="jumpcloud")
    removed_app = Endpoint(hostname="wss-removed-app", source="jumpcloud")
    failed_scan = Endpoint(hostname="wss-failed-scan", source="jumpcloud")
    removed_s1 = Endpoint(hostname="wss-removed-s1", source="jumpcloud")
    db_session.add_all([installed, removed_app, failed_scan, removed_s1])
    await db_session.flush()
    for endpoint in (installed, removed_app, failed_scan, removed_s1):
        db_session.add(SecurityAgent(
            endpoint_id=endpoint.id,
            product_name="symantec_wss",
            status="active",
            version="old",
        ))
    await db_session.flush()

    collector = SentinelOneCollector(credentials={"api_key": "test"}, db=db_session)

    async def fake_apps(_client, s1_id):
        if s1_id == "s1-installed":
            return [{"product": "symantec_wss", "version": "9.1"}]
        if s1_id == "s1-failed":
            return None
        return []

    monkeypatch.setattr(collector, "_fetch_apps_for_agent", fake_apps)
    try:
        await collector._collect_app_agents({
            "s1-installed": str(installed.id),
            "s1-removed-app": str(removed_app.id),
            "s1-failed": str(failed_scan.id),
        })
    finally:
        await collector.client.aclose()

    agents = list((await db_session.execute(
        select(SecurityAgent).where(SecurityAgent.product_name == "symantec_wss")
    )).scalars())
    by_endpoint = {agent.endpoint_id: agent for agent in agents}
    assert set(by_endpoint) == {installed.id, failed_scan.id}
    assert by_endpoint[installed.id].version == "9.1"
    assert by_endpoint[failed_scan.id].version == "old"


async def test_dlp_sync_does_not_collapse_multiple_devices_for_one_user(db_session):
    first = Endpoint(hostname="alice-laptop", username="alice", source="jumpcloud")
    second = Endpoint(hostname="alice-desktop", username="alice", source="jumpcloud")
    stale = Endpoint(hostname="old-dlp", source="symantec")
    db_session.add_all([first, second, stale])
    await db_session.flush()
    db_session.add(SecurityAgent(
        endpoint_id=stale.id,
        product_name="symantec",
        status="active",
    ))
    await db_session.flush()

    collector = SymantecCollector(
        credentials={"db_host": "test", "db_type": "oracle"},
        db=db_session,
    )
    count = await collector._upsert_agents([{
        "agentname": "alice-new-device",
        "username": "DOMAIN\\alice",
        "version": "16.1",
        "lastconnectiontime": datetime.now(timezone.utc),
        "agentstatename": "Enabled",
        "agentgroupname": "Default",
    }])

    assert count == 1
    dlp_agents = list((await db_session.execute(
        select(SecurityAgent).where(SecurityAgent.product_name == "symantec")
    )).scalars())
    assert len(dlp_agents) == 1
    dlp_endpoint = await db_session.get(Endpoint, dlp_agents[0].endpoint_id)
    assert dlp_endpoint.hostname == "alice-new-device"
    assert dlp_endpoint.source == "symantec"
    assert stale.is_active is False
    assert stale.lifecycle_state == "stale"

    # The lower-confidence correlation fallback must also preserve these
    # distinct devices because the username is not unique in JumpCloud.
    await deduplicate_endpoints(db_session)
    endpoints = list((await db_session.execute(select(Endpoint))).scalars())
    assert {endpoint.hostname for endpoint in endpoints} == {
        "alice-laptop", "alice-desktop", "alice-new-device", "old-dlp",
    }


async def test_dlp_agent_ids_preserve_normalized_hostname_collisions(db_session):
    now = datetime.now(timezone.utc)
    records = [
        {
            "agentid": "dlp-alice-laptop",
            "agentname": "alice-laptop",
            "username": "DOMAIN\\alice",
            "lastconnectiontime": now,
        },
        {
            "agentid": "dlp-alice-desktop",
            "agentname": "alice-desktop",
            "username": "DOMAIN\\alice",
            "lastconnectiontime": now,
        },
    ]
    collector = SymantecCollector(
        credentials={"db_host": "test", "db_type": "oracle"},
        db=db_session,
    )
    first_count = await collector._upsert_agents(records)
    second_count = await collector._upsert_agents(records)

    agents = list((await db_session.execute(
        select(SecurityAgent).where(SecurityAgent.product_name == "symantec")
    )).scalars())
    assert first_count == second_count == 2
    assert {agent.source_id for agent in agents} == {
        "dlp-alice-laptop", "dlp-alice-desktop",
    }
    assert len({agent.endpoint_id for agent in agents}) == 2

    # Correlation must not merge two endpoints backed by distinct authoritative
    # DLP identities, even though their normalized hostnames collide.
    await deduplicate_endpoints(db_session)
    endpoints = list((await db_session.execute(select(Endpoint))).scalars())
    assert {endpoint.hostname for endpoint in endpoints} == {"alice-laptop", "alice-desktop"}


async def test_dlp_restores_stale_canonical_endpoint_but_not_analyst_state(db_session):
    stale = Endpoint(
        hostname="still-in-dlp",
        source="jumpcloud",
        is_active=False,
        lifecycle_state="stale",
    )
    decommissioned = Endpoint(
        hostname="retired-by-analyst",
        source="jumpcloud",
        is_active=False,
        lifecycle_state="decommissioned",
    )
    db_session.add_all([stale, decommissioned])
    await db_session.flush()

    collector = SymantecCollector(
        credentials={"db_host": "test", "db_type": "oracle"},
        db=db_session,
    )
    await collector._upsert_agents([
        {"agentid": "dlp-current", "agentname": "still-in-dlp"},
        {"agentid": "dlp-retired", "agentname": "retired-by-analyst"},
    ])

    assert stale.is_active is True
    assert stale.lifecycle_state == "active"
    assert decommissioned.is_active is False
    assert decommissioned.lifecycle_state == "decommissioned"
