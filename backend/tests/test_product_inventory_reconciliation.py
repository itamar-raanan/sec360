from datetime import datetime, timezone

import pytest
from sqlalchemy import select

from app.collectors.sentinelone import SentinelOneCollector
from app.collectors.symantec import SymantecCollector
from app.collectors.jumpcloud import JumpCloudCollector
from app.engines.correlation import deduplicate_endpoints
from app.models.agent import SecurityAgent
from app.models.compliance import ComplianceExclusion
from app.models.endpoint import Endpoint


pytestmark = pytest.mark.asyncio


@pytest.mark.parametrize("product", ["sentinelone", "symantec", "symantec_wss"])
async def test_jumpcloud_removal_cannot_hide_security_product_inventory(db_session, product):
    endpoint = Endpoint(hostname="removed-from-jc-only", source="jumpcloud")
    orphan = Endpoint(hostname="removed-from-everywhere", source="jumpcloud")
    ignored = Endpoint(
        hostname="analyst-ignored", source="jumpcloud",
        is_active=False, lifecycle_state="ignored",
    )
    db_session.add_all([endpoint, orphan, ignored])
    await db_session.flush()
    db_session.add_all([
        SecurityAgent(endpoint_id=endpoint.id, product_name=product, status="inactive"),
        SecurityAgent(endpoint_id=ignored.id, product_name=product, status="active"),
    ])
    await db_session.flush()

    collector = JumpCloudCollector(credentials={"api_key": "test"}, db=db_session)
    # Include repeated JC refreshes: the count must not depend on another
    # successful S1/DLP refresh reviving this machine afterwards.
    await collector._upsert_systems([])
    await collector._upsert_systems([])

    assert endpoint.is_active is True
    assert endpoint.lifecycle_state == "active"
    assert orphan.is_active is False
    assert orphan.lifecycle_state == "stale"
    assert ignored.is_active is False
    assert ignored.lifecycle_state == "ignored"


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


@pytest.mark.parametrize("reverse_order", [False, True])
@pytest.mark.parametrize("target_exists", [False, True])
async def test_dlp_repairs_existing_shared_mapping_using_source_hostnames(db_session, reverse_order, target_exists):
    """Reproduce the production collision: 4402 and 459 on the same endpoint."""
    canonical = Endpoint(
        hostname="Lirans-MacBook-Pro-3", source="jumpcloud", username="liran",
        owner_assignment_source="manual", owner_assignment_evidence="Unassigned by analyst",
    )
    db_session.add(canonical)
    await db_session.flush()
    canonical_id = canonical.id
    db_session.add(ComplianceExclusion(
        endpoint_id=canonical.id, agent_key="symantec_dlp",
        reason="Exception for the original Mac only", created_by="analyst@example.test",
    ))
    target_id = None
    if target_exists:
        target = Endpoint(hostname="liran-P6792-28494", source="sentinelone")
        db_session.add(target)
        await db_session.flush()
        target_id = target.id
        db_session.add(SecurityAgent(
            endpoint_id=target.id, product_name="sentinelone", source_id="s1-other-machine",
        ))
    agents = [
        SecurityAgent(endpoint_id=canonical.id, product_name="symantec", source_id=source_id)
        for source_id in ("4402", "459")
    ]
    db_session.add_all(agents)
    await db_session.flush()
    original_agent_ids = {agent.source_id: agent.id for agent in agents}
    records = [
        {"agentid": 4402, "agentname": "liran-P6792-28494", "username": "DOMAIN\\liran", "agentstatename": "Blocked"},
        {"agentid": 459, "agentname": "Lirans-MacBook-Pro-3", "username": "DOMAIN\\liran", "agentstatename": "Disabled"},
    ]
    if reverse_order:
        records.reverse()
    collector = SymantecCollector(credentials={"db_host": "test", "db_type": "oracle"}, db=db_session)
    try:
        for _ in range(2):
            assert await collector._upsert_agents(records) == 2
            await db_session.commit()
            db_session.expire_all()
            await deduplicate_endpoints(db_session)
            await db_session.commit()
            db_session.expire_all()
            rows = (await db_session.execute(
                select(SecurityAgent.id, SecurityAgent.source_id, Endpoint.id, Endpoint.hostname)
                .join(Endpoint, SecurityAgent.endpoint_id == Endpoint.id)
                .where(SecurityAgent.product_name == "symantec")
            )).all()
            by_source = {row.source_id: row for row in rows}
            assert len(rows) == 2
            assert by_source["459"].hostname == "Lirans-MacBook-Pro-3"
            assert by_source["459"][2] == canonical_id
            assert by_source["4402"].hostname == "liran-P6792-28494"
            assert by_source["4402"][2] != canonical_id
            if target_id:
                assert by_source["4402"][2] == target_id
            assert {row.source_id: row[0] for row in rows} == original_agent_ids
            assert (await db_session.get(Endpoint, canonical_id)).owner_assignment_source == "manual"
            assert (await db_session.get(Endpoint, by_source["4402"][2])).owner_assignment_source is None
            exclusions = (await db_session.execute(select(ComplianceExclusion))).scalars().all()
            assert [item.endpoint_id for item in exclusions] == [canonical_id]
            assert len((await db_session.execute(select(Endpoint.id))).all()) == 2
    finally:
        await collector.client.aclose()


async def test_dlp_does_not_assign_a_new_device_by_username_only(db_session):
    canonical = Endpoint(hostname="alice-macbook-pro", source="jumpcloud", username="alice")
    db_session.add(canonical)
    await db_session.flush()
    canonical_id = canonical.id
    collector = SymantecCollector(credentials={"db_host": "test", "db_type": "oracle"}, db=db_session)
    try:
        assert await collector._upsert_agents([
            {"agentid": 123, "agentname": "alice-workstation-123", "username": "DOMAIN\\alice"},
        ]) == 1
    finally:
        await collector.client.aclose()
    agent = (await db_session.execute(select(SecurityAgent))).scalar_one()
    assert agent.endpoint_id != canonical_id
    endpoint = await db_session.get(Endpoint, agent.endpoint_id)
    assert endpoint.hostname == "alice-workstation-123"


async def test_new_dlp_agent_cannot_claim_a_machine_reserved_for_an_existing_id(db_session):
    canonical = Endpoint(hostname="shared-source-hostname", source="jumpcloud")
    db_session.add(canonical)
    await db_session.flush()
    canonical_id = canonical.id
    db_session.add(SecurityAgent(
        endpoint_id=canonical.id, product_name="symantec", source_id="459",
    ))
    await db_session.flush()
    collector = SymantecCollector(credentials={"db_host": "test", "db_type": "oracle"}, db=db_session)
    try:
        # The new agent appears before the existing agent in the API response.
        assert await collector._upsert_agents([
            {"agentid": 4402, "agentname": "shared-source-hostname"},
            {"agentid": 459, "agentname": "shared-source-hostname"},
        ]) == 2
    finally:
        await collector.client.aclose()
    agents = (await db_session.execute(select(SecurityAgent))).scalars().all()
    by_source = {agent.source_id: agent for agent in agents}
    assert by_source["459"].endpoint_id == canonical_id
    assert by_source["4402"].endpoint_id != canonical_id


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
