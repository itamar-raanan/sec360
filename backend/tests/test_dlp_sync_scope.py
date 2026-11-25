from unittest.mock import AsyncMock

import pytest

from app.collectors.symantec import SymantecCollector


pytestmark = pytest.mark.asyncio


async def test_dlp_inventory_sync_does_not_execute_policy_sql(db_session, monkeypatch):
    collector = SymantecCollector(credentials={"db_host": "test", "db_type": "oracle"}, db=db_session)
    records = [{"agentid": 1, "agentname": "dlp-device"}]
    monkeypatch.setattr(collector, "_query_dlp_agents", AsyncMock(return_value=records))
    monkeypatch.setattr(collector, "_upsert_agents", AsyncMock(return_value=1))
    query_policies = AsyncMock(return_value=([{"object_id": 1}], False))
    capture_policies = AsyncMock(return_value=1)
    monkeypatch.setattr("app.services.dlp_policy_search.query_dlp_policy_exclusions", query_policies)
    monkeypatch.setattr("app.services.dlp_policy_tracking.capture_dlp_policy_changes", capture_policies)
    try:
        inventory_result = await collector.collect_inventory()
        assert inventory_result == {"records_synced": 1}
        query_policies.assert_not_awaited()
        capture_policies.assert_not_awaited()
        collector._upsert_agents.assert_awaited_once_with(records)

        full_result = await collector.collect()
        assert full_result == {
            "records_synced": 1, "policy_patterns_synced": 1, "policy_changes_logged": 1,
        }
        query_policies.assert_awaited_once()
        capture_policies.assert_awaited_once()
    finally:
        await collector.client.aclose()
