from datetime import datetime, timedelta, timezone
from time import perf_counter

import pytest
from sqlalchemy import delete, event, select

from app.engines.compliance import evaluate_endpoint, run_full_compliance
from app.engines.risk import endpoint_risk_score, update_all_risk_scores, user_risk_score
from app.models.activity import ActivityEvent
from app.models.agent import SecurityAgent
from app.models.compliance import ComplianceExclusion, ComplianceStatus
from app.models.endpoint import Endpoint
from app.models.integration import IntegrationConfig
from app.models.puppet import PuppetNode
from app.models.system_settings import SystemSettings
from app.models.user import User
from app.services.compliance_agents import load_required_compliance_agents


pytestmark = pytest.mark.asyncio


async def _seed(db, count):
    now = datetime.now(timezone.utc)
    db.add(SystemSettings(id=1, min_s1_version="2", min_dlp_version="2", min_wss_version="2"))
    db.add_all([
        IntegrationConfig(
            integration_type=key, display_name=key, credentials={"configured": True},
            is_enabled=True, status="connected",
        )
        for key in ("sentinelone", "symantec_dlp", "puppet")
    ])
    users = [
        User(
            email=f"user-{index}@example.test", full_name=f"User {index}",
            mfa_enabled=bool(index % 2),
            last_login=now - timedelta(days=45 if index == 0 else 1),
        )
        for index in range(10)
    ]
    db.add_all(users)
    await db.flush()
    endpoints = []
    for index in range(count):
        endpoint = Endpoint(
            hostname=f"device-{index}", source="jumpcloud",
            owner_user_id=users[index % len(users)].id if index % 9 else None,
        )
        db.add(endpoint)
        await db.flush()
        endpoints.append(endpoint)
        for product, divisor in (("sentinelone", 2), ("symantec", 3), ("symantec_wss", 5)):
            if index % divisor == 0:
                db.add(SecurityAgent(
                    endpoint_id=endpoint.id, product_name=product, status="inactive",
                    version="1" if index % 4 == 0 else "2",
                ))
        if index % 7 == 0:
            db.add(PuppetNode(certname=endpoint.hostname, endpoint_id=endpoint.id, synced_at=now))
        if index % 11 == 0 or index % 13 == 0:
            db.add(ComplianceExclusion(
                endpoint_id=endpoint.id, agent_key="*" if index % 11 == 0 else "symantec_dlp",
                reason="Approved exception", created_by="analyst@example.test",
            ))
    for index, country in enumerate(("US", "DE", "IL", "JP", "US", "IL")):
        db.add(ActivityEvent(
            user_id=users[0].id, event_type="login", country=country,
            timestamp=now - timedelta(hours=6 - index),
        ))
    await db.commit()
    return [endpoint.id for endpoint in endpoints], [user.id for user in users]


def _status_values(status):
    return (
        status.status, status.edr_installed, status.edr_version_ok,
        status.dlp_installed, status.dlp_version_ok, status.wss_installed,
        status.wss_version_ok, status.disk_encrypted, status.device_control_enabled,
        dict(status.agent_presence),
    )


@pytest.mark.parametrize("count", [12, 600])
async def test_batch_evaluation_matches_individual_results_with_bounded_reads(db_session, db_engine, count):
    endpoint_ids, user_ids = await _seed(db_session, count)
    reads = []

    def count_read(_connection, _cursor, statement, _params, _context, _many):
        if statement.lstrip().upper().startswith("SELECT"):
            reads.append(statement)

    event.listen(db_engine.sync_engine, "before_cursor_execute", count_read)
    try:
        required = await load_required_compliance_agents(db_session)
        expected_statuses = {}
        for endpoint_id in endpoint_ids:
            status = await evaluate_endpoint(endpoint_id, db_session, required_agents=required)
            expected_statuses[endpoint_id] = _status_values(status)
        await db_session.commit()
        expected_endpoints = {
            endpoint_id: (await endpoint_risk_score(endpoint_id, db_session))["score"]
            for endpoint_id in endpoint_ids
        }
        expected_users = {
            user_id: (await user_risk_score(user_id, db_session))["score"]
            for user_id in user_ids
        }
        individual_reads = len(reads)
    finally:
        event.remove(db_engine.sync_engine, "before_cursor_execute", count_read)
    assert expected_users[user_ids[0]] == 75
    assert expected_users[user_ids[1]] == 25

    # Exercise creation of new Compliance rows as well as the risk refresh.
    await db_session.execute(delete(ComplianceStatus))
    await db_session.commit()
    db_session.expire_all()
    reads.clear()
    event.listen(db_engine.sync_engine, "before_cursor_execute", count_read)
    try:
        started = perf_counter()
        compliance_result = await run_full_compliance(db_session)
        compliance_reads = len(reads)
        reads.clear()
        risk_result = await update_all_risk_scores(db_session)
        risk_reads = len(reads)
        elapsed = perf_counter() - started
    finally:
        event.remove(db_engine.sync_engine, "before_cursor_execute", count_read)
    await db_session.commit()
    assert compliance_result["evaluated"] == count
    assert risk_result == {"users_updated": len(user_ids), "endpoints_updated": count}
    assert compliance_reads <= 25
    assert risk_reads <= 15
    actual_statuses = {
        status.endpoint_id: _status_values(status)
        for status in (await db_session.execute(select(ComplianceStatus))).scalars()
    }
    assert actual_statuses == expected_statuses
    assert dict((await db_session.execute(select(Endpoint.id, Endpoint.risk_score))).all()) == expected_endpoints
    assert dict((await db_session.execute(select(User.id, User.risk_score))).all()) == expected_users
    assert compliance_reads + risk_reads < individual_reads
    print(f"{count} endpoints: individual={individual_reads} SELECTs, batched compliance={compliance_reads}, risk={risk_reads}, elapsed={elapsed:.3f}s")
