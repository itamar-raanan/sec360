from datetime import datetime, timezone
from types import SimpleNamespace
import uuid

import pytest
from sqlalchemy import select

from app.models.change_event import ChangeEvent, SiemDelivery
from app.models.compliance import ComplianceStatus
from app.models.endpoint import Endpoint
from app.models.integration import IntegrationConfig
from app.models.user import User
from app.services.change_tracking import capture_inventory_changes, record_change_event
from app.services.dlp_policy_tracking import capture_dlp_policy_changes
from app.services.siem import audit_log_to_ecs, change_event_to_ecs


pytestmark = pytest.mark.asyncio


def test_change_event_maps_to_ecs_host_document():
    event = ChangeEvent(
        id=uuid.uuid4(),
        event_type="endpoint.product_missing",
        entity_type="endpoint",
        entity_id="endpoint-1",
        entity_name="laptop-1",
        action="missing",
        severity="warning",
        source="sentinelone",
        before={"present": True},
        after={"present": False},
        details={"product": "sentinelone"},
        timestamp=datetime(2026, 9, 27, 10, 0, tzinfo=timezone.utc),
    )

    document = change_event_to_ecs(event)

    assert document["ecs"]["version"] == "8.11.0"
    assert document["event"]["action"] == "endpoint.product_missing"
    assert document["event"]["category"] == ["host"]
    assert document["host"] == {"id": "endpoint-1", "name": "laptop-1"}
    assert document["sec360"]["change"]["details"]["product"] == "sentinelone"


def test_audit_log_maps_actor_and_source_ip_to_ecs():
    audit = SimpleNamespace(
        id=uuid.uuid4(),
        action="update_compliance_exclusions",
        resource_type="endpoint",
        resource_id="endpoint-1",
        timestamp=datetime(2026, 9, 27, 10, 0, tzinfo=timezone.utc),
        ip_address="192.0.2.10",
        details={"actor_id": "admin-1", "actor_email": "admin@example.com"},
    )

    document = audit_log_to_ecs(audit)

    assert document["event"]["category"] == ["configuration"]
    assert document["user"]["email"] == "admin@example.com"
    assert document["source"]["ip"] == "192.0.2.10"


async def test_inventory_changes_create_events_and_siem_deliveries(db_session):
    endpoint = Endpoint(
        hostname="workstation-1",
        source="jumpcloud",
        is_active=True,
        lifecycle_state="active",
    )
    user = User(
        full_name="Test User",
        email="test.user@example.com",
        employment_status="active",
        suspended=False,
    )
    db_session.add_all([endpoint, user])
    await db_session.flush()
    status = ComplianceStatus(
        endpoint_id=endpoint.id,
        status="non_compliant",
        agent_presence={"sentinelone": False},
    )
    db_session.add_all([
        status,
        IntegrationConfig(
            integration_type="sentinelone",
            display_name="SentinelOne",
            credentials={"url": "https://example.invalid", "token": "test"},
            is_enabled=True,
            status="connected",
        ),
    ])
    await db_session.flush()

    # The first run establishes a baseline without flooding an upgraded system.
    assert await capture_inventory_changes(db_session) == 0

    status.agent_presence = {"sentinelone": True}
    status.status = "compliant"
    user.suspended = True
    await db_session.flush()

    emitted = await capture_inventory_changes(db_session)
    assert emitted >= 3
    event_types = set((await db_session.execute(select(ChangeEvent.event_type))).scalars().all())
    assert "endpoint.product_added" in event_types
    assert "endpoint.compliance_changed" in event_types
    assert "user.disabled" in event_types
    deliveries = (await db_session.execute(select(SiemDelivery))).scalars().all()
    assert len(deliveries) == len(event_types)


async def test_new_endpoint_does_not_report_initial_products_as_changes(db_session):
    db_session.add(IntegrationConfig(
        integration_type="sentinelone",
        display_name="SentinelOne",
        credentials={"url": "https://example.invalid", "token": "test"},
        is_enabled=True,
        status="connected",
    ))
    await db_session.flush()

    # Establish the global tracking marker before the endpoint appears.
    assert await capture_inventory_changes(db_session) == 0

    endpoint = Endpoint(
        hostname="new-workstation",
        source="jumpcloud",
        is_active=True,
        lifecycle_state="active",
    )
    db_session.add(endpoint)
    await db_session.flush()
    db_session.add(ComplianceStatus(
        endpoint_id=endpoint.id,
        status="compliant",
        agent_presence={"sentinelone": True},
    ))
    await db_session.flush()

    await capture_inventory_changes(db_session)
    event_types = (await db_session.execute(
        select(ChangeEvent.event_type).where(ChangeEvent.entity_id == str(endpoint.id))
    )).scalars().all()

    assert event_types == ["endpoint.detected"]


async def test_newly_tracked_product_uses_existing_endpoint_state_as_baseline(db_session):
    endpoint = Endpoint(
        hostname="existing-workstation",
        source="jumpcloud",
        is_active=True,
        lifecycle_state="active",
    )
    db_session.add(endpoint)
    await db_session.flush()
    status = ComplianceStatus(
        endpoint_id=endpoint.id,
        status="compliant",
        agent_presence={},
    )
    db_session.add(status)
    await db_session.flush()

    assert await capture_inventory_changes(db_session) == 0

    db_session.add(IntegrationConfig(
        integration_type="sentinelone",
        display_name="SentinelOne",
        credentials={"url": "https://example.invalid", "token": "test"},
        is_enabled=True,
        status="connected",
    ))
    status.agent_presence = {"sentinelone": True}
    await db_session.flush()

    assert await capture_inventory_changes(db_session) == 0
    product_events = (await db_session.execute(
        select(ChangeEvent).where(
            ChangeEvent.entity_id == str(endpoint.id),
            ChangeEvent.event_type.in_({"endpoint.product_added", "endpoint.product_missing"}),
        )
    )).scalars().all()
    assert product_events == []


async def test_dlp_exclusion_event_contains_actor_and_added_scope(db_session):
    event = await record_change_event(
        db_session,
        event_type="endpoint.dlp_exclusion_added",
        entity_type="endpoint",
        entity_id="endpoint-1",
        entity_name="workstation-1",
        action="added",
        severity="warning",
        source="analyst",
        actor_email="analyst@example.com",
        before={"excluded_agents": []},
        after={"excluded_agents": ["symantec_dlp"]},
        details={
            "added": ["symantec_dlp"],
            "removed": [],
            "reason": "Approved exception",
            "changed_by": "analyst@example.com",
            "diff_only": True,
        },
    )
    await db_session.flush()

    assert event.actor_email == "analyst@example.com"
    assert event.details["added"] == ["symantec_dlp"]
    delivery = (await db_session.execute(select(SiemDelivery))).scalar_one()
    assert delivery.payload["event"]["action"] == "endpoint.dlp_exclusion_added"
    assert delivery.payload["user"]["email"] == "analyst@example.com"


async def test_dlp_policy_pattern_edit_records_before_after_and_editor(db_session):
    original = [{
        "object_id": 42,
        "object_uuid": "pattern-42",
        "object_name": "Approved senders",
        "object_status": "ACTIVE",
        "user_patterns": "old@example.com",
        "modified_date": "2026-09-27T10:00:00",
        "modified_by_id": 7,
        "modified_by_name": "DLP Admin",
        "policy_id": 100,
        "policy_name": "Outbound PII",
        "used_as": "SENDER",
        "policy_active_status": 1,
    }]
    updated = [{
        **original[0],
        "user_patterns": "old@example.com,new@example.com",
        "modified_date": "2026-09-27T11:00:00",
    }]

    # First observation is a silent baseline; the second is a real edit.
    assert await capture_dlp_policy_changes(db_session, original) == 0
    assert await capture_dlp_policy_changes(db_session, updated) == 1

    event = (await db_session.execute(
        select(ChangeEvent).where(ChangeEvent.event_type == "dlp.policy_pattern_changed")
    )).scalar_one()
    assert event.entity_name == "Approved senders"
    assert event.actor_email == "DLP Admin"
    assert event.before == {"user_patterns": []}
    assert event.after == {"user_patterns": ["new@example.com"]}
    assert event.details["changed_fields"] == ["user_patterns"]
    assert event.details["diff_only"] is True
    assert "modified_date" not in event.details["changed_fields"]
    assert event.details["policies"] == ["Outbound PII"]
    delivery = (await db_session.execute(
        select(SiemDelivery).where(SiemDelivery.source_id == str(event.id))
    )).scalar_one()
    assert delivery.payload["event"]["category"] == ["configuration"]
    assert delivery.payload["user"]["name"] == "DLP Admin"

    # Reading the same policy state again must not create a duplicate.
    assert await capture_dlp_policy_changes(db_session, updated) == 0


async def test_dlp_policy_metadata_only_update_does_not_create_noise(db_session):
    original = [{
        "object_id": 43,
        "object_uuid": "pattern-43",
        "object_name": "Approved recipients",
        "user_patterns": "alice@example.com",
        "modified_date": "2026-09-27T10:00:00",
        "modified_by_id": 7,
        "modified_by_name": "DLP Admin",
    }]
    metadata_only = [{
        **original[0],
        "modified_date": "2026-09-27T11:00:00",
        "modified_by_id": 8,
        "modified_by_name": "Another Admin",
    }]

    assert await capture_dlp_policy_changes(db_session, original) == 0
    assert await capture_dlp_policy_changes(db_session, metadata_only) == 0
    assert (await db_session.execute(
        select(ChangeEvent).where(ChangeEvent.event_type == "dlp.policy_pattern_changed")
    )).scalars().all() == []


async def test_dlp_pattern_add_and_remove_store_presence_only(db_session):
    pattern = [{
        "object_id": 44,
        "object_uuid": "pattern-44",
        "object_name": "Temporary exception",
        "user_patterns": "temporary@example.com",
        "modified_by_name": "DLP Admin",
    }]

    assert await capture_dlp_policy_changes(db_session, []) == 0
    assert await capture_dlp_policy_changes(db_session, pattern) == 1
    assert await capture_dlp_policy_changes(db_session, []) == 1

    events = (await db_session.execute(
        select(ChangeEvent)
        .where(ChangeEvent.entity_id == "pattern-44")
        .order_by(ChangeEvent.timestamp)
    )).scalars().all()
    assert events[0].before == {"pattern_exists": False}
    assert events[0].after == {"pattern_exists": True}
    assert events[1].before == {"pattern_exists": True}
    assert events[1].after == {"pattern_exists": False}
