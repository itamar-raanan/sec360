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
        },
    )
    await db_session.flush()

    assert event.actor_email == "analyst@example.com"
    assert event.details["added"] == ["symantec_dlp"]
    delivery = (await db_session.execute(select(SiemDelivery))).scalar_one()
    assert delivery.payload["event"]["action"] == "endpoint.dlp_exclusion_added"
    assert delivery.payload["user"]["email"] == "analyst@example.com"
