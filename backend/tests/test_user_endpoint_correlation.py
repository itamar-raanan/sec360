from datetime import datetime, timezone

import pytest
from sqlalchemy import select

from app.collectors.active_directory import ActiveDirectoryCollector
from app.engines.correlation import match_user_to_endpoint
from app.models.endpoint import Endpoint
from app.models.user import User


pytestmark = pytest.mark.asyncio


def _user(email: str, name: str) -> User:
    return User(
        email=email,
        full_name=name,
        employment_status="active",
        mfa_enabled=False,
        suspended=False,
    )


async def test_correlation_uses_exact_unique_username_and_corrects_legacy_owner(db_session):
    alice = _user("alice@example.com", "Alice Correct")
    wrong = _user("alex@example.com", "Alex Wrong")
    endpoint = Endpoint(
        hostname="shared-device-name",
        username="DOMAIN\\alice",
        owner=wrong,
        source="sentinelone",
    )
    db_session.add_all([alice, wrong, endpoint])
    await db_session.flush()

    assert await match_user_to_endpoint(db_session) == 1
    assert endpoint.owner_user_id == alice.id
    assert endpoint.owner_assignment_source == "endpoint_username"
    assert endpoint.owner_assignment_confidence == 1.0
    assert "alice@example.com" in endpoint.owner_assignment_evidence
    assert endpoint.owner_assigned_at is not None


async def test_correlation_rejects_partial_first_name_and_ambiguous_prefixes(db_session):
    users = [
        _user("benh@example.com", "Ben Harris"),
        _user("sam@corp.example", "Sam One"),
        _user("sam@subsidiary.example", "Sam Two"),
    ]
    partial = Endpoint(hostname="ben-laptop", username="ben", source="sentinelone")
    first_name = Endpoint(hostname="harris-device", username="harris", source="symantec")
    ambiguous = Endpoint(hostname="sam-laptop", username="sam", source="jumpcloud")
    db_session.add_all([*users, partial, first_name, ambiguous])
    await db_session.flush()

    assert await match_user_to_endpoint(db_session) == 0
    assert partial.owner_user_id is None
    assert first_name.owner_user_id is None
    assert ambiguous.owner_user_id is None


async def test_correlation_preserves_manual_assignment_and_manual_unassignment(db_session):
    alice = _user("alice@example.com", "Alice")
    bob = _user("bob@example.com", "Bob")
    manually_assigned = Endpoint(
        hostname="alice-laptop",
        username="alice",
        owner=bob,
        owner_assignment_source="manual",
        owner_assignment_confidence=1.0,
        owner_assignment_evidence="Assigned by analyst@example.com",
        owner_assigned_at=datetime.now(timezone.utc),
    )
    manually_unassigned = Endpoint(
        hostname="alice-desktop",
        username="alice",
        owner_assignment_source="manual",
        owner_assignment_confidence=1.0,
        owner_assignment_evidence="Unassigned by analyst@example.com",
        owner_assigned_at=datetime.now(timezone.utc),
    )
    db_session.add_all([alice, bob, manually_assigned, manually_unassigned])
    await db_session.flush()

    assert await match_user_to_endpoint(db_session) == 0
    assert manually_assigned.owner_user_id == bob.id
    assert manually_unassigned.owner_user_id is None


async def test_correlation_does_not_guess_from_hostname_without_reported_username(db_session):
    alice = _user("alice@example.com", "Alice")
    endpoint = Endpoint(hostname="alice-laptop", username=None, source="jumpcloud")
    db_session.add_all([alice, endpoint])
    await db_session.flush()

    assert await match_user_to_endpoint(db_session) == 0
    assert endpoint.owner_user_id is None
    assert endpoint.owner_assignment_source is None
    assert endpoint.owner_assignment_confidence is None

    stored = (await db_session.execute(
        select(Endpoint).where(Endpoint.id == endpoint.id)
    )).scalar_one()
    assert stored.owner_user_id is None


async def test_active_directory_linking_is_exact_and_preserves_manual_owner(db_session):
    alice = _user("alice@example.com", "Alice")
    bob = _user("bob@example.com", "Bob")
    automatic = Endpoint(hostname="device-1", username="DOMAIN\\alice")
    manual = Endpoint(
        hostname="device-2",
        username="DOMAIN\\alice",
        owner=bob,
        owner_assignment_source="manual",
    )
    db_session.add_all([alice, bob, automatic, manual])
    await db_session.flush()

    collector = ActiveDirectoryCollector({"import_mode": "manual"}, db_session)
    assert await collector.link_users_to_endpoints([alice.email, bob.email]) == 1
    assert automatic.owner_user_id == alice.id
    assert automatic.owner_assignment_source == "active_directory_username"
    assert automatic.owner_assignment_confidence == 1.0
    assert manual.owner_user_id == bob.id
    assert manual.owner_assignment_source == "manual"
