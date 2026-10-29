from datetime import UTC

import pytest
from pydantic import ValidationError

from app.schemas.event import EventIn
from app.services.event_parser import EventParser
from tests.conftest import make_event


def test_fingerprint_is_deterministic():
    a = EventIn(**make_event())
    b = EventIn(**make_event())
    assert EventParser.fingerprint(a) == EventParser.fingerprint(b)


def test_fingerprint_changes_when_event_changes():
    a = EventIn(**make_event())
    b = EventIn(**make_event(source_ip="203.0.113.8"))
    assert EventParser.fingerprint(a) != EventParser.fingerprint(b)


def test_fingerprint_ignores_attribute_key_order_and_username_case():
    a = EventIn(**make_event(username="Alice", attributes={"a": 1, "b": 2}))
    b = EventIn(**make_event(username="alice", attributes={"b": 2, "a": 1}))
    assert EventParser.fingerprint(a) == EventParser.fingerprint(b)


def test_timestamps_are_normalized_to_utc():
    event = EventIn(**make_event(timestamp="2026-10-28T08:00:00-04:00"))
    assert event.timestamp.tzinfo == UTC
    assert event.timestamp.hour == 12


def test_naive_timestamp_assumed_utc():
    event = EventIn(**make_event(timestamp="2026-10-28T12:00:00"))
    assert event.timestamp.tzinfo == UTC


def test_normalize_lowercases_username():
    row = EventParser.normalize(EventIn(**make_event(username="ALICE")))
    assert row["username"] == "alice"


@pytest.mark.parametrize(
    "bad",
    [
        {"source_ip": "not-an-ip"},
        {"event_type": "Has Spaces!"},
        {"outcome": "maybe"},
        {"source": ""},
        {"unexpected_field": 1},
        {"attributes": {"blob": "x" * 20_000}},
    ],
)
def test_invalid_events_are_rejected(bad):
    with pytest.raises(ValidationError):
        EventIn(**make_event(**bad))
