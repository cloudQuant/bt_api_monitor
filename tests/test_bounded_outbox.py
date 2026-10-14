"""Tests for caller-bounded durable outbox appends."""

from __future__ import annotations

import sqlite3
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier

import pytest

from bt_api_monitor.durable import (
    MAX_OUTBOX_CAPACITY_BYTES,
    MAX_OUTBOX_CAPACITY_EVENTS,
    DurableOutbox,
    OutboxCapacityError,
    OutboxConflictError,
    OutboxError,
    OutboxEvent,
    SequencedOutboxEvent,
)


def _event(
    event_id: str,
    *,
    scope: str = "account:1",
    event_type: str = "risk.decision",
    data: dict[str, object] | None = None,
    occurred_at: float = 1_700_000_000.0,
) -> OutboxEvent:
    return OutboxEvent(
        event_id=event_id,
        scope=scope,
        event_type=event_type,
        data=data if data is not None else {"decision": "allow"},
        occurred_at=occurred_at,
    )


def _logical_bytes(event: OutboxEvent) -> int:
    return sum(
        len(value.encode("utf-8"))
        for value in (event.event_id, event.scope, event.event_type, event.data_json)
    )


def _stored_events(database) -> list[tuple[object, ...]]:
    with sqlite3.connect(database) as connection:
        return connection.execute(
            """
            SELECT sequence, event_id, scope, event_type, data_json
            FROM monitor_outbox_events ORDER BY sequence
            """
        ).fetchall()


def test_bounded_append_rejects_full_count_without_modifying_rows(tmp_path) -> None:
    database = tmp_path / "monitor.db"
    outbox = DurableOutbox(database)
    first = _event("bounded-first")
    outbox.append_bounded(first, max_events=1, max_bytes=4096)
    before = _stored_events(database)

    with pytest.raises(OutboxCapacityError):
        outbox.append_bounded(_event("bounded-second"), max_events=1, max_bytes=4096)

    assert _stored_events(database) == before


def test_bounded_append_rejects_full_bytes_without_modifying_rows(tmp_path) -> None:
    database = tmp_path / "monitor.db"
    outbox = DurableOutbox(database)
    first = _event("bounded-first")
    byte_limit = _logical_bytes(first)
    outbox.append_bounded(first, max_events=2, max_bytes=byte_limit)
    before = _stored_events(database)

    with pytest.raises(OutboxCapacityError):
        outbox.append_bounded(_event("bounded-second"), max_events=2, max_bytes=byte_limit)

    assert _stored_events(database) == before


def test_bounded_append_rejects_legacy_oversize_history(tmp_path) -> None:
    database = tmp_path / "monitor.db"
    outbox = DurableOutbox(database)
    outbox.append(_event("legacy-large", data={"message": "x" * (64 * 1024)}))
    before = _stored_events(database)

    with pytest.raises(OutboxCapacityError):
        outbox.append_bounded(_event("bounded-new"), max_events=100, max_bytes=4096)

    assert _stored_events(database) == before


def test_full_capacity_duplicate_returns_sequence_and_conflict_still_rejects(tmp_path) -> None:
    database = tmp_path / "monitor.db"
    outbox = DurableOutbox(database)
    original = _event("bounded-retry")
    capacity_bytes = _logical_bytes(original)
    first = outbox.append_bounded(
        original,
        max_events=1,
        max_bytes=capacity_bytes,
    )

    duplicate = outbox.append_bounded(
        _event("bounded-retry"),
        max_events=1,
        max_bytes=capacity_bytes,
    )
    assert duplicate.sequence == first.sequence
    assert duplicate.event == first.event

    with pytest.raises(OutboxConflictError):
        outbox.append_bounded(
            _event("bounded-retry", data={"decision": "deny"}),
            max_events=1,
            max_bytes=capacity_bytes,
        )
    assert len(_stored_events(database)) == 1


def test_bounded_capacity_is_recomputed_after_reopening_outbox(tmp_path) -> None:
    database = tmp_path / "monitor.db"
    first_event = _event("reopen-first")
    second_event = _event("reopen-second")
    byte_limit = _logical_bytes(first_event) + _logical_bytes(second_event)
    first = DurableOutbox(database).append_bounded(
        first_event,
        max_events=2,
        max_bytes=byte_limit,
    )

    reopened = DurableOutbox(database)
    duplicate = reopened.append_bounded(
        _event("reopen-first"),
        max_events=2,
        max_bytes=byte_limit,
    )
    second = reopened.append_bounded(
        second_event,
        max_events=2,
        max_bytes=byte_limit,
    )
    assert duplicate.sequence == first.sequence
    assert second.sequence > first.sequence

    with pytest.raises(OutboxCapacityError):
        reopened.append_bounded(
            _event("reopen-third"),
            max_events=2,
            max_bytes=byte_limit,
        )
    assert len(_stored_events(database)) == 2


def test_two_outbox_handles_serialize_capacity_check_and_insert(tmp_path) -> None:
    database = tmp_path / "monitor.db"
    first_outbox = DurableOutbox(database)
    second_outbox = DurableOutbox(database)
    start = Barrier(2)

    def append_one(outbox: DurableOutbox, value: OutboxEvent):
        start.wait(timeout=5)
        try:
            return outbox.append_bounded(value, max_events=1, max_bytes=4096)
        except OutboxCapacityError:
            return None

    with ThreadPoolExecutor(max_workers=2) as executor:
        first_future = executor.submit(append_one, first_outbox, _event("race-first"))
        second_future = executor.submit(append_one, second_outbox, _event("race-second"))
        results = (first_future.result(timeout=10), second_future.result(timeout=10))

    inserted = [result for result in results if result is not None]
    rejected = [result for result in results if result is None]
    assert len(inserted) == 1
    assert len(rejected) == 1
    assert type(inserted[0]) is SequencedOutboxEvent
    assert inserted[0].sequence == 1
    assert len(_stored_events(database)) == 1


def test_logical_byte_capacity_counts_utf8_fields_exactly(tmp_path) -> None:
    value = _event(
        "事件-α",
        scope="账户-β",
        event_type="风险.警报",
        data={"instrument": "futures-🧪"},
    )
    exact_bytes = _logical_bytes(value)
    database = tmp_path / "monitor.db"
    stored = DurableOutbox(database).append_bounded(
        value,
        max_events=2,
        max_bytes=exact_bytes,
    )
    assert stored.event == value

    too_small_database = tmp_path / "too-small.db"
    with pytest.raises(OutboxCapacityError):
        DurableOutbox(too_small_database).append_bounded(
            value,
            max_events=2,
            max_bytes=exact_bytes - 1,
        )
    assert _stored_events(too_small_database) == []


@pytest.mark.parametrize(
    ("max_events", "max_bytes"),
    [
        (True, 100),
        (1.0, 100),
        ("2", 100),
        (0, 100),
        (-1, 100),
        (MAX_OUTBOX_CAPACITY_EVENTS + 1, 100),
        (1, False),
        (1, 100.0),
        (1, 0),
        (1, -1),
        (1, MAX_OUTBOX_CAPACITY_BYTES + 1),
    ],
)
def test_capacity_limits_require_bounded_exact_positive_integers(
    tmp_path, monkeypatch, max_events, max_bytes
) -> None:
    outbox = DurableOutbox(tmp_path / "monitor.db")

    def unexpected_transaction():
        raise AssertionError("invalid capacity limits must be rejected before SQLite writes")

    monkeypatch.setattr(outbox, "_transaction", unexpected_transaction)
    with pytest.raises(ValueError):
        outbox.append_bounded(
            _event("invalid-capacity"),
            max_events=max_events,
            max_bytes=max_bytes,
        )


def test_read_only_outbox_rejects_bounded_append(tmp_path) -> None:
    database = tmp_path / "monitor.db"
    writer = DurableOutbox(database)
    original = _event("readonly-original")
    writer.append(original)
    before = _stored_events(database)
    readonly = DurableOutbox(database, read_only=True)

    with pytest.raises(OutboxError, match="cannot perform writes"):
        readonly.append_bounded(
            _event("readonly-new"),
            max_events=10,
            max_bytes=4096,
        )

    assert _stored_events(database) == before


def test_unbounded_append_keeps_its_existing_behavior(tmp_path) -> None:
    outbox = DurableOutbox(tmp_path / "monitor.db")
    first = outbox.append_bounded(_event("bounded-one"), max_events=1, max_bytes=4096)
    second = outbox.append(_event("unbounded-two"))

    assert first.sequence == 1
    assert second.sequence == 2
