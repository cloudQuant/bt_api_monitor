"""Fake-only contracts for authenticated read-only monitor event pages."""

from __future__ import annotations

import hashlib
import json
import multiprocessing
import os
import sqlite3
import time
from contextlib import suppress
from dataclasses import replace
from pathlib import Path

import pytest

import bt_api_monitor
import bt_api_monitor.durable as durable_module
import bt_api_monitor.readonly_events as readonly_module
from bt_api_monitor import (
    MAX_EVENT_READ_PAGE_SIZE,
    DurableOutbox,
    DurableOutboxConsumer,
    EventReadAuthenticationError,
    EventReadCursorError,
    EventReadError,
    EventReadItemV1,
    EventReadPageV1,
    EventReadReplayError,
    OutboxError,
    OutboxEvent,
    ReadOnlyEventService,
    SequencedOutboxEvent,
    sign_event_read_request,
    verify_event_read_page,
)

_KEY = b"local-fake-event-read-key-32-bytes-minimum"


def _event(event_id: str, event_type: str, scope: str = "scope:alpha") -> OutboxEvent:
    return OutboxEvent(
        event_id=event_id,
        scope=scope,
        event_type=event_type,
        data={"decision": "allow", "score": 7},
        occurred_at=1_800_000_000.0,
    )


def _service(
    outbox: DurableOutbox,
    *,
    event_types: str | tuple[str, ...] = "risk.decision",
    scope: str = "scope:alpha",
    initial_cursor: int = 0,
) -> ReadOnlyEventService:
    if not outbox.is_read_only:
        outbox = DurableOutbox(outbox._database_path, read_only=True)
    return ReadOnlyEventService(
        outbox,
        scope,
        event_types,
        generation=4,
        hmac_key=_KEY,
        service_instance_ref="service-instance-0004",
        initial_cursor=initial_cursor,
    )


def _request(
    service: ReadOnlyEventService,
    *,
    after_sequence: int = 0,
    limit: int = 10,
    request_ref: str = "request-reference-0001",
    nonce: str = "nonce-value-00000001",
    scope: str = "scope:alpha",
    event_types: str | tuple[str, ...] = "risk.decision",
    issued_at: float | None = None,
):
    return sign_event_read_request(
        key=_KEY,
        service_instance_ref=service.service_instance_ref,
        generation=service.generation,
        scope=scope,
        event_types=event_types,
        after_sequence=after_sequence,
        limit=limit,
        request_ref=request_ref,
        nonce=nonce,
        issued_at=time.time() if issued_at is None else issued_at,
    )


def _source_facts() -> tuple[tuple[str, ...], tuple[str, ...]]:
    package_root = Path(bt_api_monitor.__file__).resolve().parent
    paths = (
        Path(bt_api_monitor.__file__).resolve(),
        Path(durable_module.__file__).resolve(),
        Path(readonly_module.__file__).resolve(),
        package_root.parent.parent / "pyproject.toml",
    )
    origins = tuple(str(path) for path in paths)
    hashes = tuple(hashlib.sha256(path.read_bytes()).hexdigest() for path in paths)
    return origins, hashes


def _wire(document: dict[str, object]) -> bytes:
    return json.dumps(
        document, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    ).encode("ascii")


def _spawned_read_service(connection, database_path: str, scope: str, service_ref: str) -> None:
    """Open an existing SQLite outbox read-only and serve one authenticated page."""
    try:
        import bt_api_monitor as worker_package
        import bt_api_monitor.durable as worker_durable
        import bt_api_monitor.readonly_events as worker_readonly
        from bt_api_monitor import (
            DurableOutbox as WorkerOutbox,
        )
        from bt_api_monitor import (
            EventReadRequestV1 as WorkerRequest,
        )
        from bt_api_monitor import (
            ReadOnlyEventService as WorkerService,
        )

        origins, hashes = _source_facts_for(
            worker_package, worker_durable, worker_readonly
        )
        outbox = WorkerOutbox(database_path, read_only=True)
        service = WorkerService(
            outbox,
            scope,
            "risk.decision",
            generation=7,
            hmac_key=_KEY,
            service_instance_ref=service_ref,
        )
        connection.send_bytes(
            _wire(
                {
                    "kind": "ready",
                    "pid": os.getpid(),
                    "parent_pid": os.getppid(),
                    "read_only": outbox.is_read_only,
                    "service_instance_ref": service.service_instance_ref,
                    "generation": service.generation,
                    "origins": list(origins),
                    "source_sha256": list(hashes),
                }
            )
        )
        raw = connection.recv_bytes(1024 * 1024)
        request_document = json.loads(raw.decode("ascii"))
        request_document["event_types"] = tuple(request_document["event_types"])
        request_document["signature"] = bytes.fromhex(request_document["signature_hex"])
        del request_document["signature_hex"]
        page = service.read_page(WorkerRequest(**request_document))
        connection.send_bytes(
            _wire(
                {
                    "kind": "page",
                    "service_instance_ref": page.service_instance_ref,
                    "generation": page.generation,
                    "scope": page.scope,
                    "event_types": list(page.event_types),
                    "request_ref": page.request_ref,
                    "nonce": page.nonce,
                    "issued_at": page.issued_at,
                    "after_sequence": page.after_sequence,
                    "limit": page.limit,
                    "cursor": page.cursor,
                    "has_more": page.has_more,
                    "observed_at": page.observed_at,
                    "events": [
                        {
                            "sequence": item.sequence,
                            "event_id": item.event_id,
                            "event_type": item.event_type,
                            "data": dict(item.data),
                            "occurred_at": item.occurred_at,
                        }
                        for item in page.events
                    ],
                    "signature_hex": page.signature.hex(),
                }
            )
        )
        close_document = json.loads(connection.recv_bytes(1024 * 1024).decode("ascii"))
        if close_document != {"kind": "close"}:
            raise ValueError("invalid close request")
        connection.send_bytes(_wire({"kind": "closed", "pid": os.getpid()}))
    except Exception:
        with suppress(Exception):
            connection.send_bytes(_wire({"kind": "error"}))
        raise
    finally:
        connection.close()


def _source_facts_for(package, durable, readonly):
    package_root = Path(package.__file__).resolve().parent
    paths = (
        Path(package.__file__).resolve(),
        Path(durable.__file__).resolve(),
        Path(readonly.__file__).resolve(),
        package_root.parent.parent / "pyproject.toml",
    )
    return (
        tuple(str(path) for path in paths),
        tuple(hashlib.sha256(path.read_bytes()).hexdigest() for path in paths),
    )


def _decode_page(document: dict[str, object]) -> EventReadPageV1:
    if document.get("kind") != "page":
        raise AssertionError("worker did not return an event page")
    events = tuple(
        EventReadItemV1(
            sequence=item["sequence"],
            event_id=item["event_id"],
            event_type=item["event_type"],
            data=item["data"],
            occurred_at=item["occurred_at"],
        )
        for item in document["events"]
    )
    return EventReadPageV1(
        service_instance_ref=document["service_instance_ref"],
        generation=document["generation"],
        scope=document["scope"],
        event_types=tuple(document["event_types"]),
        request_ref=document["request_ref"],
        nonce=document["nonce"],
        issued_at=document["issued_at"],
        after_sequence=document["after_sequence"],
        limit=document["limit"],
        cursor=document["cursor"],
        has_more=document["has_more"],
        observed_at=document["observed_at"],
        events=events,
        signature=bytes.fromhex(document["signature_hex"]),
    )


def test_signed_pages_progress_across_types_without_checkpoint_writes(tmp_path, monkeypatch) -> None:
    outbox = DurableOutbox(tmp_path / "monitor.db")
    first = outbox.append(_event("event-1", "risk.decision"))
    outbox.append(_event("event-2", "risk.other"))
    third = outbox.append(_event("event-3", "risk.alert"))
    fourth = outbox.append(_event("event-4", "risk.decision"))
    outbox.acknowledge("existing-consumer", "scope:alpha", first.sequence)
    checkpoint_before = outbox.checkpoint("existing-consumer", "scope:alpha")

    def unexpected_checkpoint_path(*_args, **_kwargs):
        raise AssertionError("read-only service must not use consumer delivery methods")

    read_only_outbox = DurableOutbox(outbox._database_path, read_only=True)
    monkeypatch.setattr(read_only_outbox, "read_pending", unexpected_checkpoint_path)
    monkeypatch.setattr(read_only_outbox, "acknowledge", unexpected_checkpoint_path)
    service = _service(read_only_outbox, event_types=("risk.alert", "risk.decision"))

    request1 = _request(
        service,
        limit=1,
        event_types=("risk.decision", "risk.alert"),
        request_ref="request-reference-0001",
        nonce="nonce-value-00000001",
    )
    same_request = _request(
        service,
        limit=1,
        event_types=("risk.alert", "risk.decision"),
        request_ref="request-reference-0001",
        nonce="nonce-value-00000001",
        issued_at=request1.issued_at,
    )
    assert request1.signature == same_request.signature
    page1 = service.read_page(request1)
    assert verify_event_read_page(request1, page1, key=_KEY)
    assert [item.event_id for item in page1.events] == ["event-1"]
    assert page1.cursor == first.sequence
    assert page1.has_more is True

    request2 = _request(
        service,
        after_sequence=page1.cursor,
        limit=1,
        request_ref="request-reference-0002",
        nonce="nonce-value-00000002",
        event_types=("risk.decision", "risk.alert"),
    )
    page2 = service.read_page(request2)
    assert verify_event_read_page(request2, page2, key=_KEY)
    assert [item.event_id for item in page2.events] == ["event-3"]
    assert page2.cursor == third.sequence
    assert page2.has_more is True

    request3 = _request(
        service,
        after_sequence=page2.cursor,
        limit=1,
        request_ref="request-reference-0003",
        nonce="nonce-value-00000003",
        event_types=("risk.alert", "risk.decision"),
    )
    page3 = service.read_page(request3)
    assert verify_event_read_page(request3, page3, key=_KEY)
    assert [item.event_id for item in page3.events] == ["event-4"]
    assert page3.cursor == fourth.sequence
    assert page3.has_more is False
    assert outbox.checkpoint("existing-consumer", "scope:alpha") == checkpoint_before
    assert not hasattr(service, "append")
    assert not hasattr(service, "acknowledge")


def test_service_rejects_reused_request_and_nonce(tmp_path) -> None:
    outbox = DurableOutbox(tmp_path / "monitor.db")
    outbox.append(_event("event-1", "risk.decision"))
    service = _service(outbox)
    request = _request(service)
    page = service.read_page(request)
    assert page.cursor == 1
    with pytest.raises(EventReadReplayError):
        service.read_page(request)

    reused_nonce = _request(
        service,
        after_sequence=1,
        request_ref="request-reference-0002",
        nonce=request.nonce,
    )
    with pytest.raises(EventReadReplayError):
        service.read_page(reused_nonce)


@pytest.mark.parametrize(
    ("scope", "event_types"),
    [
        ("scope:other", "risk.decision"),
        ("scope:alpha", "risk.alert"),
    ],
)
def test_service_rejects_signed_cross_scope_or_event_type_request(
    tmp_path, scope, event_types
) -> None:
    service = _service(DurableOutbox(tmp_path / "monitor.db"))
    request = _request(
        service,
        scope=scope,
        event_types=event_types,
        request_ref="request-reference-0009",
        nonce="nonce-value-00000009",
    )
    with pytest.raises(EventReadAuthenticationError):
        service.read_page(request)


def test_request_and_response_tampering_fails_authentication(tmp_path) -> None:
    outbox = DurableOutbox(tmp_path / "monitor.db")
    outbox.append(_event("event-1", "risk.decision"))
    service = _service(outbox)
    request = _request(service)
    with pytest.raises(EventReadError):
        replace(request, signature=b"short")
    damaged_request = replace(request, signature=b"x" * 32)
    with pytest.raises(EventReadAuthenticationError):
        service.read_page(damaged_request)

    page = service.read_page(request)
    changed_event = replace(page.events[0], data={"decision": "deny", "score": 7})
    damaged_page = replace(page, events=(changed_event,))
    with pytest.raises(EventReadAuthenticationError):
        verify_event_read_page(request, damaged_page, key=_KEY)


def test_service_rejects_cursor_regression_and_ahead_requests(tmp_path) -> None:
    outbox = DurableOutbox(tmp_path / "monitor.db")
    outbox.append(_event("event-1", "risk.decision"))
    service = _service(outbox)
    first = service.read_page(_request(service))
    assert first.cursor == 1

    regressed = _request(
        service,
        after_sequence=0,
        request_ref="request-reference-0002",
        nonce="nonce-value-00000002",
    )
    with pytest.raises(EventReadCursorError):
        service.read_page(regressed)
    ahead = _request(
        service,
        after_sequence=2,
        request_ref="request-reference-0003",
        nonce="nonce-value-00000003",
    )
    with pytest.raises(EventReadCursorError):
        service.read_page(ahead)


def test_multi_type_page_uses_one_read_when_events_arrive_between_legacy_queries(
    tmp_path, monkeypatch
) -> None:
    path = tmp_path / "monitor.db"
    writer = DurableOutbox(path)
    outbox = DurableOutbox(path, read_only=True)
    event_types = ("risk.alert", "risk.decision")
    service = _service(outbox, event_types=event_types)
    actual_read = outbox.read_page_types
    typed_reads = []

    def single_snapshot_read(scope, requested_types, after_sequence, limit):
        typed_reads.append((scope, requested_types, after_sequence, limit))
        # This models the exact gap after the old risk.alert query returned
        # empty and before its separate risk.decision query began.
        writer.append(_event("alert-1", "risk.alert"))
        writer.append(_event("decision-2", "risk.decision"))
        return actual_read(scope, requested_types, after_sequence, limit)

    monkeypatch.setattr(outbox, "read_page_types", single_snapshot_read)
    monkeypatch.setattr(
        outbox,
        "read_page",
        lambda *_args, **_kwargs: pytest.fail("service must use one multi-type SQLite read"),
    )

    page = service.read_page(_request(service, event_types=event_types))
    assert len(typed_reads) == 1
    assert [item.sequence for item in page.events] == [1, 2]
    assert [item.event_type for item in page.events] == list(event_types)
    assert page.cursor == 2
    assert page.has_more is False

    next_page = service.read_page(
        _request(
            service,
            event_types=event_types,
            after_sequence=page.cursor,
            request_ref="request-reference-0002",
            nonce="nonce-value-00000002",
        )
    )
    assert next_page.events == ()
    assert next_page.cursor == 2


@pytest.mark.parametrize("limit", [0, MAX_EVENT_READ_PAGE_SIZE + 1])
def test_request_page_size_is_bounded_before_storage(tmp_path, limit) -> None:
    service = _service(DurableOutbox(tmp_path / "monitor.db"))
    with pytest.raises(EventReadError):
        _request(service, limit=limit)


def test_malformed_outbox_rows_fail_closed_without_advancing_cursor(tmp_path, monkeypatch) -> None:
    path = tmp_path / "monitor.db"
    DurableOutbox(path)
    outbox = DurableOutbox(path, read_only=True)
    service = _service(outbox)
    malformed_event = _event("bad-row", "risk.decision", scope="scope:other")
    malformed = SequencedOutboxEvent(sequence=1, event=malformed_event)
    monkeypatch.setattr(
        outbox,
        "read_page_types",
        lambda _scope, _event_types, _after, _limit: ([malformed], False),
    )
    with pytest.raises(EventReadError):
        service.read_page(_request(service))

    monkeypatch.setattr(
        outbox,
        "read_page_types",
        lambda _scope, _event_types, _after, _limit: ([], 1),
    )
    next_request = _request(
        service,
        request_ref="request-reference-0002",
        nonce="nonce-value-00000002",
    )
    with pytest.raises(EventReadError):
        service.read_page(next_request)

    malformed_data_event = _event("bad-data", "risk.decision")
    object.__setattr__(malformed_data_event, "data", {"api_token": "redacted-in-test"})
    malformed_data = SequencedOutboxEvent(sequence=1, event=malformed_data_event)
    monkeypatch.setattr(
        outbox,
        "read_page_types",
        lambda _scope, _event_types, _after, _limit: ([malformed_data], False),
    )
    invalid_content_request = _request(
        service,
        request_ref="request-reference-0003",
        nonce="nonce-value-00000003",
    )
    with pytest.raises(EventReadError):
        service.read_page(invalid_content_request)


def test_key_and_signatures_are_hidden_from_repr_and_service_has_no_write_api(tmp_path) -> None:
    service = _service(DurableOutbox(tmp_path / "monitor.db"))
    request = _request(service)
    page = service.read_page(request)
    rendered = repr(service) + repr(request) + repr(page)
    assert _KEY.decode("ascii") not in rendered
    assert repr(request.signature) not in rendered
    assert repr(page.signature) not in rendered
    assert not hasattr(service, "append")
    assert not hasattr(service, "acknowledge")
    assert not hasattr(service, "write_event")


@pytest.mark.parametrize(
    "secret_name",
    ["apiKey", "API_KEY", "api-key", "xApiKeyHash", "nested.api_key", "PassPhrase"],
)
def test_outbox_rejects_secret_keys_after_case_separator_and_nesting_normalization(
    secret_name,
) -> None:
    parts = secret_name.split(".")
    data = {parts[-1]: "synthetic-secret"}
    for name in reversed(parts[:-1]):
        data = {name: data}
    with pytest.raises(ValueError, match="must be redacted"):
        OutboxEvent(
            event_id="event-secret-test",
            scope="scope:alpha",
            event_type="risk.decision",
            data=data,
            occurred_at=1_800_000_000.0,
        )


def test_redaction_preserves_order_key_and_reference_metadata(tmp_path) -> None:
    outbox = DurableOutbox(tmp_path / "monitor.db")
    outbox.append(
        OutboxEvent(
            event_id="event-order-metadata-0001",
            scope="scope:alpha",
            event_type="risk.decision",
            data={"order_key": "order-17", "orderKeyRef": "opaque-order-ref-0001"},
            occurred_at=1_800_000_000.0,
        )
    )
    service = _service(outbox)
    page = service.read_page(_request(service))
    assert dict(page.events[0].data) == {
        "order_key": "order-17",
        "orderKeyRef": "opaque-order-ref-0001",
    }


def test_readonly_outbox_does_not_initialize_or_allow_mutation(tmp_path, monkeypatch) -> None:
    path = tmp_path / "monitor.db"
    with pytest.raises(OutboxError):
        DurableOutbox(path, read_only=True)
    assert not path.exists()

    writer = DurableOutbox(path)
    writer.append(_event("event-readonly-0001", "risk.decision"))

    def unexpected_schema_init(*_args, **_kwargs):
        raise AssertionError("read-only open must not initialize the SQLite schema")

    monkeypatch.setattr(DurableOutbox, "_initialize_schema", unexpected_schema_init)
    readonly = DurableOutbox(path, read_only=True)
    assert readonly.is_read_only is True
    with pytest.raises(OutboxError, match="cannot perform writes"):
        readonly.append(_event("event-readonly-0002", "risk.decision"))
    with pytest.raises(OutboxError, match="cannot perform writes"):
        readonly.acknowledge("consumer", "scope:alpha", 1)
    with pytest.raises(ValueError, match="requires a writable"):
        DurableOutboxConsumer(readonly, "consumer", "scope:alpha", lambda _event: None)
    with readonly._connection() as connection:
        assert connection.execute("PRAGMA query_only").fetchone()[0] == 1
        with pytest.raises(sqlite3.OperationalError, match="readonly"):
            connection.execute(
                "INSERT INTO monitor_consumer_checkpoints VALUES (?, ?, ?, ?)",
                ("consumer", "scope:alpha", 1, time.time()),
            )


def test_service_requires_readonly_outbox(tmp_path) -> None:
    with pytest.raises(EventReadError, match="read-only DurableOutbox"):
        ReadOnlyEventService(
            DurableOutbox(tmp_path / "monitor.db"),
            "scope:alpha",
            "risk.decision",
            generation=4,
            hmac_key=_KEY,
        )


def test_spawned_readonly_service_authenticates_local_page_and_exits_cleanly(tmp_path) -> None:
    database_path = tmp_path / "monitor.db"
    writer = DurableOutbox(database_path)
    first = writer.append(
        OutboxEvent(
            event_id="event-process-page-0001",
            scope="scope:process",
            event_type="risk.decision",
            data={"decision": "allow", "order_key": "order-21"},
            occurred_at=1_800_000_000.0,
        )
    )
    writer.acknowledge("existing-consumer", "scope:process", first.sequence)
    checkpoint_before = writer.checkpoint("existing-consumer", "scope:process")
    with writer._connection() as connection:
        rows_before = connection.execute(
            "SELECT sequence, event_id, scope, event_type, data_json, occurred_at "
            "FROM monitor_outbox_events ORDER BY sequence"
        ).fetchall()
        checkpoints_before = connection.execute(
            "SELECT consumer_id, scope, sequence, updated_at "
            "FROM monitor_consumer_checkpoints ORDER BY consumer_id, scope"
        ).fetchall()

    context = multiprocessing.get_context("spawn")
    parent, child = context.Pipe(duplex=True)
    service_ref = "service-process-instance-0007"
    process = context.Process(
        target=_spawned_read_service,
        args=(child, str(database_path), "scope:process", service_ref),
        daemon=False,
    )
    process.start()
    child.close()
    close_ack = None
    try:
        assert parent.poll(5.0), "monitor process did not send its source handshake"
        ready = json.loads(parent.recv_bytes(1024 * 1024).decode("ascii"))
        expected_origins, expected_hashes = _source_facts()
        assert ready == {
            "kind": "ready",
            "pid": process.pid,
            "parent_pid": os.getpid(),
            "read_only": True,
            "service_instance_ref": service_ref,
            "generation": 7,
            "origins": list(expected_origins),
            "source_sha256": list(expected_hashes),
        }
        assert ready["pid"] != ready["parent_pid"]

        request = sign_event_read_request(
            key=_KEY,
            service_instance_ref=service_ref,
            generation=7,
            scope="scope:process",
            event_types="risk.decision",
            after_sequence=0,
            limit=4,
            request_ref="request-process-page-0001",
            nonce="nonce-process-page-0001",
            issued_at=time.time(),
        )
        parent.send_bytes(
            _wire(
                {
                    "service_instance_ref": request.service_instance_ref,
                    "generation": request.generation,
                    "scope": request.scope,
                    "event_types": list(request.event_types),
                    "after_sequence": request.after_sequence,
                    "limit": request.limit,
                    "request_ref": request.request_ref,
                    "nonce": request.nonce,
                    "issued_at": request.issued_at,
                    "signature_hex": request.signature.hex(),
                }
            )
        )
        assert parent.poll(5.0), "monitor process did not return an event page"
        page_document = json.loads(parent.recv_bytes(1024 * 1024).decode("ascii"))
        assert page_document.get("kind") == "page", page_document
        page = _decode_page(page_document)
        assert verify_event_read_page(request, page, key=_KEY)
        assert [item.event_id for item in page.events] == ["event-process-page-0001"]
        assert [item.sequence for item in page.events] == [first.sequence]
        assert page.cursor == first.sequence and page.has_more is False

        parent.send_bytes(_wire({"kind": "close"}))
        assert parent.poll(5.0), "monitor process did not acknowledge close"
        close_ack = json.loads(parent.recv_bytes(1024 * 1024).decode("ascii"))
        assert close_ack == {"kind": "closed", "pid": process.pid}
        process.join(timeout=5.0)
        assert not process.is_alive()
        assert process.exitcode == 0
        assert writer.checkpoint("existing-consumer", "scope:process") == checkpoint_before
        with writer._connection() as connection:
            rows_after = connection.execute(
                "SELECT sequence, event_id, scope, event_type, data_json, occurred_at "
                "FROM monitor_outbox_events ORDER BY sequence"
            ).fetchall()
            checkpoints_after = connection.execute(
                "SELECT consumer_id, scope, sequence, updated_at "
                "FROM monitor_consumer_checkpoints ORDER BY consumer_id, scope"
            ).fetchall()
        assert [tuple(row) for row in rows_after] == [tuple(row) for row in rows_before]
        assert [tuple(row) for row in checkpoints_after] == [
            tuple(row) for row in checkpoints_before
        ]
    finally:
        if process.is_alive():
            process.terminate()
            process.join(timeout=2.0)
        if process.exitcode is not None:
            with suppress(ValueError):
                process.close()
        parent.close()
