"""Focused service-owned durable event ingress tests."""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path

import pytest
from bt_api_base.service_protocol import WireIdentity, WireRole, WireScope

from bt_api_monitor.durable import DurableOutbox
from bt_api_monitor.service_component import MonitorReadTarget
from bt_api_monitor.service_ingress import (
    DEFAULT_INGRESS_MAX_BYTES,
    DEFAULT_INGRESS_MAX_EVENT_BYTES,
    DEFAULT_INGRESS_MAX_EVENTS,
    MONITOR_INGRESS_OPERATIONS,
    MonitorIngressService,
    MonitorIngressServiceError,
    MonitorIngressTarget,
    validate_service_options,
)


def _scope(
    *,
    account_ref: str = "account-a",
    strategy_ref: str = "strategy-a",
    run_id: str | None = None,
) -> WireScope:
    return WireScope(
        execution_domain_ref="paper:demo",
        account_ref=account_ref,
        strategy_ref=strategy_ref,
        run_id=run_id,
    )


def _identity(
    *,
    principal_ref: str = "service:monitor-producer",
    actor_ref: str = "producer-a",
    role: WireRole = WireRole.SERVICE,
) -> WireIdentity:
    return WireIdentity(
        role=role,
        principal_ref=principal_ref,
        actor_ref=actor_ref,
        delegate_ref="delegate-a",
    )


def _target() -> MonitorIngressTarget:
    return MonitorReadTarget(
        outbox_scope="monitor:strategy-a",
        event_types=("order.status", "risk.alert"),
    )


def _service(
    path: Path,
    *,
    max_events: int = DEFAULT_INGRESS_MAX_EVENTS,
    max_bytes: int = DEFAULT_INGRESS_MAX_BYTES,
    max_event_bytes: int = DEFAULT_INGRESS_MAX_EVENT_BYTES,
) -> tuple[DurableOutbox, MonitorIngressService]:
    outbox = DurableOutbox(path)
    service = MonitorIngressService(
        outbox,
        {_scope(): _target()},
        max_events=max_events,
        max_bytes=max_bytes,
        max_event_bytes=max_event_bytes,
    )
    return outbox, service


def _arguments(
    *,
    event_id: str = "source-event-1",
    event_type: str = "order.status",
    occurred_at: int | float = 1_800_000_000,
    data: Mapping[str, object] | None = None,
) -> dict[str, object]:
    return {
        "schema_version": 1,
        "event_id": event_id,
        "event_type": event_type,
        "occurred_at": occurred_at,
        "data": {"status": "accepted"} if data is None else data,
    }


def _handle(
    service: MonitorIngressService,
    arguments: Mapping[str, object],
    *,
    identity: WireIdentity | None = None,
    scope: WireScope | None = None,
    principal_ref: str = "service:monitor-producer",
    operation: str = "events.append",
) -> Mapping[str, object]:
    return service.handle(
        operation,
        principal_ref=principal_ref,
        identity=_identity() if identity is None else identity,
        scope=_scope() if scope is None else scope,
        arguments=arguments,
    )


def _assert_error(code: str, call) -> None:
    with pytest.raises(MonitorIngressServiceError) as captured:
        call()
    assert captured.value.code == code


def test_service_append_persists_trusted_identity_and_is_idempotent(tmp_path: Path) -> None:
    outbox, service = _service(tmp_path / "ingress.sqlite")
    args = _arguments(data={"status": "accepted", "attempt": 2})

    first = _handle(service, args)
    retry = _handle(service, args)

    assert frozenset({"events.append"}) == MONITOR_INGRESS_OPERATIONS
    assert set(first) == {"event_id", "source_event_id", "sequence"}
    assert first == retry
    assert first["source_event_id"] == "source-event-1"
    assert first["sequence"] == 1
    rows, has_more = outbox.read_page_types(
        "monitor:strategy-a", ("order.status", "risk.alert"), 0, 10
    )
    assert not has_more
    assert len(rows) == 1
    assert rows[0].event.event_id == first["event_id"]
    assert rows[0].event.data == {
        "producer": {
            "role": "service",
            "principal_ref": "service:monitor-producer",
            "actor_ref": "producer-a",
            "delegate_ref": "delegate-a",
        },
        "source_event_id": "source-event-1",
        "payload": {"status": "accepted", "attempt": 2},
    }
    assert not hasattr(service, "close")
    with pytest.raises(TypeError):
        first["sequence"] = 3  # type: ignore[index]


def test_event_identity_excludes_run_but_binds_full_producer_identity(tmp_path: Path) -> None:
    outbox, service = _service(tmp_path / "identity.sqlite")
    args = _arguments()

    base = _handle(service, args)
    same_run_independent = _handle(service, args, scope=_scope(run_id="run-2"))
    second_producer = _handle(
        service,
        args,
        identity=_identity(actor_ref="producer-b"),
    )

    assert same_run_independent == base
    assert second_producer["event_id"] != base["event_id"]
    assert second_producer["sequence"] == 2
    rows, _ = outbox.read_page_types("monitor:strategy-a", ("order.status", "risk.alert"), 0, 10)
    assert len(rows) == 2
    assert rows[0].event.data["payload"] == rows[1].event.data["payload"]


def test_options_are_immutable_and_durable_role_is_explicit(tmp_path: Path) -> None:
    options = validate_service_options(
        {"role": "durable_ingress", "max_events": 12, "max_bytes": 131072},
        ("service.telemetry_ingress",),
    )
    assert dict(options) == {
        "role": "durable_ingress",
        "max_events": 12,
        "max_bytes": 131072,
        "max_event_bytes": DEFAULT_INGRESS_MAX_EVENT_BYTES,
    }
    with pytest.raises(TypeError):
        options["max_events"] = 5  # type: ignore[index]
    _assert_error(
        "UNSUPPORTED_SERVICE_OPTIONS",
        lambda: validate_service_options({}, ("service.telemetry_ingress",)),
    )
    _assert_error(
        "INVALID_BIND_PORTS",
        lambda: validate_service_options(
            {"role": "durable_ingress"}, ("service.telemetry_ingress", "service.monitor_query")
        ),
    )
    _assert_error(
        "UNSUPPORTED_SERVICE_OPTIONS",
        lambda: validate_service_options(
            {"role": "durable_ingress", "bind": "service.telemetry_ingress"},
            ("service.telemetry_ingress",),
        ),
    )
    _assert_error(
        "INVALID_LIMITS",
        lambda: validate_service_options(
            {"role": "durable_ingress", "max_events": True},
            ("service.telemetry_ingress",),
        ),
    )


@pytest.mark.parametrize(
    ("arguments", "code"),
    [
        ({**_arguments(), "schema_version": True}, "UNSUPPORTED_SCHEMA_VERSION"),
        ({**_arguments(), "producer": {"principal_ref": "client-controlled"}}, "UNKNOWN_ARGUMENT"),
        (
            {key: value for key, value in _arguments().items() if key != "event_id"},
            "MISSING_ARGUMENT",
        ),
        (_arguments(event_id="bad id "), "INVALID_EVENT_ID"),
        (_arguments(event_id="x" * 257), "INVALID_EVENT_ID"),
        (_arguments(event_type="unapproved.event"), "EVENT_TYPE_NOT_GRANTED"),
        (_arguments(occurred_at=float("nan")), "INVALID_EVENT_TIME"),
        (_arguments(occurred_at=True), "INVALID_EVENT_TIME"),
        (_arguments(data={"api_token": "private"}), "EVENT_DATA_INVALID"),
    ],
)
def test_invalid_requests_are_rejected_before_persistence(
    tmp_path: Path, arguments: Mapping[str, object], code: str
) -> None:
    outbox, service = _service(tmp_path / f"invalid-{code}.sqlite")

    _assert_error(code, lambda: _handle(service, arguments))

    rows, _ = outbox.read_page_types("monitor:strategy-a", ("order.status", "risk.alert"), 0, 10)
    assert rows == []


def test_request_size_depth_and_node_limits_are_enforced(tmp_path: Path) -> None:
    outbox, service = _service(
        tmp_path / "bounds.sqlite", max_events=10, max_bytes=4096, max_event_bytes=256
    )
    _assert_error(
        "EVENT_TOO_LARGE",
        lambda: _handle(service, _arguments(data={"description": "é" * 200})),
    )

    deep: dict[str, object] = {}
    current = deep
    for _ in range(40):
        nested: dict[str, object] = {}
        current["child"] = nested
        current = nested
    _assert_error("INVALID_EVENT_DATA", lambda: _handle(service, _arguments(data=deep)))

    _assert_error(
        "INVALID_EVENT_DATA",
        lambda: _handle(service, _arguments(data={f"key-{index}": index for index in range(3000)})),
    )
    rows, _ = outbox.read_page_types("monitor:strategy-a", ("order.status", "risk.alert"), 0, 10)
    assert rows == []


def test_identity_scope_and_operation_are_bound_before_append(tmp_path: Path) -> None:
    outbox, service = _service(tmp_path / "auth.sqlite")

    _assert_error(
        "IDENTITY_MISMATCH",
        lambda: _handle(service, _arguments(), principal_ref="service:other"),
    )
    _assert_error(
        "SERVICE_ROLE_REQUIRED",
        lambda: _handle(
            service,
            _arguments(),
            identity=_identity(role=WireRole.STRATEGY_CLIENT),
        ),
    )
    _assert_error(
        "SCOPE_NOT_GRANTED",
        lambda: _handle(service, _arguments(), scope=_scope(account_ref="account-b")),
    )
    _assert_error(
        "UNSUPPORTED_OPERATION",
        lambda: _handle(service, _arguments(), operation="telemetry.append"),
    )

    rows, _ = outbox.read_page_types("monitor:strategy-a", ("order.status", "risk.alert"), 0, 10)
    assert rows == []


def test_capacity_rejects_new_events_but_allows_exact_full_outbox_retry(
    tmp_path: Path,
) -> None:
    outbox, service = _service(tmp_path / "capacity.sqlite", max_events=1)
    args = _arguments()
    original = _handle(service, args)

    assert _handle(service, args) == original
    _assert_error(
        "OUTBOX_CAPACITY",
        lambda: _handle(service, _arguments(event_id="source-event-2")),
    )
    _assert_error(
        "EVENT_ID_CONFLICT",
        lambda: _handle(service, _arguments(data={"status": "different"})),
    )

    rows, _ = outbox.read_page_types("monitor:strategy-a", ("order.status", "risk.alert"), 0, 10)
    assert len(rows) == 1


def test_service_requires_a_borrowed_writable_outbox(tmp_path: Path) -> None:
    path = tmp_path / "readonly.sqlite"
    DurableOutbox(path)
    readonly = DurableOutbox(path, read_only=True)

    with pytest.raises(MonitorIngressServiceError) as captured:
        MonitorIngressService(readonly, {_scope(): _target()})
    assert captured.value.code == "WRITABLE_OUTBOX_REQUIRED"
