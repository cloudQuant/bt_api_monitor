"""Focused tests for bounded, in-memory Monitor telemetry service ingress."""

from __future__ import annotations

from collections.abc import Mapping

import pytest
from bt_api_base.service_protocol import WireIdentity, WireRole, WireScope
from bt_api_base.telemetry_protocol import TelemetrySample

from bt_api_monitor.service_telemetry import (
    DEFAULT_HEARTBEAT_TIMEOUT_SECONDS,
    DEFAULT_TELEMETRY_MAX_BYTES,
    DEFAULT_TELEMETRY_MAX_STREAMS,
    DEFAULT_TELEMETRY_RETENTION_SECONDS,
    TELEMETRY_OPERATIONS,
    MonitorTelemetryService,
    MonitorTelemetryServiceError,
    validate_service_options,
)


class FakeClock:
    def __init__(self, value: float = 100.0) -> None:
        self.value = value

    def __call__(self) -> float:
        return self.value


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
    principal_ref: str = "strategy:demo",
    actor_ref: str = "strategy-a",
    role: WireRole = WireRole.STRATEGY_CLIENT,
) -> WireIdentity:
    return WireIdentity(
        role=role,
        principal_ref=principal_ref,
        actor_ref=actor_ref,
        delegate_ref="delegated-by-a",
    )


def _sample(
    *,
    stream_id: str = "stream-a",
    sequence: int = 1,
    kind: str = "heartbeat",
    observed_at: int | float = 1_800_000_000,
    metrics: Mapping[str, int | float] | None = None,
) -> dict[str, object]:
    return TelemetrySample(
        stream_id=stream_id,
        sequence=sequence,
        kind=kind,
        observed_at=observed_at,
        metrics={} if kind == "heartbeat" else {"cpu.load": 0.25} if metrics is None else metrics,
        dropped_queue_total=0,
        dropped_delivery_total=0,
    ).to_dict()


def _service(
    clock: FakeClock,
    *,
    targets: frozenset[WireScope] | None = None,
    max_streams: int = DEFAULT_TELEMETRY_MAX_STREAMS,
    max_bytes: int = DEFAULT_TELEMETRY_MAX_BYTES,
    heartbeat_timeout_seconds: int | float = DEFAULT_HEARTBEAT_TIMEOUT_SECONDS,
    retention_seconds: int | float = DEFAULT_TELEMETRY_RETENTION_SECONDS,
) -> MonitorTelemetryService:
    return MonitorTelemetryService(
        frozenset({_scope()}) if targets is None else targets,
        max_streams=max_streams,
        max_bytes=max_bytes,
        heartbeat_timeout_seconds=heartbeat_timeout_seconds,
        retention_seconds=retention_seconds,
        clock=clock,
    )


def _handle(
    service: MonitorTelemetryService,
    operation: str,
    arguments: Mapping[str, object],
    *,
    identity: WireIdentity | None = None,
    scope: WireScope | None = None,
    principal_ref: str | None = None,
    result_fits=None,
) -> Mapping[str, object]:
    caller = _identity() if identity is None else identity
    return service.handle(
        operation,
        principal_ref=caller.principal_ref if principal_ref is None else principal_ref,
        identity=caller,
        scope=_scope() if scope is None else scope,
        arguments=arguments,
        result_fits=result_fits,
    )


def _assert_error(code: str, call) -> None:
    with pytest.raises(MonitorTelemetryServiceError) as captured:
        call()
    assert captured.value.code == code


def test_append_and_snapshot_keep_latest_metrics_and_heartbeat() -> None:
    clock = FakeClock(100.0)
    service = _service(clock)
    strategy = _identity()
    app = _identity(
        principal_ref="application:monitor",
        actor_ref="dashboard-a",
        role=WireRole.APPLICATION_CLIENT,
    )
    run_scope = _scope(run_id="run-a")

    reply = _handle(
        service,
        "telemetry.append",
        _sample(stream_id="worker-a"),
        identity=strategy,
        scope=run_scope,
    )
    assert reply == {"stream_id": "worker-a", "sequence": 1, "accepted": True}
    clock.value = 102.0
    _handle(
        service,
        "telemetry.append",
        _sample(
            stream_id="worker-a",
            sequence=2,
            kind="metrics",
            metrics={"cpu.load": 0.75, "orders.open": 2},
        ),
        identity=strategy,
        scope=run_scope,
    )

    snapshot = _handle(service, "telemetry.snapshot", {}, identity=app)

    assert snapshot["state"] == "collected"
    assert len(snapshot["streams"]) == 1
    stream = snapshot["streams"][0]
    assert stream["producer"] == {
        "role": "strategy_client",
        "principal_ref": "strategy:demo",
        "actor_ref": "strategy-a",
        "delegate_ref": "delegated-by-a",
    }
    assert stream["scope"]["run_id"] == "run-a"
    assert stream["stream_id"] == "worker-a"
    assert stream["sequence"] == 2
    assert stream["status"] == "fresh"
    assert stream["heartbeat"]["sequence"] == 1
    assert stream["heartbeat_age_seconds"] == 2.0
    assert stream["metrics"]["sequence"] == 2
    assert stream["metrics"]["metrics"] == {"cpu.load": 0.75, "orders.open": 2}
    assert stream["metrics_age_seconds"] == 0.0
    assert stream["received_age_seconds"] == 0.0

    stream["metrics"]["metrics"]["cpu.load"] = 100.0
    reread = _handle(service, "telemetry.snapshot", {}, identity=app)
    assert reread["streams"][0]["metrics"]["metrics"]["cpu.load"] == 0.75


def test_empty_or_metric_only_snapshot_is_not_collected_without_heartbeat() -> None:
    clock = FakeClock()
    service = _service(clock)
    app = _identity(
        principal_ref="application:monitor",
        actor_ref="dashboard-a",
        role=WireRole.APPLICATION_CLIENT,
    )

    empty = _handle(service, "telemetry.snapshot", {}, identity=app)
    assert empty == {"state": "not_collected", "streams": []}

    _handle(
        service,
        "telemetry.append",
        _sample(kind="metrics", metrics={"latency.ms": 12.0}),
    )
    metrics_only = _handle(service, "telemetry.snapshot", {}, identity=app)
    row = metrics_only["streams"][0]
    assert metrics_only["state"] == "collected"
    assert row["status"] == "not_collected"
    assert row["heartbeat"] is None
    assert row["heartbeat_age_seconds"] is None
    assert row["metrics"]["metrics"] == {"latency.ms": 12.0}


def test_duplicate_does_not_extend_heartbeat_freshness_and_conflicts_are_rejected() -> None:
    clock = FakeClock(0.0)
    service = _service(clock, heartbeat_timeout_seconds=30)
    app = _identity(
        principal_ref="application:monitor",
        actor_ref="dashboard-a",
        role=WireRole.APPLICATION_CLIENT,
    )
    heartbeat = _sample()
    _handle(service, "telemetry.append", heartbeat)

    clock.value = 20.0
    assert _handle(service, "telemetry.append", heartbeat)["accepted"] is True
    fresh = _handle(service, "telemetry.snapshot", {}, identity=app)
    assert fresh["streams"][0]["heartbeat_age_seconds"] == 20.0
    assert fresh["streams"][0]["status"] == "fresh"

    divergent = _sample(sequence=1)
    divergent["dropped_delivery_total"] = 1
    _assert_error(
        "SEQUENCE_CONFLICT",
        lambda: _handle(service, "telemetry.append", divergent),
    )
    _handle(service, "telemetry.append", _sample(sequence=2, kind="metrics"))
    _assert_error(
        "STALE_SEQUENCE",
        lambda: _handle(service, "telemetry.append", heartbeat),
    )

    clock.value = 30.1
    stale = _handle(service, "telemetry.snapshot", {}, identity=app)
    assert stale["streams"][0]["status"] == "stale"
    assert stale["streams"][0]["heartbeat_age_seconds"] == pytest.approx(30.1)


def test_scope_and_identity_isolation_preserves_run_attribution() -> None:
    clock = FakeClock()
    service = _service(clock)
    producer_a = _identity()
    producer_b = _identity(
        principal_ref="service:producer-b", actor_ref="actor-b", role=WireRole.SERVICE
    )
    app = _identity(
        principal_ref="application:monitor",
        actor_ref="dashboard-a",
        role=WireRole.APPLICATION_CLIENT,
    )

    _handle(
        service,
        "telemetry.append",
        _sample(stream_id="same"),
        identity=producer_a,
        scope=_scope(run_id="run-a"),
    )
    _handle(
        service,
        "telemetry.append",
        _sample(stream_id="same"),
        identity=producer_b,
        scope=_scope(run_id="run-a"),
    )
    _handle(
        service,
        "telemetry.append",
        _sample(stream_id="same"),
        identity=producer_a,
        scope=_scope(run_id="run-b"),
    )

    exact_run = _handle(
        service, "telemetry.snapshot", {}, identity=app, scope=_scope(run_id="run-a")
    )
    wildcard_strategy = _handle(service, "telemetry.snapshot", {}, identity=app)
    assert len(exact_run["streams"]) == 2
    assert {item["producer"]["actor_ref"] for item in exact_run["streams"]} == {
        "strategy-a",
        "actor-b",
    }
    assert len(wildcard_strategy["streams"]) == 3
    assert {item["scope"]["run_id"] for item in wildcard_strategy["streams"]} == {
        "run-a",
        "run-b",
    }
    _assert_error(
        "SCOPE_NOT_GRANTED",
        lambda: _handle(
            service,
            "telemetry.snapshot",
            {},
            identity=app,
            scope=_scope(strategy_ref="strategy-b"),
        ),
    )


def test_capacity_rejection_preserves_existing_stream_without_partial_update() -> None:
    clock = FakeClock()
    service = _service(clock, max_bytes=2048)
    strategy = _identity()
    app = _identity(
        principal_ref="application:monitor",
        actor_ref="dashboard-a",
        role=WireRole.APPLICATION_CLIENT,
    )
    _handle(service, "telemetry.append", _sample())

    large_metrics = {f"metric_{index:02d}_" + "x" * 50: 2**80 for index in range(32)}
    update = _sample(
        sequence=2,
        kind="metrics",
        metrics=large_metrics,
    )
    _assert_error(
        "TELEMETRY_CAPACITY",
        lambda: _handle(service, "telemetry.append", update, identity=strategy),
    )
    snapshot = _handle(service, "telemetry.snapshot", {}, identity=app)
    assert len(snapshot["streams"]) == 1
    assert snapshot["streams"][0]["sequence"] == 1
    assert snapshot["streams"][0]["metrics"] is None


def test_max_stream_capacity_and_retention_expiry_are_bounded() -> None:
    clock = FakeClock(0.0)
    service = _service(
        clock,
        max_streams=1,
        heartbeat_timeout_seconds=5,
        retention_seconds=10,
    )
    app = _identity(
        principal_ref="application:monitor",
        actor_ref="dashboard-a",
        role=WireRole.APPLICATION_CLIENT,
    )
    _handle(service, "telemetry.append", _sample(stream_id="stream-a"))
    _assert_error(
        "TELEMETRY_CAPACITY",
        lambda: _handle(service, "telemetry.append", _sample(stream_id="stream-b")),
    )

    clock.value = 10.0
    empty = _handle(service, "telemetry.snapshot", {}, identity=app)
    assert empty == {"state": "not_collected", "streams": []}

    _handle(service, "telemetry.append", _sample(stream_id="stream-b"))
    assert _handle(service, "telemetry.snapshot", {}, identity=app)["state"] == "collected"


def test_parser_bounds_metrics_and_snapshot_result_fit_callback() -> None:
    clock = FakeClock()
    service = _service(clock)
    too_many_metrics = _sample(kind="metrics")
    too_many_metrics["metrics"] = {f"metric{index}": index for index in range(33)}
    _assert_error(
        "INVALID_SAMPLE",
        lambda: _handle(service, "telemetry.append", too_many_metrics),
    )
    _handle(service, "telemetry.append", _sample())

    seen: list[Mapping[str, object]] = []

    def reject_snapshot(result: Mapping[str, object]) -> bool:
        seen.append(result)
        return False

    _assert_error(
        "SNAPSHOT_TOO_LARGE",
        lambda: _handle(
            service,
            "telemetry.snapshot",
            {},
            identity=_identity(
                principal_ref="application:monitor",
                actor_ref="dashboard-a",
                role=WireRole.APPLICATION_CLIENT,
            ),
            result_fits=reject_snapshot,
        ),
    )
    assert len(seen) == 1
    assert seen[0]["state"] == "collected"


def test_snapshot_fit_callback_cannot_mutate_result_or_deadlock_reentry() -> None:
    clock = FakeClock()
    service = _service(clock)
    app = _identity(
        principal_ref="application:monitor",
        actor_ref="dashboard-a",
        role=WireRole.APPLICATION_CLIENT,
    )
    _handle(service, "telemetry.append", _sample())

    def inspect_and_reenter(candidate: Mapping[str, object]) -> bool:
        assert candidate["state"] == "collected"
        streams = candidate["streams"]
        assert isinstance(streams, list)
        streams.clear()
        _handle(service, "telemetry.append", _sample(sequence=2, kind="metrics"))
        return True

    result = _handle(
        service,
        "telemetry.snapshot",
        {},
        identity=app,
        result_fits=inspect_and_reenter,
    )
    assert len(result["streams"]) == 1
    assert result["streams"][0]["sequence"] == 1
    assert _handle(service, "telemetry.snapshot", {}, identity=app)["streams"][0]["sequence"] == 2


def test_role_binding_and_service_options_are_strict_and_immutable() -> None:
    options = validate_service_options(
        {
            "role": "telemetry_ingress",
            "max_streams": 12,
            "max_bytes": 8192,
            "heartbeat_timeout_seconds": 15,
            "retention_seconds": 60,
        },
        ("service.telemetry_ingress", "service.monitor_query"),
    )
    assert dict(options) == {
        "role": "telemetry_ingress",
        "max_streams": 12,
        "max_bytes": 8192,
        "heartbeat_timeout_seconds": 15.0,
        "retention_seconds": 60.0,
    }
    with pytest.raises(TypeError):
        options["max_streams"] = 13  # type: ignore[index]
    assert frozenset({"telemetry.append", "telemetry.snapshot"}) == TELEMETRY_OPERATIONS

    _assert_error(
        "UNSUPPORTED_SERVICE_OPTIONS",
        lambda: validate_service_options({}, ("service.telemetry_ingress",)),
    )
    _assert_error(
        "UNSUPPORTED_SERVICE_OPTIONS",
        lambda: validate_service_options(
            {"role": "telemetry_ingress", "unknown": True},
            ("service.telemetry_ingress",),
        ),
    )
    _assert_error(
        "INVALID_BIND_PORTS",
        lambda: validate_service_options(
            {"role": "telemetry_ingress"}, ("service.monitor_control",)
        ),
    )
    _assert_error(
        "INVALID_BIND_PORTS",
        lambda: validate_service_options(
            {"role": "telemetry_ingress"},
            ("service.telemetry_ingress", []),  # type: ignore[arg-type]
        ),
    )
    _assert_error(
        "INVALID_LIMITS",
        lambda: validate_service_options(
            {
                "role": "telemetry_ingress",
                "heartbeat_timeout_seconds": 60,
                "retention_seconds": 30,
            },
            ("service.telemetry_ingress",),
        ),
    )

    clock = FakeClock()
    service = _service(clock)
    app = _identity(
        principal_ref="application:monitor",
        actor_ref="dashboard-a",
        role=WireRole.APPLICATION_CLIENT,
    )
    _assert_error(
        "APPEND_ROLE_REQUIRED",
        lambda: _handle(service, "telemetry.append", _sample(), identity=app),
    )
    _assert_error(
        "QUERY_ROLE_REQUIRED",
        lambda: _handle(service, "telemetry.snapshot", {}, identity=_identity()),
    )
    _assert_error(
        "IDENTITY_MISMATCH",
        lambda: _handle(
            service,
            "telemetry.snapshot",
            {},
            identity=app,
            principal_ref="application:forged",
        ),
    )
