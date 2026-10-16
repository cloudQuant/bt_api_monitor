"""Focused persistence and scope tests for Monitor threshold evaluation."""

from __future__ import annotations

import ast
import dataclasses
import sys
from pathlib import Path

import pytest
from bt_api_base.service_protocol import WireIdentity, WireRole, WireScope

import bt_api_monitor.threshold_rules as threshold_rules_module
from bt_api_monitor.durable import DurableOutbox, OutboxDeliveryError, OutboxEvent
from bt_api_monitor.service_ingress import MonitorIngressService, MonitorIngressTarget
from bt_api_monitor.threshold_rules import (
    DEFAULT_MAX_DIMENSION_KEYS,
    DEFAULT_MAX_WINDOW_EVENTS,
    DEFAULT_RULE_CONSUMER_ID,
    MAX_RULE_VERSION,
    MAX_WINDOW_EVENTS,
    THRESHOLD_ALERT_ID_PREFIX,
    ScopedThresholdRuleLoop,
    ThresholdLateEventError,
    ThresholdRule,
    ThresholdRuleCapacityError,
    ThresholdRuleError,
)

_SCOPE_A = "monitor:scope-a"
_SCOPE_B = "monitor:scope-b"
_SCOPE_UNCONFIGURED = "monitor:unconfigured"
_CHAIN_SCOPE = "monitor:threshold-a"
_EVENT_TYPE = "order.status"


class MutableClock:
    def __init__(self, value: float = 1_700_000_000.0) -> None:
        self._value = value

    def __call__(self) -> float:
        return self._value

    def advance(self, seconds: float) -> None:
        self._value += seconds


def _rule(
    *,
    rule_id: str = "rule-a",
    outbox_scope: str = _SCOPE_A,
    event_type: str = _EVENT_TYPE,
    window_seconds: float = 60.0,
    threshold_count: int = 2,
    **overrides,
) -> ThresholdRule:
    return ThresholdRule(
        rule_id=rule_id,
        outbox_scope=outbox_scope,
        event_type=event_type,
        window_seconds=window_seconds,
        threshold_count=threshold_count,
        **overrides,
    )


def _event(
    event_id: str,
    *,
    scope: str = _SCOPE_A,
    event_type: str = _EVENT_TYPE,
    occurred_at: float = 1_700_000_000.0,
    data=None,
) -> OutboxEvent:
    return OutboxEvent(
        event_id=event_id,
        scope=scope,
        event_type=event_type,
        data={"status": "rejected"} if data is None else data,
        occurred_at=occurred_at,
    )


def _chain_scope() -> WireScope:
    return WireScope(
        execution_domain_ref="paper:dim08",
        account_ref="account-a",
        strategy_ref="strategy-a",
    )


def _chain_identity() -> WireIdentity:
    return WireIdentity(
        role=WireRole.SERVICE,
        principal_ref="service:dim08-producer",
        actor_ref="producer-a",
        delegate_ref="delegate-a",
    )


def test_rule_configuration_is_scoped_versioned_and_bounded(tmp_path: Path) -> None:
    rule = _rule(window_seconds=60, threshold_count=3)
    assert rule.window_seconds == 60.0
    assert rule.rule_version == 1
    assert rule.dimension_fields == ()
    assert rule.max_dimension_keys == DEFAULT_MAX_DIMENSION_KEYS
    assert rule.max_window_events == DEFAULT_MAX_WINDOW_EVENTS

    invalid_rule_kwargs = (
        {"rule_id": ""},
        {"rule_id": "wild*card"},
        {"rule_id": "spaced id"},
        {"rule_id": "r" * 129},
        {"outbox_scope": ""},
        {"outbox_scope": " padded "},
        {"outbox_scope": "*"},
        {"outbox_scope": "x" * 257},
        {"event_type": "bad\x01type"},
        {"event_type": "*"},
        {"window_seconds": 0},
        {"window_seconds": -1},
        {"window_seconds": float("inf")},
        {"window_seconds": float("nan")},
        {"window_seconds": True},
        {"window_seconds": 86_401.0},
        {"threshold_count": 0},
        {"threshold_count": True},
        {"threshold_count": 1_000_001},
        {"rule_version": 0},
        {"rule_version": True},
        {"rule_version": MAX_RULE_VERSION + 1},
        {"dimension_fields": ("order_id",)},
        {"dimension_fields": ("account_ref", "account_ref")},
        {"dimension_fields": ("account_ref",) * 6},
        {"max_dimension_keys": 0},
        {"max_dimension_keys": True},
        {"max_window_events": 1},
        {"max_window_events": MAX_WINDOW_EVENTS + 1},
        {"allowed_lateness_seconds": -1},
        {"allowed_lateness_seconds": float("nan")},
        {"late_event_policy": "drop-silently"},
        {"late_event_policy": []},
        {"trading_day_field": "local_date"},
    )
    for overrides in invalid_rule_kwargs:
        with pytest.raises(ThresholdRuleError):
            _rule(**{"window_seconds": 60.0, "threshold_count": 3, **overrides})

    database = tmp_path / "rules.sqlite"
    outbox = DurableOutbox(database, clock=MutableClock())
    read_only = DurableOutbox(database, read_only=True)
    valid = (_rule(),)
    with pytest.raises(ThresholdRuleError):
        ScopedThresholdRuleLoop(outbox, list(valid), lambda _alert: None)  # type: ignore[arg-type]
    with pytest.raises(ThresholdRuleError):
        ScopedThresholdRuleLoop(outbox, (), lambda _alert: None)
    with pytest.raises(ThresholdRuleError):
        ScopedThresholdRuleLoop(outbox, (valid[0], valid[0]), lambda _alert: None)
    with pytest.raises(ThresholdRuleError):
        ScopedThresholdRuleLoop(outbox, ("not-a-rule",), lambda _alert: None)  # type: ignore[arg-type]
    with pytest.raises(ThresholdRuleError):
        ScopedThresholdRuleLoop(read_only, valid, lambda _alert: None)
    with pytest.raises(ThresholdRuleError):
        ScopedThresholdRuleLoop(outbox, valid, None)  # type: ignore[arg-type]
    with pytest.raises(ThresholdRuleError):
        ScopedThresholdRuleLoop(outbox, valid, lambda _alert: None, consumer_id=" ")
    with pytest.raises(ThresholdRuleError):
        ScopedThresholdRuleLoop(outbox, valid, lambda _alert: None, clock=1)  # type: ignore[arg-type]

    loop = ScopedThresholdRuleLoop(outbox, valid, lambda _alert: None, clock=MutableClock())
    with pytest.raises(ThresholdRuleError):
        loop.run_once(limit=0)
    with pytest.raises(ThresholdRuleError):
        loop.run_once(limit=True)
    with pytest.raises(ThresholdRuleError):
        loop.checkpoint("monitor:not-configured")
    with pytest.raises(ThresholdRuleError):
        loop.rule_status("not-a-rule")


def test_rule_version_is_immutable_and_activates_after_durable_progress(tmp_path: Path) -> None:
    clock = MutableClock()
    database = tmp_path / "version.sqlite"
    outbox = DurableOutbox(database, clock=clock)
    outbox.append(_event("v1-1", occurred_at=100.0))
    outbox.append(_event("v1-2", occurred_at=101.0))
    v1 = _rule(window_seconds=60.0, threshold_count=2)
    delivered_v1 = []
    loop_v1 = ScopedThresholdRuleLoop(outbox, (v1,), delivered_v1.append, clock=clock)
    assert len(loop_v1.run_once()) == 1
    assert loop_v1.checkpoint(_SCOPE_A) == 2

    with pytest.raises(ThresholdRuleError, match="reused"):
        ScopedThresholdRuleLoop(
            DurableOutbox(database, clock=clock),
            (_rule(window_seconds=60.0, threshold_count=3),),
            lambda _alert: None,
            clock=clock,
        )

    v2 = _rule(rule_version=2, window_seconds=60.0, threshold_count=3)
    delivered_v2 = []
    loop_v2 = ScopedThresholdRuleLoop(
        DurableOutbox(database, clock=clock), (v2,), delivered_v2.append, clock=clock
    )
    assert loop_v2.rule_status("rule-a").effective_after_sequence == 2
    with pytest.raises(ThresholdRuleError, match="superseded"):
        loop_v1.run_once()

    for sequence in range(3, 6):
        outbox.append(_event(f"v2-{sequence}", occurred_at=99.0 + sequence))
    alerts = loop_v2.run_once()
    assert [alert.triggering_event_id for alert in alerts] == ["v2-5"]
    assert alerts[0].rule_version == 2
    status = loop_v2.rule_status("rule-a")
    assert status.rule_version == 2
    assert status.effective_after_sequence == 2
    assert status.counted_events == 3
    assert status.last_counted_sequence == 5
    assert status.alerts_emitted == 1

    with pytest.raises(ThresholdRuleError, match="older rule versions"):
        ScopedThresholdRuleLoop(
            DurableOutbox(database, clock=clock), (v1,), lambda _alert: None, clock=clock
        )


def test_rule_version_cannot_change_its_authorized_outbox_scope(tmp_path: Path) -> None:
    clock = MutableClock()
    database = tmp_path / "scope-version.sqlite"
    outbox = DurableOutbox(database, clock=clock)
    rule_v1 = _rule(rule_id="stable-rule", outbox_scope=_SCOPE_A, threshold_count=2)
    loop_v1 = ScopedThresholdRuleLoop(outbox, (rule_v1,), lambda _alert: None, clock=clock)
    assert loop_v1.configured_scopes == (_SCOPE_A,)

    moved_v2 = _rule(
        rule_id="stable-rule",
        outbox_scope=_SCOPE_B,
        rule_version=2,
        threshold_count=2,
    )
    with pytest.raises(ThresholdRuleError, match="scope cannot change"):
        ScopedThresholdRuleLoop(
            DurableOutbox(database, clock=clock), (moved_v2,), lambda _alert: None, clock=clock
        )


def test_event_time_window_rearms_after_elapsed_source_time(tmp_path: Path) -> None:
    clock = MutableClock()
    outbox = DurableOutbox(tmp_path / "rules.sqlite", clock=clock)
    for index, event_time in enumerate((1000.0, 1010.0, 1010.0), start=1):
        outbox.append(_event(f"synthetic-{index}", occurred_at=event_time))
    delivered = []
    loop = ScopedThresholdRuleLoop(
        outbox, (_rule(window_seconds=10.0, threshold_count=2),), delivered.append, clock=clock
    )

    first_pass = loop.run_once()
    assert [alert.rule_id for alert in first_pass] == ["rule-a"]
    first = first_pass[0]
    assert first.alert_id.startswith(THRESHOLD_ALERT_ID_PREFIX)
    assert first.observed_count == 2
    assert first.triggering_event_id == "synthetic-2"
    assert first.triggering_sequence == 2
    assert first.triggered_at == 1010.0
    assert first.evaluated_watermark == 1010.0

    status = loop.rule_status("rule-a")
    assert status.window_count == 3
    assert status.alerts_emitted == 1
    assert status.armed is False
    assert len(delivered) == 1

    outbox.append(_event("synthetic-4", occurred_at=1021.0))
    outbox.append(_event("synthetic-5", occurred_at=1022.0))
    second_pass = loop.run_once()
    assert len(second_pass) == 1
    second = second_pass[0]
    assert second.triggering_event_id == "synthetic-5"
    assert second.observed_count == 2
    assert second.alert_id != first.alert_id
    assert len(delivered) == 2


def test_ack_lost_at_crossing_restart_does_not_recount_or_retrigger(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    clock = MutableClock()
    database = tmp_path / "rules.sqlite"
    outbox = DurableOutbox(database, clock=clock)
    for index in range(1, 6):
        outbox.append(_event(f"synthetic-{index}", occurred_at=1000.0 + index))
    delivered = []
    rule = _rule(window_seconds=60.0, threshold_count=3)
    loop = ScopedThresholdRuleLoop(outbox, (rule,), delivered.append, clock=clock)
    original_acknowledge = outbox.acknowledge
    failing = {"armed": True}

    def flaky_acknowledge(consumer_id: str, scope: str, sequence: int) -> None:
        if sequence == 3 and failing["armed"]:
            failing["armed"] = False
            raise RuntimeError("checkpoint write lost at crossing")
        original_acknowledge(consumer_id, scope, sequence)

    monkeypatch.setattr(outbox, "acknowledge", flaky_acknowledge)
    with pytest.raises(OutboxDeliveryError):
        loop.run_once(limit=10)
    assert [alert.triggering_event_id for alert in delivered] == ["synthetic-3"]
    assert loop.checkpoint(_SCOPE_A) == 2
    assert loop.rule_status("rule-a").window_count == 3
    assert loop.rule_status("rule-a").pending_alerts == 0
    monkeypatch.undo()

    restarted = ScopedThresholdRuleLoop(
        DurableOutbox(database, clock=clock), (rule,), delivered.append, clock=clock
    )
    assert restarted.run_once(limit=10) == ()
    assert restarted.checkpoint(_SCOPE_A) == 5
    status = restarted.rule_status("rule-a")
    assert status.window_count == 5
    assert status.counted_events == 5
    assert status.last_counted_sequence == 5
    assert status.alerts_emitted == 1
    assert status.pending_alerts == 0
    assert [alert.triggering_event_id for alert in delivered] == ["synthetic-3"]


def test_sink_failure_survives_restart_as_the_same_pending_alert(tmp_path: Path) -> None:
    clock = MutableClock()
    database = tmp_path / "rules.sqlite"
    outbox = DurableOutbox(database, clock=clock)
    for index in range(1, 4):
        outbox.append(
            _event(
                f"synthetic-{index}",
                occurred_at=1000.0 + index,
                data={
                    "source_event_id": f"provider-event-{index}",
                    "payload": {"source": {"stream_epoch": "source-epoch-1", "sequence": index}},
                },
            )
        )
    attempts = []

    def failing_sink(alert) -> None:
        attempts.append(alert)
        raise RuntimeError("alert transport unavailable")

    rule = _rule(window_seconds=60.0, threshold_count=3)
    first = ScopedThresholdRuleLoop(outbox, (rule,), failing_sink, clock=clock)
    with pytest.raises(OutboxDeliveryError):
        first.run_once()
    assert first.checkpoint(_SCOPE_A) == 2
    assert len(attempts) == 1
    assert first.rule_status("rule-a").window_count == 3
    pending_status = first.rule_status("rule-a")
    assert pending_status.alerts_triggered == 1
    assert pending_status.alerts_emitted == 0
    assert pending_status.pending_alerts == 1

    accepted = []
    restarted = ScopedThresholdRuleLoop(
        DurableOutbox(database, clock=clock), (rule,), accepted.append, clock=clock
    )
    alerts = restarted.run_once()
    assert [alert.alert_id for alert in alerts] == [attempts[0].alert_id]
    assert len(accepted) == 1
    assert accepted[0].triggering_event_id == "synthetic-3"
    assert accepted[0].triggering_sequence == 3
    assert attempts[0].alert_id == accepted[0].alert_id
    assert attempts[0] == accepted[0]
    assert accepted[0].source_event_id == "provider-event-3"
    assert accepted[0].source_stream_epoch == "source-epoch-1"
    assert accepted[0].source_sequence == 3
    assert accepted[0].source_completeness == "received_event_only"
    assert restarted.checkpoint(_SCOPE_A) == 3
    status = restarted.rule_status("rule-a")
    assert status.window_count == 3
    assert status.counted_events == 3
    assert status.alerts_triggered == 1
    assert status.alerts_emitted == 1
    assert status.pending_alerts == 0


def test_run_limit_bounds_pending_alerts_across_configured_scopes(tmp_path: Path) -> None:
    database = tmp_path / "alert-budget.sqlite"
    clock = MutableClock()
    outbox = DurableOutbox(database, clock=clock)
    outbox.append(_event("scope-a", scope=_SCOPE_A, occurred_at=100.0))
    outbox.append(_event("scope-b", scope=_SCOPE_B, occurred_at=101.0))
    rule_a = _rule(rule_id="rule-a", outbox_scope=_SCOPE_A, threshold_count=1)
    rule_b = _rule(rule_id="rule-b", outbox_scope=_SCOPE_B, threshold_count=1)

    def unavailable_sink(_alert) -> None:
        raise RuntimeError("temporary sink failure")

    for rule in (rule_a, rule_b):
        failing_loop = ScopedThresholdRuleLoop(
            DurableOutbox(database, clock=clock), (rule,), unavailable_sink, clock=clock
        )
        with pytest.raises(OutboxDeliveryError):
            failing_loop.run_once(limit=1)
        pending = failing_loop.rule_status(rule.rule_id)
        assert pending.alerts_triggered == 1
        assert pending.alerts_emitted == 0
        assert pending.pending_alerts == 1

    delivered = []
    recovered = ScopedThresholdRuleLoop(
        DurableOutbox(database, clock=clock), (rule_a, rule_b), delivered.append, clock=clock
    )
    first_batch = recovered.run_once(limit=1)
    assert [alert.triggering_event_id for alert in first_batch] == ["scope-a"]
    assert [alert.triggering_event_id for alert in delivered] == ["scope-a"]
    assert recovered.rule_status("rule-a").pending_alerts == 0
    assert recovered.rule_status("rule-b").pending_alerts == 1
    assert recovered.checkpoint(_SCOPE_A) == 1
    assert recovered.checkpoint(_SCOPE_B) == 0

    second_batch = recovered.run_once(limit=1)
    assert [alert.triggering_event_id for alert in second_batch] == ["scope-b"]
    assert [alert.triggering_event_id for alert in delivered] == ["scope-a", "scope-b"]
    assert recovered.checkpoint(_SCOPE_B) == 2
    assert recovered.rule_status("rule-a").alerts_triggered == 1
    assert recovered.rule_status("rule-a").alerts_emitted == 1
    assert recovered.rule_status("rule-b").alerts_triggered == 1
    assert recovered.rule_status("rule-b").alerts_emitted == 1


def test_dimension_labels_are_allowlisted_and_cardinality_is_bounded(tmp_path: Path) -> None:
    database = tmp_path / "dimension-cap.sqlite"
    outbox = DurableOutbox(database, clock=MutableClock())
    rule = _rule(
        threshold_count=1,
        dimension_fields=("account_ref", "instrument_key"),
        max_dimension_keys=1,
    )
    delivered = []
    loop = ScopedThresholdRuleLoop(outbox, (rule,), delivered.append, clock=MutableClock())
    outbox.append(
        _event(
            "dimension-1",
            occurred_at=1000.0,
            data={
                "account_ref": "account-a",
                "instrument_key": {"venue": "synthetic", "product": "future", "symbol": "A"},
                "order_id": "private-order-label-must-not-be-selected",
            },
        )
    )
    alerts = loop.run_once()
    assert len(alerts) == 1
    assert dict(alerts[0].dimension_map) == {
        "account_ref": "account-a",
        "instrument_key": '{"product":"future","symbol":"A","venue":"synthetic"}',
    }
    assert "order_id" not in alerts[0].dimension_map

    outbox.append(
        _event(
            "dimension-2",
            occurred_at=1001.0,
            data={
                "account_ref": "account-a",
                "instrument_key": {"venue": "synthetic", "product": "future", "symbol": "B"},
            },
        )
    )
    with pytest.raises(OutboxDeliveryError) as error:
        loop.run_once()
    assert isinstance(error.value.__cause__, ThresholdRuleCapacityError)
    assert loop.checkpoint(_SCOPE_A) == 1
    status = loop.rule_status("rule-a")
    assert status.dimension_keys == 1
    assert status.window_count == 1
    assert status.alerts_emitted == 1


def test_late_events_and_trading_day_reset_have_explicit_event_time_semantics(
    tmp_path: Path,
) -> None:
    clock = MutableClock()
    outbox = DurableOutbox(tmp_path / "trading-day.sqlite", clock=clock)
    rule = _rule(
        window_seconds=600.0,
        threshold_count=2,
        dimension_fields=("instrument_key",),
        allowed_lateness_seconds=5.0,
        trading_day_field="trading_day",
        late_event_policy="ignore",
    )
    delivered = []
    loop = ScopedThresholdRuleLoop(outbox, (rule,), delivered.append, clock=clock)

    rows = (
        ("day1-1", "2026-10-15", 1000.0),
        ("day1-2", "2026-10-15", 1010.0),
        ("day2-1", "2026-10-16", 1015.0),
        ("late-day1", "2026-10-15", 1012.0),
        ("late-clock", "2026-10-16", 1008.0),
        ("day2-2", "2026-10-16", 1016.0),
    )
    for event_id, trading_day, occurred_at in rows:
        outbox.append(
            _event(
                event_id,
                occurred_at=occurred_at,
                data={"instrument_key": "X:future:1", "trading_day": trading_day},
            )
        )

    alerts = loop.run_once(limit=10)
    assert [alert.triggering_event_id for alert in alerts] == ["day1-2", "day2-2"]
    assert alerts[0].evaluated_watermark == 1010.0
    assert alerts[1].triggered_at == 1016.0
    status = loop.rule_status("rule-a")
    assert status.last_counted_sequence == 6
    assert status.counted_events == 4
    assert status.window_count == 2
    assert status.late_events == 2
    assert status.alerts_emitted == 2
    assert status.pending_alerts == 0


def test_late_reject_leaves_source_event_unacknowledged(tmp_path: Path) -> None:
    clock = MutableClock()
    outbox = DurableOutbox(tmp_path / "late-reject.sqlite", clock=clock)
    outbox.append(_event("on-time-1", occurred_at=100.0))
    outbox.append(_event("on-time-2", occurred_at=110.0))
    outbox.append(_event("too-late", occurred_at=100.0))
    rule = _rule(
        threshold_count=2,
        allowed_lateness_seconds=2.0,
        late_event_policy="reject",
    )
    loop = ScopedThresholdRuleLoop(outbox, (rule,), lambda _alert: None, clock=clock)
    with pytest.raises(OutboxDeliveryError) as error:
        loop.run_once(limit=10)
    assert isinstance(error.value.__cause__, ThresholdLateEventError)
    assert loop.checkpoint(_SCOPE_A) == 2
    status = loop.rule_status("rule-a")
    assert status.last_counted_sequence == 2
    assert status.late_events == 0
    assert status.counted_events == 2


def test_partial_producer_cursor_is_rejected_without_acknowledgement(tmp_path: Path) -> None:
    outbox = DurableOutbox(tmp_path / "partial-source-cursor.sqlite")
    outbox.append(
        _event(
            "partial-source-cursor",
            data={"payload": {"source": {"stream_epoch": "epoch-a"}}},
        )
    )
    loop = ScopedThresholdRuleLoop(outbox, (_rule(threshold_count=1),), lambda _alert: None)

    with pytest.raises(OutboxDeliveryError) as error:
        loop.run_once()

    assert isinstance(error.value.__cause__, ThresholdRuleError)
    assert "both epoch and sequence" in str(error.value.__cause__)
    assert loop.checkpoint(_SCOPE_A) == 0
    assert loop.rule_status("rule-a").last_counted_sequence == 0


def test_rules_stay_isolated_to_configured_scopes_and_event_types(tmp_path: Path) -> None:
    clock = MutableClock()
    outbox = DurableOutbox(tmp_path / "scope.sqlite", clock=clock)
    outbox.append(_event("a-1", occurred_at=100.0))
    outbox.append(_event("a-2", occurred_at=101.0))
    outbox.append(_event("a-cancelled", event_type="order.cancelled", occurred_at=102.0))
    outbox.append(_event("b-1", scope=_SCOPE_B, occurred_at=100.0))
    outbox.append(_event("b-2", scope=_SCOPE_B, occurred_at=101.0))
    outbox.append(_event("not-configured", scope=_SCOPE_UNCONFIGURED, occurred_at=103.0))
    delivered = []
    loop = ScopedThresholdRuleLoop(
        outbox,
        (
            _rule(rule_id="rule-a", outbox_scope=_SCOPE_A, threshold_count=2),
            _rule(rule_id="rule-b", outbox_scope=_SCOPE_B, threshold_count=3),
        ),
        delivered.append,
        clock=clock,
    )
    assert loop.configured_scopes == (_SCOPE_A, _SCOPE_B)
    with pytest.raises(ThresholdRuleError):
        loop.checkpoint("monitor:ungranted")

    alerts = loop.run_once()
    assert [alert.triggering_event_id for alert in alerts] == ["a-2"]
    assert loop.rule_status("rule-a").window_count == 2
    assert loop.rule_status("rule-a").alerts_emitted == 1
    assert loop.rule_status("rule-b").window_count == 2
    assert loop.rule_status("rule-b").alerts_emitted == 0
    assert outbox.read_pending(DEFAULT_RULE_CONSUMER_ID, _SCOPE_UNCONFIGURED, limit=1)[
        0
    ].event.event_id == ("not-configured")


def test_real_ingress_producer_restart_reuses_durable_window_without_risk_calls(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Real producer -> SQLite outbox -> persistent rule -> idempotent alert sink."""

    database = tmp_path / "chain.sqlite"
    clock = MutableClock()
    modules_before = set(sys.modules)
    outbox = DurableOutbox(database, clock=clock)
    producer = MonitorIngressService(
        outbox,
        {
            _chain_scope(): MonitorIngressTarget(
                outbox_scope=_CHAIN_SCOPE, event_types=(_EVENT_TYPE,)
            )
        },
    )
    produced = []
    for index in range(1, 6):
        produced.append(
            producer.handle(
                "events.append",
                principal_ref="service:dim08-producer",
                identity=_chain_identity(),
                scope=_chain_scope(),
                arguments={
                    "schema_version": 1,
                    "event_id": f"source-{index}",
                    "event_type": _EVENT_TYPE,
                    "occurred_at": 1_800_000_000 + index,
                    "data": {
                        "status": "rejected",
                        "attempt": index,
                        "account_ref": "account-a",
                        "strategy_ref": "strategy-a",
                        "instrument_key": "X:future:1",
                        "product": "future",
                        "generation": "session-1",
                    },
                },
            )
        )
    durable_event_ids = [row["event_id"] for row in produced]
    assert len(set(durable_event_ids)) == 5

    calls = []
    distinct_alerts = {}

    def idempotent_sink(alert) -> None:
        calls.append(alert.alert_id)
        distinct_alerts.setdefault(alert.alert_id, alert)

    rule = ThresholdRule(
        rule_id="rule.ingress-status.v1",
        outbox_scope=_CHAIN_SCOPE,
        event_type=_EVENT_TYPE,
        window_seconds=600.0,
        threshold_count=3,
        rule_version=1,
        dimension_fields=("strategy_ref", "account_ref", "instrument_key", "product"),
    )
    outbox_one = DurableOutbox(database, clock=clock)
    loop_one = ScopedThresholdRuleLoop(outbox_one, (rule,), idempotent_sink, clock=clock)
    original_acknowledge = outbox_one.acknowledge
    failing = {"armed": True}

    def flaky_acknowledge(consumer_id: str, scope: str, sequence: int) -> None:
        if sequence == 2 and failing["armed"]:
            failing["armed"] = False
            raise RuntimeError("checkpoint write lost")
        original_acknowledge(consumer_id, scope, sequence)

    monkeypatch.setattr(outbox_one, "acknowledge", flaky_acknowledge)
    with pytest.raises(OutboxDeliveryError) as error:
        loop_one.run_once(limit=10)
    assert calls == []
    assert loop_one.checkpoint(_CHAIN_SCOPE) == 1, repr(error.value.__cause__)

    # A replacement loop sees the persisted sequence-2 state before replay;
    # it counts each remaining source event exactly once.
    outbox_two = DurableOutbox(database, clock=clock)
    loop_two = ScopedThresholdRuleLoop(outbox_two, (rule,), idempotent_sink, clock=clock)
    alerts = loop_two.run_once(limit=10)
    assert len(alerts) == 1
    alert = alerts[0]
    assert calls == [alert.alert_id]
    assert list(distinct_alerts) == [alert.alert_id]
    assert alert.triggering_event_id == durable_event_ids[2]
    assert alert.observed_count == 3 == alert.threshold_count
    assert alert.source_generation == "session-1"
    assert alert.source_event_id == "source-3"
    assert alert.source_stream_epoch is None
    assert alert.source_sequence is None
    assert alert.source_completeness == "received_event_only"
    assert dict(alert.dimension_map) == {
        "account_ref": "account-a",
        "instrument_key": "X:future:1",
        "product": "future",
        "strategy_ref": "strategy-a",
    }
    assert loop_two.checkpoint(_CHAIN_SCOPE) == 5
    status = loop_two.rule_status("rule.ingress-status.v1")
    assert status.window_count == 5
    assert status.counted_events == 5
    assert status.last_counted_sequence == 5
    assert status.alerts_emitted == 1
    assert status.armed is False

    # Restarting with the same version and no new source rows retains state.
    loop_three = ScopedThresholdRuleLoop(
        DurableOutbox(database, clock=clock), (rule,), idempotent_sink, clock=clock
    )
    assert loop_three.run_once(limit=10) == ()
    assert loop_three.checkpoint(_CHAIN_SCOPE) == 5
    assert loop_three.rule_status("rule.ingress-status.v1").counted_events == 5
    assert len(calls) == 1

    with DurableOutbox(database, read_only=True)._connection() as connection:
        alert_rows = connection.execute(
            "SELECT alert_id, delivery_state, attempts FROM monitor_threshold_alert_outbox"
        ).fetchall()
    assert len(alert_rows) == 1
    assert alert_rows[0]["delivery_state"] == "DELIVERED"
    assert alert_rows[0]["attempts"] == 1

    rows, has_more = DurableOutbox(database, read_only=True).read_page(
        _CHAIN_SCOPE, _EVENT_TYPE, 0, 10
    )
    assert [row.event.event_id for row in rows] == durable_event_ids
    assert has_more is False

    # 告警不冒充硬风控: the whole producer/consumer path never imports Risk.
    new_modules = set(sys.modules) - modules_before
    forbidden = sorted(
        module
        for module in new_modules
        if "risk" in module.lower() or "admission" in module.lower()
    )
    assert forbidden == []
    assert "bt_api_risk" not in sys.modules
    imported_modules = set()
    for node in ast.walk(
        ast.parse(Path(threshold_rules_module.__file__).read_text(encoding="utf-8"))
    ):
        if isinstance(node, ast.Import):
            imported_modules.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module is not None:
            imported_modules.add(node.module)
    assert not any(
        "risk" in name.lower() or "admission" in name.lower() for name in imported_modules
    )
    assert "subprocess" not in imported_modules
    public_surface = sorted(name for name in dir(loop_three) if not name.startswith("_"))
    assert public_surface == ["checkpoint", "configured_scopes", "rule_status", "run_once"]
    with pytest.raises(dataclasses.FrozenInstanceError):
        alert.observed_count = 99  # type: ignore[misc]
