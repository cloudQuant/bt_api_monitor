from __future__ import annotations

import json
import sqlite3

import pytest
from bt_api_base.service_protocol import WireIdentity, WireRole, WireScope

from bt_api_monitor.durable import (
    DurableOutbox,
    OutboxDeliveryError,
    OutboxEvent,
    SequencedOutboxEvent,
)
from bt_api_monitor.service_ingress import MonitorIngressTarget
from bt_api_monitor.threshold_rules import (
    ScopedThresholdRuleLoop,
    ThresholdRule,
    ThresholdRuleCapacityError,
    ThresholdRuleError,
    ThresholdRuleStoragePolicy,
    _matches_rule_event,
)
from bt_api_monitor.threshold_service import (
    THRESHOLD_ALERT_EVENT_TYPE,
    ThresholdRuleConsumerSupervisor,
    ThresholdServiceError,
    TrustedThresholdTarget,
    parse_threshold_service_config,
)

_DOMAIN = "threshold-service-unit"
_SOURCE_EVENT = "synthetic.quote.v1"
_SCOPE_A = WireScope(_DOMAIN, account_ref="account-a", strategy_ref="strategy-a")
_TARGET_A = TrustedThresholdTarget(
    "target-a",
    _SCOPE_A,
    MonitorIngressTarget("threshold:account-a:strategy-a", (_SOURCE_EVENT,)),
)


def _policy(**overrides) -> ThresholdRuleStoragePolicy:
    values = {
        "max_rule_configs": 8,
        "max_dimension_groups": 8,
        "max_window_events": 16,
        "max_label_bytes": 32_768,
        "max_alert_rows": 8,
        "alert_retention_seconds": 3_600,
    }
    values.update(overrides)
    return ThresholdRuleStoragePolicy(**values)


def _config(*, event_type: str = _SOURCE_EVENT, max_keys: int = 1) -> dict:
    return {
        "schema_version": 1,
        "consumer_id": "threshold-consumer-unit",
        "outbox_max_events": 32,
        "outbox_max_bytes": 65_536,
        "storage_policy": {
            "max_rule_configs": 8,
            "max_dimension_groups": 8,
            "max_window_events": 16,
            "max_label_bytes": 32_768,
            "max_alert_rows": 8,
            "alert_retention_seconds": 3_600,
        },
        "rules": [
            {
                "rule_id": "quote-count",
                "rule_version": 1,
                "target_ref": "target-a",
                "event_type": event_type,
                "window_seconds": 60,
                "threshold_count": 2,
                "dimension_fields": ["instrument_key"],
                "max_dimension_keys": max_keys,
                "max_window_events": 4,
                "allowed_lateness_seconds": 5,
                "late_event_policy": "ignore",
                "trading_day_field": None,
            }
        ],
    }


def _event(event_id: str, instrument: str, occurred_at: float) -> OutboxEvent:
    return OutboxEvent(
        event_id=event_id,
        scope=_TARGET_A.ingress_target.outbox_scope,
        event_type=_SOURCE_EVENT,
        data={"payload": {"instrument_key": {"instrument_id": instrument}}},
        occurred_at=occurred_at,
    )


def test_operator_config_derives_exact_scope_and_rejects_request_scope_fields() -> None:
    parsed = parse_threshold_service_config(json.dumps(_config()), {"target-a": _TARGET_A})
    assert parsed.rules[0].outbox_scope == _TARGET_A.ingress_target.outbox_scope
    assert parsed.rules[0].event_type == _SOURCE_EVENT
    assert parsed.target_refs == ("target-a",)

    raw = _config()
    raw["rules"][0]["outbox_scope"] = "client-chosen"
    with pytest.raises(ThresholdServiceError) as error:
        parse_threshold_service_config(json.dumps(raw), {"target-a": _TARGET_A})
    assert error.value.code == "RULE_FIELDS_INVALID"


def test_execution_business_selector_binds_operator_identity_and_exact_scope() -> None:
    producer = WireIdentity(WireRole.SERVICE, "service:execution-relay", "relay-a")
    scope = WireScope(_DOMAIN, account_ref="account-a", strategy_ref="strategy-a")
    target = TrustedThresholdTarget(
        "target-a",
        scope,
        MonitorIngressTarget(
            "execution-monitor:account-a:strategy-a",
            ("execution.lifecycle", "execution.cancellation"),
        ),
        producer_identity=producer,
        source_provider="binance",
        source_environment="paper",
    )
    raw = _config(event_type="execution.lifecycle")
    rule = raw["rules"][0]
    rule["dimension_fields"] = ["account_ref", "strategy_ref"]
    rule["execution_event_selector"] = {
        "schema": "sdk.execution_monitor_projection.v2",
        "stream": "execution",
        "business_event_type": "intent_recorded",
        "state": "PENDING_ADMISSION",
    }

    parsed = parse_threshold_service_config(json.dumps(raw), {"target-a": target})
    selector = parsed.rules[0].execution_event_selector
    assert selector is not None
    assert selector.producer == producer
    assert (selector.source_provider, selector.source_environment) == (
        "binance",
        "paper",
    )
    assert (selector.account_ref, selector.strategy_ref) == ("account-a", "strategy-a")
    assert (selector.stream, selector.business_event_type, selector.state) == (
        "execution",
        "intent_recorded",
        "PENDING_ADMISSION",
    )

    def projected_event(*, provider: str = "binance", environment: str = "paper"):
        payload = {
            "schema": "sdk.execution_monitor_projection.v2",
            "journal_generation": "journal-generation-1",
            "stream": "execution",
            "source_sequence": 1,
            "source_event_id": "execution-event-1",
            "source_created_at_ns": 1_700_000_000_000_000_000,
            "source_scope_key": "execution-scope-key",
            "source_scope": {
                "provider": provider,
                "environment": environment,
                "account_ref": "account-a",
                "strategy_id": "strategy-a",
                "trading_day": None,
            },
            "business_event_type": "intent_recorded",
            "state": "PENDING_ADMISSION",
            "intent_id": "intent-1",
            "cancel_id": None,
            "target_intent_id": None,
        }
        event = OutboxEvent(
            event_id="monitor-event-1",
            scope=target.ingress_target.outbox_scope,
            event_type="execution.lifecycle",
            data={
                "producer": {
                    "role": "service",
                    "principal_ref": producer.principal_ref,
                    "actor_ref": producer.actor_ref,
                    "delegate_ref": producer.delegate_ref,
                },
                "source_event_id": "monitor-event-1",
                "payload": payload,
            },
            occurred_at=1_700_000_000.0,
        )
        return SequencedOutboxEvent(1, event)

    assert _matches_rule_event(parsed.rules[0], projected_event()) is True
    for source_override in (
        {"provider": "other-provider"},
        {"environment": "live"},
    ):
        with pytest.raises(ThresholdRuleError, match="source scope does not match"):
            _matches_rule_event(
                parsed.rules[0], projected_event(**source_override)
            )

    forged = json.loads(json.dumps(raw))
    forged["rules"][0]["execution_event_selector"]["producer"] = {
        "principal_ref": "client-chosen"
    }
    with pytest.raises(ThresholdServiceError) as producer_fields:
        parse_threshold_service_config(json.dumps(forged), {"target-a": target})
    assert producer_fields.value.code == "RULE_EXECUTION_SELECTOR_INVALID"

    with pytest.raises(ThresholdServiceError) as missing_producer:
        parse_threshold_service_config(
            json.dumps(raw),
            {
                "target-a": TrustedThresholdTarget(
                    "target-a", scope, target.ingress_target
                )
            },
        )
    assert missing_producer.value.code == "RULE_EXECUTION_PRODUCER_NOT_TRUSTED"

    missing_source_scope = TrustedThresholdTarget(
        "target-a", scope, target.ingress_target, producer_identity=producer
    )
    with pytest.raises(ThresholdServiceError) as source_scope_not_trusted:
        parse_threshold_service_config(json.dumps(raw), {"target-a": missing_source_scope})
    assert source_scope_not_trusted.value.code == "RULE_EXECUTION_SOURCE_SCOPE_NOT_TRUSTED"

    wrong_business_fact = json.loads(json.dumps(raw))
    wrong_business_fact["rules"][0]["execution_event_selector"]["business_event_type"] = (
        "intent_state_changed"
    )
    with pytest.raises(ThresholdServiceError) as unsupported_fact:
        parse_threshold_service_config(json.dumps(wrong_business_fact), {"target-a": target})
    assert unsupported_fact.value.code == "RULE_EXECUTION_SELECTOR_INVALID"


def test_operator_config_rejects_alert_feedback_and_global_budget_overflow() -> None:
    raw = _config(event_type=THRESHOLD_ALERT_EVENT_TYPE)
    with pytest.raises(ThresholdServiceError) as alert_kind:
        parse_threshold_service_config(json.dumps(raw), {"target-a": _TARGET_A})
    assert alert_kind.value.code == "RULE_EVENT_TYPE_NOT_GRANTED"

    raw = _config(max_keys=2)
    raw["storage_policy"]["max_dimension_groups"] = 1
    raw["storage_policy"]["max_label_bytes"] = 4_096
    with pytest.raises(ThresholdServiceError) as budget:
        parse_threshold_service_config(json.dumps(raw), {"target-a": _TARGET_A})
    assert budget.value.code == "DIMENSION_BUDGET_EXCEEDS_GLOBAL_POLICY"

    duplicate = '{"schema_version":1,"schema_version":1}'
    with pytest.raises(ThresholdServiceError) as duplicate_field:
        parse_threshold_service_config(duplicate, {"target-a": _TARGET_A})
    assert duplicate_field.value.code == "CONFIG_JSON_INVALID"


def test_operator_config_enforces_global_rule_window_and_label_budgets() -> None:
    too_many_rules = _config()
    second_rule = dict(too_many_rules["rules"][0])
    second_rule["rule_id"] = "quote-count-secondary"
    too_many_rules["rules"].append(second_rule)
    too_many_rules["storage_policy"]["max_rule_configs"] = 1
    with pytest.raises(ThresholdServiceError) as rule_count:
        parse_threshold_service_config(json.dumps(too_many_rules), {"target-a": _TARGET_A})
    assert rule_count.value.code == "RULE_COUNT_EXCEEDS_GLOBAL_POLICY"

    too_many_window_events = _config()
    too_many_window_events["storage_policy"]["max_window_events"] = 3
    with pytest.raises(ThresholdServiceError) as window_budget:
        parse_threshold_service_config(
            json.dumps(too_many_window_events), {"target-a": _TARGET_A}
        )
    assert window_budget.value.code == "WINDOW_BUDGET_EXCEEDS_GLOBAL_POLICY"

    too_many_label_bytes = _config(max_keys=2)
    too_many_label_bytes["storage_policy"]["max_label_bytes"] = 4_095
    with pytest.raises(ThresholdServiceError) as label_budget:
        parse_threshold_service_config(json.dumps(too_many_label_bytes), {"target-a": _TARGET_A})
    assert label_budget.value.code == "LABEL_STORAGE_EXCEEDS_GLOBAL_POLICY"


def test_global_dimension_limit_keeps_overflow_event_pending(tmp_path) -> None:
    database = tmp_path / "threshold-global-limit.sqlite"
    outbox = DurableOutbox(database)
    rule = ThresholdRule(
        rule_id="global-dimension-limit",
        outbox_scope=_TARGET_A.ingress_target.outbox_scope,
        event_type=_SOURCE_EVENT,
        window_seconds=60,
        threshold_count=4,
        dimension_fields=("instrument_key",),
        max_dimension_keys=4,
        max_window_events=4,
    )
    loop = ScopedThresholdRuleLoop(
        outbox,
        (rule,),
        lambda _alert: None,
        consumer_id="global-limit-consumer",
        storage_policy=_policy(max_dimension_groups=1),
    )
    first = outbox.append(_event("source-a", "contract-a", 10_000.0))
    loop.run_once()
    assert loop.checkpoint(rule.outbox_scope) == first.sequence

    second = outbox.append(_event("source-b", "contract-b", 10_001.0))
    with pytest.raises(OutboxDeliveryError) as error:
        loop.run_once()
    assert isinstance(error.value.__cause__, ThresholdRuleCapacityError)
    assert loop.checkpoint(rule.outbox_scope) == first.sequence
    pending = outbox.read_pending("global-limit-consumer", rule.outbox_scope)
    assert [item.sequence for item in pending] == [second.sequence]


def test_global_window_capacity_keeps_overflow_source_event_pending(tmp_path) -> None:
    database = tmp_path / "threshold-global-window.sqlite"
    outbox = DurableOutbox(database)
    rule = ThresholdRule(
        rule_id="global-window-limit",
        outbox_scope=_TARGET_A.ingress_target.outbox_scope,
        event_type=_SOURCE_EVENT,
        window_seconds=60,
        threshold_count=2,
        dimension_fields=("instrument_key",),
        max_dimension_keys=2,
        max_window_events=2,
    )
    loop = ScopedThresholdRuleLoop(
        outbox,
        (rule,),
        lambda _alert: None,
        consumer_id="global-window-consumer",
        storage_policy=_policy(max_dimension_groups=2, max_window_events=1),
    )
    outbox.append(_event("window-a", "contract-a", 10_000.0))
    second = outbox.append(_event("window-b", "contract-b", 10_001.0))

    with pytest.raises(OutboxDeliveryError) as error:
        loop.run_once(limit=2)

    assert isinstance(error.value.__cause__, ThresholdRuleCapacityError)
    assert "global window-event capacity" in str(error.value.__cause__)
    assert loop.checkpoint(rule.outbox_scope) == 1
    assert loop.rule_status(rule.rule_id).window_count == 1
    pending = outbox.read_pending("global-window-consumer", rule.outbox_scope, limit=2)
    assert [item.sequence for item in pending] == [second.sequence]


def test_global_label_byte_capacity_keeps_overflow_source_event_pending(tmp_path) -> None:
    database = tmp_path / "threshold-global-labels.sqlite"
    outbox = DurableOutbox(database)
    rule = ThresholdRule(
        rule_id="global-label-limit",
        outbox_scope=_TARGET_A.ingress_target.outbox_scope,
        event_type=_SOURCE_EVENT,
        window_seconds=60,
        threshold_count=1,
        dimension_fields=("instrument_key",),
        max_dimension_keys=2,
        max_window_events=2,
    )
    loop = ScopedThresholdRuleLoop(
        outbox,
        (rule,),
        lambda _alert: None,
        consumer_id="global-label-consumer",
        storage_policy=_policy(
            max_dimension_groups=2,
            max_window_events=2,
            max_label_bytes=250,
        ),
    )
    first = outbox.append(_event("label-a", "A" * 100, 10_000.0))
    second = outbox.append(_event("label-b", "B" * 100, 10_001.0))

    with pytest.raises(OutboxDeliveryError) as error:
        loop.run_once(limit=2)

    assert isinstance(error.value.__cause__, ThresholdRuleCapacityError)
    assert "global dimension-label capacity" in str(error.value.__cause__)
    assert loop.checkpoint(rule.outbox_scope) == first.sequence
    assert loop.rule_status(rule.rule_id).dimension_keys == 1
    pending = outbox.read_pending("global-label-consumer", rule.outbox_scope, limit=2)
    assert [item.sequence for item in pending] == [second.sequence]


def test_alert_retention_prunes_only_delivered_rows_and_policy_is_pinned(tmp_path) -> None:
    database = tmp_path / "threshold-retention.sqlite"
    now = [20_000.0]
    outbox = DurableOutbox(database)
    rule = ThresholdRule(
        rule_id="retention",
        outbox_scope=_TARGET_A.ingress_target.outbox_scope,
        event_type=_SOURCE_EVENT,
        window_seconds=60,
        threshold_count=1,
        dimension_fields=("instrument_key",),
        max_dimension_keys=1,
        max_window_events=1,
    )
    policy = _policy(max_dimension_groups=1, max_window_events=1, max_alert_rows=1)
    loop = ScopedThresholdRuleLoop(
        outbox,
        (rule,),
        lambda _alert: None,
        consumer_id="retention-consumer",
        clock=lambda: now[0],
        storage_policy=policy,
    )
    outbox.append(_event("retained-source", "contract-a", now[0]))
    loop.run_once()

    with sqlite3.connect(database) as connection:
        row = connection.execute(
            "SELECT COUNT(*) FROM monitor_threshold_alert_outbox WHERE delivery_state='DELIVERED'"
        ).fetchone()
        assert row[0] == 1
        connection.execute(
            "UPDATE monitor_threshold_alert_outbox SET delivered_at=?",
            (now[0] - policy.alert_retention_seconds - 1,),
        )
    now[0] += 1
    loop.run_once()
    with sqlite3.connect(database) as connection:
        assert connection.execute(
            "SELECT COUNT(*) FROM monitor_threshold_alert_outbox"
        ).fetchone()[0] == 0

    with pytest.raises(ThresholdRuleError, match="storage policy"):
        ScopedThresholdRuleLoop(
            DurableOutbox(database),
            (rule,),
            lambda _alert: None,
            consumer_id="retention-consumer",
            clock=lambda: now[0],
            storage_policy=_policy(max_dimension_groups=2, max_window_events=1, max_alert_rows=1),
        )


def test_alert_table_capacity_keeps_pending_alert_and_source_event_unacknowledged(
    tmp_path,
) -> None:
    database = tmp_path / "threshold-alert-capacity.sqlite"
    now = [30_000.0]
    outbox = DurableOutbox(database, clock=lambda: now[0])
    raw = _config(max_keys=2)
    raw["storage_policy"]["max_alert_rows"] = 1
    raw["rules"][0]["threshold_count"] = 1
    raw["rules"][0]["max_window_events"] = 2
    parsed = parse_threshold_service_config(json.dumps(raw), {"target-a": _TARGET_A})
    sink_available = [False]
    delivered = []

    def sink(alert) -> None:
        if not sink_available[0]:
            raise RuntimeError("controlled sink outage")
        delivered.append(alert)

    first = outbox.append(_event("capacity-first", "contract-a", now[0]))
    second = outbox.append(_event("capacity-second", "contract-b", now[0] + 1.0))
    loop = ScopedThresholdRuleLoop(
        outbox,
        parsed.rules,
        sink,
        consumer_id=parsed.consumer_id,
        clock=lambda: now[0],
        storage_policy=parsed.storage_policy,
    )

    with pytest.raises(OutboxDeliveryError):
        loop.run_once(limit=1)
    assert loop.checkpoint(_TARGET_A.ingress_target.outbox_scope) == 0
    with sqlite3.connect(database) as connection:
        row = connection.execute(
            "SELECT alert_id, delivery_state FROM monitor_threshold_alert_outbox"
        ).fetchone()
    assert row is not None and row[1] == "PENDING"
    first_alert_id = row[0]

    # Pending alerts survive their retention age.  A successful retry settles
    # the existing alert, but retained table capacity still blocks a different
    # crossing until that delivered row ages out normally.
    now[0] += parsed.storage_policy.alert_retention_seconds + 1
    sink_available[0] = True
    recovered = loop.run_once(limit=1)
    assert [alert.alert_id for alert in recovered] == [first_alert_id]
    assert [alert.alert_id for alert in delivered] == [first_alert_id]
    assert loop.checkpoint(_TARGET_A.ingress_target.outbox_scope) == first.sequence

    with pytest.raises(OutboxDeliveryError) as capacity_error:
        loop.run_once(limit=1)
    assert isinstance(capacity_error.value.__cause__, ThresholdRuleCapacityError)
    assert loop.checkpoint(_TARGET_A.ingress_target.outbox_scope) == first.sequence
    assert [
        item.event.event_id
        for item in outbox.read_pending(
            parsed.consumer_id, _TARGET_A.ingress_target.outbox_scope, limit=2
        )
    ] == ["capacity-second"]
    status = loop.rule_status(parsed.rules[0].rule_id)
    assert status.alerts_triggered == 1
    assert status.alerts_emitted == 1
    assert status.pending_alerts == 0
    with sqlite3.connect(database) as connection:
        rows = connection.execute(
            "SELECT alert_id, delivery_state FROM monitor_threshold_alert_outbox"
        ).fetchall()
    assert rows == [(first_alert_id, "DELIVERED")]
    assert second.sequence > first.sequence


def test_supervisor_close_retries_unconfirmed_process_and_pipe_cleanup(tmp_path) -> None:
    class Process:
        pid = 1234
        _closed = False

        def __init__(self) -> None:
            self.alive = True
            self.close_calls = 0

        def is_alive(self) -> bool:
            return self.alive

        def join(self, _timeout: float) -> None:
            return None

        def terminate(self) -> None:
            self.alive = False

        def close(self) -> None:
            self.close_calls += 1
            if self.close_calls == 1:
                raise OSError("injected process-handle close failure")
            self._closed = True

    class Pipe:
        def __init__(self) -> None:
            self.close_calls = 0

        def send(self, _message: object) -> None:
            return None

        def poll(self, _timeout: float) -> bool:
            return False

        def close(self) -> None:
            self.close_calls += 1
            if self.close_calls == 1:
                raise OSError("injected pipe close failure")

    supervisor = ThresholdRuleConsumerSupervisor(
        str(tmp_path / "threshold-close-retry.sqlite"),
        parse_threshold_service_config(json.dumps(_config()), {"target-a": _TARGET_A}),
        startup_timeout_seconds=1.0,
        shutdown_timeout_seconds=0.05,
        poll_interval_seconds=0.05,
    )
    process = Process()
    pipe = Pipe()
    supervisor._process = process
    supervisor._pipe = pipe
    supervisor._ready = True
    supervisor._state = "ready"

    with pytest.raises(ThresholdServiceError) as first_close:
        supervisor.close()
    assert first_close.value.code == "WORKER_CLOSE_UNCONFIRMED"
    assert supervisor.status["state"] == "close_uncertain"
    assert supervisor.status["process_id"] == process.pid
    assert supervisor.status["outstanding_pipe_count"] == 1
    assert supervisor.status["closed"] is False

    # The process exits after the first bounded reap attempt.  A repeated
    # close must revisit the retained process and pipe instead of returning
    # just because shutdown was requested once.
    process.alive = False
    supervisor.close()
    assert supervisor.status["state"] == "closed"
    assert supervisor.status["process_id"] is None
    assert supervisor.status["outstanding_pipe_count"] == 0
    assert supervisor.status["closed"] is True
    assert process.close_calls == 2
    assert pipe.close_calls == 2


def test_supervisor_stops_restart_after_partial_spawn_cleanup_is_uncertain(tmp_path) -> None:
    class Pipe:
        def close(self) -> None:
            return None

    class Process:
        pid = 5678

        def __init__(self) -> None:
            self.start_calls = 0

        def start(self) -> None:
            self.start_calls += 1
            raise OSError("injected partial process start failure")

        def join(self, _timeout: float) -> None:
            return None

        def is_alive(self) -> bool:
            return True

        def terminate(self) -> None:
            return None

    class Context:
        def __init__(self) -> None:
            self.process = Process()

        def Pipe(self, *, duplex: bool):
            assert duplex is True
            return Pipe(), Pipe()

        def Process(self, **_kwargs):
            return self.process

    class StopEvent:
        def __init__(self) -> None:
            self.wait_calls = 0

        def wait(self, _timeout: float) -> bool:
            self.wait_calls += 1
            return False

    supervisor = ThresholdRuleConsumerSupervisor(
        str(tmp_path / "threshold-restart-uncertain.sqlite"),
        parse_threshold_service_config(json.dumps(_config()), {"target-a": _TARGET_A}),
        startup_timeout_seconds=1.0,
        shutdown_timeout_seconds=0.05,
        poll_interval_seconds=0.05,
    )
    context = Context()
    supervisor._context = context
    supervisor._stop = StopEvent()
    supervisor._state = "restart_failed"

    supervisor._supervise()

    assert context.process.start_calls == 1
    assert supervisor.status["state"] == "restart_cleanup_uncertain"
    assert supervisor.status["process_id"] == context.process.pid
    assert supervisor.status["outstanding_pipe_count"] == 0
    assert supervisor.status["restart_count"] == 1
