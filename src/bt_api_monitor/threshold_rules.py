"""Durable, scoped windowed-count threshold rules for Monitor outbox facts.

Rules count one accepted source event once, identified by its immutable
outbox sequence. Configuration, source progress, bounded dimension windows,
and alert delivery state live in the same SQLite database as the producer
outbox. Rule evaluation commits before the existing consumer advances its
checkpoint, so a lost ACK replays an already-evaluated sequence without
recounting it or creating a second alert.

Windows use ``OutboxEvent.occurred_at`` as UTC epoch seconds. The rule states
its allowed lateness and optional ISO trading-day field. A sink receives a
stable ``alert_id`` and must use it as its idempotency key: a process can fail
after a sink accepts an alert but before SQLite records delivery, so arbitrary
external callbacks can only be retried at least once. The durable alert itself
is unique per rule version, source event, and dimension set.

This evaluator is observation-only. It adds no service role, provider access,
control action, Risk admission, order dispatch, worker, or scheduler. Callers
must already be authorized for the exact outbox scope they configure; normal
Monitor ingress and read-service Registry checks remain the authorization
boundary.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import date
from types import MappingProxyType

from .durable import (
    DurableOutbox,
    DurableOutboxConsumer,
    OutboxDeliveryError,
    SequencedOutboxEvent,
)

THRESHOLD_ALERT_ID_PREFIX = "monitor-threshold-alert-v2:"
DEFAULT_RULE_CONSUMER_ID = "monitor.threshold-rules.v2"
MAX_RULE_WINDOW_SECONDS = 86_400.0
MAX_RULE_THRESHOLD_COUNT = 1_000_000
MAX_RUN_LIMIT = 1000
MAX_RULE_VERSION = 2_147_483_647
MAX_DIMENSION_FIELDS = 5
MAX_DIMENSION_KEYS = 10_000
DEFAULT_MAX_DIMENSION_KEYS = 128
MAX_WINDOW_EVENTS = 100_000
DEFAULT_MAX_WINDOW_EVENTS = 10_000
MAX_DIMENSION_VALUE_BYTES = 512
MAX_DIMENSION_KEY_BYTES = 2048
MAX_LATE_SECONDS = 86_400.0
MAX_PERSISTED_RULE_CONFIGS = 4_096
MAX_PERSISTED_DIMENSION_GROUPS = 16_384
MAX_PERSISTED_WINDOW_EVENTS = 131_072
MAX_PERSISTED_LABEL_BYTES = 64 * 1024 * 1024
MAX_PERSISTED_ALERT_ROWS = 100_000
MAX_ALERT_RETENTION_SECONDS = 90 * 24 * 60 * 60
DEFAULT_ALERT_RETENTION_SECONDS = 30 * 24 * 60 * 60
_SOURCE_COMPLETENESS_EVENT_ONLY = "received_event_only"
_ALERT_ID_DOMAIN = "bt-api-monitor.threshold-alert.v2"
_MAX_RULE_ID_BYTES = 128
_MAX_SCOPE_TEXT_BYTES = 256
_MAX_EVENT_TYPE_BYTES = 128
_RULE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_ALLOWED_DIMENSIONS = frozenset(
    {
        "account_ref",
        "strategy_ref",
        "instrument_key",
        "product",
        "group_ref",
        "group_id",
        "resource_pool",
        "resource_pool_ref",
    }
)


class ThresholdRuleError(ValueError):
    """A rule, bounded run request, event, or persisted contract is invalid."""


class ThresholdRuleCapacityError(ThresholdRuleError):
    """A configured dimension/window bound was reached; the source event stays pending."""


class ThresholdLateEventError(ThresholdRuleError):
    """A source event exceeds the rule's allowed event-time lateness."""


@dataclass(frozen=True)
class ThresholdRuleStoragePolicy:
    """Global durable-state bounds shared by every consumer using one database.

    These values are operator policy, not request fields.  The first loop
    persists the policy in SQLite; later workers must reopen the database with
    the same policy so a restart cannot silently enlarge its storage budget.
    """

    max_rule_configs: int = MAX_PERSISTED_RULE_CONFIGS
    max_dimension_groups: int = MAX_PERSISTED_DIMENSION_GROUPS
    max_window_events: int = MAX_PERSISTED_WINDOW_EVENTS
    max_label_bytes: int = MAX_PERSISTED_LABEL_BYTES
    max_alert_rows: int = MAX_PERSISTED_ALERT_ROWS
    alert_retention_seconds: int = DEFAULT_ALERT_RETENTION_SECONDS

    def __post_init__(self) -> None:
        limits = (
            (self.max_rule_configs, 1, MAX_PERSISTED_RULE_CONFIGS),
            (self.max_dimension_groups, 1, MAX_PERSISTED_DIMENSION_GROUPS),
            (self.max_window_events, 1, MAX_PERSISTED_WINDOW_EVENTS),
            (self.max_label_bytes, 1, MAX_PERSISTED_LABEL_BYTES),
            (self.max_alert_rows, 1, MAX_PERSISTED_ALERT_ROWS),
            (self.alert_retention_seconds, 3_600, MAX_ALERT_RETENTION_SECONDS),
        )
        if any(
            type(value) is not int or not lower <= value <= upper
            for value, lower, upper in limits
        ):
            raise ThresholdRuleError("storage policy is outside its bounded range")


DEFAULT_THRESHOLD_STORAGE_POLICY = ThresholdRuleStoragePolicy()


@dataclass(frozen=True)
class ThresholdRule:
    """One exact scope/event-type rule with immutable, explicitly versioned semantics.

    A rule version cannot be reused with different fields. Increase
    ``rule_version`` to activate changed semantics. The new version starts
    after the greater of the durable consumer checkpoint and the old
    version's last evaluated sequence; old history is not silently replayed
    under new policy.
    """

    rule_id: str
    outbox_scope: str
    event_type: str
    window_seconds: float
    threshold_count: int
    rule_version: int = 1
    dimension_fields: tuple[str, ...] = ()
    max_dimension_keys: int = DEFAULT_MAX_DIMENSION_KEYS
    max_window_events: int = DEFAULT_MAX_WINDOW_EVENTS
    allowed_lateness_seconds: float = 0.0
    late_event_policy: str = "ignore"
    trading_day_field: str | None = None

    def __post_init__(self) -> None:
        if (
            type(self.rule_id) is not str
            or len(self.rule_id.encode("utf-8", "strict")) > _MAX_RULE_ID_BYTES
            or _RULE_ID_RE.fullmatch(self.rule_id) is None
        ):
            raise ThresholdRuleError("rule_id has an invalid format")
        _validate_scoped_text("outbox_scope", self.outbox_scope, _MAX_SCOPE_TEXT_BYTES)
        _validate_scoped_text("event_type", self.event_type, _MAX_EVENT_TYPE_BYTES)
        if isinstance(self.window_seconds, bool) or not isinstance(
            self.window_seconds, (int, float)
        ):
            raise ThresholdRuleError("window_seconds must be a finite duration")
        try:
            window_seconds = float(self.window_seconds)
        except OverflowError:
            raise ThresholdRuleError("window_seconds must be a finite duration") from None
        if not math.isfinite(window_seconds) or not 0.0 < window_seconds <= MAX_RULE_WINDOW_SECONDS:
            raise ThresholdRuleError("window_seconds is outside the bounded range")
        if (
            type(self.threshold_count) is not int
            or not 1 <= self.threshold_count <= MAX_RULE_THRESHOLD_COUNT
        ):
            raise ThresholdRuleError("threshold_count is outside the bounded range")
        if type(self.rule_version) is not int or not 1 <= self.rule_version <= MAX_RULE_VERSION:
            raise ThresholdRuleError("rule_version must be a positive bounded integer")
        if (
            type(self.dimension_fields) is not tuple
            or len(self.dimension_fields) > MAX_DIMENSION_FIELDS
            or any(
                type(field) is not str or field not in _ALLOWED_DIMENSIONS
                for field in self.dimension_fields
            )
            or len(set(self.dimension_fields)) != len(self.dimension_fields)
        ):
            raise ThresholdRuleError("dimension_fields is outside the controlled allowlist")
        if (
            type(self.max_dimension_keys) is not int
            or not 1 <= self.max_dimension_keys <= MAX_DIMENSION_KEYS
        ):
            raise ThresholdRuleError("max_dimension_keys is outside the bounded range")
        if (
            type(self.max_window_events) is not int
            or not self.threshold_count <= self.max_window_events <= MAX_WINDOW_EVENTS
        ):
            raise ThresholdRuleError(
                "max_window_events cannot cover the threshold or exceeds its bound"
            )
        if isinstance(self.allowed_lateness_seconds, bool) or not isinstance(
            self.allowed_lateness_seconds, (int, float)
        ):
            raise ThresholdRuleError("allowed_lateness_seconds must be a finite duration")
        try:
            allowed_lateness = float(self.allowed_lateness_seconds)
        except OverflowError:
            raise ThresholdRuleError("allowed_lateness_seconds must be a finite duration") from None
        if not math.isfinite(allowed_lateness) or not 0.0 <= allowed_lateness <= MAX_LATE_SECONDS:
            raise ThresholdRuleError("allowed_lateness_seconds is outside the bounded range")
        if type(self.late_event_policy) is not str or self.late_event_policy not in {
            "ignore",
            "reject",
        }:
            raise ThresholdRuleError("late_event_policy must be ignore or reject")
        if self.trading_day_field is not None and self.trading_day_field != "trading_day":
            raise ThresholdRuleError("trading_day_field must be the explicit trading_day field")


@dataclass(frozen=True)
class ThresholdAlert:
    """One durable threshold crossing; its stable ID is the sink idempotency key."""

    alert_id: str
    rule_id: str
    rule_version: int
    outbox_scope: str
    event_type: str
    dimensions: tuple[tuple[str, str], ...]
    window_seconds: float
    threshold_count: int
    observed_count: int
    triggering_event_id: str
    triggering_sequence: int
    source_event_id: str
    source_stream_epoch: str | None
    source_sequence: int | None
    source_completeness: str
    triggered_at: float
    evaluated_watermark: float
    source_generation: str | None
    source_kind: str = "monitor.durable_outbox"

    @property
    def dimension_map(self) -> Mapping[str, str]:
        """Return immutable bounded labels suitable for an authorized detail view."""

        return MappingProxyType(dict(self.dimensions))


@dataclass(frozen=True)
class ThresholdRuleStatus:
    """Durable aggregate state for one active rule version."""

    rule_id: str
    rule_version: int
    window_count: int
    counted_events: int
    last_counted_sequence: int
    alerts_triggered: int
    alerts_emitted: int
    pending_alerts: int
    late_events: int
    dimension_keys: int
    effective_after_sequence: int
    armed: bool


AlertSink = Callable[[ThresholdAlert], None]


class ScopedThresholdRuleLoop:
    """Consume exact authorized outbox scopes and persist windowed counters.

    One stable consumer identity owns checkpoints across process restarts.
    Evaluation state and alert records use the outbox's SQLite database; no
    second store or independent delivery ledger is created. The supplied sink
    must deduplicate by ``ThresholdAlert.alert_id`` because a crash after the
    external sink accepts an alert but before its delivered receipt commits is
    inherently at-least-once.
    """

    def __init__(
        self,
        outbox: DurableOutbox,
        rules: tuple[ThresholdRule, ...],
        alert_sink: AlertSink,
        *,
        consumer_id: str = DEFAULT_RULE_CONSUMER_ID,
        clock: Callable[[], float] | None = None,
        storage_policy: ThresholdRuleStoragePolicy = DEFAULT_THRESHOLD_STORAGE_POLICY,
    ) -> None:
        if not isinstance(outbox, DurableOutbox) or outbox.is_read_only:
            raise ThresholdRuleError("outbox must be a writable DurableOutbox")
        if type(rules) is not tuple or not rules:
            raise ThresholdRuleError("rules must be a non-empty tuple")
        if any(type(rule) is not ThresholdRule for rule in rules):
            raise ThresholdRuleError("rules must contain ThresholdRule values")
        if len({rule.rule_id for rule in rules}) != len(rules):
            raise ThresholdRuleError("duplicate rule_id values are not allowed")
        _validate_scoped_text("consumer_id", consumer_id, _MAX_SCOPE_TEXT_BYTES)
        if not callable(alert_sink):
            raise ThresholdRuleError("alert_sink must be callable")
        if clock is not None and not callable(clock):
            raise ThresholdRuleError("clock must be callable")
        if type(storage_policy) is not ThresholdRuleStoragePolicy:
            raise ThresholdRuleError("storage_policy must be an operator policy value")
        if len(rules) > storage_policy.max_rule_configs:
            raise ThresholdRuleCapacityError("configured rule count exceeds storage policy")

        scope_rules: dict[str, list[ThresholdRule]] = {}
        for rule in rules:
            scope_rules.setdefault(rule.outbox_scope, []).append(rule)
        self._outbox = outbox
        self._consumer_id = consumer_id
        self._alert_sink = alert_sink
        self._clock = time.time if clock is None else clock
        self._storage_policy = storage_policy
        self._rules = {rule.rule_id: rule for rule in rules}
        self._scope_rules = {
            scope: tuple(sorted(group, key=lambda rule: rule.rule_id))
            for scope, group in sorted(scope_rules.items())
        }
        self._initialize_and_register_rules()

    @property
    def configured_scopes(self) -> tuple[str, ...]:
        """Return the exact configured outbox scopes this instance may consume."""

        return tuple(self._scope_rules)

    def checkpoint(self, outbox_scope: str) -> int:
        """Return the durable consumer checkpoint for one configured scope."""

        if outbox_scope not in self._scope_rules:
            raise ThresholdRuleError("outbox_scope is not configured")
        return self._outbox.checkpoint(self._consumer_id, outbox_scope)

    def rule_status(self, rule_id: str) -> ThresholdRuleStatus:
        """Return bounded aggregate state without exposing unconfigured scopes."""

        rule = self._rules.get(rule_id)
        if rule is None:
            raise ThresholdRuleError("rule_id is not configured")
        with self._outbox._connection() as connection:
            config = self._config_row(connection, rule)
            progress = connection.execute(
                """
                SELECT last_sequence, late_events FROM monitor_threshold_rule_progress
                WHERE consumer_id = ? AND rule_id = ? AND rule_version = ?
                """,
                (self._consumer_id, rule.rule_id, rule.rule_version),
            ).fetchone()
            groups = connection.execute(
                """
                SELECT COALESCE(SUM(window_count), 0) AS window_count,
                       COALESCE(SUM(counted_events), 0) AS counted_events,
                       COALESCE(MIN(armed), 1) AS all_armed,
                       COUNT(*) AS dimension_keys
                FROM monitor_threshold_rule_groups
                WHERE consumer_id = ? AND rule_id = ? AND rule_version = ?
                """,
                (self._consumer_id, rule.rule_id, rule.rule_version),
            ).fetchone()
            alerts = connection.execute(
                """
                SELECT COUNT(*) AS triggered,
                       COALESCE(SUM(CASE WHEN delivery_state = 'DELIVERED' THEN 1 ELSE 0 END), 0)
                           AS delivered,
                       COALESCE(SUM(CASE WHEN delivery_state = 'PENDING' THEN 1 ELSE 0 END), 0)
                           AS pending
                FROM monitor_threshold_alert_outbox
                WHERE consumer_id = ? AND rule_id = ? AND rule_version = ?
                """,
                (self._consumer_id, rule.rule_id, rule.rule_version),
            ).fetchone()
        if progress is None or groups is None or alerts is None:
            raise ThresholdRuleError("durable rule state is incomplete")
        return ThresholdRuleStatus(
            rule_id=rule.rule_id,
            rule_version=rule.rule_version,
            window_count=int(groups["window_count"]),
            counted_events=int(groups["counted_events"]),
            last_counted_sequence=int(progress["last_sequence"]),
            alerts_triggered=int(alerts["triggered"]),
            alerts_emitted=int(alerts["delivered"]),
            pending_alerts=int(alerts["pending"]),
            late_events=int(progress["late_events"]),
            dimension_keys=int(groups["dimension_keys"]),
            effective_after_sequence=int(config["activation_sequence"]),
            armed=bool(groups["all_armed"]),
        )

    def run_once(self, limit: int = 100) -> tuple[ThresholdAlert, ...]:
        """Retry a bounded number of alerts and consume a bounded source page."""

        if type(limit) is not int or not 1 <= limit <= MAX_RUN_LIMIT:
            raise ThresholdRuleError("limit is outside the bounded run range")
        self._prune_expired_delivered_alerts()
        self._assert_all_active()
        emitted: list[ThresholdAlert] = []
        alert_budget = [limit]
        source_budget = limit
        for scope, rules in self._scope_rules.items():
            # This also retries a crossing whose source event was already
            # evaluated but remained unacknowledged after a sink failure.
            attempted = self._deliver_pending_alerts(scope, emitted, limit=alert_budget[0])
            alert_budget[0] -= attempted
        for scope, rules in self._scope_rules.items():
            if source_budget <= 0:
                break
            consumer = DurableOutboxConsumer(
                self._outbox,
                self._consumer_id,
                scope,
                self._deliver_for_scope(scope, rules, emitted, alert_budget),
            )
            consumed = consumer.consume(limit=source_budget)
            source_budget -= len(consumed)
        return tuple(emitted)

    def _deliver_for_scope(
        self,
        scope: str,
        rules: tuple[ThresholdRule, ...],
        emitted: list[ThresholdAlert],
        alert_budget: list[int],
    ) -> Callable[[SequencedOutboxEvent], None]:
        def deliver(item: SequencedOutboxEvent) -> None:
            for rule in rules:
                self._evaluate(rule, item)
            attempted = self._deliver_pending_alerts(scope, emitted, limit=alert_budget[0])
            alert_budget[0] -= attempted

        return deliver

    def _evaluate(self, rule: ThresholdRule, item: SequencedOutboxEvent) -> None:
        """Atomically persist event disposition, window state, and any alert."""

        if item.event.scope != rule.outbox_scope:
            raise ThresholdRuleError("event scope does not match the configured rule")
        with self._outbox._transaction() as connection:
            self._assert_active_on_connection(connection, rule)
            progress = connection.execute(
                """
                SELECT last_sequence, processed_events, late_events
                FROM monitor_threshold_rule_progress
                WHERE consumer_id = ? AND rule_id = ? AND rule_version = ?
                """,
                (self._consumer_id, rule.rule_id, rule.rule_version),
            ).fetchone()
            if progress is None:
                raise ThresholdRuleError("durable rule progress is missing")
            last_sequence = int(progress["last_sequence"])
            if item.sequence <= last_sequence:
                # State commits before checkpoint. A replay after lost ACK is
                # an already-applied source sequence, not a new observation.
                return
            next_row = connection.execute(
                """
                SELECT sequence FROM monitor_outbox_events
                WHERE scope = ? AND sequence > ? ORDER BY sequence ASC LIMIT 1
                """,
                (rule.outbox_scope, last_sequence),
            ).fetchone()
            if next_row is None or int(next_row["sequence"]) != item.sequence:
                raise ThresholdRuleError("source event sequence is not the next scoped fact")

            late_events = int(progress["late_events"])
            if item.event.event_type == rule.event_type:
                dimensions = _dimension_values(rule, item)
                dimension_json = _canonical_json(dict(dimensions))
                dimension_key = _sha256(dimension_json.encode("utf-8"))
                group = connection.execute(
                    """
                    SELECT window_json, armed, counted_events,
                           window_count, watermark, trading_day, late_events
                    FROM monitor_threshold_rule_groups
                    WHERE consumer_id = ? AND rule_id = ? AND rule_version = ?
                      AND dimension_key = ?
                    """,
                    (self._consumer_id, rule.rule_id, rule.rule_version, dimension_key),
                ).fetchone()
                if group is None:
                    current_keys = connection.execute(
                        """
                        SELECT COUNT(*) AS n FROM monitor_threshold_rule_groups
                        WHERE consumer_id = ? AND rule_id = ? AND rule_version = ?
                        """,
                        (self._consumer_id, rule.rule_id, rule.rule_version),
                    ).fetchone()
                    if current_keys is None or int(current_keys["n"]) >= rule.max_dimension_keys:
                        raise ThresholdRuleCapacityError("rule dimension-key capacity reached")
                    window: list[list[object]] = []
                    armed = True
                    counted_events = 0
                    watermark: float | None = None
                    trading_day: str | None = None
                    group_late_events = 0
                else:
                    window = _decode_window(group["window_json"])
                    armed = bool(group["armed"])
                    counted_events = int(group["counted_events"])
                    watermark = None if group["watermark"] is None else float(group["watermark"])
                    trading_day = group["trading_day"]
                    group_late_events = int(group["late_events"])

                event_time = float(item.event.occurred_at)
                incoming_day = _event_trading_day(rule, item)
                late_reason = None
                if incoming_day is not None and trading_day is not None:
                    if incoming_day < trading_day:
                        late_reason = "trading_day_regression"
                    elif incoming_day > trading_day:
                        window = []
                        watermark = None
                        armed = True
                        trading_day = incoming_day
                elif incoming_day is not None:
                    trading_day = incoming_day

                if (
                    late_reason is None
                    and watermark is not None
                    and event_time < watermark - float(rule.allowed_lateness_seconds)
                ):
                    late_reason = "beyond_allowed_lateness"

                if late_reason is not None:
                    if rule.late_event_policy == "reject":
                        raise ThresholdLateEventError(late_reason)
                    late_events += 1
                    group_late_events += 1
                    self._assert_group_storage_capacity(
                        connection,
                        rule,
                        dimension_json,
                        0 if group is None else len(window),
                        len(window),
                        group_exists=group is not None,
                    )
                    self._write_group(
                        connection,
                        rule,
                        dimension_key,
                        dimension_json,
                        window,
                        armed,
                        counted_events,
                        watermark,
                        trading_day,
                        group_late_events,
                        item.sequence,
                        item.event.event_id,
                        late_reason,
                    )
                else:
                    watermark = event_time if watermark is None else max(watermark, event_time)
                    cutoff = watermark - float(rule.window_seconds)
                    window = [entry for entry in window if float(entry[0]) >= cutoff]
                    if event_time >= cutoff:
                        window.append([event_time, item.sequence, item.event.event_id])
                        window.sort(key=lambda entry: (float(entry[0]), int(entry[1])))
                        if len(window) > rule.max_window_events:
                            raise ThresholdRuleCapacityError("rule window-event capacity reached")
                        counted_events += 1
                    if len(window) < rule.threshold_count:
                        armed = True
                    if armed and len(window) >= rule.threshold_count:
                        armed = False
                        alert = _make_alert(
                            self._consumer_id,
                            rule,
                            dimensions,
                            item,
                            event_time,
                            watermark,
                            _source_generation(item),
                            _source_lineage(item),
                            len(window),
                        )
                        self._insert_alert(connection, alert)
                    self._assert_group_storage_capacity(
                        connection,
                        rule,
                        dimension_json,
                        0 if group is None else int(group["window_count"]),
                        len(window),
                        group_exists=group is not None,
                    )
                    self._write_group(
                        connection,
                        rule,
                        dimension_key,
                        dimension_json,
                        window,
                        armed,
                        counted_events,
                        watermark,
                        trading_day,
                        group_late_events,
                        None,
                        None,
                        None,
                    )

            connection.execute(
                """
                UPDATE monitor_threshold_rule_progress
                SET last_sequence = ?, processed_events = processed_events + 1,
                    late_events = ?, updated_at = ?
                WHERE consumer_id = ? AND rule_id = ? AND rule_version = ?
                """,
                (
                    item.sequence,
                    late_events,
                    _finite_clock(self._clock),
                    self._consumer_id,
                    rule.rule_id,
                    rule.rule_version,
                ),
            )

    def _write_group(
        self,
        connection,
        rule: ThresholdRule,
        dimension_key: str,
        dimension_json: str,
        window: list[list[object]],
        armed: bool,
        counted_events: int,
        watermark: float | None,
        trading_day: str | None,
        late_events: int,
        late_sequence: int | None,
        late_event_id: str | None,
        late_reason: str | None,
    ) -> None:
        connection.execute(
            """
            INSERT INTO monitor_threshold_rule_groups
                (consumer_id, rule_id, rule_version, dimension_key, dimensions_json,
                 window_json, armed, counted_events, window_count,
                 watermark, trading_day, late_events, last_late_sequence,
                 last_late_event_id, last_late_reason)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(consumer_id, rule_id, rule_version, dimension_key) DO UPDATE SET
                dimensions_json = excluded.dimensions_json,
                window_json = excluded.window_json,
                armed = excluded.armed,
                counted_events = excluded.counted_events,
                window_count = excluded.window_count,
                watermark = excluded.watermark,
                trading_day = excluded.trading_day,
                late_events = excluded.late_events,
                last_late_sequence = COALESCE(excluded.last_late_sequence, last_late_sequence),
                last_late_event_id = COALESCE(excluded.last_late_event_id, last_late_event_id),
                last_late_reason = COALESCE(excluded.last_late_reason, last_late_reason)
            """,
            (
                self._consumer_id,
                rule.rule_id,
                rule.rule_version,
                dimension_key,
                dimension_json,
                _canonical_json(window),
                int(armed),
                counted_events,
                len(window),
                watermark,
                trading_day,
                late_events,
                late_sequence,
                late_event_id,
                late_reason,
            ),
        )

    def _assert_group_storage_capacity(
        self,
        connection,
        rule: ThresholdRule,
        dimension_json: str,
        previous_window_count: int,
        next_window_count: int,
        *,
        group_exists: bool,
    ) -> None:
        """Enforce database-wide group, window, and label budgets atomically."""

        totals = connection.execute(
            """
            SELECT COUNT(*) AS groups,
                   COALESCE(SUM(window_count), 0) AS window_events,
                   COALESCE(SUM(length(CAST(dimensions_json AS BLOB))), 0) AS label_bytes
            FROM monitor_threshold_rule_groups
            """
        ).fetchone()
        if totals is None:
            raise ThresholdRuleError("durable threshold storage totals are unavailable")
        group_count = int(totals["groups"])
        label_bytes = int(totals["label_bytes"])
        if not group_exists:
            if group_count >= self._storage_policy.max_dimension_groups:
                raise ThresholdRuleCapacityError("global dimension-group capacity reached")
            label_bytes += len(dimension_json.encode("utf-8"))
        window_events = int(totals["window_events"]) - previous_window_count + next_window_count
        if window_events > self._storage_policy.max_window_events:
            raise ThresholdRuleCapacityError("global window-event capacity reached")
        if label_bytes > self._storage_policy.max_label_bytes:
            raise ThresholdRuleCapacityError("global dimension-label capacity reached")

    def _prune_expired_delivered_alerts(self) -> int:
        """Apply bounded audit retention without dropping pending delivery work."""

        cutoff = _finite_clock(self._clock) - self._storage_policy.alert_retention_seconds
        with self._outbox._transaction() as connection:
            cursor = connection.execute(
                """
                DELETE FROM monitor_threshold_alert_outbox
                WHERE delivery_state = 'DELIVERED' AND delivered_at < ?
                """,
                (cutoff,),
            )
            return int(cursor.rowcount)

    def _insert_alert(self, connection, alert: ThresholdAlert) -> None:
        existing = connection.execute(
            "SELECT 1 FROM monitor_threshold_alert_outbox WHERE alert_id = ?",
            (alert.alert_id,),
        ).fetchone()
        if existing is None:
            cutoff = _finite_clock(self._clock) - self._storage_policy.alert_retention_seconds
            connection.execute(
                """
                DELETE FROM monitor_threshold_alert_outbox
                WHERE delivery_state = 'DELIVERED' AND delivered_at < ?
                """,
                (cutoff,),
            )
            retained = connection.execute(
                "SELECT COUNT(*) AS n FROM monitor_threshold_alert_outbox"
            ).fetchone()
            if retained is None or int(retained["n"]) >= self._storage_policy.max_alert_rows:
                raise ThresholdRuleCapacityError("durable alert retention capacity reached")
        values = (
            self._consumer_id,
            alert.rule_id,
            alert.rule_version,
            alert.outbox_scope,
            alert.event_type,
            _canonical_json(dict(alert.dimensions)),
            alert.window_seconds,
            alert.threshold_count,
            alert.observed_count,
            alert.triggering_event_id,
            alert.triggering_sequence,
            alert.source_event_id,
            alert.source_stream_epoch,
            alert.source_sequence,
            alert.source_completeness,
            alert.triggered_at,
            alert.evaluated_watermark,
            alert.source_generation,
            _finite_clock(self._clock),
        )
        connection.execute(
            """
            INSERT INTO monitor_threshold_alert_outbox
                (alert_id, consumer_id, rule_id, rule_version, scope, event_type, dimensions_json,
                 window_seconds, threshold_count, observed_count, triggering_event_id,
                 triggering_sequence, source_event_id, source_stream_epoch, source_sequence,
                 source_completeness, triggered_at, evaluated_watermark, source_generation,
                 delivery_state, attempts, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'PENDING', 0, ?)
            ON CONFLICT(alert_id) DO NOTHING
            """,
            (alert.alert_id, *values),
        )
        stored = connection.execute(
            """
            SELECT rule_id, rule_version, scope, event_type, dimensions_json,
                   triggering_event_id, triggering_sequence, source_event_id,
                   source_stream_epoch, source_sequence, source_completeness
            FROM monitor_threshold_alert_outbox WHERE alert_id = ?
            """,
            (alert.alert_id,),
        ).fetchone()
        if stored is None or (
            str(stored["rule_id"]) != alert.rule_id
            or int(stored["rule_version"]) != alert.rule_version
            or str(stored["scope"]) != alert.outbox_scope
            or str(stored["event_type"]) != alert.event_type
            or str(stored["dimensions_json"]) != _canonical_json(dict(alert.dimensions))
            or str(stored["triggering_event_id"]) != alert.triggering_event_id
            or int(stored["triggering_sequence"]) != alert.triggering_sequence
            or str(stored["source_event_id"]) != alert.source_event_id
            or (
                None
                if stored["source_stream_epoch"] is None
                else str(stored["source_stream_epoch"])
            )
            != alert.source_stream_epoch
            or (None if stored["source_sequence"] is None else int(stored["source_sequence"]))
            != alert.source_sequence
            or str(stored["source_completeness"]) != alert.source_completeness
        ):
            raise ThresholdRuleError("durable alert ID conflicts with different content")

    def _deliver_pending_alerts(
        self, scope: str, emitted: list[ThresholdAlert], *, limit: int
    ) -> int:
        if limit <= 0:
            return 0
        with self._outbox._connection() as connection:
            rows = connection.execute(
                """
                SELECT * FROM monitor_threshold_alert_outbox
                WHERE consumer_id = ? AND scope = ? AND delivery_state = 'PENDING'
                ORDER BY created_at ASC, alert_id ASC LIMIT ?
                """,
                (self._consumer_id, scope, min(limit, MAX_RUN_LIMIT)),
            ).fetchall()
        attempted = 0
        for row in rows:
            alert = _alert_from_row(row)
            with self._outbox._transaction() as connection:
                claimed = connection.execute(
                    """
                    UPDATE monitor_threshold_alert_outbox
                    SET attempts = attempts + 1
                    WHERE alert_id = ? AND delivery_state = 'PENDING'
                    """,
                    (alert.alert_id,),
                )
                if claimed.rowcount != 1:
                    continue
                attempted += 1
            try:
                self._alert_sink(alert)
            except Exception as error:
                raise OutboxDeliveryError(
                    "threshold alert delivery failed; durable alert remains pending"
                ) from error
            with self._outbox._transaction() as connection:
                delivered = connection.execute(
                    """
                    UPDATE monitor_threshold_alert_outbox
                    SET delivery_state = 'DELIVERED', delivered_at = ?
                    WHERE alert_id = ? AND delivery_state = 'PENDING'
                    """,
                    (_finite_clock(self._clock), alert.alert_id),
                )
                if delivered.rowcount == 1:
                    emitted.append(alert)
        return attempted

    def _initialize_and_register_rules(self) -> None:
        with self._outbox._transaction() as connection:
            _create_schema(connection)
            _ensure_storage_policy(connection, self._storage_policy, self._clock)
            for rule in self._rules.values():
                config_json = _rule_config_json(rule)
                config = connection.execute(
                    """
                    SELECT config_json, activation_sequence
                    FROM monitor_threshold_rule_configs
                    WHERE consumer_id = ? AND rule_id = ? AND rule_version = ?
                    """,
                    (self._consumer_id, rule.rule_id, rule.rule_version),
                ).fetchone()
                active = connection.execute(
                    """
                    SELECT rule_version FROM monitor_threshold_rule_active
                    WHERE consumer_id = ? AND rule_id = ?
                    """,
                    (self._consumer_id, rule.rule_id),
                ).fetchone()
                if config is not None:
                    if str(config["config_json"]) != config_json:
                        raise ThresholdRuleError(
                            "rule version was reused with changed configuration"
                        )
                    if active is None or int(active["rule_version"]) != rule.rule_version:
                        raise ThresholdRuleError("older rule versions cannot be reactivated")
                    continue
                if active is not None and rule.rule_version <= int(active["rule_version"]):
                    raise ThresholdRuleError("rule_version must increase for changed semantics")
                previous_config = connection.execute(
                    """
                    SELECT scope FROM monitor_threshold_rule_configs
                    WHERE consumer_id = ? AND rule_id = ?
                    ORDER BY rule_version DESC LIMIT 1
                    """,
                    (self._consumer_id, rule.rule_id),
                ).fetchone()
                if (
                    previous_config is not None
                    and str(previous_config["scope"]) != rule.outbox_scope
                ):
                    raise ThresholdRuleError(
                        "rule scope cannot change across versions; create a new rule_id"
                    )

                current_configs = connection.execute(
                    "SELECT COUNT(*) AS n FROM monitor_threshold_rule_configs"
                ).fetchone()
                if (
                    current_configs is None
                    or int(current_configs["n"]) >= self._storage_policy.max_rule_configs
                ):
                    raise ThresholdRuleCapacityError("durable rule-config capacity reached")

                checkpoint_row = connection.execute(
                    """
                    SELECT sequence FROM monitor_consumer_checkpoints
                    WHERE consumer_id = ? AND scope = ?
                    """,
                    (self._consumer_id, rule.outbox_scope),
                ).fetchone()
                checkpoint = 0 if checkpoint_row is None else int(checkpoint_row["sequence"])
                old_progress = connection.execute(
                    """
                    SELECT COALESCE(MAX(last_sequence), 0) AS last_sequence
                    FROM monitor_threshold_rule_progress
                    WHERE consumer_id = ? AND rule_id = ?
                    """,
                    (self._consumer_id, rule.rule_id),
                ).fetchone()
                activation_sequence = max(checkpoint, int(old_progress["last_sequence"]))
                now = _finite_clock(self._clock)
                connection.execute(
                    """
                    INSERT INTO monitor_threshold_rule_configs
                        (consumer_id, rule_id, rule_version, scope, event_type,
                         config_json, activation_sequence, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        self._consumer_id,
                        rule.rule_id,
                        rule.rule_version,
                        rule.outbox_scope,
                        rule.event_type,
                        config_json,
                        activation_sequence,
                        now,
                    ),
                )
                connection.execute(
                    """
                    INSERT INTO monitor_threshold_rule_progress
                        (consumer_id, rule_id, rule_version, scope, last_sequence,
                         processed_events, late_events, updated_at)
                    VALUES (?, ?, ?, ?, ?, 0, 0, ?)
                    """,
                    (
                        self._consumer_id,
                        rule.rule_id,
                        rule.rule_version,
                        rule.outbox_scope,
                        activation_sequence,
                        now,
                    ),
                )
                connection.execute(
                    """
                    INSERT INTO monitor_threshold_rule_active
                        (consumer_id, rule_id, rule_version)
                    VALUES (?, ?, ?)
                    ON CONFLICT(consumer_id, rule_id) DO UPDATE SET
                        rule_version = excluded.rule_version
                    """,
                    (self._consumer_id, rule.rule_id, rule.rule_version),
                )

    def _assert_all_active(self) -> None:
        with self._outbox._connection() as connection:
            for rule in self._rules.values():
                self._assert_active_on_connection(connection, rule)

    def _assert_active_on_connection(self, connection, rule: ThresholdRule) -> None:
        active = connection.execute(
            """
            SELECT rule_version FROM monitor_threshold_rule_active
            WHERE consumer_id = ? AND rule_id = ?
            """,
            (self._consumer_id, rule.rule_id),
        ).fetchone()
        if active is None or int(active["rule_version"]) != rule.rule_version:
            raise ThresholdRuleError("this loop holds a superseded rule version")

    def _config_row(self, connection, rule: ThresholdRule):
        row = connection.execute(
            """
            SELECT activation_sequence FROM monitor_threshold_rule_configs
            WHERE consumer_id = ? AND rule_id = ? AND rule_version = ?
            """,
            (self._consumer_id, rule.rule_id, rule.rule_version),
        ).fetchone()
        if row is None:
            raise ThresholdRuleError("durable rule configuration is missing")
        return row


def _create_schema(connection) -> None:
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS monitor_threshold_storage_policy (
            policy_id INTEGER PRIMARY KEY CHECK (policy_id = 1),
            policy_json TEXT NOT NULL,
            created_at REAL NOT NULL
        )
        """
    )
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS monitor_threshold_rule_configs (
            consumer_id TEXT NOT NULL,
            rule_id TEXT NOT NULL,
            rule_version INTEGER NOT NULL,
            scope TEXT NOT NULL,
            event_type TEXT NOT NULL,
            config_json TEXT NOT NULL,
            activation_sequence INTEGER NOT NULL,
            created_at REAL NOT NULL,
            PRIMARY KEY (consumer_id, rule_id, rule_version)
        )
        """
    )
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS monitor_threshold_rule_active (
            consumer_id TEXT NOT NULL,
            rule_id TEXT NOT NULL,
            rule_version INTEGER NOT NULL,
            PRIMARY KEY (consumer_id, rule_id)
        )
        """
    )
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS monitor_threshold_rule_progress (
            consumer_id TEXT NOT NULL,
            rule_id TEXT NOT NULL,
            rule_version INTEGER NOT NULL,
            scope TEXT NOT NULL,
            last_sequence INTEGER NOT NULL,
            processed_events INTEGER NOT NULL,
            late_events INTEGER NOT NULL,
            updated_at REAL NOT NULL,
            PRIMARY KEY (consumer_id, rule_id, rule_version)
        )
        """
    )
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS monitor_threshold_rule_groups (
            consumer_id TEXT NOT NULL,
            rule_id TEXT NOT NULL,
            rule_version INTEGER NOT NULL,
            dimension_key TEXT NOT NULL,
            dimensions_json TEXT NOT NULL,
            window_json TEXT NOT NULL,
            armed INTEGER NOT NULL CHECK (armed IN (0, 1)),
            counted_events INTEGER NOT NULL,
            window_count INTEGER NOT NULL,
            watermark REAL,
            trading_day TEXT,
            late_events INTEGER NOT NULL,
            last_late_sequence INTEGER,
            last_late_event_id TEXT,
            last_late_reason TEXT,
            PRIMARY KEY (consumer_id, rule_id, rule_version, dimension_key)
        )
        """
    )
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS monitor_threshold_alert_outbox (
            alert_id TEXT PRIMARY KEY,
            consumer_id TEXT NOT NULL,
            rule_id TEXT NOT NULL,
            rule_version INTEGER NOT NULL,
            scope TEXT NOT NULL,
            event_type TEXT NOT NULL,
            dimensions_json TEXT NOT NULL,
            window_seconds REAL NOT NULL,
            threshold_count INTEGER NOT NULL,
            observed_count INTEGER NOT NULL,
            triggering_event_id TEXT NOT NULL,
            triggering_sequence INTEGER NOT NULL,
            source_event_id TEXT NOT NULL,
            source_stream_epoch TEXT,
            source_sequence INTEGER,
            source_completeness TEXT NOT NULL,
            triggered_at REAL NOT NULL,
            evaluated_watermark REAL NOT NULL,
            source_generation TEXT,
            delivery_state TEXT NOT NULL CHECK (delivery_state IN ('PENDING', 'DELIVERED')),
            attempts INTEGER NOT NULL,
            created_at REAL NOT NULL,
            delivered_at REAL
        )
        """
    )
    connection.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_monitor_threshold_alert_delivery
        ON monitor_threshold_alert_outbox(consumer_id, scope, delivery_state, created_at)
        """
    )
    connection.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_monitor_threshold_alert_retention
        ON monitor_threshold_alert_outbox(delivery_state, delivered_at)
        """
    )


def _ensure_storage_policy(
    connection,
    policy: ThresholdRuleStoragePolicy,
    clock: Callable[[], float],
) -> None:
    policy_json = _storage_policy_json(policy)
    current = connection.execute(
        "SELECT policy_json FROM monitor_threshold_storage_policy WHERE policy_id = 1"
    ).fetchone()
    if current is None:
        connection.execute(
            "INSERT INTO monitor_threshold_storage_policy(policy_id, policy_json, created_at) "
            "VALUES (1, ?, ?)",
            (policy_json, _finite_clock(clock)),
        )
    elif str(current["policy_json"]) != policy_json:
        raise ThresholdRuleError("storage policy does not match the durable database policy")
    totals = connection.execute(
        """
        SELECT
            (SELECT COUNT(*) FROM monitor_threshold_rule_configs) AS rule_configs,
            (SELECT COUNT(*) FROM monitor_threshold_rule_groups) AS dimension_groups,
            (SELECT COALESCE(SUM(window_count), 0) FROM monitor_threshold_rule_groups)
                AS window_events,
            (SELECT COALESCE(SUM(length(CAST(dimensions_json AS BLOB))), 0)
             FROM monitor_threshold_rule_groups) AS label_bytes,
            (SELECT COUNT(*) FROM monitor_threshold_alert_outbox) AS alert_rows
        """
    ).fetchone()
    if totals is None or (
        int(totals["rule_configs"]) > policy.max_rule_configs
        or int(totals["dimension_groups"]) > policy.max_dimension_groups
        or int(totals["window_events"]) > policy.max_window_events
        or int(totals["label_bytes"]) > policy.max_label_bytes
        or int(totals["alert_rows"]) > policy.max_alert_rows
    ):
        raise ThresholdRuleCapacityError("durable threshold state exceeds storage policy")


def _storage_policy_json(policy: ThresholdRuleStoragePolicy) -> str:
    return _canonical_json(
        {
            "alert_retention_seconds": policy.alert_retention_seconds,
            "max_alert_rows": policy.max_alert_rows,
            "max_dimension_groups": policy.max_dimension_groups,
            "max_label_bytes": policy.max_label_bytes,
            "max_rule_configs": policy.max_rule_configs,
            "max_window_events": policy.max_window_events,
            "schema_version": 1,
        }
    )


def _rule_config_json(rule: ThresholdRule) -> str:
    return _canonical_json(
        {
            "allowed_lateness_seconds": float(rule.allowed_lateness_seconds),
            "count_unit": "one_per_unique_outbox_sequence",
            "dimension_fields": list(rule.dimension_fields),
            "event_time_basis": "outbox.occurred_at_utc_epoch_seconds",
            "event_type": rule.event_type,
            "late_event_policy": rule.late_event_policy,
            "max_dimension_keys": rule.max_dimension_keys,
            "max_window_events": rule.max_window_events,
            "outbox_scope": rule.outbox_scope,
            "rule_id": rule.rule_id,
            "rule_version": rule.rule_version,
            "threshold_count": rule.threshold_count,
            "trading_day_field": rule.trading_day_field,
            "trading_day_policy": (
                "reset_forward_iso_day_reject_or_ignore_regression"
                if rule.trading_day_field is not None
                else "continuous_no_trading_day_partition"
            ),
            "window_boundary": "inclusive_event_time_gte_watermark_minus_window",
            "window_seconds": float(rule.window_seconds),
        }
    )


def _dimension_values(
    rule: ThresholdRule, item: SequencedOutboxEvent
) -> tuple[tuple[str, str], ...]:
    values = []
    for field in rule.dimension_fields:
        value = _source_data_value(item, field)
        if value is _MISSING:
            raise ThresholdRuleError("source event is missing a configured dimension")
        if field == "instrument_key" and isinstance(value, Mapping):
            encoded = _canonical_json(_plain_json(value))
        elif type(value) is str:
            encoded = value
        else:
            raise ThresholdRuleError("dimension values must be bounded text or instrument keys")
        try:
            raw = encoded.encode("utf-8", "strict")
        except UnicodeError:
            raise ThresholdRuleError("dimension value is not valid UTF-8") from None
        if (
            not raw
            or len(raw) > MAX_DIMENSION_VALUE_BYTES
            or any(ord(character) < 32 or ord(character) == 127 for character in encoded)
        ):
            raise ThresholdRuleError("dimension value is outside the bounded label range")
        values.append((field, encoded))
    dimension_json = _canonical_json(dict(values))
    if len(dimension_json.encode("utf-8")) > MAX_DIMENSION_KEY_BYTES:
        raise ThresholdRuleError("dimension key is outside the bounded label range")
    return tuple(values)


def _event_trading_day(rule: ThresholdRule, item: SequencedOutboxEvent) -> str | None:
    if rule.trading_day_field is None:
        return None
    value = _source_data_value(item, rule.trading_day_field)
    if type(value) is not str:
        raise ThresholdRuleError("source event requires an ISO trading_day")
    try:
        parsed = date.fromisoformat(value)
    except ValueError:
        raise ThresholdRuleError("source event trading_day is not ISO YYYY-MM-DD") from None
    if parsed.isoformat() != value:
        raise ThresholdRuleError("source event trading_day is not canonical ISO YYYY-MM-DD")
    return value


def _source_generation(item: SequencedOutboxEvent) -> str | None:
    value = _source_data_value(item, "reconnect_generation")
    if value is _MISSING:
        value = _source_data_value(item, "generation")
    if value is _MISSING or value is None:
        return None
    if type(value) is int and value >= 0:
        rendered = str(value)
    elif type(value) is str and value and value == value.strip():
        rendered = value
    else:
        raise ThresholdRuleError("source generation is outside the bounded metadata contract")
    try:
        encoded = rendered.encode("utf-8", "strict")
    except UnicodeError:
        raise ThresholdRuleError(
            "source generation is outside the bounded metadata contract"
        ) from None
    if len(encoded) > 128:
        raise ThresholdRuleError("source generation is outside the bounded metadata contract")
    return rendered


def _source_lineage(item: SequencedOutboxEvent) -> tuple[str, str | None, int | None]:
    """Keep bounded producer identity/cursor beside the durable outbox cursor.

    ``source_completeness`` on the alert deliberately remains
    ``received_event_only``: a producer sequence identifies this event but
    does not prove that the complete upstream stream or market state was seen.
    """

    source_event_id = item.event.data.get("source_event_id", item.event.event_id)
    _validate_lineage_text("source event ID", source_event_id, 256)
    payload = item.event.data.get("payload")
    source = payload.get("source", _MISSING) if isinstance(payload, Mapping) else _MISSING
    if source is _MISSING:
        return source_event_id, None, None
    if not isinstance(source, Mapping):
        raise ThresholdRuleError("source cursor metadata must be a mapping")
    epoch = source.get("stream_epoch", _MISSING)
    sequence = source.get("sequence", _MISSING)
    if epoch is _MISSING and sequence is _MISSING:
        return source_event_id, None, None
    if epoch is _MISSING or sequence is _MISSING:
        raise ThresholdRuleError("source cursor must include both epoch and sequence")
    _validate_lineage_text("source stream epoch", epoch, 128)
    if type(sequence) is not int or not 1 <= sequence < (1 << 63):
        raise ThresholdRuleError("source sequence is outside the bounded cursor range")
    return source_event_id, epoch, sequence


def _validate_lineage_text(name: str, value: object, max_bytes: int) -> None:
    if type(value) is not str or not value or value != value.strip():
        raise ThresholdRuleError(name + " is outside the bounded metadata contract")
    try:
        encoded = value.encode("utf-8", "strict")
    except UnicodeError:
        raise ThresholdRuleError(name + " is outside the bounded metadata contract") from None
    if len(encoded) > max_bytes or any(
        ord(character) < 32 or ord(character) == 127 for character in value
    ):
        raise ThresholdRuleError(name + " is outside the bounded metadata contract")


_MISSING = object()


def _source_data_value(item: SequencedOutboxEvent, field: str):
    payload = item.event.data.get("payload")
    if isinstance(payload, Mapping) and field in payload:
        return payload[field]
    return item.event.data.get(field, _MISSING)


def _make_alert(
    consumer_id: str,
    rule: ThresholdRule,
    dimensions: tuple[tuple[str, str], ...],
    item: SequencedOutboxEvent,
    triggered_at: float,
    watermark: float,
    source_generation: str | None,
    source_lineage: tuple[str, str | None, int | None],
    observed_count: int,
) -> ThresholdAlert:
    alert_id = _alert_id(consumer_id, rule, dimensions, item.event.event_id)
    source_event_id, source_stream_epoch, source_sequence = source_lineage
    return ThresholdAlert(
        alert_id=alert_id,
        rule_id=rule.rule_id,
        rule_version=rule.rule_version,
        outbox_scope=rule.outbox_scope,
        event_type=rule.event_type,
        dimensions=dimensions,
        window_seconds=float(rule.window_seconds),
        threshold_count=rule.threshold_count,
        observed_count=observed_count,
        triggering_event_id=item.event.event_id,
        triggering_sequence=item.sequence,
        source_event_id=source_event_id,
        source_stream_epoch=source_stream_epoch,
        source_sequence=source_sequence,
        source_completeness=_SOURCE_COMPLETENESS_EVENT_ONLY,
        triggered_at=triggered_at,
        evaluated_watermark=watermark,
        source_generation=source_generation,
    )


def _alert_id(
    consumer_id: str,
    rule: ThresholdRule,
    dimensions: tuple[tuple[str, str], ...],
    triggering_event_id: str,
) -> str:
    payload = {
        "consumer_id": consumer_id,
        "dimension_key": dict(dimensions),
        "domain": _ALERT_ID_DOMAIN,
        "event_id": triggering_event_id,
        "outbox_scope": rule.outbox_scope,
        "rule_id": rule.rule_id,
        "rule_version": rule.rule_version,
    }
    return THRESHOLD_ALERT_ID_PREFIX + _sha256(_canonical_json(payload).encode("utf-8"))


def _alert_from_row(row) -> ThresholdAlert:
    dimensions_raw = json.loads(str(row["dimensions_json"]))
    dimensions = tuple(sorted((str(key), str(value)) for key, value in dimensions_raw.items()))
    return ThresholdAlert(
        alert_id=str(row["alert_id"]),
        rule_id=str(row["rule_id"]),
        rule_version=int(row["rule_version"]),
        outbox_scope=str(row["scope"]),
        event_type=str(row["event_type"]),
        dimensions=dimensions,
        window_seconds=float(row["window_seconds"]),
        threshold_count=int(row["threshold_count"]),
        observed_count=int(row["observed_count"]),
        triggering_event_id=str(row["triggering_event_id"]),
        triggering_sequence=int(row["triggering_sequence"]),
        source_event_id=str(row["source_event_id"]),
        source_stream_epoch=(
            None if row["source_stream_epoch"] is None else str(row["source_stream_epoch"])
        ),
        source_sequence=(None if row["source_sequence"] is None else int(row["source_sequence"])),
        source_completeness=str(row["source_completeness"]),
        triggered_at=float(row["triggered_at"]),
        evaluated_watermark=float(row["evaluated_watermark"]),
        source_generation=(
            None if row["source_generation"] is None else str(row["source_generation"])
        ),
    )


def _decode_window(raw: object) -> list[list[object]]:
    try:
        value = json.loads(str(raw))
    except (TypeError, ValueError):
        raise ThresholdRuleError("persisted rule window is invalid") from None
    if type(value) is not list or any(
        type(entry) is not list
        or len(entry) != 3
        or type(entry[0]) not in (int, float)
        or not math.isfinite(float(entry[0]))
        or type(entry[1]) is not int
        or entry[1] <= 0
        or type(entry[2]) is not str
        or not entry[2]
        for entry in value
    ):
        raise ThresholdRuleError("persisted rule window is invalid")
    return value


def _canonical_json(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _plain_json(value):
    if isinstance(value, Mapping):
        return {key: _plain_json(nested) for key, nested in value.items()}
    if isinstance(value, (tuple, list)):
        return [_plain_json(nested) for nested in value]
    return value


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _finite_clock(clock: Callable[[], float]) -> float:
    value = clock()
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ThresholdRuleError("clock must return a finite timestamp")
    result = float(value)
    if not math.isfinite(result):
        raise ThresholdRuleError("clock must return a finite timestamp")
    return result


def _validate_scoped_text(name: str, value: object, max_bytes: int) -> None:
    if type(value) is not str or not value or value != value.strip():
        raise ThresholdRuleError(name + " is required and must be trimmed text")
    try:
        encoded = value.encode("utf-8", "strict")
    except UnicodeError:
        raise ThresholdRuleError(name + " is not valid UTF-8") from None
    if len(encoded) > max_bytes or any(
        ord(character) < 32 or ord(character) == 127 for character in value
    ):
        raise ThresholdRuleError(name + " is outside the bounded text range")
    if "*" in value:
        raise ThresholdRuleError(name + " must not contain wildcards")


__all__ = [
    "DEFAULT_ALERT_RETENTION_SECONDS",
    "DEFAULT_MAX_DIMENSION_KEYS",
    "DEFAULT_MAX_WINDOW_EVENTS",
    "DEFAULT_RULE_CONSUMER_ID",
    "MAX_DIMENSION_FIELDS",
    "MAX_DIMENSION_KEYS",
    "MAX_RULE_THRESHOLD_COUNT",
    "MAX_RULE_VERSION",
    "MAX_RULE_WINDOW_SECONDS",
    "MAX_RUN_LIMIT",
    "MAX_PERSISTED_ALERT_ROWS",
    "MAX_PERSISTED_DIMENSION_GROUPS",
    "MAX_PERSISTED_LABEL_BYTES",
    "MAX_PERSISTED_RULE_CONFIGS",
    "MAX_PERSISTED_WINDOW_EVENTS",
    "MAX_WINDOW_EVENTS",
    "DEFAULT_THRESHOLD_STORAGE_POLICY",
    "THRESHOLD_ALERT_ID_PREFIX",
    "ScopedThresholdRuleLoop",
    "ThresholdAlert",
    "ThresholdLateEventError",
    "ThresholdRule",
    "ThresholdRuleCapacityError",
    "ThresholdRuleError",
    "ThresholdRuleStatus",
    "ThresholdRuleStoragePolicy",
]
