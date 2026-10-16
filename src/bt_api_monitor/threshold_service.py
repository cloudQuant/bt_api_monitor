"""Trusted operator composition for durable threshold-rule consumers.

The service-resource provider below is the supported startup seam.  It wraps
the same provider that supplies Monitor's normal writable outbox and ingress
targets, then makes the threshold worker an owned Host resource.  Rule JSON is
operator input parsed before start; request arguments never select a rule,
scope, retention window, or storage budget.
"""

from __future__ import annotations

import json
import multiprocessing
import threading
import time
from collections.abc import Mapping
from contextlib import suppress
from dataclasses import dataclass
from types import MappingProxyType
from typing import Callable

from bt_api_base.service_protocol import WireScope

from .durable import (
    MAX_OUTBOX_CAPACITY_BYTES,
    MAX_OUTBOX_CAPACITY_EVENTS,
    DurableOutbox,
    OutboxCapacityError,
    OutboxConflictError,
    OutboxEvent,
)
from .service_ingress import MonitorIngressTarget
from .threshold_rules import (
    THRESHOLD_ALERT_ID_PREFIX,
    ScopedThresholdRuleLoop,
    ThresholdAlert,
    ThresholdRule,
    ThresholdRuleError,
    ThresholdRuleStoragePolicy,
)

THRESHOLD_ALERT_EVENT_TYPE = "monitor.threshold_alert.v1"
THRESHOLD_ALERT_SCHEMA = "bt_api.monitor.threshold_alert.v1"
MAX_THRESHOLD_CONFIG_BYTES = 65_536
MAX_THRESHOLD_RULES = 64
MAX_THRESHOLD_TARGETS = 64
MAX_THRESHOLD_RULE_WINDOW_TOTAL = 131_072
MAX_THRESHOLD_RULE_LABEL_TOTAL = 32_768
MAX_WORKER_STARTUP_SECONDS = 30.0
MAX_WORKER_SHUTDOWN_SECONDS = 10.0
MAX_WORKER_POLL_SECONDS = 2.0
MAX_WORKER_RESTARTS_PER_WINDOW = 8
WORKER_RESTART_WINDOW_SECONDS = 60.0
_CONFIG_FIELDS = frozenset(
    {"schema_version", "consumer_id", "outbox_max_events", "outbox_max_bytes", "storage_policy", "rules"}
)
_STORAGE_FIELDS = frozenset(
    {
        "max_rule_configs",
        "max_dimension_groups",
        "max_window_events",
        "max_label_bytes",
        "max_alert_rows",
        "alert_retention_seconds",
    }
)
_RULE_FIELDS = frozenset(
    {
        "rule_id",
        "rule_version",
        "target_ref",
        "event_type",
        "window_seconds",
        "threshold_count",
        "dimension_fields",
        "max_dimension_keys",
        "max_window_events",
        "allowed_lateness_seconds",
        "late_event_policy",
        "trading_day_field",
    }
)
_SAFE_REF_CHARS = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._:-")


class ThresholdServiceError(RuntimeError):
    """A finite trusted-configuration or worker lifecycle failure."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True)
class TrustedThresholdTarget:
    """One operator-owned exact account/strategy binding for Monitor ingress."""

    target_ref: str
    scope: WireScope
    ingress_target: MonitorIngressTarget

    def __post_init__(self) -> None:
        _validate_ref(self.target_ref, "INVALID_TRUSTED_TARGET")
        if type(self.scope) is not WireScope or type(self.ingress_target) is not MonitorIngressTarget:
            raise ThresholdServiceError("INVALID_TRUSTED_TARGET")
        if (
            not self.scope.execution_domain_ref
            or not self.scope.account_ref
            or not self.scope.strategy_ref
            or self.scope.account_refs
            or self.scope.group_id is not None
            or self.scope.leg_id is not None
        ):
            raise ThresholdServiceError("EXACT_ACCOUNT_STRATEGY_SCOPE_REQUIRED")
        if THRESHOLD_ALERT_EVENT_TYPE in self.ingress_target.event_types:
            raise ThresholdServiceError("ALERT_EVENT_KIND_MUST_NOT_BE_INGRESS_GRANTED")


@dataclass(frozen=True)
class ThresholdServiceConfig:
    """Immutable rules parsed from a bounded operator-owned JSON document."""

    consumer_id: str
    outbox_max_events: int
    outbox_max_bytes: int
    storage_policy: ThresholdRuleStoragePolicy
    rules: tuple[ThresholdRule, ...]
    target_refs: tuple[str, ...]


def parse_threshold_service_config(
    document: bytes | str,
    trusted_targets: Mapping[str, TrustedThresholdTarget],
) -> ThresholdServiceConfig:
    """Parse strict operator policy and bind every rule to trusted scope data.

    The JSON can choose rule semantics within fixed limits but cannot provide
    an outbox scope or account/strategy identity.  Those are resolved only
    through ``trusted_targets`` supplied by the operator from its Registry and
    ingress-target configuration.
    """

    if type(document) is bytes:
        if not 1 <= len(document) <= MAX_THRESHOLD_CONFIG_BYTES:
            raise ThresholdServiceError("CONFIG_SIZE_INVALID")
        try:
            text = document.decode("utf-8", "strict")
        except UnicodeError:
            raise ThresholdServiceError("CONFIG_ENCODING_INVALID") from None
    elif type(document) is str:
        try:
            encoded = document.encode("utf-8", "strict")
        except UnicodeError:
            raise ThresholdServiceError("CONFIG_ENCODING_INVALID") from None
        if not 1 <= len(encoded) <= MAX_THRESHOLD_CONFIG_BYTES:
            raise ThresholdServiceError("CONFIG_SIZE_INVALID")
        text = document
    else:
        raise ThresholdServiceError("CONFIG_DOCUMENT_REQUIRED")

    if not isinstance(trusted_targets, Mapping) or not 1 <= len(trusted_targets) <= MAX_THRESHOLD_TARGETS:
        raise ThresholdServiceError("TRUSTED_TARGETS_REQUIRED")
    copied_targets: dict[str, TrustedThresholdTarget] = {}
    scopes_seen: set[WireScope] = set()
    outbox_scopes_seen: set[str] = set()
    for key, target in trusted_targets.items():
        if type(target) is not TrustedThresholdTarget or key != target.target_ref:
            raise ThresholdServiceError("INVALID_TRUSTED_TARGETS")
        if target.scope in scopes_seen or target.ingress_target.outbox_scope in outbox_scopes_seen:
            raise ThresholdServiceError("AMBIGUOUS_TRUSTED_TARGETS")
        scopes_seen.add(target.scope)
        outbox_scopes_seen.add(target.ingress_target.outbox_scope)
        copied_targets[key] = target

    try:
        raw = json.loads(
            text,
            object_pairs_hook=_unique_object,
            parse_constant=_reject_json_constant,
        )
    except Exception:
        raise ThresholdServiceError("CONFIG_JSON_INVALID") from None
    if type(raw) is not dict or set(raw) != _CONFIG_FIELDS:
        raise ThresholdServiceError("CONFIG_FIELDS_INVALID")
    if type(raw["schema_version"]) is not int or raw["schema_version"] != 1:
        raise ThresholdServiceError("CONFIG_VERSION_UNSUPPORTED")
    consumer_id = raw["consumer_id"]
    _validate_ref(consumer_id, "CONSUMER_ID_INVALID")
    max_events = raw["outbox_max_events"]
    max_bytes = raw["outbox_max_bytes"]
    if (
        type(max_events) is not int
        or not 1 <= max_events <= MAX_OUTBOX_CAPACITY_EVENTS
        or type(max_bytes) is not int
        or not 1 <= max_bytes <= MAX_OUTBOX_CAPACITY_BYTES
    ):
        raise ThresholdServiceError("OUTBOX_CAPACITY_INVALID")

    storage = raw["storage_policy"]
    if type(storage) is not dict or set(storage) != _STORAGE_FIELDS:
        raise ThresholdServiceError("STORAGE_POLICY_FIELDS_INVALID")
    try:
        policy = ThresholdRuleStoragePolicy(
            max_rule_configs=storage["max_rule_configs"],
            max_dimension_groups=storage["max_dimension_groups"],
            max_window_events=storage["max_window_events"],
            max_label_bytes=storage["max_label_bytes"],
            max_alert_rows=storage["max_alert_rows"],
            alert_retention_seconds=storage["alert_retention_seconds"],
        )
    except ThresholdRuleError:
        raise ThresholdServiceError("STORAGE_POLICY_INVALID") from None

    raw_rules = raw["rules"]
    if type(raw_rules) is not list or not 1 <= len(raw_rules) <= MAX_THRESHOLD_RULES:
        raise ThresholdServiceError("RULE_COUNT_INVALID")
    parsed_rules: list[ThresholdRule] = []
    target_refs: list[str] = []
    rule_ids: set[str] = set()
    dimension_key_budget = 0
    window_event_budget = 0
    label_budget = 0
    for item in raw_rules:
        if type(item) is not dict or set(item) != _RULE_FIELDS:
            raise ThresholdServiceError("RULE_FIELDS_INVALID")
        target_ref = item["target_ref"]
        _validate_ref(target_ref, "RULE_TARGET_INVALID")
        target = copied_targets.get(target_ref)
        if target is None:
            raise ThresholdServiceError("RULE_TARGET_NOT_TRUSTED")
        event_type = item["event_type"]
        if (
            type(event_type) is not str
            or event_type == THRESHOLD_ALERT_EVENT_TYPE
            or event_type not in target.ingress_target.event_types
        ):
            raise ThresholdServiceError("RULE_EVENT_TYPE_NOT_GRANTED")
        dimensions = item["dimension_fields"]
        if type(dimensions) is not list or any(type(field) is not str for field in dimensions):
            raise ThresholdServiceError("RULE_DIMENSIONS_INVALID")
        try:
            rule = ThresholdRule(
                rule_id=item["rule_id"],
                outbox_scope=target.ingress_target.outbox_scope,
                event_type=event_type,
                window_seconds=item["window_seconds"],
                threshold_count=item["threshold_count"],
                rule_version=item["rule_version"],
                dimension_fields=tuple(dimensions),
                max_dimension_keys=item["max_dimension_keys"],
                max_window_events=item["max_window_events"],
                allowed_lateness_seconds=item["allowed_lateness_seconds"],
                late_event_policy=item["late_event_policy"],
                trading_day_field=item["trading_day_field"],
            )
        except ThresholdRuleError:
            raise ThresholdServiceError("RULE_INVALID") from None
        if rule.rule_id in rule_ids:
            raise ThresholdServiceError("DUPLICATE_RULE_ID")
        rule_ids.add(rule.rule_id)
        parsed_rules.append(rule)
        target_refs.append(target_ref)
        dimension_key_budget += rule.max_dimension_keys
        window_event_budget += rule.max_window_events
        label_budget += rule.max_dimension_keys * 2_048

    if len(parsed_rules) > policy.max_rule_configs:
        raise ThresholdServiceError("RULE_COUNT_EXCEEDS_GLOBAL_POLICY")
    if dimension_key_budget > policy.max_dimension_groups:
        raise ThresholdServiceError("DIMENSION_BUDGET_EXCEEDS_GLOBAL_POLICY")
    if window_event_budget > policy.max_window_events or window_event_budget > MAX_THRESHOLD_RULE_WINDOW_TOTAL:
        raise ThresholdServiceError("WINDOW_BUDGET_EXCEEDS_GLOBAL_POLICY")
    if dimension_key_budget * 5 > MAX_THRESHOLD_RULE_LABEL_TOTAL:
        raise ThresholdServiceError("LABEL_CARDINALITY_EXCEEDS_GLOBAL_POLICY")
    if label_budget > policy.max_label_bytes:
        raise ThresholdServiceError("LABEL_STORAGE_EXCEEDS_GLOBAL_POLICY")

    return ThresholdServiceConfig(
        consumer_id=consumer_id,
        outbox_max_events=max_events,
        outbox_max_bytes=max_bytes,
        storage_policy=policy,
        rules=tuple(parsed_rules),
        target_refs=tuple(target_refs),
    )


class ThresholdRuleConsumerSupervisor:
    """Own one spawned SQLite consumer and restart it after bounded failures."""

    def __init__(
        self,
        database_path: str,
        config: ThresholdServiceConfig,
        *,
        startup_timeout_seconds: float = 10.0,
        shutdown_timeout_seconds: float = 5.0,
        poll_interval_seconds: float = 0.05,
    ) -> None:
        for name, value, maximum in (
            ("startup_timeout_seconds", startup_timeout_seconds, MAX_WORKER_STARTUP_SECONDS),
            ("shutdown_timeout_seconds", shutdown_timeout_seconds, MAX_WORKER_SHUTDOWN_SECONDS),
            ("poll_interval_seconds", poll_interval_seconds, MAX_WORKER_POLL_SECONDS),
        ):
            if (
                isinstance(value, bool)
                or type(value) not in (int, float)
                or not 0.01 <= float(value) <= maximum
            ):
                raise ThresholdServiceError(name.upper() + "_INVALID")
        if type(config) is not ThresholdServiceConfig:
            raise ThresholdServiceError("PARSED_CONFIG_REQUIRED")
        if type(database_path) is not str or not database_path:
            raise ThresholdServiceError("DATABASE_PATH_REQUIRED")
        self._database_path = database_path
        self._config = config
        self._startup_timeout = float(startup_timeout_seconds)
        self._shutdown_timeout = float(shutdown_timeout_seconds)
        self._poll_interval = float(poll_interval_seconds)
        self._context = multiprocessing.get_context("spawn")
        self._lock = threading.RLock()
        self._close_call_lock = threading.Lock()
        self._stop = threading.Event()
        self._process = None
        self._pipe = None
        self._extra_pipes: list[object] = []
        self._thread: threading.Thread | None = None
        self._state = "new"
        self._ready = False
        self._closed = False
        self._start_count = 0
        self._restart_count = 0
        self._last_exit_code: int | None = None
        self._last_failure_code: str | None = None
        self._restart_times: list[float] = []

    @property
    def ready(self) -> bool:
        with self._lock:
            return self._ready and not self._closed

    @property
    def status(self) -> Mapping[str, object]:
        with self._lock:
            process = self._process
            return MappingProxyType(
                {
                    "state": self._state,
                    "ready": self._ready and not self._closed,
                    "process_id": None if process is None else process.pid,
                    "start_count": self._start_count,
                    "restart_count": self._restart_count,
                    "last_exit_code": self._last_exit_code,
                    "last_failure_code": self._last_failure_code,
                    "outstanding_pipe_count": (self._pipe is not None) + len(self._extra_pipes),
                    "closed": self._state == "closed",
                }
            )

    def start(self) -> ThresholdRuleConsumerSupervisor:
        with self._lock:
            if self._state != "new":
                raise ThresholdServiceError("WORKER_INVALID_STATE")
            self._state = "starting"
            self._spawn_ready_locked()
            self._thread = threading.Thread(
                target=self._supervise,
                name="monitor-threshold-rule-supervisor",
                daemon=True,
            )
            self._thread.start()
            return self

    def close(self) -> None:
        with self._close_call_lock:
            failures: list[str] = []
            with self._lock:
                if self._state == "closed":
                    return
                self._closed = True
                self._ready = False
                self._state = "closing"
                self._stop.set()
                process = self._process
                pipe = self._pipe

            if process is not None and pipe is not None and getattr(process, "pid", None) is not None:
                try:
                    if process.is_alive():
                        pipe.send(("close",))
                        if not pipe.poll(self._shutdown_timeout):
                            failures.append("WORKER_CLOSE_ACK_TIMEOUT")
                        else:
                            reply = pipe.recv()
                            if reply != ("closed",):
                                failures.append("WORKER_CLOSE_ACK_INVALID")
                except Exception:
                    failures.append("WORKER_CLOSE_ACK_FAILED")

            process_reaped = process is None or self._reap_process(process, failures)
            if process is not None and process_reaped:
                with self._lock:
                    if self._process is process:
                        self._process = None

            if pipe is not None and self._close_pipe(pipe, failures):
                with self._lock:
                    if self._pipe is pipe:
                        self._pipe = None

            with self._lock:
                self._extra_pipes = [
                    extra_pipe
                    for extra_pipe in self._extra_pipes
                    if not self._close_pipe(extra_pipe, failures)
                ]
                thread = self._thread

            if thread is not None and thread.ident is not None:
                if thread is threading.current_thread():
                    failures.append("SUPERVISOR_THREAD_JOIN_SELF")
                else:
                    thread.join(self._shutdown_timeout)
                    if thread.is_alive():
                        failures.append("SUPERVISOR_THREAD_JOIN_TIMEOUT")

            with self._lock:
                resources_closed = (
                    self._process is None
                    and self._pipe is None
                    and not self._extra_pipes
                    and (thread is None or thread.ident is None or not thread.is_alive())
                )
                self._state = "closed" if resources_closed and not failures else "close_uncertain"
                if failures:
                    self._last_failure_code = failures[0]
            if failures or not resources_closed:
                raise ThresholdServiceError("WORKER_CLOSE_UNCONFIRMED")

    def _spawn_ready_locked(self) -> None:
        parent_pipe = child_pipe = process = None
        try:
            parent_pipe, child_pipe = self._context.Pipe(duplex=True)
            process = self._context.Process(
                target=_threshold_worker_entry,
                args=(
                    self._database_path,
                    self._config.rules,
                    self._config.consumer_id,
                    self._config.outbox_max_events,
                    self._config.outbox_max_bytes,
                    self._config.storage_policy,
                    child_pipe,
                    self._poll_interval,
                ),
                name="monitor-threshold-rule-consumer",
            )
            process.start()
            child_pipe.close()
            child_pipe = None
            if not parent_pipe.poll(self._startup_timeout):
                raise ThresholdServiceError("WORKER_READY_TIMEOUT")
            message = parent_pipe.recv()
            if message != ("ready", 1):
                if type(message) is tuple and len(message) == 2 and message[0] == "failed":
                    self._last_failure_code = _safe_failure_code(message[1])
                raise ThresholdServiceError("WORKER_START_REJECTED")
        except BaseException:
            cleanup_failures: list[str] = []
            if process is not None:
                if self._reap_process(process, cleanup_failures):
                    process = None
                else:
                    self._process = process
            if parent_pipe is not None:
                if self._close_pipe(parent_pipe, cleanup_failures):
                    parent_pipe = None
                else:
                    self._pipe = parent_pipe
            if child_pipe is not None:
                if self._close_pipe(child_pipe, cleanup_failures):
                    child_pipe = None
                else:
                    self._extra_pipes.append(child_pipe)
            if cleanup_failures:
                self._last_failure_code = "START_CLEANUP_UNCONFIRMED"
                self._ready = False
                self._state = "start_cleanup_uncertain"
            raise
        self._process = process
        self._pipe = parent_pipe
        self._start_count += 1
        self._ready = True
        self._state = "ready"

    def _supervise(self) -> None:
        while not self._stop.wait(self._poll_interval):
            delay = 0.0
            with self._lock:
                if self._closed:
                    return
                process = self._process
                if process is None:
                    if self._state != "restart_failed":
                        continue
                    now = time.monotonic()
                    self._restart_times = [
                        value for value in self._restart_times
                        if now - value <= WORKER_RESTART_WINDOW_SECONDS
                    ]
                    if len(self._restart_times) >= MAX_WORKER_RESTARTS_PER_WINDOW:
                        self._state = "restart_limit"
                        return
                    self._restart_times.append(now)
                    self._restart_count += 1
                    self._state = "restarting"
                    delay = min(0.1 * (2 ** min(self._restart_count - 1, 4)), 2.0)
                elif process.is_alive():
                    continue
                else:
                    pipe = self._pipe
                    self._last_failure_code = self._read_failure_code(pipe)
                    self._last_exit_code = process.exitcode
                    reap_failures: list[str] = []
                    self._ready = False
                    process_reaped = self._reap_process(process, reap_failures)
                    pipe_closed = self._close_pipe(pipe, reap_failures)
                    if process_reaped:
                        self._process = None
                    if pipe_closed:
                        self._pipe = None
                    if not process_reaped or not pipe_closed:
                        self._last_failure_code = "CHILD_CLEANUP_UNCONFIRMED"
                        self._state = "cleanup_uncertain"
                        return
                    now = time.monotonic()
                    self._restart_times = [
                        value for value in self._restart_times
                        if now - value <= WORKER_RESTART_WINDOW_SECONDS
                    ]
                    if reap_failures:
                        self._last_failure_code = "CHILD_CLEANUP_UNCONFIRMED"
                    if len(self._restart_times) >= MAX_WORKER_RESTARTS_PER_WINDOW:
                        self._state = "restart_limit"
                        return
                    self._restart_times.append(now)
                    self._restart_count += 1
                    self._state = "restarting"
                    delay = min(0.1 * (2 ** min(self._restart_count - 1, 4)), 2.0)
            if self._stop.wait(delay):
                return
            with self._lock:
                if self._closed:
                    return
                try:
                    self._spawn_ready_locked()
                except BaseException:
                    self._ready = False
                    if self._process is not None or self._pipe is not None or self._extra_pipes:
                        self._state = "restart_cleanup_uncertain"
                        return
                    self._state = "restart_failed"

    def _read_failure_code(self, pipe: object | None) -> str | None:
        if pipe is None:
            return self._last_failure_code
        try:
            if pipe.poll(0):  # type: ignore[attr-defined]
                message = pipe.recv()  # type: ignore[attr-defined]
                if type(message) is tuple and len(message) == 2 and message[0] == "failed":
                    return _safe_failure_code(message[1])
        except Exception:
            return "CHILD_STATUS_UNAVAILABLE"
        return self._last_failure_code

    def _reap_process(self, process: object, failures: list[str]) -> bool:
        if getattr(process, "_closed", False):
            return True
        try:
            pid = getattr(process, "pid", None)
            if pid is not None:
                process.join(self._shutdown_timeout)  # type: ignore[attr-defined]
            if pid is not None and process.is_alive():  # type: ignore[attr-defined]
                process.terminate()  # type: ignore[attr-defined]
                process.join(self._shutdown_timeout)  # type: ignore[attr-defined]
            if (
                pid is not None
                and process.is_alive()  # type: ignore[attr-defined]
                and callable(getattr(process, "kill", None))
            ):
                process.kill()  # type: ignore[attr-defined]
                process.join(self._shutdown_timeout)  # type: ignore[attr-defined]
            if pid is not None and process.is_alive():  # type: ignore[attr-defined]
                failures.append("CHILD_PROCESS_REAP_UNCONFIRMED")
                return False
            process.close()  # type: ignore[attr-defined]
            return True
        except Exception:
            failures.append("CHILD_PROCESS_CLEANUP_FAILED")
            return bool(getattr(process, "_closed", False))

    @staticmethod
    def _close_pipe(pipe: object | None, failures: list[str]) -> bool:
        if pipe is None:
            return True
        try:
            pipe.close()  # type: ignore[attr-defined]
            return True
        except Exception:
            failures.append("CHILD_PIPE_CLOSE_FAILED")
            return False


class MonitorThresholdResourceProvider:
    """Wrap a normal Host provider and own a scoped threshold worker at start.

    Construct this in the trusted local operator using a fixed parsed service
    config, Registry-derived grants/targets, and the existing provider that
    supplies Monitor's writable outbox.  It is not a wire-facing API.
    """

    def __init__(
        self,
        resource_provider: Callable[..., object],
        *,
        monitor_instance_id: str,
        config_document: bytes | str,
        trusted_targets: Mapping[str, TrustedThresholdTarget],
        startup_timeout_seconds: float = 10.0,
        shutdown_timeout_seconds: float = 5.0,
        poll_interval_seconds: float = 0.05,
    ) -> None:
        if not callable(resource_provider):
            raise ThresholdServiceError("BASE_RESOURCE_PROVIDER_REQUIRED")
        _validate_ref(monitor_instance_id, "MONITOR_INSTANCE_INVALID")
        self._provider = resource_provider
        self._instance_id = monitor_instance_id
        self._targets = MappingProxyType(dict(trusted_targets))
        self._config = parse_threshold_service_config(config_document, self._targets)
        self._startup_timeout = startup_timeout_seconds
        self._shutdown_timeout = shutdown_timeout_seconds
        self._poll_interval = poll_interval_seconds
        self._supervisor_lock = threading.Lock()
        self._supervisor: ThresholdRuleConsumerSupervisor | None = None

    @property
    def status(self) -> Mapping[str, object]:
        """Finite local operator view of this provider's owned child."""

        with self._supervisor_lock:
            supervisor = self._supervisor
        if supervisor is None:
            return MappingProxyType(
                {
                    "state": "not_started",
                    "ready": False,
                    "process_id": None,
                    "start_count": 0,
                    "restart_count": 0,
                    "last_exit_code": None,
                    "last_failure_code": None,
                    "outstanding_pipe_count": 0,
                    "closed": False,
                }
            )
        return supervisor.status

    def close(self) -> None:
        """Retry cleanup when a prior Host/startup close was uncertain."""

        with self._supervisor_lock:
            supervisor = self._supervisor
        if supervisor is not None:
            state = supervisor.status["state"]
            if state == "closed":
                return
            if not isinstance(state, str) or not state.endswith("_uncertain"):
                raise ThresholdServiceError("SUPERVISOR_CLOSE_RETRY_NOT_PENDING")
            supervisor.close()

    def __call__(
        self,
        component: str,
        instance_id: str,
        options: Mapping[str, object],
        scope: WireScope,
    ):
        resources = self._provider(component, instance_id, options, scope)
        if component != "monitor" or instance_id != self._instance_id:
            return resources
        supervisor: ThresholdRuleConsumerSupervisor | None = None
        try:
            if not isinstance(options, Mapping) or options.get("role") != "durable_ingress":
                raise ThresholdServiceError("DURABLE_INGRESS_ROLE_REQUIRED")
            if type(scope) is not WireScope:
                raise ThresholdServiceError("HOST_SCOPE_INVALID")
            _validate_bound_targets(self._targets, resources, scope)
            outbox = resources.values.get("outbox")  # type: ignore[attr-defined]
            if type(outbox) is not DurableOutbox or outbox.is_read_only:
                raise ThresholdServiceError("WRITABLE_OUTBOX_REQUIRED")
            supervisor = ThresholdRuleConsumerSupervisor(
                str(outbox.database_path),
                self._config,
                startup_timeout_seconds=self._startup_timeout,
                shutdown_timeout_seconds=self._shutdown_timeout,
                poll_interval_seconds=self._poll_interval,
            )
            with self._supervisor_lock:
                current = self._supervisor
                if current is not None and current.status["state"] != "closed":
                    raise ThresholdServiceError("THRESHOLD_SUPERVISOR_ALREADY_BOUND")
                self._supervisor = supervisor
            supervisor.start()
            return _owned_resources_with_supervisor(resources, supervisor)
        except BaseException as primary:
            cleanup: list[str] = []
            if supervisor is not None:
                with self._supervisor_lock:
                    if self._supervisor is None:
                        self._supervisor = supervisor
                try:
                    supervisor.close()
                except Exception:
                    cleanup.append("THRESHOLD_WORKER_CLOSE_FAILED")
            try:
                resources.close()  # type: ignore[attr-defined]
            except Exception:
                cleanup.append("BASE_RESOURCE_CLOSE_FAILED")
            if cleanup:
                with suppress(Exception):
                    setattr(  # noqa: B010 - preserve the original startup exception.
                        primary, "threshold_cleanup_codes", tuple(cleanup)
                    )
            raise


def create_monitor_threshold_resource_provider(
    resource_provider: Callable[..., object],
    *,
    monitor_instance_id: str,
    config_document: bytes | str,
    trusted_targets: Mapping[str, TrustedThresholdTarget],
    startup_timeout_seconds: float = 10.0,
    shutdown_timeout_seconds: float = 5.0,
    poll_interval_seconds: float = 0.05,
) -> MonitorThresholdResourceProvider:
    """Create the callable passed to normal ``ServiceHost`` startup.

    The operator supplies the already-selected Monitor resource provider,
    bounded rule document, and target map built from the deployment's exact
    Registry grants.  Parsing and scope binding happen here, before Host start;
    the spawned consumer is then started/closed with the Monitor component's
    ordinary resource lifecycle.
    """

    return MonitorThresholdResourceProvider(
        resource_provider,
        monitor_instance_id=monitor_instance_id,
        config_document=config_document,
        trusted_targets=trusted_targets,
        startup_timeout_seconds=startup_timeout_seconds,
        shutdown_timeout_seconds=shutdown_timeout_seconds,
        poll_interval_seconds=poll_interval_seconds,
    )


def _owned_resources_with_supervisor(resources: object, supervisor: ThresholdRuleConsumerSupervisor):
    try:
        from bt_api_py.service_components import ComponentResources
    except Exception:
        raise ThresholdServiceError("HOST_RESOURCE_API_UNAVAILABLE") from None
    if type(resources) is not ComponentResources:
        raise ThresholdServiceError("HOST_RESOURCES_INVALID")

    def close_owned() -> None:
        first: BaseException | None = None
        try:
            supervisor.close()
        except BaseException as exc:
            first = exc
        try:
            resources.close()
        except BaseException as exc:
            if first is None:
                first = exc
        if first is not None:
            raise first

    return ComponentResources.owned(
        resources.values,
        ready=lambda: resources.ready() is True and supervisor.ready,
        close=close_owned,
        internal_ports=resources.internal_ports,
        risk_policy_bindings=resources.risk_policy_bindings,
        shared_collateral_domains=resources.shared_collateral_domains,
    )


def _validate_bound_targets(
    trusted_targets: Mapping[str, TrustedThresholdTarget], resources: object, host_scope: WireScope
) -> None:
    values = getattr(resources, "values", None)
    targets = values.get("targets") if isinstance(values, Mapping) else None
    if not isinstance(targets, Mapping) or len(targets) != len(trusted_targets):
        raise ThresholdServiceError("INGRESS_TARGET_BINDING_MISMATCH")
    for binding in trusted_targets.values():
        if binding.scope.execution_domain_ref != host_scope.execution_domain_ref:
            raise ThresholdServiceError("TARGET_DOMAIN_MISMATCH")
        for field in ("account_ref", "strategy_ref", "portfolio_ref", "manual_book_ref"):
            expected = getattr(host_scope, field)
            if expected is not None and getattr(binding.scope, field) != expected:
                raise ThresholdServiceError("TARGET_OUTSIDE_HOST_SCOPE")
        if targets.get(binding.scope) != binding.ingress_target:
            raise ThresholdServiceError("INGRESS_TARGET_BINDING_MISMATCH")


def _threshold_worker_entry(
    database_path: str,
    rules: tuple[ThresholdRule, ...],
    consumer_id: str,
    outbox_max_events: int,
    outbox_max_bytes: int,
    storage_policy: ThresholdRuleStoragePolicy,
    control,
    poll_interval: float,
) -> None:
    outbox = None
    try:
        outbox = DurableOutbox(database_path)

        def append_alert(alert: ThresholdAlert) -> None:
            if (
                type(alert) is not ThresholdAlert
                or alert.alert_id.startswith(THRESHOLD_ALERT_ID_PREFIX) is False
                or alert.outbox_scope not in {rule.outbox_scope for rule in rules}
                or alert.event_type == THRESHOLD_ALERT_EVENT_TYPE
            ):
                raise ThresholdServiceError("ALERT_SCOPE_OR_KIND_INVALID")
            event = OutboxEvent(
                event_id=alert.alert_id,
                scope=alert.outbox_scope,
                event_type=THRESHOLD_ALERT_EVENT_TYPE,
                data={
                    "schema": THRESHOLD_ALERT_SCHEMA,
                    "alert_id": alert.alert_id,
                    "rule_id": alert.rule_id,
                    "rule_version": alert.rule_version,
                    "source_event_type": alert.event_type,
                    "source_event_id": alert.source_event_id,
                    "triggering_event_id": alert.triggering_event_id,
                    "triggering_sequence": alert.triggering_sequence,
                    "dimensions": dict(alert.dimensions),
                    "observed_count": alert.observed_count,
                    "threshold_count": alert.threshold_count,
                    "window_seconds": alert.window_seconds,
                    "source_completeness": alert.source_completeness,
                    "triggered_at": alert.triggered_at,
                },
                occurred_at=alert.triggered_at,
            )
            try:
                outbox.append_bounded(
                    event,
                    max_events=outbox_max_events,
                    max_bytes=outbox_max_bytes,
                )
            except OutboxCapacityError:
                raise ThresholdServiceError("ALERT_OUTBOX_CAPACITY") from None
            except OutboxConflictError:
                raise ThresholdServiceError("ALERT_OUTBOX_ID_CONFLICT") from None

        loop = ScopedThresholdRuleLoop(
            outbox,
            rules,
            append_alert,
            consumer_id=consumer_id,
            storage_policy=storage_policy,
        )
        control.send(("ready", 1))
        while True:
            if control.poll(poll_interval):
                command = control.recv()
                if command == ("close",):
                    control.send(("closed",))
                    return
                if command != ("status",):
                    control.send(("failed", "CONTROL_MESSAGE_INVALID"))
                    raise SystemExit(2)
                control.send(("status", loop.configured_scopes))
            loop.run_once(limit=100)
    except SystemExit:
        raise
    except BaseException as exc:
        with suppress(Exception):
            control.send(("failed", _failure_code(exc)))
        raise SystemExit(2) from None
    finally:
        with suppress(Exception):
            control.close()
        if outbox is not None:
            # DurableOutbox opens SQLite connections per operation; there is
            # no persistent connection to leak across worker restarts.
            del outbox


def _failure_code(error: BaseException) -> str:
    cause = error
    while cause.__cause__ is not None and cause.__cause__ is not cause:
        cause = cause.__cause__
    if isinstance(cause, ThresholdRuleError):
        return "RULE_OR_CAPACITY_FAILURE"
    if isinstance(cause, (OutboxCapacityError, OutboxConflictError)):
        return "OUTBOX_WRITE_FAILURE"
    return "PERSISTENCE_FAILURE"


def _safe_failure_code(value: object) -> str:
    if type(value) is str and value in {
        "RULE_OR_CAPACITY_FAILURE",
        "OUTBOX_WRITE_FAILURE",
        "PERSISTENCE_FAILURE",
        "CONTROL_MESSAGE_INVALID",
    }:
        return value
    return "WORKER_FAILURE"


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON field")
        result[key] = value
    return result


def _reject_json_constant(_value: str):
    raise ValueError("non-finite JSON number")


def _validate_ref(value: object, code: str) -> None:
    if type(value) is not str or not value or value != value.strip():
        raise ThresholdServiceError(code)
    try:
        if len(value.encode("utf-8", "strict")) > 128:
            raise ThresholdServiceError(code)
    except UnicodeError:
        raise ThresholdServiceError(code) from None
    if any(character not in _SAFE_REF_CHARS for character in value):
        raise ThresholdServiceError(code)


__all__ = [
    "MAX_THRESHOLD_CONFIG_BYTES",
    "THRESHOLD_ALERT_EVENT_TYPE",
    "THRESHOLD_ALERT_SCHEMA",
    "MonitorThresholdResourceProvider",
    "ThresholdRuleConsumerSupervisor",
    "ThresholdServiceConfig",
    "ThresholdServiceError",
    "TrustedThresholdTarget",
    "create_monitor_threshold_resource_provider",
    "parse_threshold_service_config",
]
