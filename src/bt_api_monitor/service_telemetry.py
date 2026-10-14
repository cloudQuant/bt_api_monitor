"""Bounded, in-memory service ingress for ordinary SDK telemetry.

Telemetry samples are producer-reported metrics and heartbeats, not complete
economic state or proof that a strategy is ready to trade. Authentication is
resolved by the service registry; this adapter binds each sample to the trusted
identity and scope supplied by that registry and keeps only a bounded latest
projection in memory.
"""

from __future__ import annotations

import hashlib
import json
import math
import threading
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any

from bt_api_base.service_protocol import WireIdentity, WireRole, WireScope
from bt_api_base.telemetry_protocol import (
    MAX_TELEMETRY_SAMPLE_BYTES,
    TelemetryProtocolError,
    TelemetrySample,
    parse_telemetry_sample,
    sample_size_bytes,
)

from .service_component import (
    MonitorReadServiceError,
    _scope_matches,
    _templates_overlap,
    _validate_requested_scope,
    _validate_scope_template,
)
from .service_component import (
    _validate_text as _validate_scope_text,
)

TELEMETRY_OPERATIONS = frozenset({"telemetry.append", "telemetry.snapshot"})

DEFAULT_TELEMETRY_MAX_STREAMS = 256
DEFAULT_TELEMETRY_MAX_BYTES = 1024 * 1024
DEFAULT_HEARTBEAT_TIMEOUT_SECONDS = 30.0
DEFAULT_TELEMETRY_RETENTION_SECONDS = 300.0
MAX_TELEMETRY_STREAMS = 10_000
MAX_TELEMETRY_STORE_BYTES = 64 * 1024 * 1024
MAX_HEARTBEAT_TIMEOUT_SECONDS = 3600.0
MAX_TELEMETRY_RETENTION_SECONDS = 86400.0
MAX_TELEMETRY_SNAPSHOT_RESULT_BYTES = 900 * 1024

_ALLOWED_BIND_PORTS = frozenset({"service.telemetry_ingress", "service.monitor_query"})
_TELEMETRY_OPTION_KEYS = frozenset(
    {
        "role",
        "max_streams",
        "max_bytes",
        "heartbeat_timeout_seconds",
        "retention_seconds",
    }
)


class MonitorTelemetryServiceError(ValueError):
    """A bounded telemetry request or trusted service binding is invalid."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True)
class _TelemetryRecord:
    latest_sample: TelemetrySample
    latest_fingerprint: str
    last_received_at: float
    heartbeat: TelemetrySample | None
    heartbeat_received_at: float | None
    metrics: TelemetrySample | None
    metrics_received_at: float | None


_RecordKey = tuple[WireIdentity, WireScope, str]


class MonitorTelemetryService:
    """Append and query bounded latest-per-stream telemetry in memory."""

    OPERATIONS = TELEMETRY_OPERATIONS

    def __init__(
        self,
        targets: frozenset[WireScope],
        *,
        max_streams: int = DEFAULT_TELEMETRY_MAX_STREAMS,
        max_bytes: int = DEFAULT_TELEMETRY_MAX_BYTES,
        heartbeat_timeout_seconds: int | float = DEFAULT_HEARTBEAT_TIMEOUT_SECONDS,
        retention_seconds: int | float = DEFAULT_TELEMETRY_RETENTION_SECONDS,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        limits = _validate_limits(
            max_streams, max_bytes, heartbeat_timeout_seconds, retention_seconds
        )
        if not callable(clock):
            raise MonitorTelemetryServiceError("INVALID_CLOCK")
        if type(targets) is not frozenset or not targets:
            raise MonitorTelemetryServiceError("TARGETS_REQUIRED")
        for target in targets:
            if type(target) is not WireScope:
                raise MonitorTelemetryServiceError("INVALID_TARGET")
            try:
                _validate_scope_template(target)
            except MonitorReadServiceError:
                raise MonitorTelemetryServiceError("INVALID_TARGET") from None
        target_list = tuple(targets)
        for index, left in enumerate(target_list):
            for right in target_list[index + 1 :]:
                if _templates_overlap(left, right):
                    raise MonitorTelemetryServiceError("AMBIGUOUS_TARGET")

        self._targets = targets
        self._max_streams = limits[0]
        self._max_bytes = limits[1]
        self._heartbeat_timeout_seconds = limits[2]
        self._retention_seconds = limits[3]
        self._clock = clock
        self._last_clock_value: float | None = None
        self._records: dict[_RecordKey, _TelemetryRecord] = {}
        self._lock = threading.RLock()

    def handle(
        self,
        operation: str,
        *,
        principal_ref: str,
        identity: WireIdentity,
        scope: WireScope,
        arguments: Mapping[str, Any],
        result_fits: Callable[[Mapping[str, Any]], bool] | None = None,
    ) -> Mapping[str, Any]:
        """Append one sample or return a bounded scope-only telemetry snapshot.

        Snapshot freshness describes the last heartbeat received by this
        process. It does not describe exchange connectivity, order state, or
        trading readiness.
        """

        if type(operation) is not str or operation not in TELEMETRY_OPERATIONS:
            raise MonitorTelemetryServiceError("UNSUPPORTED_OPERATION")
        _validate_text(principal_ref, "INVALID_PRINCIPAL")
        if type(identity) is not WireIdentity:
            raise MonitorTelemetryServiceError("INVALID_IDENTITY")
        if identity.principal_ref != principal_ref:
            raise MonitorTelemetryServiceError("IDENTITY_MISMATCH")
        self._resolve_scope(scope)

        if operation == "telemetry.append":
            if identity.role not in (WireRole.STRATEGY_CLIENT, WireRole.SERVICE):
                raise MonitorTelemetryServiceError("APPEND_ROLE_REQUIRED")
            sample = _parse_sample(arguments)
            with self._lock:
                now = self._now()
                return self._append_sample(identity, scope, sample, now)

        if identity.role not in (WireRole.APPLICATION_CLIENT, WireRole.SERVICE):
            raise MonitorTelemetryServiceError("QUERY_ROLE_REQUIRED")
        if result_fits is not None and not callable(result_fits):
            raise MonitorTelemetryServiceError("INVALID_RESULT_FIT")
        if not isinstance(arguments, Mapping) or arguments:
            raise MonitorTelemetryServiceError("INVALID_ARGUMENTS")
        with self._lock:
            now = self._now()
            active_records = self._active_records(now)
            result = _snapshot(scope, active_records, now, self._heartbeat_timeout_seconds)
            if _canonical_size(result) > MAX_TELEMETRY_SNAPSHOT_RESULT_BYTES:
                raise MonitorTelemetryServiceError("SNAPSHOT_TOO_LARGE")
        if result_fits is not None:
            # The trusted transport predicate may itself call service code. Keep
            # it outside the state lock and give it a detached candidate so it
            # cannot mutate the snapshot that will be returned.
            candidate = json.loads(_canonical_json(result))
            try:
                fits = result_fits(candidate)
            except Exception:
                raise MonitorTelemetryServiceError("RESULT_FIT_FAILED") from None
            if type(fits) is not bool:
                raise MonitorTelemetryServiceError("RESULT_FIT_FAILED")
            if not fits:
                raise MonitorTelemetryServiceError("SNAPSHOT_TOO_LARGE")
        with self._lock:
            self._discard_expired(self._active_records(self._now()))
        return result

    def _resolve_scope(self, scope: WireScope) -> None:
        if type(scope) is not WireScope:
            raise MonitorTelemetryServiceError("INVALID_SCOPE")
        try:
            _validate_requested_scope(scope)
        except MonitorReadServiceError:
            raise MonitorTelemetryServiceError("UNSUPPORTED_SCOPE") from None
        if not any(_scope_matches(template, scope) for template in self._targets):
            raise MonitorTelemetryServiceError("SCOPE_NOT_GRANTED")

    def _append_sample(
        self, identity: WireIdentity, scope: WireScope, sample: TelemetrySample, now: float
    ) -> Mapping[str, Any]:
        key = (identity, scope, sample.stream_id)
        active_records = self._active_records(now)
        previous = active_records.get(key)
        fingerprint = _sample_fingerprint(sample)
        if previous is not None:
            previous_sequence = previous.latest_sample.sequence
            if sample.sequence < previous_sequence:
                raise MonitorTelemetryServiceError("STALE_SEQUENCE")
            if sample.sequence == previous_sequence:
                if fingerprint != previous.latest_fingerprint:
                    raise MonitorTelemetryServiceError("SEQUENCE_CONFLICT")
                self._discard_expired(active_records)
                return _append_reply(sample)

        next_record = _updated_record(previous, sample, fingerprint, now)
        next_size = _record_size(identity, scope, next_record)
        retained_count = len(active_records) - (1 if previous is not None else 0)
        retained_bytes = sum(
            _record_size(record_key[0], record_key[1], record)
            for record_key, record in active_records.items()
            if record_key != key
        )
        if retained_count + 1 > self._max_streams or retained_bytes + next_size > self._max_bytes:
            raise MonitorTelemetryServiceError("TELEMETRY_CAPACITY")

        self._discard_expired(active_records)
        self._records[key] = next_record
        return _append_reply(sample)

    def _active_records(self, now: float) -> dict[_RecordKey, _TelemetryRecord]:
        return {
            key: record
            for key, record in self._records.items()
            if now - record.last_received_at < self._retention_seconds
        }

    def _discard_expired(self, active_records: Mapping[_RecordKey, _TelemetryRecord]) -> None:
        active_keys = active_records.keys()
        for key in tuple(self._records):
            if key not in active_keys:
                del self._records[key]

    def _now(self) -> float:
        try:
            raw_value = self._clock()
            if type(raw_value) not in (int, float):
                raise ValueError
            value = float(raw_value)
        except Exception:
            raise MonitorTelemetryServiceError("INVALID_CLOCK") from None
        if not math.isfinite(value) or value < 0:
            raise MonitorTelemetryServiceError("INVALID_CLOCK")
        if self._last_clock_value is not None and value < self._last_clock_value:
            raise MonitorTelemetryServiceError("CLOCK_REGRESSED")
        self._last_clock_value = value
        return value


def validate_service_options(
    options: Mapping[str, Any], bind_ports: tuple[str, ...]
) -> Mapping[str, Any]:
    """Validate the ordinary telemetry ingress role and permitted bind ports."""

    if not isinstance(options, Mapping) or type(bind_ports) is not tuple:
        raise MonitorTelemetryServiceError("INVALID_SERVICE_OPTIONS")
    if (
        not options
        or set(options) - _TELEMETRY_OPTION_KEYS
        or type(options.get("role")) is not str
        or options.get("role") != "telemetry_ingress"
    ):
        raise MonitorTelemetryServiceError("UNSUPPORTED_SERVICE_OPTIONS")
    if (
        not bind_ports
        or any(type(port) is not str or port not in _ALLOWED_BIND_PORTS for port in bind_ports)
        or len(set(bind_ports)) != len(bind_ports)
    ):
        raise MonitorTelemetryServiceError("INVALID_BIND_PORTS")
    limits = _validate_limits(
        options.get("max_streams", DEFAULT_TELEMETRY_MAX_STREAMS),
        options.get("max_bytes", DEFAULT_TELEMETRY_MAX_BYTES),
        options.get("heartbeat_timeout_seconds", DEFAULT_HEARTBEAT_TIMEOUT_SECONDS),
        options.get("retention_seconds", DEFAULT_TELEMETRY_RETENTION_SECONDS),
    )
    return MappingProxyType(
        {
            "role": "telemetry_ingress",
            "max_streams": limits[0],
            "max_bytes": limits[1],
            "heartbeat_timeout_seconds": limits[2],
            "retention_seconds": limits[3],
        }
    )


def _validate_limits(
    max_streams: object,
    max_bytes: object,
    heartbeat_timeout_seconds: object,
    retention_seconds: object,
) -> tuple[int, int, float, float]:
    if type(max_streams) is not int or not 1 <= max_streams <= MAX_TELEMETRY_STREAMS:
        raise MonitorTelemetryServiceError("INVALID_LIMITS")
    if type(max_bytes) is not int or not 1 <= max_bytes <= MAX_TELEMETRY_STORE_BYTES:
        raise MonitorTelemetryServiceError("INVALID_LIMITS")
    heartbeat_timeout = _finite_seconds(heartbeat_timeout_seconds, MAX_HEARTBEAT_TIMEOUT_SECONDS)
    retention = _finite_seconds(retention_seconds, MAX_TELEMETRY_RETENTION_SECONDS)
    if (
        heartbeat_timeout < 1
        or retention < heartbeat_timeout
        or retention > MAX_TELEMETRY_RETENTION_SECONDS
    ):
        raise MonitorTelemetryServiceError("INVALID_LIMITS")
    return max_streams, max_bytes, heartbeat_timeout, retention


def _finite_seconds(value: object, maximum: float) -> float:
    if type(value) not in (int, float):
        raise MonitorTelemetryServiceError("INVALID_LIMITS")
    try:
        normalized = float(value)
    except (OverflowError, ValueError):
        raise MonitorTelemetryServiceError("INVALID_LIMITS") from None
    if not math.isfinite(normalized) or normalized < 1 or normalized > maximum:
        raise MonitorTelemetryServiceError("INVALID_LIMITS")
    return normalized


def _parse_sample(arguments: Mapping[str, Any]) -> TelemetrySample:
    try:
        sample = parse_telemetry_sample(arguments)
        sample_size_bytes(sample)
    except TelemetryProtocolError:
        raise MonitorTelemetryServiceError("INVALID_SAMPLE") from None
    except Exception:
        raise MonitorTelemetryServiceError("INVALID_SAMPLE") from None
    return sample


def _updated_record(
    previous: _TelemetryRecord | None,
    sample: TelemetrySample,
    fingerprint: str,
    now: float,
) -> _TelemetryRecord:
    if sample.kind == "heartbeat":
        heartbeat = sample
        heartbeat_received_at: float | None = now
        metrics = previous.metrics if previous is not None else None
        metrics_received_at = previous.metrics_received_at if previous is not None else None
    else:
        heartbeat = previous.heartbeat if previous is not None else None
        heartbeat_received_at = previous.heartbeat_received_at if previous is not None else None
        metrics = sample
        metrics_received_at = now
    return _TelemetryRecord(
        latest_sample=sample,
        latest_fingerprint=fingerprint,
        last_received_at=now,
        heartbeat=heartbeat,
        heartbeat_received_at=heartbeat_received_at,
        metrics=metrics,
        metrics_received_at=metrics_received_at,
    )


def _snapshot(
    requested_scope: WireScope,
    records: Mapping[_RecordKey, _TelemetryRecord],
    now: float,
    heartbeat_timeout_seconds: float,
) -> dict[str, Any]:
    matching = [
        (key, record) for key, record in records.items() if _scope_matches(requested_scope, key[1])
    ]
    matching.sort(key=lambda item: _canonical_json(_record_identity_document(item[0])))
    streams: list[dict[str, Any]] = []
    for key, record in matching:
        heartbeat_age = _age(now, record.heartbeat_received_at)
        metrics_age = _age(now, record.metrics_received_at)
        status = "not_collected"
        if heartbeat_age is not None:
            status = "fresh" if heartbeat_age <= heartbeat_timeout_seconds else "stale"
        streams.append(
            {
                **_record_identity_document(key),
                "stream_id": key[2],
                "sequence": record.latest_sample.sequence,
                "status": status,
                "received_age_seconds": max(0.0, now - record.last_received_at),
                "heartbeat_age_seconds": heartbeat_age,
                "heartbeat": _detach_sample(record.heartbeat),
                "metrics_age_seconds": metrics_age,
                "metrics": _detach_sample(record.metrics),
            }
        )
    return {"state": "collected" if streams else "not_collected", "streams": streams}


def _record_identity_document(key: _RecordKey) -> dict[str, Any]:
    identity, scope, _stream_id = key
    return {
        "producer": {
            "role": identity.role.value,
            "principal_ref": identity.principal_ref,
            "actor_ref": identity.actor_ref,
            "delegate_ref": identity.delegate_ref,
        },
        "scope": _scope_document(scope),
    }


def _scope_document(scope: WireScope) -> dict[str, Any]:
    return {
        "execution_domain_ref": scope.execution_domain_ref,
        "account_ref": scope.account_ref,
        "account_refs": list(scope.account_refs),
        "strategy_ref": scope.strategy_ref,
        "run_id": scope.run_id,
        "manual_book_ref": scope.manual_book_ref,
        "portfolio_ref": scope.portfolio_ref,
        "group_id": scope.group_id,
        "leg_id": scope.leg_id,
    }


def _record_size(identity: WireIdentity, scope: WireScope, record: _TelemetryRecord) -> int:
    return _canonical_size(
        {
            **_record_identity_document((identity, scope, record.latest_sample.stream_id)),
            "stream_id": record.latest_sample.stream_id,
            "latest_sample": record.latest_sample.to_dict(),
            "latest_fingerprint": record.latest_fingerprint,
            "last_received_at": record.last_received_at,
            "heartbeat": _detach_sample(record.heartbeat),
            "heartbeat_received_at": record.heartbeat_received_at,
            "metrics": _detach_sample(record.metrics),
            "metrics_received_at": record.metrics_received_at,
        }
    )


def _sample_fingerprint(sample: TelemetrySample) -> str:
    encoded = _canonical_json(sample.to_dict()).encode("utf-8", errors="strict")
    return hashlib.sha256(encoded).hexdigest()


def _append_reply(sample: TelemetrySample) -> Mapping[str, Any]:
    return {
        "stream_id": sample.stream_id,
        "sequence": sample.sequence,
        "accepted": True,
    }


def _detach_sample(sample: TelemetrySample | None) -> dict[str, Any] | None:
    return None if sample is None else sample.to_dict()


def _age(now: float, received_at: float | None) -> float | None:
    return None if received_at is None else max(0.0, now - received_at)


def _canonical_json(value: object) -> str:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
    except (TypeError, ValueError, OverflowError, RecursionError, UnicodeEncodeError):
        raise MonitorTelemetryServiceError("INVALID_RESULT") from None


def _canonical_size(value: object) -> int:
    return len(_canonical_json(value).encode("utf-8", errors="strict"))


def _validate_text(value: object, error_code: str) -> None:
    try:
        _validate_scope_text(value, 256, error_code)
    except MonitorReadServiceError:
        raise MonitorTelemetryServiceError(error_code) from None


__all__ = [
    "DEFAULT_HEARTBEAT_TIMEOUT_SECONDS",
    "DEFAULT_TELEMETRY_MAX_BYTES",
    "DEFAULT_TELEMETRY_MAX_STREAMS",
    "DEFAULT_TELEMETRY_RETENTION_SECONDS",
    "MAX_HEARTBEAT_TIMEOUT_SECONDS",
    "MAX_TELEMETRY_SAMPLE_BYTES",
    "MAX_TELEMETRY_SNAPSHOT_RESULT_BYTES",
    "MAX_TELEMETRY_STORE_BYTES",
    "MAX_TELEMETRY_STREAMS",
    "MonitorTelemetryService",
    "MonitorTelemetryServiceError",
    "TELEMETRY_OPERATIONS",
    "validate_service_options",
]
