"""Durable, service-owned ingress for bounded monitor event records.

This component accepts one explicitly authorized service operation. It is a
durable event intake, not an ordinary strategy telemetry port or a complete
economic-fact model. Authentication and authorization are owned by the service
registry; this adapter binds the authenticated identity and registered scope to
one trusted outbox mapping before accepting data.
"""

from __future__ import annotations

import hashlib
import json
import math
from collections.abc import Mapping
from types import MappingProxyType
from typing import Any

from bt_api_base.service_protocol import WireIdentity, WireRole, WireScope

from .durable import (
    MAX_OUTBOX_CAPACITY_BYTES,
    MAX_OUTBOX_CAPACITY_EVENTS,
    DurableOutbox,
    OutboxCapacityError,
    OutboxConflictError,
    OutboxEvent,
    SequencedOutboxEvent,
)
from .service_component import (
    MonitorReadServiceError,
    MonitorReadTarget,
    _scope_matches,
    _templates_overlap,
    _validate_requested_scope,
    _validate_scope_template,
)
from .service_component import (
    _validate_text as _validate_scope_text,
)

MONITOR_INGRESS_OPERATIONS = frozenset({"events.append"})

DEFAULT_INGRESS_MAX_EVENTS = 10_000
DEFAULT_INGRESS_MAX_BYTES = 64 * 1024 * 1024
DEFAULT_INGRESS_MAX_EVENT_BYTES = 64 * 1024
MAX_INGRESS_EVENT_BYTES = 64 * 1024
MAX_INGRESS_EVENT_ID_BYTES = 256
MAX_INGRESS_EVENT_TYPE_BYTES = 128
MAX_INGRESS_JSON_DEPTH = 32
MAX_INGRESS_JSON_NODES = 4096
_MIN_EVENT_TIME = -62_135_596_800.0
_MAX_EVENT_TIME = 253_402_300_799.0
_ALL_BIND_PORTS = frozenset(
    {
        "service.telemetry_ingress",
        "service.monitor_query",
        "service.monitor_control",
    }
)
_INGRESS_BIND_PORT = "service.telemetry_ingress"
_INGRESS_OPTION_KEYS = frozenset({"role", "max_events", "max_bytes", "max_event_bytes"})
_REQUEST_FIELDS = frozenset({"schema_version", "event_id", "event_type", "occurred_at", "data"})
_SCOPE_IDENTITY_FIELDS = (
    "execution_domain_ref",
    "account_ref",
    "account_refs",
    "strategy_ref",
    "manual_book_ref",
    "portfolio_ref",
    "group_id",
    "leg_id",
)

# The alias preserves the existing monitor target's exact matching and
# allowlist contract while giving ingress configurations a role-specific name.
MonitorIngressTarget = MonitorReadTarget


class MonitorIngressServiceError(ValueError):
    """A bounded ingress request or trusted service binding is invalid."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class MonitorIngressService:
    """Append authenticated service events to a borrowed durable outbox."""

    OPERATIONS = MONITOR_INGRESS_OPERATIONS

    def __init__(
        self,
        outbox: DurableOutbox,
        targets: Mapping[WireScope, MonitorIngressTarget],
        *,
        max_events: int = DEFAULT_INGRESS_MAX_EVENTS,
        max_bytes: int = DEFAULT_INGRESS_MAX_BYTES,
        max_event_bytes: int = DEFAULT_INGRESS_MAX_EVENT_BYTES,
    ) -> None:
        if type(outbox) is not DurableOutbox or outbox.is_read_only is not False:
            raise MonitorIngressServiceError("WRITABLE_OUTBOX_REQUIRED")
        self._max_events, self._max_bytes, self._max_event_bytes = _validate_limits(
            max_events, max_bytes, max_event_bytes
        )
        if not isinstance(targets, Mapping) or not targets:
            raise MonitorIngressServiceError("TARGETS_REQUIRED")

        copied_targets: dict[WireScope, MonitorIngressTarget] = {}
        outbox_scopes: set[str] = set()
        for template, target in targets.items():
            if type(template) is not WireScope or type(target) is not MonitorIngressTarget:
                raise MonitorIngressServiceError("INVALID_TARGET")
            try:
                _validate_scope_template(template)
            except Exception:
                raise MonitorIngressServiceError("INVALID_TARGET") from None
            if target.outbox_scope in outbox_scopes:
                raise MonitorIngressServiceError("AMBIGUOUS_TARGET")
            outbox_scopes.add(target.outbox_scope)
            copied_targets[template] = target

        templates = tuple(copied_targets)
        for index, left in enumerate(templates):
            for right in templates[index + 1 :]:
                if _templates_overlap(left, right):
                    raise MonitorIngressServiceError("AMBIGUOUS_TARGET")

        self._outbox = outbox
        self._targets = MappingProxyType(copied_targets)

    def handle(
        self,
        operation: str,
        *,
        principal_ref: str,
        identity: WireIdentity,
        scope: WireScope,
        arguments: Mapping[str, Any],
    ) -> Mapping[str, Any]:
        """Validate one service event and atomically persist it with capacity bounds."""

        if type(operation) is not str or operation not in self.OPERATIONS:
            raise MonitorIngressServiceError("UNSUPPORTED_OPERATION")
        _validate_text(principal_ref, 256, "INVALID_PRINCIPAL")
        if type(identity) is not WireIdentity:
            raise MonitorIngressServiceError("INVALID_IDENTITY")
        if identity.principal_ref != principal_ref:
            raise MonitorIngressServiceError("IDENTITY_MISMATCH")
        if identity.role is not WireRole.SERVICE:
            raise MonitorIngressServiceError("SERVICE_ROLE_REQUIRED")
        target = self._resolve_target(scope)
        request = _parse_request(arguments, target, self._max_event_bytes)

        producer = {
            "role": identity.role.value,
            "principal_ref": identity.principal_ref,
            "actor_ref": identity.actor_ref,
            "delegate_ref": identity.delegate_ref,
        }
        stable_scope = {field: getattr(scope, field) for field in _SCOPE_IDENTITY_FIELDS}
        stable_scope["account_refs"] = list(stable_scope["account_refs"])
        event_id = "service-event:" + _sha256(
            _canonical_json(
                {
                    "identity": producer,
                    "scope": stable_scope,
                    "outbox_scope": target.outbox_scope,
                    "source_event_id": request["event_id"],
                }
            )
        )
        durable_data = {
            "producer": producer,
            "source_event_id": request["event_id"],
            "payload": request["data"],
        }
        try:
            event = OutboxEvent(
                event_id=event_id,
                scope=target.outbox_scope,
                event_type=request["event_type"],
                data=durable_data,
                occurred_at=request["occurred_at"],
            )
        except Exception:
            raise MonitorIngressServiceError("EVENT_DATA_INVALID") from None
        logical_event_bytes = sum(
            len(value.encode("utf-8"))
            for value in (event.event_id, event.scope, event.event_type, event.data_json)
        )
        if logical_event_bytes > self._max_event_bytes:
            raise MonitorIngressServiceError("EVENT_TOO_LARGE")

        try:
            row = self._outbox.append_bounded(
                event, max_events=self._max_events, max_bytes=self._max_bytes
            )
        except OutboxCapacityError:
            raise MonitorIngressServiceError("OUTBOX_CAPACITY") from None
        except OutboxConflictError:
            raise MonitorIngressServiceError("EVENT_ID_CONFLICT") from None
        except Exception:
            raise MonitorIngressServiceError("OUTBOX_APPEND_FAILED") from None
        if (
            type(row) is not SequencedOutboxEvent
            or type(row.event) is not OutboxEvent
            or type(row.sequence) is not int
            or not 1 <= row.sequence < (1 << 63)
            or row.event.event_id != event.event_id
            or row.event.fingerprint != event.fingerprint
        ):
            raise MonitorIngressServiceError("MALFORMED_OUTBOX_RESULT")
        return MappingProxyType(
            {
                "event_id": row.event.event_id,
                "source_event_id": request["event_id"],
                "sequence": row.sequence,
            }
        )

    def _resolve_target(self, scope: WireScope) -> MonitorIngressTarget:
        if type(scope) is not WireScope:
            raise MonitorIngressServiceError("INVALID_SCOPE")
        try:
            _validate_requested_scope(scope)
        except Exception:
            raise MonitorIngressServiceError("UNSUPPORTED_SCOPE") from None
        matches = [
            target for template, target in self._targets.items() if _scope_matches(template, scope)
        ]
        if len(matches) != 1:
            raise MonitorIngressServiceError("SCOPE_NOT_GRANTED")
        return matches[0]


def validate_service_options(
    options: Mapping[str, Any], bind_ports: tuple[str, ...]
) -> Mapping[str, Any]:
    """Validate the explicitly opted-in durable ingress role and its fixed bind port."""

    if not isinstance(options, Mapping) or type(bind_ports) is not tuple:
        raise MonitorIngressServiceError("INVALID_SERVICE_OPTIONS")
    if any(type(port) is not str or port not in _ALL_BIND_PORTS for port in bind_ports):
        raise MonitorIngressServiceError("INVALID_BIND_PORTS")
    if len(set(bind_ports)) != len(bind_ports):
        raise MonitorIngressServiceError("INVALID_BIND_PORTS")
    if (
        not options
        or set(options) - _INGRESS_OPTION_KEYS
        or type(options.get("role")) is not str
        or options.get("role") != "durable_ingress"
    ):
        raise MonitorIngressServiceError("UNSUPPORTED_SERVICE_OPTIONS")
    if bind_ports != (_INGRESS_BIND_PORT,):
        raise MonitorIngressServiceError("INVALID_BIND_PORTS")
    limits = _validate_limits(
        options.get("max_events", DEFAULT_INGRESS_MAX_EVENTS),
        options.get("max_bytes", DEFAULT_INGRESS_MAX_BYTES),
        options.get("max_event_bytes", DEFAULT_INGRESS_MAX_EVENT_BYTES),
    )
    return MappingProxyType(
        {
            "role": "durable_ingress",
            "max_events": limits[0],
            "max_bytes": limits[1],
            "max_event_bytes": limits[2],
        }
    )


def _validate_limits(max_events: object, max_bytes: object, max_event_bytes: object):
    values = (max_events, max_bytes, max_event_bytes)
    if any(type(value) is not int or value <= 0 for value in values):
        raise MonitorIngressServiceError("INVALID_LIMITS")
    if (
        max_events > MAX_OUTBOX_CAPACITY_EVENTS
        or max_bytes > MAX_OUTBOX_CAPACITY_BYTES
        or max_event_bytes > MAX_INGRESS_EVENT_BYTES
        or max_event_bytes > max_bytes
    ):
        raise MonitorIngressServiceError("INVALID_LIMITS")
    return max_events, max_bytes, max_event_bytes


def _parse_request(
    arguments: Mapping[str, Any], target: MonitorIngressTarget, max_event_bytes: int
) -> dict[str, Any]:
    if not isinstance(arguments, Mapping) or any(type(key) is not str for key in arguments):
        raise MonitorIngressServiceError("INVALID_ARGUMENTS")
    if set(arguments) != _REQUEST_FIELDS:
        if set(arguments) - _REQUEST_FIELDS:
            raise MonitorIngressServiceError("UNKNOWN_ARGUMENT")
        raise MonitorIngressServiceError("MISSING_ARGUMENT")
    if type(arguments["schema_version"]) is not int or arguments["schema_version"] != 1:
        raise MonitorIngressServiceError("UNSUPPORTED_SCHEMA_VERSION")

    _validate_text(arguments["event_id"], MAX_INGRESS_EVENT_ID_BYTES, "INVALID_EVENT_ID")
    _validate_text(arguments["event_type"], MAX_INGRESS_EVENT_TYPE_BYTES, "INVALID_EVENT_TYPE")
    if arguments["event_type"] not in target.event_types:
        raise MonitorIngressServiceError("EVENT_TYPE_NOT_GRANTED")
    occurred_at = arguments["occurred_at"]
    if type(occurred_at) not in (int, float) or (
        type(occurred_at) is int and occurred_at.bit_length() > 64
    ):
        raise MonitorIngressServiceError("INVALID_EVENT_TIME")
    try:
        occurred_at_value = float(occurred_at)
    except (OverflowError, ValueError):
        raise MonitorIngressServiceError("INVALID_EVENT_TIME") from None
    if (
        not math.isfinite(occurred_at_value)
        or not _MIN_EVENT_TIME <= occurred_at_value <= _MAX_EVENT_TIME
    ):
        raise MonitorIngressServiceError("INVALID_EVENT_TIME")
    data = arguments["data"]
    if not isinstance(data, Mapping):
        raise MonitorIngressServiceError("INVALID_EVENT_DATA")
    try:
        _validate_json_tree(data)
        plain_data = _to_json_values(data)
        request_bytes = len(
            _canonical_json(
                {
                    "schema_version": 1,
                    "event_id": arguments["event_id"],
                    "event_type": arguments["event_type"],
                    "occurred_at": occurred_at_value,
                    "data": plain_data,
                }
            ).encode("utf-8")
        )
    except Exception:
        raise MonitorIngressServiceError("INVALID_EVENT_DATA") from None
    if request_bytes > max_event_bytes:
        raise MonitorIngressServiceError("EVENT_TOO_LARGE")
    return {
        "event_id": arguments["event_id"],
        "event_type": arguments["event_type"],
        "occurred_at": occurred_at_value,
        "data": plain_data,
    }


def _validate_json_tree(value: Mapping[str, Any]) -> None:
    node_count = 0
    raw_text_bytes = 0

    def visit(item: Any, depth: int) -> None:
        nonlocal node_count, raw_text_bytes
        node_count += 1
        if node_count > MAX_INGRESS_JSON_NODES or depth > MAX_INGRESS_JSON_DEPTH:
            raise ValueError("event JSON dimensions exceed their bounds")
        if isinstance(item, Mapping):
            for key, nested in item.items():
                node_count += 1
                if node_count > MAX_INGRESS_JSON_NODES or type(key) is not str:
                    raise ValueError("event JSON mapping is invalid")
                encoded_key = key.encode("utf-8", "strict")
                raw_text_bytes += len(encoded_key)
                if len(encoded_key) > 128 or raw_text_bytes > MAX_INGRESS_EVENT_BYTES:
                    raise ValueError("event JSON text exceeds its bound")
                visit(nested, depth + 1)
        elif isinstance(item, (list, tuple)):
            for nested in item:
                visit(nested, depth + 1)
        elif type(item) is str:
            encoded = item.encode("utf-8", "strict")
            raw_text_bytes += len(encoded)
            if raw_text_bytes > MAX_INGRESS_EVENT_BYTES:
                raise ValueError("event JSON text exceeds its bound")
        elif type(item) is int:
            if item.bit_length() > 256:
                raise ValueError("event JSON integer exceeds its bound")
        elif type(item) is float:
            if not math.isfinite(item):
                raise ValueError("event JSON number must be finite")
        elif item is not None and type(item) is not bool:
            raise ValueError("event JSON value has an unsupported type")

    visit(value, 1)


def _to_json_values(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {key: _to_json_values(nested) for key, nested in value.items()}
    if isinstance(value, (tuple, list)):
        return [_to_json_values(nested) for nested in value]
    return value


def _validate_text(value: object, max_bytes: int, error_code: str) -> None:
    try:
        _validate_scope_text(value, max_bytes, error_code)
    except MonitorReadServiceError:
        raise MonitorIngressServiceError(error_code) from None


def _canonical_json(value: object) -> str:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    )


def _sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


__all__ = [
    "DEFAULT_INGRESS_MAX_BYTES",
    "DEFAULT_INGRESS_MAX_EVENT_BYTES",
    "DEFAULT_INGRESS_MAX_EVENTS",
    "MAX_INGRESS_EVENT_BYTES",
    "MONITOR_INGRESS_OPERATIONS",
    "MonitorIngressService",
    "MonitorIngressServiceError",
    "MonitorIngressTarget",
    "validate_service_options",
]
