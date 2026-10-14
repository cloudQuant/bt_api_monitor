"""Read-only monitor service component for the optional service host.

This module contains no transport, provider, or service-runtime integration.
The host supplies an authenticated principal and registry-validated scope, and
owns the borrowed read-only outbox for the full lifetime of this adapter.
"""

from __future__ import annotations

import math
from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any

from bt_api_base.service_protocol import WireScope

from .durable import DurableOutbox, OutboxEvent, SequencedOutboxEvent

MONITOR_READ_OPERATIONS = frozenset({"monitor.query", "monitor.read_after"})
MAX_MONITOR_READ_PAGE_SIZE = 100
_MAX_CURSOR = (1 << 63) - 1
_MAX_EVENT_TYPES = 16
_MAX_SCOPE_TEXT_BYTES = 256
_MAX_EVENT_TYPE_BYTES = 128
_ALLOWED_BIND_PORTS = frozenset(
    {
        "service.telemetry_ingress",
        "service.monitor_query",
        "service.monitor_control",
    }
)
_ARGUMENT_FIELDS = frozenset({"after_sequence", "limit"})
_SUPPORTED_SCOPE_FIELDS = (
    "execution_domain_ref",
    "account_ref",
    "strategy_ref",
    "portfolio_ref",
    "manual_book_ref",
)


class MonitorReadServiceError(ValueError):
    """A bounded monitor request or trusted service binding is invalid."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True)
class MonitorReadTarget:
    """Trusted mapping from a wire-scope template to one outbox view."""

    outbox_scope: str
    event_types: tuple[str, ...]

    def __post_init__(self) -> None:
        _validate_text(self.outbox_scope, _MAX_SCOPE_TEXT_BYTES, "INVALID_TARGET")
        if (
            type(self.event_types) is not tuple
            or not 1 <= len(self.event_types) <= _MAX_EVENT_TYPES
        ):
            raise MonitorReadServiceError("INVALID_TARGET")
        for event_type in self.event_types:
            _validate_text(event_type, _MAX_EVENT_TYPE_BYTES, "INVALID_TARGET")
        if len(set(self.event_types)) != len(self.event_types):
            raise MonitorReadServiceError("INVALID_TARGET")
        object.__setattr__(self, "event_types", tuple(sorted(self.event_types)))


class MonitorReadService:
    """Serve bounded pages from a borrowed, permanently read-only outbox."""

    OPERATIONS = MONITOR_READ_OPERATIONS

    def __init__(
        self,
        outbox: DurableOutbox,
        targets: Mapping[WireScope, MonitorReadTarget],
    ) -> None:
        if type(outbox) is not DurableOutbox or outbox.is_read_only is not True:
            raise MonitorReadServiceError("READ_ONLY_OUTBOX_REQUIRED")
        if not isinstance(targets, Mapping) or not targets:
            raise MonitorReadServiceError("TARGETS_REQUIRED")

        copied_targets: dict[WireScope, MonitorReadTarget] = {}
        outbox_scopes: set[str] = set()
        for template, target in targets.items():
            if type(template) is not WireScope or type(target) is not MonitorReadTarget:
                raise MonitorReadServiceError("INVALID_TARGET")
            _validate_scope_template(template)
            if target.outbox_scope in outbox_scopes:
                raise MonitorReadServiceError("AMBIGUOUS_TARGET")
            outbox_scopes.add(target.outbox_scope)
            copied_targets[template] = target

        templates = tuple(copied_targets)
        for index, left in enumerate(templates):
            for right in templates[index + 1 :]:
                if _templates_overlap(left, right):
                    raise MonitorReadServiceError("AMBIGUOUS_TARGET")

        self._outbox = outbox
        self._targets = MappingProxyType(copied_targets)

    def handle(
        self,
        operation: str,
        *,
        principal_ref: str,
        scope: WireScope,
        arguments: Mapping[str, Any],
    ) -> Mapping[str, Any]:
        """Return a detached, JSON-compatible read page.

        Principal authentication and authorization are owned by the service
        registry. This adapter validates the supplied principal shape, then
        confines the request to one configured scope target; it keeps no
        per-client cursor or checkpoint state.
        """

        if type(operation) is not str or operation not in self.OPERATIONS:
            raise MonitorReadServiceError("UNSUPPORTED_OPERATION")
        _validate_text(principal_ref, _MAX_SCOPE_TEXT_BYTES, "INVALID_PRINCIPAL")
        target = self._resolve_target(scope)
        after_sequence, limit = _parse_arguments(operation, arguments)

        try:
            rows, has_more = self._outbox.read_page_types(
                target.outbox_scope, target.event_types, after_sequence, limit
            )
        except Exception:
            # Storage details and event content are not part of the wire API.
            raise MonitorReadServiceError("OUTBOX_READ_FAILED") from None

        _validate_page(rows, has_more, target, after_sequence, limit)
        events = tuple(_event_document(row) for row in rows)
        next_cursor = rows[-1].sequence if rows else after_sequence
        return {
            "requested_cursor": after_sequence,
            "next_cursor": next_cursor,
            "has_more": has_more,
            "events": events,
        }

    def _resolve_target(self, scope: WireScope) -> MonitorReadTarget:
        if type(scope) is not WireScope:
            raise MonitorReadServiceError("INVALID_SCOPE")
        _validate_requested_scope(scope)
        matches = [
            target for template, target in self._targets.items() if _scope_matches(template, scope)
        ]
        if len(matches) != 1:
            raise MonitorReadServiceError("SCOPE_NOT_GRANTED")
        return matches[0]


def validate_service_options(
    options: Mapping[str, Any], bind_ports: tuple[str, ...]
) -> Mapping[str, Any]:
    """Validate the currently empty Monitor service option contract.

    Binding ports select in-process wiring only. They do not create remote
    capabilities; the runtime advertises only ``MonitorReadService.OPERATIONS``.
    """

    if not isinstance(options, Mapping) or options:
        raise MonitorReadServiceError("UNSUPPORTED_SERVICE_OPTIONS")
    if type(bind_ports) is not tuple:
        raise MonitorReadServiceError("INVALID_BIND_PORTS")
    if any(type(port) is not str or port not in _ALLOWED_BIND_PORTS for port in bind_ports):
        raise MonitorReadServiceError("INVALID_BIND_PORTS")
    if len(set(bind_ports)) != len(bind_ports):
        raise MonitorReadServiceError("INVALID_BIND_PORTS")
    return MappingProxyType({})


def _parse_arguments(operation: str, arguments: Mapping[str, Any]) -> tuple[int, int]:
    if not isinstance(arguments, Mapping):
        raise MonitorReadServiceError("INVALID_ARGUMENTS")
    if any(type(key) is not str for key in arguments):
        raise MonitorReadServiceError("INVALID_ARGUMENTS")
    if set(arguments) - _ARGUMENT_FIELDS:
        # In particular, clients cannot supply their own scope or event filter.
        raise MonitorReadServiceError("UNKNOWN_ARGUMENT")
    if operation == "monitor.read_after" and "after_sequence" not in arguments:
        raise MonitorReadServiceError("CURSOR_REQUIRED")

    after_sequence = arguments.get("after_sequence", 0)
    limit = arguments.get("limit", MAX_MONITOR_READ_PAGE_SIZE)
    if type(after_sequence) is not int or not 0 <= after_sequence <= _MAX_CURSOR:
        raise MonitorReadServiceError("INVALID_CURSOR")
    if type(limit) is not int or not 1 <= limit <= MAX_MONITOR_READ_PAGE_SIZE:
        raise MonitorReadServiceError("INVALID_LIMIT")
    return after_sequence, limit


def _validate_page(
    rows: object,
    has_more: object,
    target: MonitorReadTarget,
    after_sequence: int,
    limit: int,
) -> None:
    if type(rows) is not list or type(has_more) is not bool:
        raise MonitorReadServiceError("MALFORMED_OUTBOX_PAGE")
    if len(rows) > limit or (has_more and len(rows) != limit) or (not rows and has_more):
        raise MonitorReadServiceError("MALFORMED_OUTBOX_PAGE")

    previous = after_sequence
    for row in rows:
        if type(row) is not SequencedOutboxEvent or type(row.event) is not OutboxEvent:
            raise MonitorReadServiceError("MALFORMED_OUTBOX_EVENT")
        event = row.event
        if (
            type(row.sequence) is not int
            or not previous < row.sequence <= _MAX_CURSOR
            or event.scope != target.outbox_scope
            or event.event_type not in target.event_types
        ):
            raise MonitorReadServiceError("MALFORMED_OUTBOX_EVENT")
        if type(event.occurred_at) not in (float, int):
            raise MonitorReadServiceError("MALFORMED_OUTBOX_EVENT")
        try:
            occurred_at = float(event.occurred_at)
        except (OverflowError, ValueError):
            raise MonitorReadServiceError("MALFORMED_OUTBOX_EVENT") from None
        if not math.isfinite(occurred_at):
            raise MonitorReadServiceError("MALFORMED_OUTBOX_EVENT")
        try:
            # Re-run the outbox's public redaction/JSON invariant in case a
            # malformed in-memory row bypassed its normal SQLite decoder.
            OutboxEvent(
                event_id=event.event_id,
                scope=event.scope,
                event_type=event.event_type,
                data=event.data,
                occurred_at=occurred_at,
            )
        except Exception:
            raise MonitorReadServiceError("MALFORMED_OUTBOX_EVENT") from None
        previous = row.sequence


def _event_document(row: SequencedOutboxEvent) -> Mapping[str, Any]:
    event = row.event
    return {
        "sequence": row.sequence,
        "event_id": event.event_id,
        "event_type": event.event_type,
        "occurred_at": float(event.occurred_at),
        "data": _to_json_values(event.data),
    }


def _to_json_values(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {key: _to_json_values(nested) for key, nested in value.items()}
    if isinstance(value, (tuple, list)):
        return [_to_json_values(nested) for nested in value]
    return value


def _scope_matches(template: WireScope, requested: WireScope) -> bool:
    if any(
        getattr(template, field) != getattr(requested, field) for field in _SUPPORTED_SCOPE_FIELDS
    ):
        return False
    if template.run_id is not None:
        return requested.run_id == template.run_id
    if template.strategy_ref is None:
        return requested.run_id is None
    # A run wildcard exists only inside the exact configured strategy scope.
    return requested.strategy_ref == template.strategy_ref


def _validate_scope_template(scope: WireScope) -> None:
    if scope.account_refs or scope.group_id is not None or scope.leg_id is not None:
        raise MonitorReadServiceError("UNSUPPORTED_SCOPE_TEMPLATE")


def _validate_requested_scope(scope: WireScope) -> None:
    if scope.account_refs or scope.group_id is not None or scope.leg_id is not None:
        raise MonitorReadServiceError("UNSUPPORTED_SCOPE")


def _templates_overlap(left: WireScope, right: WireScope) -> bool:
    if any(getattr(left, field) != getattr(right, field) for field in _SUPPORTED_SCOPE_FIELDS):
        return False
    if left.run_id is not None and right.run_id is not None:
        return left.run_id == right.run_id
    if left.run_id is None and right.run_id is None:
        return left.strategy_ref is not None
    wildcard = left if left.run_id is None else right
    return wildcard.strategy_ref is not None


def _validate_text(value: object, max_bytes: int, error_code: str) -> None:
    if type(value) is not str or not value or value != value.strip():
        raise MonitorReadServiceError(error_code)
    try:
        encoded = value.encode("utf-8", "strict")
    except UnicodeError:
        raise MonitorReadServiceError(error_code) from None
    if len(encoded) > max_bytes or any(
        ord(character) < 32 or ord(character) == 127 for character in value
    ):
        raise MonitorReadServiceError(error_code)


__all__ = [
    "MAX_MONITOR_READ_PAGE_SIZE",
    "MONITOR_READ_OPERATIONS",
    "MonitorReadService",
    "MonitorReadServiceError",
    "MonitorReadTarget",
    "validate_service_options",
]
