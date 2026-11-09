"""Passive, source-bound Gateway relay heartbeats for a Monitor service.

The authenticated service host owns transport and authorization.  This
component does not initiate messages, write control commands, interpret clocks,
or claim that business events have been durably consumed.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
import threading
from types import MappingProxyType
from typing import Any

from bt_api_base.service_protocol import WireIdentity, WireRole, WireScope

HEARTBEAT_OPERATIONS = frozenset({"monitor.heartbeat"})
GATEWAY_HEARTBEAT_OPERATIONS = HEARTBEAT_OPERATIONS
_FIELDS = frozenset({"schema_version", "relay_epoch", "heartbeat_id", "sent_at_ns"})
_MAX_REF_BYTES = 128
_MAX_TARGETS = 1024


class GatewayHeartbeatError(ValueError):
    """A finite error that never includes request or principal values."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def validate_service_options(
    options: Mapping[str, Any], bind_ports: tuple[str, ...]
) -> Mapping[str, Any]:
    """Select the passive heartbeat role and its one explicit ingress port."""
    if not isinstance(options, Mapping) or dict(options) != {"role": "gateway_heartbeat"}:
        raise GatewayHeartbeatError("UNSUPPORTED_SERVICE_OPTIONS")
    if type(bind_ports) is not tuple or bind_ports != ("service.telemetry_ingress",):
        raise GatewayHeartbeatError("INVALID_BIND_PORTS")
    return MappingProxyType({"role": "gateway_heartbeat"})


def _text(value: object, limit: int = _MAX_REF_BYTES) -> bool:
    return (
        type(value) is str
        and 1 <= len(value) <= limit
        and value == value.strip()
        and all(32 <= ord(char) <= 126 for char in value)
    )


def _principal_text(value: object) -> bool:
    if type(value) is not str or not value or value != value.strip():
        return False
    try:
        return len(value.encode("utf-8", errors="strict")) <= 256 and all(
            ord(char) >= 32 and not 127 <= ord(char) <= 159 for char in value
        )
    except UnicodeEncodeError:
        return False


class GatewayHeartbeatService:
    """Respond only to an authorized relay's current-epoch request.

    ``validate_current_epoch`` is trusted integration code, not an assertion
    provided by the wire sender. It must consult the currently authenticated
    registration/relay generation. Gateway must additionally match its own
    pending request and its original monotonic send time before using an ACK.
    """

    OPERATIONS = GATEWAY_HEARTBEAT_OPERATIONS

    def __init__(
        self,
        *,
        monitor_principal: str,
        targets: frozenset[tuple[WireIdentity, WireScope]],
        validate_current_epoch: Callable[[WireIdentity, WireScope, str], bool] | None = None,
    ) -> None:
        if not _principal_text(monitor_principal):
            raise GatewayHeartbeatError("INVALID_MONITOR_PRINCIPAL")
        if type(targets) is not frozenset or not 1 <= len(targets) <= _MAX_TARGETS:
            raise GatewayHeartbeatError("INVALID_TARGETS")
        if any(
            type(item) is not tuple
            or len(item) != 2
            or type(item[0]) is not WireIdentity
            or item[0].role is not WireRole.SERVICE
            or item[0].delegate_ref is not None
            or type(item[1]) is not WireScope
            for item in targets
        ):
            raise GatewayHeartbeatError("INVALID_TARGETS")
        if validate_current_epoch is not None and not callable(validate_current_epoch):
            raise GatewayHeartbeatError("INVALID_EPOCH_VALIDATOR")
        self._monitor_principal = monitor_principal
        self._targets = targets
        self._validate_current_epoch = validate_current_epoch
        self._validator_lock = threading.Lock()

    def bind_current_epoch_validator(
        self, validator: Callable[[WireIdentity, WireScope, str], bool]
    ) -> None:
        """Install trusted host-owned validation once; an unbound service cannot ACK."""
        if not callable(validator):
            raise GatewayHeartbeatError("INVALID_EPOCH_VALIDATOR")
        with self._validator_lock:
            if self._validate_current_epoch is not None:
                raise GatewayHeartbeatError("EPOCH_VALIDATOR_ALREADY_BOUND")
            self._validate_current_epoch = validator

    @property
    def monitor_principal(self) -> str:
        """Return the configured Monitor principal for trusted host binding."""
        return self._monitor_principal

    def handle(
        self,
        operation: str,
        *,
        principal_ref: str,
        identity: WireIdentity,
        scope: WireScope,
        registration_id: str,
        arguments: Mapping[str, Any],
    ) -> Mapping[str, Any]:
        """Return a bounded ACK on the same authenticated request only."""
        if type(operation) is not str or operation not in self.OPERATIONS:
            raise GatewayHeartbeatError("UNSUPPORTED_OPERATION")
        if (
            type(identity) is not WireIdentity
            or type(principal_ref) is not str
            or identity.principal_ref != principal_ref
            or type(scope) is not WireScope
            or (identity, scope) not in self._targets
        ):
            raise GatewayHeartbeatError("UNAUTHORIZED_RELAY")
        if type(arguments) is not dict or arguments.keys() != _FIELDS:
            raise GatewayHeartbeatError("INVALID_HEARTBEAT")
        version, epoch, heartbeat_id, sent_at = (
            arguments["schema_version"], arguments["relay_epoch"],
            arguments["heartbeat_id"], arguments["sent_at_ns"],
        )
        if (
            type(version) is not int or version != 1
            or not _text(epoch) or not _text(heartbeat_id)
            or type(sent_at) is not int or not 0 < sent_at < 2**63
        ):
            raise GatewayHeartbeatError("INVALID_HEARTBEAT")
        if not _text(registration_id) or registration_id != epoch:
            raise GatewayHeartbeatError("REGISTRATION_EPOCH_MISMATCH")
        with self._validator_lock:
            validator = self._validate_current_epoch
        if validator is None:
            raise GatewayHeartbeatError("EPOCH_VALIDATOR_UNBOUND")
        try:
            current = validator(identity, scope, epoch)
        except Exception:
            raise GatewayHeartbeatError("EPOCH_VALIDATION_FAILED") from None
        if current is not True:
            raise GatewayHeartbeatError("STALE_OR_UNVERIFIED_EPOCH")
        return {
            "schema_version": 1,
            "relay_epoch": epoch,
            "heartbeat_id": heartbeat_id,
            "sent_at_ns": sent_at,
            "monitor_principal": self._monitor_principal,
        }
