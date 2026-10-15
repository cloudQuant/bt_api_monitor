"""Authenticated service adapter for durable monitor control commands.

The service host supplies an authenticated ``WireIdentity`` and a validated
``WireScope``. This adapter binds application submissions to an exact trusted
caller and verified issuer, and binds owner claim/results to one exact service
identity and executor. It records requests and owner outcomes; it does not
perform account actions or infer risk state.
"""

from __future__ import annotations

import base64
import binascii
from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any

from bt_api_base.service_protocol import WireIdentity, WireRole, WireScope

from .control import (
    ClaimedControlCommand,
    ControlAuthorizationError,
    ControlClaimError,
    ControlCommandBinding,
    ControlCommandEnvelope,
    ControlConflictError,
    ControlIngress,
    ControlOwnerOutcome,
    ControlStatus,
    DurableControlLedger,
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

MONITOR_CONTROL_SUBMIT_OPERATIONS = frozenset({"monitor.control"})
MONITOR_CONTROL_OWNER_OPERATIONS = frozenset({"monitor.claim", "monitor.acknowledge"})
MONITOR_CONTROL_OPERATIONS = MONITOR_CONTROL_SUBMIT_OPERATIONS.union(
    MONITOR_CONTROL_OWNER_OPERATIONS
)

MONITOR_CONTROL_PUBLIC_PORT = "service.monitor_control"
MONITOR_CONTROL_OWNER_PORT = "service.owner_control"
_CONTROL_OPTIONS = frozenset({"role"})
_SUBMIT_FIELDS = frozenset({"schema_version", "payload_b64", "signature_b64"})
_CLAIM_FIELDS = frozenset({"schema_version"})
_ACKNOWLEDGE_FIELDS = frozenset({"schema_version", "command_id", "outcome"})
_MAX_CONTROL_PAYLOAD_BYTES = 64 * 1024
_MAX_CONTROL_SIGNATURE_BYTES = 16 * 1024
_MAX_PAYLOAD_B64_CHARS = ((_MAX_CONTROL_PAYLOAD_BYTES + 2) // 3) * 4
_MAX_SIGNATURE_B64_CHARS = ((_MAX_CONTROL_SIGNATURE_BYTES + 2) // 3) * 4
_MAX_CONTROL_TEXT_BYTES = 256

MONITOR_CONTROL_PORT_OPERATIONS = MappingProxyType(
    {
        MONITOR_CONTROL_PUBLIC_PORT: MONITOR_CONTROL_SUBMIT_OPERATIONS,
        MONITOR_CONTROL_OWNER_PORT: MONITOR_CONTROL_OWNER_OPERATIONS,
    }
)


class MonitorControlServiceError(ValueError):
    """A finite control request, identity, scope, or owner binding failure."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True)
class MonitorControlTarget:
    """Trusted control route for one exact wire-scope template.

    ``caller_bindings`` is an allowlist keyed by the full authenticated
    identity, including its delegate reference. Each binding independently
    fixes the signed issuer, account, mode, command scope, and permitted
    actions. ``owner_identity`` and ``executor_id`` jointly identify the one
    owner allowed to claim and acknowledge commands in that scope.
    """

    ingress: ControlIngress
    caller_bindings: Mapping[WireIdentity, ControlCommandBinding]
    owner_identity: WireIdentity
    executor_id: str

    def __post_init__(self) -> None:
        if type(self.ingress) is not ControlIngress:
            raise MonitorControlServiceError("INVALID_TARGET")
        if type(self.ingress.ledger) is not DurableControlLedger:
            raise MonitorControlServiceError("INVALID_TARGET")
        if not isinstance(self.caller_bindings, Mapping) or not self.caller_bindings:
            raise MonitorControlServiceError("INVALID_TARGET")
        if type(self.owner_identity) is not WireIdentity:
            raise MonitorControlServiceError("INVALID_TARGET")
        if self.owner_identity.role is not WireRole.SERVICE:
            raise MonitorControlServiceError("INVALID_TARGET")
        _validate_text(self.executor_id, "INVALID_TARGET")

        copied: dict[WireIdentity, ControlCommandBinding] = {}
        route: tuple[str, str, str] | None = None
        for identity, binding in self.caller_bindings.items():
            if (
                type(identity) is not WireIdentity
                or identity.role is not WireRole.APPLICATION_CLIENT
                or identity.delegate_ref is None
                or type(binding) is not ControlCommandBinding
            ):
                raise MonitorControlServiceError("INVALID_TARGET")
            _validate_text(binding.issuer, "INVALID_TARGET")
            _validate_text(binding.account_id, "INVALID_TARGET")
            _validate_text(binding.mode, "INVALID_TARGET")
            _validate_text(binding.scope, "INVALID_TARGET")
            binding_route = (binding.account_id, binding.mode, binding.scope)
            if route is None:
                route = binding_route
            elif binding_route != route:
                raise MonitorControlServiceError("INVALID_TARGET")
            copied[identity] = binding

        if self.owner_identity in copied:
            raise MonitorControlServiceError("INVALID_TARGET")
        object.__setattr__(self, "caller_bindings", MappingProxyType(copied))

    @property
    def command_scope(self) -> str:
        """The one durable scope shared by this route's caller bindings."""

        return next(iter(self.caller_bindings.values())).scope

    @property
    def account_id(self) -> str:
        """The one account bound to every caller on this route."""

        return next(iter(self.caller_bindings.values())).account_id

    @property
    def mode(self) -> str:
        """The one execution mode bound to every caller on this route."""

        return next(iter(self.caller_bindings.values())).mode


class MonitorControlService:
    """Submit signed commands and expose scoped owner claim/result operations."""

    OPERATIONS = MONITOR_CONTROL_OPERATIONS
    SUBMIT_OPERATIONS = MONITOR_CONTROL_SUBMIT_OPERATIONS
    OWNER_OPERATIONS = MONITOR_CONTROL_OWNER_OPERATIONS

    def __init__(self, targets: Mapping[WireScope, MonitorControlTarget]) -> None:
        if not isinstance(targets, Mapping) or not targets:
            raise MonitorControlServiceError("TARGETS_REQUIRED")

        copied: dict[WireScope, MonitorControlTarget] = {}
        ledger_routes: set[tuple[int, str]] = set()
        for template, target in targets.items():
            if type(template) is not WireScope or type(target) is not MonitorControlTarget:
                raise MonitorControlServiceError("INVALID_TARGET")
            try:
                _validate_scope_template(template)
            except MonitorReadServiceError:
                raise MonitorControlServiceError("INVALID_TARGET") from None
            ledger_route = (id(target.ingress.ledger), target.command_scope)
            if ledger_route in ledger_routes:
                raise MonitorControlServiceError("AMBIGUOUS_TARGET")
            ledger_routes.add(ledger_route)
            copied[template] = target

        templates = tuple(copied)
        for index, left in enumerate(templates):
            for right in templates[index + 1 :]:
                if _templates_overlap(left, right):
                    raise MonitorControlServiceError("AMBIGUOUS_TARGET")
        self._targets = MappingProxyType(copied)

    def handle(
        self,
        operation: str,
        *,
        principal_ref: str,
        identity: WireIdentity,
        scope: WireScope,
        arguments: Mapping[str, Any],
    ) -> Mapping[str, Any]:
        """Handle one registry-authenticated request using its exact wire scope."""

        if type(operation) is not str or operation not in self.OPERATIONS:
            raise MonitorControlServiceError("UNSUPPORTED_OPERATION")
        _validate_text(principal_ref, "INVALID_PRINCIPAL")
        if type(identity) is not WireIdentity:
            raise MonitorControlServiceError("INVALID_IDENTITY")
        if identity.principal_ref != principal_ref:
            raise MonitorControlServiceError("IDENTITY_MISMATCH")
        target = self._resolve_target(scope)

        if operation in self.SUBMIT_OPERATIONS:
            return self._submit(target, identity, arguments)
        if identity.role is not WireRole.SERVICE or identity != target.owner_identity:
            raise MonitorControlServiceError("OWNER_IDENTITY_REQUIRED")
        if operation == "monitor.claim":
            return self._claim(target, arguments)
        return self._acknowledge(target, arguments)

    def _submit(
        self,
        target: MonitorControlTarget,
        identity: WireIdentity,
        arguments: Mapping[str, Any],
    ) -> Mapping[str, Any]:
        if identity.role is not WireRole.APPLICATION_CLIENT:
            raise MonitorControlServiceError("APPLICATION_ROLE_REQUIRED")
        binding = target.caller_bindings.get(identity)
        if binding is None:
            raise MonitorControlServiceError("CALLER_DELEGATION_NOT_GRANTED")
        envelope = _parse_envelope(arguments)
        try:
            result = target.ingress.submit(envelope, binding=binding)
        except ControlConflictError:
            raise MonitorControlServiceError("COMMAND_ID_CONFLICT") from None
        except ControlAuthorizationError:
            raise MonitorControlServiceError("CONTROL_NOT_AUTHORIZED") from None
        except Exception:
            raise MonitorControlServiceError("CONTROL_SUBMISSION_FAILED") from None
        _validate_ledger_result(result, target, expected_executor=None)
        return _command_status(result)

    def _claim(
        self, target: MonitorControlTarget, arguments: Mapping[str, Any]
    ) -> Mapping[str, Any]:
        _parse_empty_operation(arguments, _CLAIM_FIELDS)
        try:
            claimed = target.ingress.ledger.claim_next(
                target.command_scope,
                target.executor_id,
                account_id=target.account_id,
                mode=target.mode,
            )
        except Exception:
            raise MonitorControlServiceError("CONTROL_CLAIM_FAILED") from None
        if claimed is None:
            return MappingProxyType({"claimed": False, "command": None})
        _validate_ledger_result(claimed, target, expected_executor=target.executor_id)
        if claimed.status is not ControlStatus.CLAIMED:
            raise MonitorControlServiceError("MALFORMED_CLAIM_RESULT")
        return MappingProxyType({"claimed": True, "command": _owner_command(claimed)})

    def _acknowledge(
        self, target: MonitorControlTarget, arguments: Mapping[str, Any]
    ) -> Mapping[str, Any]:
        command_id, outcome = _parse_owner_outcome(arguments)
        try:
            current = target.ingress.ledger.get(command_id)
        except Exception:
            raise MonitorControlServiceError("CONTROL_STATUS_READ_FAILED") from None
        if current is None:
            raise MonitorControlServiceError("COMMAND_NOT_FOUND")
        _validate_ledger_result(current, target, expected_executor=target.executor_id)
        try:
            target.ingress.ledger.finish_owner_outcome(
                command_id, target.executor_id, outcome
            )
            result = target.ingress.ledger.get(command_id)
        except ControlClaimError:
            raise MonitorControlServiceError("OWNER_OUTCOME_REJECTED") from None
        except Exception:
            raise MonitorControlServiceError("OWNER_OUTCOME_WRITE_FAILED") from None
        if result is None:
            raise MonitorControlServiceError("MALFORMED_OWNER_OUTCOME")
        _validate_ledger_result(result, target, expected_executor=target.executor_id)
        if result.outcome != outcome.value:
            raise MonitorControlServiceError("OWNER_OUTCOME_CONFLICT")
        return _command_status(result)

    def _resolve_target(self, scope: WireScope) -> MonitorControlTarget:
        if type(scope) is not WireScope:
            raise MonitorControlServiceError("INVALID_SCOPE")
        try:
            _validate_requested_scope(scope)
        except MonitorReadServiceError:
            raise MonitorControlServiceError("UNSUPPORTED_SCOPE") from None
        matches = [
            target for template, target in self._targets.items() if _scope_matches(template, scope)
        ]
        if len(matches) != 1:
            raise MonitorControlServiceError("SCOPE_NOT_GRANTED")
        return matches[0]


def validate_service_options(
    options: Mapping[str, Any], bind_ports: tuple[str, ...]
) -> Mapping[str, Any]:
    """Require the public submit bind for the explicitly selected control role.

    The service composition registers owner claim/result calls separately on
    its internal ``service.owner_control`` port; that port is never a client
    bind and must be authorized by the service runtime independently.
    """

    if not isinstance(options, Mapping) or set(options) != _CONTROL_OPTIONS:
        raise MonitorControlServiceError("UNSUPPORTED_SERVICE_OPTIONS")
    if options.get("role") != "control" or type(options.get("role")) is not str:
        raise MonitorControlServiceError("UNSUPPORTED_SERVICE_OPTIONS")
    if type(bind_ports) is not tuple:
        raise MonitorControlServiceError("INVALID_BIND_PORTS")
    if any(type(port) is not str for port in bind_ports) or len(set(bind_ports)) != len(
        bind_ports
    ):
        raise MonitorControlServiceError("INVALID_BIND_PORTS")
    if bind_ports != (MONITOR_CONTROL_PUBLIC_PORT,):
        raise MonitorControlServiceError("INVALID_BIND_PORTS")
    return MappingProxyType({"role": "control"})


def _parse_envelope(arguments: Mapping[str, Any]) -> ControlCommandEnvelope:
    values = _parse_fields(arguments, _SUBMIT_FIELDS)
    _require_schema_v1(values)
    payload_encoded = values["payload_b64"]
    signature_encoded = values["signature_b64"]
    if (
        type(payload_encoded) is not str
        or not payload_encoded
        or len(payload_encoded) > _MAX_PAYLOAD_B64_CHARS
        or type(signature_encoded) is not str
        or not signature_encoded
        or len(signature_encoded) > _MAX_SIGNATURE_B64_CHARS
    ):
        raise MonitorControlServiceError("INVALID_ENVELOPE_ENCODING")
    try:
        payload_bytes = payload_encoded.encode("ascii", "strict")
        signature_bytes = signature_encoded.encode("ascii", "strict")
        payload = base64.b64decode(payload_bytes, validate=True)
        signature = base64.b64decode(signature_bytes, validate=True)
    except (UnicodeEncodeError, binascii.Error, ValueError):
        raise MonitorControlServiceError("INVALID_ENVELOPE_ENCODING") from None
    if (
        base64.b64encode(payload) != payload_bytes
        or base64.b64encode(signature) != signature_bytes
    ):
        raise MonitorControlServiceError("INVALID_ENVELOPE_ENCODING")
    try:
        return ControlCommandEnvelope(payload=payload, signature=signature)
    except ValueError:
        raise MonitorControlServiceError("INVALID_ENVELOPE") from None


def _parse_empty_operation(
    arguments: Mapping[str, Any], expected_fields: frozenset[str]
) -> Mapping[str, Any]:
    values = _parse_fields(arguments, expected_fields)
    _require_schema_v1(values)
    return values


def _parse_owner_outcome(
    arguments: Mapping[str, Any],
) -> tuple[str, ControlOwnerOutcome]:
    values = _parse_fields(arguments, _ACKNOWLEDGE_FIELDS)
    _require_schema_v1(values)
    command_id = values["command_id"]
    _validate_text(command_id, "INVALID_COMMAND_ID")
    raw_outcome = values["outcome"]
    if type(raw_outcome) is not str:
        raise MonitorControlServiceError("INVALID_OWNER_OUTCOME")
    try:
        outcome = ControlOwnerOutcome(raw_outcome)
    except ValueError:
        raise MonitorControlServiceError("INVALID_OWNER_OUTCOME") from None
    return command_id, outcome


def _parse_fields(
    arguments: Mapping[str, Any], expected_fields: frozenset[str]
) -> Mapping[str, Any]:
    if not isinstance(arguments, Mapping) or any(type(key) is not str for key in arguments):
        raise MonitorControlServiceError("INVALID_ARGUMENTS")
    supplied = set(arguments)
    if supplied != expected_fields:
        if supplied - expected_fields:
            raise MonitorControlServiceError("UNKNOWN_ARGUMENT")
        raise MonitorControlServiceError("MISSING_ARGUMENT")
    return arguments


def _require_schema_v1(arguments: Mapping[str, Any]) -> None:
    if type(arguments["schema_version"]) is not int or arguments["schema_version"] != 1:
        raise MonitorControlServiceError("UNSUPPORTED_SCHEMA_VERSION")


def _validate_ledger_result(
    result: object,
    target: MonitorControlTarget,
    *,
    expected_executor: str | None,
) -> None:
    if type(result) is not ClaimedControlCommand:
        raise MonitorControlServiceError("MALFORMED_CONTROL_RESULT")
    if (
        type(result.status) is not ControlStatus
        or result.command.account_id != target.account_id
        or result.command.mode != target.mode
        or result.command.scope != target.command_scope
        or not any(
            binding.issuer == result.command.issuer
            and result.command.action in binding.actions
            for binding in target.caller_bindings.values()
        )
    ):
        raise MonitorControlServiceError("CONTROL_RESULT_BINDING_MISMATCH")
    if expected_executor is not None:
        if result.executor_id != expected_executor:
            raise MonitorControlServiceError("CONTROL_RESULT_BINDING_MISMATCH")
    elif result.executor_id not in (None, target.executor_id):
        raise MonitorControlServiceError("CONTROL_RESULT_BINDING_MISMATCH")
    if result.status in (
        ControlStatus.ACKNOWLEDGED,
        ControlStatus.REJECTED,
        ControlStatus.EXPIRED,
        ControlStatus.UNKNOWN,
    ):
        if type(result.outcome) is not str or not result.outcome:
            raise MonitorControlServiceError("MALFORMED_CONTROL_RESULT")
    elif result.outcome is not None:
        raise MonitorControlServiceError("MALFORMED_CONTROL_RESULT")


def _command_status(command: ClaimedControlCommand) -> Mapping[str, Any]:
    typed_outcome = (
        command.outcome
        if command.outcome in {outcome.value for outcome in ControlOwnerOutcome}
        else None
    )
    owner_final = (
        command.status is ControlStatus.ACKNOWLEDGED
        and typed_outcome == ControlOwnerOutcome.APPLIED.value
    ) or (
        command.status is ControlStatus.REJECTED
        and typed_outcome == ControlOwnerOutcome.REJECTED.value
    )
    # This is the owner's final disposition of this command only. The monitor
    # has no risk-cause state and this flag never certifies a freeze as resolved.
    return MappingProxyType(
        {
            "command_id": command.command.command_id,
            "status": command.status.value,
            "outcome": typed_outcome,
            "request_recorded": True,
            "owner_final": owner_final,
            "reconciliation_required": command.status is ControlStatus.UNKNOWN
            or command.status in (ControlStatus.ACKNOWLEDGED, ControlStatus.REJECTED)
            and not owner_final,
        }
    )


def _owner_command(command: ClaimedControlCommand) -> Mapping[str, Any]:
    value = command.command
    return MappingProxyType(
        {
            "command_id": value.command_id,
            "account_id": value.account_id,
            "mode": value.mode,
            "scope": value.scope,
            "action": value.action.value,
            "issuer": value.issuer,
            "reason": value.reason,
            "receipt_digest": value.receipt_digest,
            "issued_at": value.issued_at,
            "expires_at": value.expires_at,
            "manual_resume_authorized": value.manual_resume_authorized,
        }
    )


def _validate_text(value: object, error_code: str) -> None:
    try:
        _validate_scope_text(value, _MAX_CONTROL_TEXT_BYTES, error_code)
    except MonitorReadServiceError:
        raise MonitorControlServiceError(error_code) from None


__all__ = [
    "MONITOR_CONTROL_OPERATIONS",
    "MONITOR_CONTROL_OWNER_OPERATIONS",
    "MONITOR_CONTROL_OWNER_PORT",
    "MONITOR_CONTROL_PORT_OPERATIONS",
    "MONITOR_CONTROL_PUBLIC_PORT",
    "MONITOR_CONTROL_SUBMIT_OPERATIONS",
    "MonitorControlService",
    "MonitorControlServiceError",
    "MonitorControlTarget",
    "validate_service_options",
]
