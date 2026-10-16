"""Offline integration tests for the authenticated monitor control adapter."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
from pathlib import Path
from typing import Any

import pytest
from bt_api_base.service_protocol import WireIdentity, WireRole, WireScope

from bt_api_monitor.control import (
    ControlAction,
    ControlCommandBinding,
    ControlCommandEnvelope,
    ControlIngress,
    ControlOwnerOutcome,
    ControlStatus,
    DurableControlLedger,
    monitor_freeze_cause_id,
)
from bt_api_monitor.ingress import (
    CONTROL_COMMAND_HMAC_DOMAIN,
    ControlIssuerPolicy,
    ControlScopeGrant,
    HmacControlCommandVerifier,
    HmacControlKey,
)
from bt_api_monitor.service_control import (
    MONITOR_CONTROL_OPERATIONS,
    MONITOR_CONTROL_OWNER_OPERATIONS,
    MONITOR_CONTROL_OWNER_PORT,
    MONITOR_CONTROL_PORT_OPERATIONS,
    MONITOR_CONTROL_PUBLIC_PORT,
    MONITOR_CONTROL_PUBLIC_OPERATIONS,
    MONITOR_CONTROL_SUBMIT_OPERATIONS,
    MONITOR_CONTROL_STATUS_OPERATIONS,
    MonitorControlService,
    MonitorControlServiceError,
    MonitorControlTarget,
    validate_service_options,
)

NOW = 1_800_000_000.0
KEY_ID = "control-test-key"
ISSUER = "operator:desk-a"
ACCOUNT_ID = "paper-account-17"
MODE = "simulation"
COMMAND_SCOPE = "account:17"
RECEIPT = "a" * 64
SECRET = b"offline-control-adapter-test-secret"


class MutableClock:
    def __call__(self) -> float:
        return NOW


class KeyResolver:
    def __init__(self, key: HmacControlKey) -> None:
        self.key = key

    def resolve(self, key_id: str) -> HmacControlKey | None:
        return self.key if key_id == self.key.key_id else None


class PolicyResolver:
    def __init__(self, policy: ControlIssuerPolicy) -> None:
        self.policy = policy

    def resolve(self, issuer: str) -> ControlIssuerPolicy | None:
        return self.policy if issuer == self.policy.issuer else None


def _scope(*, account_ref: str = "account-17") -> WireScope:
    return WireScope(execution_domain_ref="paper:demo", account_ref=account_ref)


def _caller(*, delegate_ref: str = "operator-delegation:desk-a") -> WireIdentity:
    return WireIdentity(
        role=WireRole.APPLICATION_CLIENT,
        principal_ref="application:operations-console",
        actor_ref="operator:alice",
        delegate_ref=delegate_ref,
    )


def _owner() -> WireIdentity:
    return WireIdentity(
        role=WireRole.SERVICE,
        principal_ref="service:account-owner-17",
        actor_ref="account-owner:17",
        delegate_ref="monitor-owner-delegation:17",
    )


def _verifier(*, actions: tuple[ControlAction, ...] = (ControlAction.FREEZE,)):
    key = HmacControlKey(
        key_id=KEY_ID,
        issuer=ISSUER,
        secret=SECRET,
        not_before_utc=NOW - 100,
        expires_at_utc=NOW + 100,
    )
    policy = ControlIssuerPolicy(
        issuer=ISSUER,
        policy_id="offline-control-policy-v1",
        grants=(
            ControlScopeGrant(
                account_id=ACCOUNT_ID,
                mode=MODE,
                scope=COMMAND_SCOPE,
                actions=actions,
                receipt_digests=(RECEIPT,),
                manual_resume_allowed=ControlAction.RESUME in actions,
            ),
        ),
        not_before_utc=NOW - 100,
        expires_at_utc=NOW + 100,
    )
    return HmacControlCommandVerifier(
        KeyResolver(key), PolicyResolver(policy), max_command_ttl_seconds=60
    )


def _verifier_for_accounts(
    *account_ids: str, mode: str = MODE
) -> HmacControlCommandVerifier:
    key = HmacControlKey(
        key_id=KEY_ID,
        issuer=ISSUER,
        secret=SECRET,
        not_before_utc=NOW - 100,
        expires_at_utc=NOW + 100,
    )
    policy = ControlIssuerPolicy(
        issuer=ISSUER,
        policy_id="offline-control-policy-v1",
        grants=tuple(
            ControlScopeGrant(
                account_id=account_id,
                mode=mode,
                scope=COMMAND_SCOPE,
                actions=(ControlAction.FREEZE,),
                receipt_digests=(RECEIPT,),
            )
            for account_id in account_ids
        ),
        not_before_utc=NOW - 100,
        expires_at_utc=NOW + 100,
    )
    return HmacControlCommandVerifier(
        KeyResolver(key), PolicyResolver(policy), max_command_ttl_seconds=60
    )


def _request(
    command_id: str,
    *,
    action: ControlAction = ControlAction.FREEZE,
    issuer_sequence: int = 1,
    account_id: str = ACCOUNT_ID,
    mode: str = MODE,
    reason: str = "offline acceptance test",
    schema_version: int | None = None,
    target_freeze_cause_id: str | None = None,
) -> dict[str, Any]:
    version = (
        schema_version
        if schema_version is not None
        else 2
        if action is ControlAction.RESUME
        else 1
    )
    claims = {
        "schema_version": version,
        "key_id": KEY_ID,
        "issuer": ISSUER,
        "command_id": command_id,
        "account_id": account_id,
        "mode": mode,
        "scope": COMMAND_SCOPE,
        "action": action.value,
        "reason": reason,
        "receipt_digest": RECEIPT,
        "issued_at": NOW - 1,
        "expires_at": NOW + 20,
        "issuer_sequence": issuer_sequence,
        "manual_resume_authorized": action is ControlAction.RESUME,
    }
    if version == 2:
        claims["target_freeze_cause_id"] = target_freeze_cause_id or (
            "monitor-freeze-v1:" + "e" * 64
            if action is ControlAction.RESUME
            else None
        )
    payload = json.dumps(
        claims, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    ).encode("utf-8")
    key_id = KEY_ID.encode("ascii")
    mac_input = (
        CONTROL_COMMAND_HMAC_DOMAIN
        + len(key_id).to_bytes(2, "big")
        + key_id
        + payload
    )
    signature = hmac.new(SECRET, mac_input, hashlib.sha256).digest()
    return {
        "schema_version": 1,
        "payload_b64": base64.b64encode(payload).decode("ascii"),
        "signature_b64": base64.b64encode(signature).decode("ascii"),
    }


def _envelope(arguments: dict[str, Any]):
    return ControlCommandEnvelope(
        payload=base64.b64decode(arguments["payload_b64"]),
        signature=base64.b64decode(arguments["signature_b64"]),
    )


def _service(
    path: Path,
    *,
    verifier: HmacControlCommandVerifier | None = None,
    binding_actions: frozenset[ControlAction] = frozenset({ControlAction.FREEZE}),
) -> tuple[DurableControlLedger, MonitorControlService]:
    ledger = DurableControlLedger(path, clock=MutableClock())
    ingress = ControlIngress(ledger, verifier or _verifier(), clock=MutableClock())
    binding = ControlCommandBinding(
        issuer=ISSUER,
        account_id=ACCOUNT_ID,
        mode=MODE,
        scope=COMMAND_SCOPE,
        actions=binding_actions,
    )
    target = MonitorControlTarget(
        ingress=ingress,
        caller_bindings={_caller(): binding},
        owner_identity=_owner(),
        executor_id="account-owner:17",
    )
    return ledger, MonitorControlService({_scope(): target})


def _handle(
    service: MonitorControlService,
    operation: str,
    arguments: dict[str, Any],
    *,
    identity: WireIdentity | None = None,
    scope: WireScope | None = None,
    principal_ref: str | None = None,
) -> Any:
    caller = _caller() if identity is None else identity
    return service.handle(
        operation,
        principal_ref=caller.principal_ref if principal_ref is None else principal_ref,
        identity=caller,
        scope=_scope() if scope is None else scope,
        arguments=arguments,
    )


def _error(code: str, call) -> None:
    with pytest.raises(MonitorControlServiceError) as captured:
        call()
    assert captured.value.code == code


def test_submit_claim_owner_result_and_exact_retry_are_one_durable_flow(tmp_path: Path) -> None:
    ledger, service = _service(tmp_path / "control.sqlite")
    arguments = _request("freeze-1")

    pending = _handle(service, "monitor.control", arguments)
    assert pending == {
        "command_id": "freeze-1",
        "status": "pending",
        "outcome": None,
        "effect_ref": None,
        "effect_result": None,
        "request_recorded": True,
        "owner_final": False,
        "reconciliation_required": False,
    }
    assert "accepted" not in pending
    assert _handle(service, "monitor.control", arguments) == pending
    _error(
        "COMMAND_ID_CONFLICT",
        lambda: _handle(
            service,
            "monitor.control",
            _request("freeze-1", reason="different signed command"),
        ),
    )
    assert ledger.get("freeze-1").status is ControlStatus.PENDING

    claimed = _handle(
        service,
        "monitor.claim",
        {"schema_version": 2, "command_id": "freeze-1"},
        identity=_owner(),
    )
    assert claimed["claimed"] is True
    assert claimed["command"]["command_id"] == "freeze-1"
    assert claimed["command"]["scope"] == COMMAND_SCOPE
    assert ledger.get("freeze-1").status is ControlStatus.CLAIMED

    final = _handle(
        service,
        "monitor.acknowledge",
        {
            "schema_version": 2,
            "command_id": "freeze-1",
            "outcome": "applied",
            "effect_ref": monitor_freeze_cause_id(ledger.get("freeze-1").command),
            "effect_result": {
                "action": "freeze",
                "cause_id": monitor_freeze_cause_id(ledger.get("freeze-1").command),
                "risk_state": "active",
            },
        },
        identity=_owner(),
    )
    assert final["status"] == "acknowledged"
    assert final["outcome"] == "applied"
    assert final["owner_final"] is True
    assert final["reconciliation_required"] is False
    expected_effect_ref = monitor_freeze_cause_id(ledger.get("freeze-1").command)
    assert final["effect_ref"] == expected_effect_ref
    assert _handle(service, "monitor.control", arguments) == final
    assert _handle(
        service,
        "monitor.acknowledge",
        {
            "schema_version": 2,
            "command_id": "freeze-1",
            "outcome": "applied",
            "effect_ref": expected_effect_ref,
            "effect_result": {
                "action": "freeze",
                "cause_id": expected_effect_ref,
                "risk_state": "active",
            },
        },
        identity=_owner(),
    ) == final

    reopened_ledger, reopened_service = _service(tmp_path / "control.sqlite")
    assert _handle(reopened_service, "monitor.control", arguments) == final
    assert _handle(
        reopened_service,
        "monitor.acknowledge",
        {
            "schema_version": 2,
            "command_id": "freeze-1",
            "outcome": "applied",
            "effect_ref": expected_effect_ref,
            "effect_result": {
                "action": "freeze",
                "cause_id": expected_effect_ref,
                "risk_state": "active",
            },
        },
        identity=_owner(),
    ) == final
    assert reopened_ledger.get("freeze-1").status is ControlStatus.ACKNOWLEDGED

    _error(
        "OWNER_OUTCOME_REJECTED",
        lambda: _handle(
            service,
            "monitor.acknowledge",
            {"schema_version": 1, "command_id": "freeze-1", "outcome": "rejected"},
            identity=_owner(),
        ),
    )
    assert ledger.get("freeze-1").outcome == ControlOwnerOutcome.APPLIED.value


def test_stop_new_migration_disabled_rejection_is_a_durable_no_effect_result(
    tmp_path: Path,
) -> None:
    actions = (ControlAction.STOP_NEW,)
    verifier = _verifier(actions=actions)
    ledger, service = _service(
        tmp_path / "stop-new-migration-disabled.sqlite",
        verifier=verifier,
        binding_actions=frozenset(actions),
    )
    request = _request(
        "stop-new-migration-disabled",
        action=ControlAction.STOP_NEW,
    )
    pending = _handle(service, "monitor.control", request)
    assert pending["status"] == ControlStatus.PENDING.value

    claimed = _handle(
        service,
        "monitor.claim",
        {"schema_version": 2, "command_id": "stop-new-migration-disabled"},
        identity=_owner(),
    )
    assert claimed["claimed"] is True

    rejected = _handle(
        service,
        "monitor.acknowledge",
        {
            "schema_version": 2,
            "command_id": "stop-new-migration-disabled",
            "outcome": ControlOwnerOutcome.REJECTED.value,
            "effect_ref": None,
            "effect_result": {
                "action": "stop_new",
                "result": "migration_write_disabled",
            },
        },
        identity=_owner(),
    )
    assert rejected["status"] == ControlStatus.REJECTED.value
    assert rejected["outcome"] == ControlOwnerOutcome.REJECTED.value
    assert rejected["owner_final"] is True
    assert rejected["effect_ref"] is None
    assert rejected["effect_result"] == {
        "action": "stop_new",
        "result": "migration_write_disabled",
    }
    assert rejected["reconciliation_required"] is False
    assert ledger.get("stop-new-migration-disabled").status is ControlStatus.REJECTED
    assert _handle(
        service,
        "monitor.control_status",
        {"schema_version": 1, "command_id": "stop-new-migration-disabled"},
    ) == rejected


def test_exact_wire_delegation_scope_and_verified_action_bind_before_write(tmp_path: Path) -> None:
    verifier = _verifier(actions=(ControlAction.FREEZE, ControlAction.DRAIN))
    ledger, service = _service(tmp_path / "bindings.sqlite", verifier=verifier)

    _error(
        "CALLER_DELEGATION_NOT_GRANTED",
        lambda: _handle(
            service,
            "monitor.control",
            _request("wrong-delegate"),
            identity=_caller(delegate_ref="operator-delegation:other"),
        ),
    )
    _error(
        "SCOPE_NOT_GRANTED",
        lambda: _handle(
            service,
            "monitor.control",
            _request("wrong-wire-scope"),
            scope=_scope(account_ref="account-18"),
        ),
    )
    _error(
        "CONTROL_NOT_AUTHORIZED",
        lambda: _handle(
            service,
            "monitor.control",
            _request("wrong-action", action=ControlAction.DRAIN),
        ),
    )
    assert ledger.get("wrong-delegate") is None
    assert ledger.get("wrong-wire-scope") is None
    assert ledger.get("wrong-action") is None


def test_owner_operations_are_separate_and_unknown_never_projects_as_final(tmp_path: Path) -> None:
    verifier = _verifier(actions=(ControlAction.FREEZE, ControlAction.RESUME))
    ledger, service = _service(
        tmp_path / "owner.sqlite",
        verifier=verifier,
        binding_actions=frozenset({ControlAction.FREEZE, ControlAction.RESUME}),
    )
    request = _request("resume-unknown", action=ControlAction.RESUME)
    _handle(service, "monitor.control", request)

    _error(
        "OWNER_IDENTITY_REQUIRED",
        lambda: _handle(
            service,
            "monitor.claim",
            {"schema_version": 1},
            identity=_caller(),
        ),
    )
    assert ledger.get("resume-unknown").status is ControlStatus.PENDING

    _handle(service, "monitor.claim", {"schema_version": 1}, identity=_owner())
    _error(
        "OWNER_IDENTITY_REQUIRED",
        lambda: _handle(
            service,
            "monitor.acknowledge",
            {"schema_version": 1, "command_id": "resume-unknown", "outcome": "applied"},
        ),
    )
    assert ledger.get("resume-unknown").status is ControlStatus.CLAIMED
    _error(
        "INVALID_OWNER_OUTCOME",
        lambda: _handle(
            service,
            "monitor.acknowledge",
            {"schema_version": 1, "command_id": "resume-unknown", "outcome": "accepted"},
            identity=_owner(),
        ),
    )
    unknown = _handle(
        service,
        "monitor.acknowledge",
        {"schema_version": 1, "command_id": "resume-unknown", "outcome": "unknown"},
        identity=_owner(),
    )
    assert unknown["status"] == "unknown"
    assert unknown["outcome"] == "unknown"
    assert unknown["owner_final"] is False
    assert unknown["reconciliation_required"] is True
    assert unknown["effect_ref"] is None
    assert "risk_resolved" not in unknown
    assert "freeze_resolved" not in unknown
    assert ledger.get("resume-unknown").status is ControlStatus.UNKNOWN
    assert _handle(service, "monitor.control", request) == unknown


def test_owner_result_requires_exact_claim_scope_and_executor(tmp_path: Path) -> None:
    ledger, service = _service(tmp_path / "owner-binding.sqlite")
    _handle(service, "monitor.control", _request("owned-by-other"))
    assert ledger.claim_next(COMMAND_SCOPE, "other-owner").command.command_id == "owned-by-other"

    _error(
        "CONTROL_RESULT_BINDING_MISMATCH",
        lambda: _handle(
            service,
            "monitor.acknowledge",
            {"schema_version": 1, "command_id": "owned-by-other", "outcome": "applied"},
            identity=_owner(),
        ),
    )
    assert ledger.get("owned-by-other").status is ControlStatus.CLAIMED
    assert ledger.get("owned-by-other").executor_id == "other-owner"


def test_owner_claim_filters_same_scope_to_its_bound_account_and_mode(tmp_path: Path) -> None:
    second_account = "paper-account-18"
    ledger, service = _service(tmp_path / "account-filter.sqlite")
    other_policy_verifier = _verifier_for_accounts(second_account)
    other_ingress = ControlIngress(
        ledger, other_policy_verifier, clock=MutableClock()
    )
    other_ingress.submit(
        _envelope(
            _request(
                "other-account-same-scope",
                account_id=second_account,
                issuer_sequence=1,
            )
        )
    )

    claimed = _handle(
        service,
        "monitor.claim",
        {"schema_version": 1},
        identity=_owner(),
    )
    assert claimed == {"claimed": False, "command": None}
    assert ledger.get("other-account-same-scope").status is ControlStatus.PENDING


def test_owner_claim_filters_same_account_and_scope_to_bound_mode(tmp_path: Path) -> None:
    other_mode = "live"
    ledger, service = _service(tmp_path / "mode-filter.sqlite")
    other_ingress = ControlIngress(
        ledger,
        _verifier_for_accounts(ACCOUNT_ID, mode=other_mode),
        clock=MutableClock(),
    )
    other_ingress.submit(
        _envelope(
            _request(
                "other-mode-same-account-scope",
                mode=other_mode,
            )
        )
    )

    claimed = _handle(
        service,
        "monitor.claim",
        {"schema_version": 1},
        identity=_owner(),
    )
    assert claimed == {"claimed": False, "command": None}
    row = ledger.get("other-mode-same-account-scope")
    assert row.command.account_id == ACCOUNT_ID
    assert row.command.mode == other_mode
    assert row.command.scope == COMMAND_SCOPE
    assert row.status is ControlStatus.PENDING


def test_control_role_requires_only_public_submit_bind_and_known_operations() -> None:
    options = validate_service_options({"role": "control"}, (MONITOR_CONTROL_PUBLIC_PORT,))
    assert dict(options) == {"role": "control"}
    assert frozenset({"monitor.control"}) == MONITOR_CONTROL_SUBMIT_OPERATIONS
    assert frozenset(
        {"monitor.claim", "monitor.acknowledge"}
    ) == MONITOR_CONTROL_OWNER_OPERATIONS
    assert MONITOR_CONTROL_OPERATIONS == (
        MONITOR_CONTROL_PUBLIC_OPERATIONS | MONITOR_CONTROL_OWNER_OPERATIONS
    )
    assert dict(MONITOR_CONTROL_PORT_OPERATIONS) == {
        "service.monitor_control": MONITOR_CONTROL_PUBLIC_OPERATIONS,
        "service.owner_control": MONITOR_CONTROL_OWNER_OPERATIONS,
    }
    assert MONITOR_CONTROL_PUBLIC_OPERATIONS == (
        MONITOR_CONTROL_SUBMIT_OPERATIONS | MONITOR_CONTROL_STATUS_OPERATIONS
    )
    _error(
        "INVALID_BIND_PORTS",
        lambda: validate_service_options(
            {"role": "control"}, (MONITOR_CONTROL_OWNER_PORT,)
        ),
    )


def test_control_status_is_private_to_the_exact_application_caller(tmp_path: Path) -> None:
    caller = _caller()
    foreign_caller = WireIdentity(
        WireRole.APPLICATION_CLIENT,
        caller.principal_ref,
        caller.actor_ref,
        "operator-delegation:another-user",
    )
    ledger = DurableControlLedger(tmp_path / "caller-private-status.sqlite", clock=MutableClock())
    ingress = ControlIngress(ledger, _verifier(), clock=MutableClock())
    caller_binding = ControlCommandBinding(
        issuer=ISSUER,
        account_id=ACCOUNT_ID,
        mode=MODE,
        scope=COMMAND_SCOPE,
        actions=frozenset({ControlAction.FREEZE}),
    )
    foreign_binding = ControlCommandBinding(
        issuer="operator:desk-b",
        account_id=ACCOUNT_ID,
        mode=MODE,
        scope=COMMAND_SCOPE,
        actions=frozenset({ControlAction.FREEZE}),
    )
    target = MonitorControlTarget(
        ingress=ingress,
        caller_bindings={caller: caller_binding, foreign_caller: foreign_binding},
        owner_identity=_owner(),
        executor_id="account-owner:17",
    )
    service = MonitorControlService({_scope(): target})
    arguments = _request("caller-private-status")
    _handle(service, "monitor.control", arguments, identity=caller)
    claim = _handle(
        service,
        "monitor.claim",
        {"schema_version": 2, "command_id": "caller-private-status"},
        identity=_owner(),
    )
    assert claim["claimed"] is True
    row = ledger.get("caller-private-status")
    assert row is not None
    cause_id = monitor_freeze_cause_id(row.command)
    _handle(
        service,
        "monitor.acknowledge",
        {
            "schema_version": 2,
            "command_id": "caller-private-status",
            "outcome": "applied",
            "effect_ref": cause_id,
            "effect_result": {
                "action": "freeze",
                "cause_id": cause_id,
                "risk_state": "active",
            },
        },
        identity=_owner(),
    )
    status = _handle(
        service,
        "monitor.control_status",
        {"schema_version": 1, "command_id": "caller-private-status"},
        identity=caller,
    )
    assert status["status"] == ControlStatus.ACKNOWLEDGED.value
    _error(
        "COMMAND_NOT_FOUND",
        lambda: _handle(
            service,
            "monitor.control_status",
            {"schema_version": 1, "command_id": "caller-private-status"},
            identity=foreign_caller,
        ),
    )
    _error(
        "UNSUPPORTED_SERVICE_OPTIONS",
        lambda: validate_service_options({"role": "read_only"}, (MONITOR_CONTROL_PUBLIC_PORT,)),
    )


def test_exact_owner_claim_cannot_pass_an_earlier_unresolved_route_command(tmp_path: Path) -> None:
    ledger, service = _service(tmp_path / "exact-claim.sqlite")
    _handle(service, "monitor.control", _request("first-command"))
    _handle(service, "monitor.control", _request("target-command", issuer_sequence=2))

    claimed = _handle(
        service,
        "monitor.claim",
        {"schema_version": 2, "command_id": "target-command"},
        identity=_owner(),
    )
    assert claimed == {"claimed": False, "command": None}
    assert ledger.get("first-command").status is ControlStatus.PENDING
    assert ledger.get("target-command").status is ControlStatus.PENDING

    first = _handle(
        service,
        "monitor.claim",
        {"schema_version": 2, "command_id": "first-command"},
        identity=_owner(),
    )
    assert first["claimed"] is True
    first_effect = monitor_freeze_cause_id(ledger.get("first-command").command)
    _handle(
        service,
        "monitor.acknowledge",
        {
            "schema_version": 2,
            "command_id": "first-command",
            "outcome": "applied",
            "effect_ref": first_effect,
            "effect_result": {
                "action": "freeze",
                "cause_id": first_effect,
                "risk_state": "active",
            },
        },
        identity=_owner(),
    )

    claimed = _handle(
        service,
        "monitor.claim",
        {"schema_version": 2, "command_id": "target-command"},
        identity=_owner(),
    )
    assert claimed["claimed"] is True
    assert claimed["command"]["command_id"] == "target-command"
    assert ledger.get("target-command").status is ControlStatus.CLAIMED

    duplicate_claim = _handle(
        service,
        "monitor.claim",
        {"schema_version": 2, "command_id": "target-command"},
        identity=_owner(),
    )
    assert duplicate_claim == {"claimed": False, "command": None}


def test_applied_outcome_is_durably_bound_to_effect_reference(tmp_path: Path) -> None:
    ledger, service = _service(tmp_path / "effect-ref.sqlite")
    request = _request("effect-command", schema_version=2)
    _handle(service, "monitor.control", request)
    _handle(
        service,
        "monitor.claim",
        {"schema_version": 2, "command_id": "effect-command"},
        identity=_owner(),
    )
    effect_ref = monitor_freeze_cause_id(ledger.get("effect-command").command)
    applied = _handle(
        service,
        "monitor.acknowledge",
        {
            "schema_version": 2,
            "command_id": "effect-command",
            "outcome": "applied",
            "effect_ref": effect_ref,
            "effect_result": {
                "action": "freeze",
                "cause_id": effect_ref,
                "activation_status": "CREATED",
                "cause_active": True,
                "has_other_active_freezes": False,
                "risk_state": "active",
            },
        },
        identity=_owner(),
    )
    assert applied["owner_final"] is True
    assert applied["effect_ref"] == effect_ref
    assert ledger.get("effect-command").effect_ref == effect_ref
    assert _handle(service, "monitor.control", request) == applied

    _error(
        "INVALID_EFFECT_RESULT",
        lambda: _handle(
            service,
            "monitor.acknowledge",
            {
                "schema_version": 2,
                "command_id": "effect-command",
                "outcome": "applied",
                "effect_ref": effect_ref,
                "effect_result": {
                    "action": "freeze",
                    "cause_id": effect_ref,
                    "risk_state": "active",
                },
            },
            identity=_owner(),
        ),
    )

    _error(
        "OWNER_EFFECT_REFERENCE_MISMATCH",
        lambda: _handle(
            service,
            "monitor.acknowledge",
            {
                "schema_version": 2,
                "command_id": "effect-command",
                "outcome": "applied",
                "effect_ref": "monitor-freeze-v1:" + "2" * 64,
                "effect_result": {
                    "action": "freeze",
                    "cause_id": "monitor-freeze-v1:" + "2" * 64,
                    "activation_status": "CREATED",
                    "cause_active": True,
                    "has_other_active_freezes": False,
                    "risk_state": "active",
                },
            },
            identity=_owner(),
        ),
    )
    assert ledger.get("effect-command").effect_ref == effect_ref
