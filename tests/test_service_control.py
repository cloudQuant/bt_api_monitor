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
    MONITOR_CONTROL_SUBMIT_OPERATIONS,
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
) -> dict[str, Any]:
    claims = {
        "schema_version": 1,
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
        {"schema_version": 1},
        identity=_owner(),
    )
    assert claimed["claimed"] is True
    assert claimed["command"]["command_id"] == "freeze-1"
    assert claimed["command"]["scope"] == COMMAND_SCOPE
    assert ledger.get("freeze-1").status is ControlStatus.CLAIMED

    final = _handle(
        service,
        "monitor.acknowledge",
        {"schema_version": 1, "command_id": "freeze-1", "outcome": "applied"},
        identity=_owner(),
    )
    assert final["status"] == "acknowledged"
    assert final["outcome"] == "applied"
    assert final["owner_final"] is True
    assert final["reconciliation_required"] is False
    assert _handle(service, "monitor.control", arguments) == final
    assert _handle(
        service,
        "monitor.acknowledge",
        {"schema_version": 1, "command_id": "freeze-1", "outcome": "applied"},
        identity=_owner(),
    ) == final

    reopened_ledger, reopened_service = _service(tmp_path / "control.sqlite")
    assert _handle(reopened_service, "monitor.control", arguments) == final
    assert _handle(
        reopened_service,
        "monitor.acknowledge",
        {"schema_version": 1, "command_id": "freeze-1", "outcome": "applied"},
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
        MONITOR_CONTROL_SUBMIT_OPERATIONS | MONITOR_CONTROL_OWNER_OPERATIONS
    )
    assert dict(MONITOR_CONTROL_PORT_OPERATIONS) == {
        "service.monitor_control": MONITOR_CONTROL_SUBMIT_OPERATIONS,
        "service.owner_control": MONITOR_CONTROL_OWNER_OPERATIONS,
    }
    _error(
        "INVALID_BIND_PORTS",
        lambda: validate_service_options(
            {"role": "control"}, (MONITOR_CONTROL_OWNER_PORT,)
        ),
    )
    _error(
        "UNSUPPORTED_SERVICE_OPTIONS",
        lambda: validate_service_options({"role": "read_only"}, (MONITOR_CONTROL_PUBLIC_PORT,)),
    )
