"""Offline Monitor side of the Gateway relay heartbeat contract."""

from __future__ import annotations

import pytest
from bt_api_base.service_protocol import WireIdentity, WireRole, WireScope

from bt_api_monitor.service_gateway_heartbeat import (
    GATEWAY_HEARTBEAT_OPERATIONS,
    GatewayHeartbeatError,
    GatewayHeartbeatService,
    validate_service_options,
)


IDENTITY = WireIdentity(WireRole.SERVICE, "gateway-principal", "gateway-relay")
SCOPE = WireScope(execution_domain_ref="domain", account_ref="account")
REQUEST = {"schema_version": 1, "relay_epoch": "epoch-1", "heartbeat_id": "h-1", "sent_at_ns": 42}


def _service(validator=lambda _i, _s, epoch: epoch == "epoch-1"):
    return GatewayHeartbeatService(
        monitor_principal="monitor-principal",
        targets=frozenset({(IDENTITY, SCOPE)}),
        validate_current_epoch=validator,
    )


def _call(service, *, request=None, identity=IDENTITY, scope=SCOPE, principal=None,
          registration_id="epoch-1"):
    return service.handle(
        "monitor.heartbeat",
        principal_ref=identity.principal_ref if principal is None else principal,
        identity=identity,
        scope=scope,
        registration_id=registration_id,
        arguments=REQUEST.copy() if request is None else request,
    )


def test_ack_is_bound_to_original_request_and_does_not_create_control_authority():
    service = _service()
    ack = _call(service)
    assert ack == {**REQUEST, "monitor_principal": "monitor-principal"}
    assert _call(service) == ack  # Retry does not issue a new time or identifier.
    assert GATEWAY_HEARTBEAT_OPERATIONS == frozenset({"monitor.heartbeat"})
    with pytest.raises(GatewayHeartbeatError, match="UNSUPPORTED_OPERATION"):
        service.handle("control.apply", principal_ref=IDENTITY.principal_ref,
                       identity=IDENTITY, scope=SCOPE, registration_id="epoch-1", arguments={})


def test_rejects_wrong_identity_scope_and_epoch_without_reflecting_input():
    service = _service()
    wrong = WireIdentity(WireRole.SERVICE, "other", "gateway-relay")
    for kwargs in ({"identity": wrong}, {"principal": "other"},
                   {"scope": WireScope(execution_domain_ref="domain", account_ref="other")},
                   {"request": {**REQUEST, "relay_epoch": "stale-epoch"}},
                   {"registration_id": "new-registration"}):
        with pytest.raises(GatewayHeartbeatError) as exc:
            _call(service, **kwargs)
        assert "stale-epoch" not in str(exc.value)


@pytest.mark.parametrize("changes", [
    {"schema_version": True}, {"schema_version": 2}, {"relay_epoch": ""},
    {"relay_epoch": " "+"x"}, {"heartbeat_id": "x\n"},
    {"heartbeat_id": "x" * 129}, {"sent_at_ns": True}, {"sent_at_ns": 0},
    {"sent_at_ns": 2**63}, {"extra": 1},
])
def test_rejects_invalid_requests(changes):
    with pytest.raises(GatewayHeartbeatError, match="INVALID_HEARTBEAT"):
        _call(_service(), request={**REQUEST, **changes})


def test_epoch_validator_must_be_trusted_and_return_exact_true():
    for value in (False, None, 1):
        with pytest.raises(GatewayHeartbeatError, match="STALE_OR_UNVERIFIED_EPOCH"):
            _call(_service(lambda *_: value))

    def broken(*_):
        raise RuntimeError("secret")

    with pytest.raises(GatewayHeartbeatError, match="EPOCH_VALIDATION_FAILED") as exc:
        _call(_service(broken))
    assert "secret" not in str(exc.value)


def test_host_epoch_validator_binding_is_one_shot_and_fails_closed_until_bound():
    service = GatewayHeartbeatService(monitor_principal="monitor-principal",
                                      targets=frozenset({(IDENTITY, SCOPE)}))
    assert service.monitor_principal == "monitor-principal"
    with pytest.raises(AttributeError):
        service.monitor_principal = "changed"
    with pytest.raises(GatewayHeartbeatError, match="EPOCH_VALIDATOR_UNBOUND"):
        _call(service)
    with pytest.raises(GatewayHeartbeatError, match="INVALID_EPOCH_VALIDATOR"):
        service.bind_current_epoch_validator(None)
    service.bind_current_epoch_validator(lambda *_: True)
    assert _call(service)["heartbeat_id"] == "h-1"
    with pytest.raises(GatewayHeartbeatError, match="EPOCH_VALIDATOR_ALREADY_BOUND"):
        service.bind_current_epoch_validator(lambda *_: True)
    with pytest.raises(GatewayHeartbeatError, match="EPOCH_VALIDATOR_ALREADY_BOUND"):
        _service().bind_current_epoch_validator(lambda *_: True)


def test_constructor_rejects_empty_targets_and_nonservice_identity():
    with pytest.raises(GatewayHeartbeatError, match="INVALID_TARGETS"):
        GatewayHeartbeatService(monitor_principal="m", targets=frozenset(),
                                validate_current_epoch=lambda *_: True)
    identity = WireIdentity(WireRole.STRATEGY_CLIENT, "strategy", "strategy")
    with pytest.raises(GatewayHeartbeatError, match="INVALID_TARGETS"):
        GatewayHeartbeatService(monitor_principal="m", targets=frozenset({(identity, SCOPE)}),
                                validate_current_epoch=lambda *_: True)


def test_monitor_principal_obeys_wire_utf8_reference_rules():
    service = GatewayHeartbeatService(
        monitor_principal="监控:一",
        targets=frozenset({(IDENTITY, SCOPE)}),
        validate_current_epoch=lambda *_: True,
    )
    assert _call(service)["monitor_principal"] == "监控:一"
    for invalid in (" " , "bad\x80ref", "\ud800", "一" * 86):
        with pytest.raises(GatewayHeartbeatError, match="INVALID_MONITOR_PRINCIPAL"):
            GatewayHeartbeatService(monitor_principal=invalid, targets=frozenset({(IDENTITY, SCOPE)}),
                                    validate_current_epoch=lambda *_: True)


def test_service_role_requires_explicit_options_and_single_ingress_port():
    options = validate_service_options({"role": "gateway_heartbeat"}, ("service.telemetry_ingress",))
    assert dict(options) == {"role": "gateway_heartbeat"}
    with pytest.raises(TypeError):
        options["role"] = "other"
    for value in ({}, {"role": "durable_ingress"}, {"role": "gateway_heartbeat", "extra": 1}):
        with pytest.raises(GatewayHeartbeatError, match="UNSUPPORTED_SERVICE_OPTIONS"):
            validate_service_options(value, ("service.telemetry_ingress",))
    with pytest.raises(GatewayHeartbeatError, match="INVALID_BIND_PORTS"):
        validate_service_options({"role": "gateway_heartbeat"}, ("service.monitor_control",))
