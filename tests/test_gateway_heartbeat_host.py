"""Gateway heartbeat through a synthetic spawned Monitor ServiceHost and CURVE."""

from __future__ import annotations

import multiprocessing
import socket
from contextlib import suppress

import pytest

zmq = pytest.importorskip("zmq")
pytest.importorskip("bt_api_py")
pytest.importorskip("bt_api_transport_zmq")
from bt_api_base.service_protocol import WireIdentity, WireRole
from bt_api_monitor.service_gateway_heartbeat import GatewayHeartbeatService
from bt_api_py.service_components import ComponentResources
from bt_api_py.service_config import parse_service_config
from bt_api_py.service_host import ServiceHost, TrustedServiceAuthority
from bt_api_py.service_registry import PrincipalGrant, ResourceGrant
from bt_api_py.service_runtime import (
    ClientCurveKeys, ServiceClientRuntime, ServiceRuntimeError, ZmqTransportFactory,
)
from bt_api_base.service_protocol import WireScope

_INGRESS_ID = "synthetic-monitor-ingress"
_INGRESS_INSTANCE = "monitor-ingress"
_INGRESS_PRINCIPAL = "synthetic-monitor-ingress-principal"
_INGRESS_SCOPE_REF = "monitor-ingress-account-v1"
_INGRESS_SECURITY_REF = "monitor-ingress-server-curve-v1"
_ACCOUNT_SCOPE = WireScope("paper:monitor-ingress", account_ref="synthetic-account")


def _endpoint():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        return f"tcp://127.0.0.1:{probe.getsockname()[1]}"


def _server_config(*, endpoint):
    return {
        "service_config_schema_version": 1, "process_role": "service",
        "service_id": _INGRESS_ID, "scope_ref": "monitor-root",
        "transport_ref": "listener", "registration_policy_ref": "policy",
        "service_requirements_ref": "requirements",
        "components": {"monitor": {"config_schema_version": 2, "settings": {
            "instance_id": _INGRESS_INSTANCE, "bind_ports": ["service.telemetry_ingress"],
            "options": {"role": "gateway_heartbeat"}}}},
        "communication": {"config_schema_version": 1, "profiles": {"listener": {
            "backend": "zmq", "config_schema_version": 1,
            "endpoints": {"rpc_bind": endpoint}, "security_profile_ref": _INGRESS_SECURITY_REF}}},
    }


def _authority(config, *, service_identity, scope, server_public, server_secret, principals,
               grants, security_ref):
    return TrustedServiceAuthority(identity=service_identity, scope=scope, scope_ref=config.scope_ref,
        scope_version="scope-v1", security_ref=security_ref, security_version="key-v1",
        registration_policy_ref=config.registration_policy_ref, registration_policy_version="policy-v1",
        service_requirements_ref=config.service_requirements_ref, service_requirements_version="req-v1",
        curve_public_key=server_public, curve_secret_key=server_secret, principals=principals, grants=grants)


def _producer_config(endpoint):
    return parse_service_config({
        "service_config_schema_version": 1, "process_role": "service",
        "service_id": "producer-a-service", "scope_ref": "producer-root",
        "transport_ref": "unused-listener", "registration_policy_ref": "producer-policy",
        "service_requirements_ref": "producer-requirements",
        "components": {"monitor": {"config_schema_version": 2, "settings": {
            "instance_id": "unused-monitor", "bind_ports": ["service.telemetry_ingress"],
            "options": {"role": "gateway_heartbeat"}}}},
        "clients": {"monitor": {"config_schema_version": 1, "settings": {
            "bindings": [{"mount": "upstream.telemetry", "service_id": _INGRESS_ID,
                "instance_id": _INGRESS_INSTANCE, "scope_ref": _INGRESS_SCOPE_REF,
                "transport_ref": "monitor-connect"}],
            "options": {"request_timeout_ms": 2000, "heartbeat_interval_seconds": 5}}}},
        "communication": {"config_schema_version": 1, "profiles": {
            "unused-listener": {"backend": "zmq", "config_schema_version": 1,
                "endpoints": {"rpc_bind": "tcp://127.0.0.1:1"}, "security_profile_ref": "unused"},
            "monitor-connect": {"backend": "zmq", "config_schema_version": 1,
                "endpoints": {"rpc_connect": endpoint}, "security_profile_ref": "producer-client-v1"}}},
    })


def _monitor_process(connection, raw_config, registry_path, keys, fault=None):
    config = parse_service_config(raw_config)
    identity = WireIdentity(WireRole.SERVICE, "synthetic-producer-a", "producer-a-service")
    monitor = WireIdentity(WireRole.SERVICE, _INGRESS_PRINCIPAL, _INGRESS_ID)
    heartbeat = GatewayHeartbeatService(
        monitor_principal="wrong-monitor" if fault == "principal" else monitor.principal_ref,
        targets=frozenset({(identity, _ACCOUNT_SCOPE)}),
        validate_current_epoch=(lambda *_: True) if fault == "prebound" else None,
    )
    grant = ResourceGrant(_INGRESS_INSTANCE, "service.telemetry_ingress", _INGRESS_SCOPE_REF,
                          _ACCOUNT_SCOPE, frozenset({"monitor.heartbeat"}))
    authority = _authority(config, service_identity=monitor, scope=_ACCOUNT_SCOPE,
        server_public=keys["server_public"], server_secret=keys["server_secret"],
        principals={keys["client_public"]: identity.principal_ref},
        grants={identity.principal_ref: (PrincipalGrant(identity, (grant,)),)},
        security_ref=_INGRESS_SECURITY_REF)
    host = ServiceHost(config, authority, registry_path,
        lambda *_: ComponentResources.borrowed({"service": heartbeat}, ready=lambda: True))
    try:
        host.start()
        connection.send(("ready", host.endpoint))
        while True:
            host.serve_once(timeout_ms=20)
            if connection.poll():
                command = connection.recv()
                if command == "close":
                    host.close()
                    connection.send("closed")
                    return
    except BaseException as error:
        with suppress(Exception):
            connection.send(("error", getattr(error, "code", type(error).__name__)))
        if fault is None:
            raise
    finally:
        if host.state not in {"closed", "failed"}:
            with suppress(Exception):
                host.close()
        connection.close()


def test_spawned_monitor_receives_authenticated_heartbeat_and_rejects_stale_epoch(tmp_path):
    server_public, server_secret = zmq.curve_keypair()
    client_public, client_secret = zmq.curve_keypair()
    keys = {"server_public": server_public, "server_secret": server_secret,
            "client_public": client_public, "client_secret": client_secret}
    endpoint = _endpoint()
    raw = _server_config(endpoint=endpoint)
    ctx = multiprocessing.get_context("spawn")
    parent, child = ctx.Pipe()
    process = ctx.Process(target=_monitor_process,
                          args=(child, raw, str(tmp_path / "monitor-registry.sqlite"), keys))
    process.start()
    child.close()
    runtime = None
    replacement = None
    try:
        assert parent.poll(15), "synthetic monitor did not start"
        ready = parent.recv()
        assert ready == ("ready", endpoint)
        identity = WireIdentity(WireRole.SERVICE, "synthetic-producer-a", "producer-a-service")
        peer = WireIdentity(WireRole.SERVICE, _INGRESS_PRINCIPAL, _INGRESS_ID)
        def create_runtime():
            return ServiceClientRuntime(_producer_config(endpoint), identity=identity,
                scope_resolver=lambda _: _ACCOUNT_SCOPE, peer_resolver=lambda _: peer,
                transport_factory=ZmqTransportFactory({"producer-client-v1": ClientCurveKeys(
                    server_public, client_public, client_secret)}),
                requested_operations={"upstream.telemetry": frozenset({"monitor.heartbeat"})})

        runtime = create_runtime()
        assert runtime.start().degraded_count == 0
        registration = runtime.bindings[0].registration_id
        request = {"schema_version": 1, "relay_epoch": registration, "heartbeat_id": "id-1", "sent_at_ns": 5}
        ack = runtime.call("upstream.telemetry", "monitor.heartbeat", request)
        assert dict(ack) == {**request, "monitor_principal": _INGRESS_PRINCIPAL}
        assert dict(runtime.call("upstream.telemetry", "monitor.heartbeat", request)) == dict(ack)
        with pytest.raises(ServiceRuntimeError):
            runtime.call("upstream.telemetry", "monitor.heartbeat",
                         {**request, "relay_epoch": "different-registration"})
        replacement = create_runtime()
        assert replacement.start().degraded_count == 0
        new_registration = replacement.bindings[0].registration_id
        assert new_registration != registration
        # Simultaneously active registrations for the same relay are ambiguous.
        with pytest.raises(ServiceRuntimeError):
            runtime.call("upstream.telemetry", "monitor.heartbeat", request)
        with pytest.raises(ServiceRuntimeError):
            replacement.call("upstream.telemetry", "monitor.heartbeat", {
                **request, "relay_epoch": new_registration})
        runtime.close()
        runtime = None
        with pytest.raises(ServiceRuntimeError):
            replacement.call("upstream.telemetry", "monitor.heartbeat", request)
        request = {**request, "relay_epoch": new_registration, "heartbeat_id": "id-2", "sent_at_ns": 9}
        assert dict(replacement.call("upstream.telemetry", "monitor.heartbeat", request)) == {
            **request, "monitor_principal": _INGRESS_PRINCIPAL}
    finally:
        if runtime is not None:
            with suppress(Exception):
                runtime.close()
        if replacement is not None:
            with suppress(Exception):
                replacement.close()
        if process.is_alive():
            with suppress(Exception):
                parent.send("close")
                if parent.poll(5):
                    parent.recv()
        process.join(8)
        if process.is_alive():
            process.terminate()  # Only this test's own synthetic child.
            process.join(5)
        parent.close()
    assert process.exitcode == 0


@pytest.mark.parametrize("fault", ["principal", "prebound"])
def test_host_rejects_wrong_monitor_identity_or_prebound_validator(tmp_path, fault):
    server_public, server_secret = zmq.curve_keypair()
    client_public, client_secret = zmq.curve_keypair()
    keys = {"server_public": server_public, "server_secret": server_secret,
            "client_public": client_public, "client_secret": client_secret}
    endpoint = _endpoint()
    ctx = multiprocessing.get_context("spawn")
    parent, child = ctx.Pipe()
    process = ctx.Process(target=_monitor_process,
        args=(child, _server_config(endpoint=endpoint), str(tmp_path / "registry.sqlite"), keys, fault))
    process.start()
    child.close()
    try:
        assert parent.poll(15), "synthetic monitor did not report startup"
        message = parent.recv()
        assert message[0] == "error"
        assert message[1] == ("GATEWAY_HEARTBEAT_IDENTITY_MISMATCH" if fault == "principal"
                              else "GATEWAY_HEARTBEAT_REGISTRY_BIND_FAILED")
    finally:
        process.join(8)
        if process.is_alive():
            process.terminate()  # Only this test's own synthetic child.
            process.join(5)
        parent.close()
    assert process.exitcode == 0
