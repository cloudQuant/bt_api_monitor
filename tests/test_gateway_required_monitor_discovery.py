"""Authenticated capability discovery versus unavailable Monitor endpoints."""

from __future__ import annotations

import multiprocessing
from contextlib import suppress
from types import SimpleNamespace

import pytest

zmq = pytest.importorskip("zmq")
pytest.importorskip("bt_api_py")
pytest.importorskip("bt_api_gateway")
pytest.importorskip("bt_api_transport_zmq")

from bt_api_base.service_protocol import WireIdentity, WireRole
from bt_api_monitor.durable import DurableOutbox
from bt_api_monitor.service_ingress import MonitorIngressTarget
from bt_api_py.gateway_required_monitor import RequiredMonitor, RequiredMonitorSettings
from bt_api_py.service_components import ComponentResources
from bt_api_py.service_config import parse_service_config
from bt_api_py.service_host import ServiceHost
from bt_api_py.service_registry import PrincipalGrant, ResourceGrant
from bt_api_py.service_runtime import ClientCurveKeys, ServiceClientRuntime, ZmqTransportFactory

from test_gateway_heartbeat_host import (
    _ACCOUNT_SCOPE, _INGRESS_ID, _INGRESS_INSTANCE, _INGRESS_PRINCIPAL, _INGRESS_SCOPE_REF,
    _INGRESS_SECURITY_REF, _authority, _endpoint, _producer_config, _server_config,
)
from test_gateway_required_monitor_integration import _start_monitor, _stop_monitor


class _Result:
    def __init__(self, callback):
        self._callback = callback

    def result(self, **_kwargs):
        return self._callback()


class _Owner:
    def binding(self):
        return SimpleNamespace(generation="generation")

    def status(self):
        return SimpleNamespace(thread_alive=True)

    def submit_service_call(self, callback):
        return _Result(callback)


class _Control:
    def active_system_causes(self, _origin):
        # The startup probe never clears an outage without a valid heartbeat.
        return ({"mode": "STOP_NEW", "scope_kind": "account", "scope_value": ""},)


def _legacy_monitor(connection, raw_config, registry_path, outbox_path, keys):
    raw_config["components"]["monitor"]["settings"]["options"] = {"role": "durable_ingress"}
    config = parse_service_config(raw_config)
    identity = WireIdentity(WireRole.SERVICE, "synthetic-producer-a", "producer-a-service")
    monitor = WireIdentity(WireRole.SERVICE, _INGRESS_PRINCIPAL, _INGRESS_ID)
    grant = ResourceGrant(_INGRESS_INSTANCE, "service.telemetry_ingress", _INGRESS_SCOPE_REF,
                          _ACCOUNT_SCOPE, frozenset({"events.append"}))
    authority = _authority(config, service_identity=monitor, scope=_ACCOUNT_SCOPE,
        server_public=keys["server_public"], server_secret=keys["server_secret"],
        principals={keys["client_public"]: identity.principal_ref},
        grants={identity.principal_ref: (PrincipalGrant(identity, (grant,)),)},
        security_ref=_INGRESS_SECURITY_REF)
    outbox = DurableOutbox(outbox_path)
    host = ServiceHost(config, authority, registry_path,
        lambda *_: ComponentResources.borrowed({"outbox": outbox, "targets": {
            _ACCOUNT_SCOPE: MonitorIngressTarget("outbox:synthetic", ("event.synthetic",))}},
            ready=lambda: True))
    try:
        host.start()
        connection.send(("ready", host.endpoint))
        while True:
            host.serve_once(timeout_ms=20)
            if connection.poll() and connection.recv() == "close":
                host.close()
                connection.send("closed")
                return
    finally:
        if host.state not in {"closed", "failed"}:
            with suppress(Exception):
                host.close()
        connection.close()


def _keys():
    server_public, server_secret = zmq.curve_keypair()
    client_public, client_secret = zmq.curve_keypair()
    return {"server_public": server_public, "server_secret": server_secret,
            "client_public": client_public, "client_secret": client_secret}


def _probe(endpoint, keys, *, wait=4):
    gateway = WireIdentity(WireRole.SERVICE, "synthetic-producer-a", "producer-a-service")
    monitor = WireIdentity(WireRole.SERVICE, _INGRESS_PRINCIPAL, _INGRESS_ID)

    def factory():
        return ServiceClientRuntime(_producer_config(endpoint), identity=gateway,
            scope_resolver=lambda _: _ACCOUNT_SCOPE, peer_resolver=lambda _: monitor,
            transport_factory=ZmqTransportFactory({"producer-client-v1": ClientCurveKeys(
                keys["server_public"], keys["client_public"], keys["client_secret"])}),
            requested_operations={"upstream.telemetry": frozenset({"monitor.heartbeat"})})

    required = RequiredMonitor(RequiredMonitorSettings(factory, gateway, monitor, _ACCOUNT_SCOPE,
        interval_seconds=0.1, timeout_seconds=0.8), "generation")
    required.start(_Owner(), _Control())
    try:
        return required.startup_probe(wait)
    finally:
        assert required.close(5), "synthetic probe cleanup was not confirmed"


def test_authenticated_legacy_discovery_is_explicitly_incompatible(tmp_path):
    keys, endpoint = _keys(), _endpoint()
    ctx = multiprocessing.get_context("spawn")
    parent, child = ctx.Pipe()
    process = ctx.Process(target=_legacy_monitor, args=(child, _server_config(endpoint=endpoint),
        str(tmp_path / "registry.sqlite"), str(tmp_path / "events.sqlite"), keys))
    process.start()
    child.close()
    try:
        assert parent.poll(10) and parent.recv() == ("ready", endpoint)
        category = _probe(endpoint, keys)
        print("authenticated_legacy_category:", category)
        assert category == "INCOMPATIBLE"
    finally:
        _stop_monitor(parent, process)


def test_unreachable_service_is_not_misclassified_as_legacy():
    category = _probe(_endpoint(), _keys())
    print("unreachable_category:", category)
    assert category in {"UNREACHABLE", "TIMEOUT"}


def test_unknown_curve_client_is_not_misclassified_as_legacy(tmp_path):
    keys, endpoint = _keys(), _endpoint()
    ctx = multiprocessing.get_context("spawn")
    parent, process = _start_monitor(ctx, endpoint, tmp_path / "registry.sqlite", keys)
    try:
        public, secret = zmq.curve_keypair()
        denied = {**keys, "client_public": public, "client_secret": secret}
        category = _probe(endpoint, denied)
        print("wrong_curve_key_category:", category)
        assert category in {"AUTH_FAILED", "UNREACHABLE", "TIMEOUT"}
    finally:
        _stop_monitor(parent, process)
