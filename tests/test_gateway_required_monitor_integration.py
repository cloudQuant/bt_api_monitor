"""Required Gateway Monitor against a real, synthetic CURVE Monitor process."""

from __future__ import annotations

import multiprocessing
import time
from contextlib import suppress

import pytest

zmq = pytest.importorskip("zmq")
pytest.importorskip("bt_api_py")
pytest.importorskip("bt_api_gateway")
pytest.importorskip("bt_api_transport_zmq")

from bt_api_base.service_protocol import WireIdentity, WireRole
from bt_api_gateway.direct_command_journal import DirectCommandJournalError, GatewayDirectCommandJournal
from bt_api_gateway.direct_dispatch import GatewayDirectDispatcher
from bt_api_gateway.session_guard import LocalAccountSessionGuard
from bt_api_py.gateway_direct_owner import GatewayDirectOwner, GatewayDirectOwnerResources
from bt_api_py.gateway_required_monitor import RequiredMonitor, RequiredMonitorSettings
from bt_api_py.service_runtime import ClientCurveKeys, ServiceClientRuntime, ZmqTransportFactory

from test_gateway_heartbeat_host import (
    _ACCOUNT_SCOPE, _INGRESS_ID, _INGRESS_PRINCIPAL, _endpoint, _monitor_process,
    _producer_config, _server_config,
)


def _wait(predicate, description, seconds=8):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(0.02)
    pytest.fail(f"timed out: {description}")


def _start_monitor(ctx, endpoint, path, keys):
    parent, child = ctx.Pipe()
    process = ctx.Process(target=_monitor_process,
                          args=(child, _server_config(endpoint=endpoint), str(path), keys))
    process.start()
    child.close()
    if not parent.poll(10):
        process.terminate()
        process.join(5)
        parent.close()
        pytest.fail("synthetic Monitor did not start")
    assert parent.recv() == ("ready", endpoint)
    return parent, process


def _stop_monitor(parent, process):
    if process.is_alive():
        parent.send("close")
        assert parent.poll(6) and parent.recv() == "closed"
    process.join(6)
    assert process.exitcode == 0
    parent.close()


@pytest.mark.parametrize("automatic", [True, False])
def test_required_monitor_outage_and_recovery_with_real_gateway_owner(tmp_path, automatic):
    server_public, server_secret = zmq.curve_keypair()
    client_public, client_secret = zmq.curve_keypair()
    keys = {"server_public": server_public, "server_secret": server_secret,
            "client_public": client_public, "client_secret": client_secret}
    endpoint = _endpoint()
    registry_path = tmp_path / "monitor-registry.sqlite"
    ctx = multiprocessing.get_context("spawn")
    parent, process = _start_monitor(ctx, endpoint, registry_path, keys)
    root = tmp_path / "guards"
    root.mkdir()
    gateway_identity = WireIdentity(WireRole.SERVICE, "synthetic-producer-a", "producer-a-service")
    monitor_identity = WireIdentity(WireRole.SERVICE, _INGRESS_PRINCIPAL, _INGRESS_ID)

    def runtime_factory():
        return ServiceClientRuntime(_producer_config(endpoint), identity=gateway_identity,
            scope_resolver=lambda _: _ACCOUNT_SCOPE, peer_resolver=lambda _: monitor_identity,
            transport_factory=ZmqTransportFactory({"producer-client-v1": ClientCurveKeys(
                server_public, client_public, client_secret)}),
            requested_operations={"upstream.telemetry": frozenset({"monitor.heartbeat"})})

    settings = RequiredMonitorSettings(runtime_factory, gateway_identity, monitor_identity, _ACCOUNT_SCOPE,
                                       interval_seconds=0.1, timeout_seconds=0.8,
                                       automatic_resume=automatic)
    holder = {}

    def create_resources():
        guard = LocalAccountSessionGuard(root, _ACCOUNT_SCOPE.account_ref, "owner")
        generation = guard.acquire()
        journal = GatewayDirectCommandJournal.create(tmp_path / "gateway.sqlite", _ACCOUNT_SCOPE.account_ref,
                                                     generation=generation)
        control = journal.enable_controls(guard)
        dispatcher = GatewayDirectDispatcher(journal, "SYN", guard, lambda *_: None,
                                             lambda _: ("key",), lambda _: True)
        monitor = RequiredMonitor(settings, generation)
        monitor.initialize_on_owner(journal, control, guard)
        holder.update(guard=guard, journal=journal, control=control, monitor=monitor)
        return GatewayDirectOwnerResources(dispatcher, journal, guard.release)

    owner = GatewayDirectOwner(create_resources, queue_size=8, max_queue_wait_seconds=2,
                               busy_timeout_seconds=1)
    monitor_closed = owner_closed = False
    try:
        assert owner.start(5)
        monitor, control = holder["monitor"], holder["control"]
        owner_call = lambda callback: owner.submit_service_call(callback).result(timeout_seconds=2)
        owner_call(lambda: control.apply("operator-freeze", "FREEZE", scope_kind="strategy",
                                         scope_value="other-strategy", origin="operator"))
        monitor.start(owner, control)
        if not automatic:
            cause, = owner_call(lambda: control.active_system_causes(monitor.origin))
            owner_call(lambda: control.resume(cause["cause_id"], expected_version=cause["version"],
                                              operation_id="manual-initial"))
        _wait(monitor.gate, "authenticated Monitor heartbeat")
        assert owner_call(lambda: control.get("operator-freeze"))["active"] == 1
        assert not owner_call(lambda: control.active_system_causes(monitor.origin))
        assert owner_call(lambda: holder["journal"].reserve(
            "strategy-a", "before-outage", "principal", {"symbol": "X"})).status == "RESERVED"

        _stop_monitor(parent, process)
        parent = process = None
        _wait(lambda: not monitor.gate(), "fail-closed after Monitor stops", seconds=3)
        _wait(lambda: bool(owner_call(lambda: control.active_system_causes(monitor.origin))),
              "persisted Monitor outage")
        cause, = owner_call(lambda: control.active_system_causes(monitor.origin))
        assert cause["mode"] == "STOP_NEW" and cause["active"] == 1
        assert owner_call(lambda: control.get("operator-freeze"))["active"] == 1
        def attempt_during_outage():
            try:
                holder["journal"].reserve("strategy-a", "during-outage", "principal", {"symbol": "X"})
            except DirectCommandJournalError as error:
                return error.code
            return "UNEXPECTEDLY_RESERVED"
        assert owner_call(attempt_during_outage) == "CONTROL_STOP_NEW"

        parent, process = _start_monitor(ctx, endpoint, registry_path, keys)
        if automatic:
            _wait(monitor.gate, "automatic recovery after Monitor restart", seconds=12)
        else:
            # Successful ACK alone cannot clear an operator-controlled cause.
            def has_fresh_proof():
                with monitor.gate._lock:
                    return monitor.gate._proof is not None and time.monotonic_ns() < monitor.gate._deadline
            _wait(has_fresh_proof, "authenticated fresh ACK in manual mode", seconds=12)
            assert not monitor.gate()
            cause, = owner_call(lambda: control.active_system_causes(monitor.origin))
            owner_call(lambda: control.resume(cause["cause_id"], expected_version=cause["version"],
                                              operation_id="manual-outage"))
            _wait(monitor.gate, "manual recovery after Monitor restart", seconds=12)
        assert not owner_call(lambda: control.active_system_causes(monitor.origin))
        assert owner_call(lambda: control.get("operator-freeze"))["active"] == 1
        assert owner_call(lambda: holder["journal"].reserve(
            "strategy-a", "after-recovery", "principal", {"symbol": "X"})).status == "RESERVED"
    finally:
        if "monitor" in holder:
            with suppress(Exception):
                monitor_closed = holder["monitor"].close(4)
        with suppress(Exception):
            owner_closed = owner.close(4)
        if process is not None:
            with suppress(Exception):
                _stop_monitor(parent, process)
    assert monitor_closed, "required Monitor worker cleanup was not confirmed"
    assert owner_closed, "synthetic Gateway owner cleanup was not confirmed"
