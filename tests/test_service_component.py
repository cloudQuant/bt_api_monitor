"""Focused read-only Monitor service adapter tests."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
from bt_api_base.service_protocol import WireScope

from bt_api_monitor.durable import DurableOutbox, OutboxEvent
from bt_api_monitor.service_component import (
    MAX_MONITOR_READ_PAGE_SIZE,
    MONITOR_READ_OPERATIONS,
    MonitorReadService,
    MonitorReadServiceError,
    MonitorReadTarget,
    validate_service_options,
)


def _scope(
    *,
    execution_domain_ref: str = "paper:demo",
    account_ref: str | None = "account-a",
    strategy_ref: str | None = "strategy-a",
    run_id: str | None = None,
    portfolio_ref: str | None = None,
    manual_book_ref: str | None = None,
) -> WireScope:
    return WireScope(
        execution_domain_ref=execution_domain_ref,
        account_ref=account_ref,
        strategy_ref=strategy_ref,
        run_id=run_id,
        portfolio_ref=portfolio_ref,
        manual_book_ref=manual_book_ref,
    )


def _event(event_id: str, scope: str, event_type: str, **data: object) -> OutboxEvent:
    return OutboxEvent(
        event_id=event_id,
        scope=scope,
        event_type=event_type,
        data=data,
        occurred_at=1_800_000_000.0,
    )


def _service(path: Path) -> tuple[DurableOutbox, MonitorReadService]:
    writer = DurableOutbox(path)
    reader = DurableOutbox(path, read_only=True)
    service = MonitorReadService(
        reader,
        {
            _scope(): MonitorReadTarget(
                outbox_scope="outbox:strategy-a",
                event_types=("risk.alert", "risk.decision"),
            )
        },
    )
    return writer, service


def _handle(
    service: MonitorReadService,
    principal: str,
    scope: WireScope | None = None,
    *,
    operation: str = "monitor.query",
    arguments: dict[str, object] | None = None,
):
    return service.handle(
        operation,
        principal_ref=principal,
        scope=scope or _scope(),
        arguments={} if arguments is None else arguments,
    )


def test_service_options_are_empty_immutable_and_bind_ports_are_finite() -> None:
    options = validate_service_options(
        {},
        (
            "service.telemetry_ingress",
            "service.monitor_query",
            "service.monitor_control",
        ),
    )
    assert dict(options) == {}
    with pytest.raises(TypeError):
        options["enabled"] = True  # type: ignore[index]

    with pytest.raises(MonitorReadServiceError, match="UNSUPPORTED_SERVICE_OPTIONS"):
        validate_service_options({"enabled": True}, ("service.monitor_query",))
    with pytest.raises(MonitorReadServiceError, match="INVALID_BIND_PORTS"):
        validate_service_options({}, ("service.owner_control",))
    with pytest.raises(MonitorReadServiceError, match="INVALID_BIND_PORTS"):
        validate_service_options({}, ("service.monitor_query", "service.monitor_query"))


def test_multi_type_read_uses_one_global_cursor_without_checkpoint_semantics(tmp_path) -> None:
    writer = DurableOutbox(tmp_path / "monitor.db")
    first = writer.append(_event("event-1", "outbox:strategy-a", "risk.alert", level="warn"))
    second = writer.append(_event("event-2", "outbox:strategy-a", "risk.decision", decision="deny"))
    third = writer.append(_event("event-3", "outbox:strategy-a", "risk.alert", level="info"))
    # The monitor's read cursor is independent of existing durable consumers.
    writer.acknowledge("existing-consumer", "outbox:strategy-a", first.sequence)
    checkpoint_before = writer.checkpoint("existing-consumer", "outbox:strategy-a")
    service = MonitorReadService(
        DurableOutbox(tmp_path / "monitor.db", read_only=True),
        {_scope(): MonitorReadTarget("outbox:strategy-a", ("risk.alert", "risk.decision"))},
    )

    page1 = _handle(service, "principal-a", arguments={"limit": 2})
    assert page1 == {
        "requested_cursor": 0,
        "next_cursor": second.sequence,
        "has_more": True,
        "events": (
            {
                "sequence": first.sequence,
                "event_id": "event-1",
                "event_type": "risk.alert",
                "occurred_at": 1_800_000_000.0,
                "data": {"level": "warn"},
            },
            {
                "sequence": second.sequence,
                "event_id": "event-2",
                "event_type": "risk.decision",
                "occurred_at": 1_800_000_000.0,
                "data": {"decision": "deny"},
            },
        ),
    }
    page2 = _handle(
        service,
        "principal-a",
        operation="monitor.read_after",
        arguments={"after_sequence": page1["next_cursor"], "limit": 2},
    )
    assert page2["requested_cursor"] == second.sequence
    assert page2["next_cursor"] == third.sequence
    assert page2["has_more"] is False
    assert [event["event_id"] for event in page2["events"]] == ["event-3"]
    assert writer.checkpoint("existing-consumer", "outbox:strategy-a") == checkpoint_before


def test_strategy_template_wildcards_only_run_for_the_exact_strategy(tmp_path) -> None:
    writer = DurableOutbox(tmp_path / "monitor.db")
    writer.append(_event("strategy-event", "outbox:strategy-a", "risk.alert", level="warn"))
    service = MonitorReadService(
        DurableOutbox(tmp_path / "monitor.db", read_only=True),
        {_scope(run_id=None): MonitorReadTarget("outbox:strategy-a", ("risk.alert",))},
    )

    assert (
        _handle(service, "principal-a", _scope(run_id="run-one"))["events"][0]["event_id"]
        == "strategy-event"
    )
    assert (
        _handle(service, "principal-b", _scope(run_id="run-two"))["events"][0]["event_id"]
        == "strategy-event"
    )
    with pytest.raises(MonitorReadServiceError, match="SCOPE_NOT_GRANTED"):
        _handle(service, "principal-a", _scope(strategy_ref="strategy-b", run_id="run-one"))


@pytest.mark.parametrize(
    "scope",
    [
        _scope(execution_domain_ref="live:venue-a"),
        _scope(account_ref="account-b"),
        _scope(strategy_ref="strategy-b"),
        _scope(portfolio_ref="portfolio-a"),
        _scope(manual_book_ref="manual-a", strategy_ref=None),
    ],
)
def test_request_must_match_every_configured_scope_dimension(tmp_path, scope) -> None:
    _, service = _service(tmp_path / "monitor.db")
    with pytest.raises(MonitorReadServiceError, match="SCOPE_NOT_GRANTED"):
        _handle(service, "principal-a", scope)


def test_unsupported_or_client_supplied_scope_fields_are_rejected(tmp_path) -> None:
    _, service = _service(tmp_path / "monitor.db")

    with pytest.raises(MonitorReadServiceError, match="UNKNOWN_ARGUMENT"):
        _handle(service, "principal-a", arguments={"after_sequence": 0, "account_ref": "other"})
    with pytest.raises(MonitorReadServiceError, match="UNKNOWN_ARGUMENT"):
        _handle(service, "principal-a", arguments={"scope": {"account_ref": "other"}})
    with pytest.raises(MonitorReadServiceError, match="UNKNOWN_ARGUMENT"):
        _handle(service, "principal-a", arguments={"event_types": ["risk.alert"]})

    grouped_scope = WireScope(
        execution_domain_ref="paper:demo",
        account_ref="account-a",
        portfolio_ref="portfolio-a",
        group_id="group-a",
        leg_id="leg-a",
    )
    with pytest.raises(MonitorReadServiceError, match="UNSUPPORTED_SCOPE"):
        _handle(service, "principal-a", grouped_scope)


def test_cursor_and_limit_are_exact_bounded_integers(tmp_path) -> None:
    _, service = _service(tmp_path / "monitor.db")
    for arguments in (
        {"after_sequence": True},
        {"after_sequence": -1},
        {"after_sequence": 1 << 63},
    ):
        with pytest.raises(MonitorReadServiceError, match="INVALID_CURSOR"):
            _handle(service, "principal-a", arguments=arguments)
    for limit in (True, 0, MAX_MONITOR_READ_PAGE_SIZE + 1):
        with pytest.raises(MonitorReadServiceError, match="INVALID_LIMIT"):
            _handle(service, "principal-a", arguments={"limit": limit})
    with pytest.raises(MonitorReadServiceError, match="CURSOR_REQUIRED"):
        _handle(service, "principal-a", operation="monitor.read_after")
    with pytest.raises(MonitorReadServiceError, match="UNSUPPORTED_OPERATION"):
        _handle(service, "principal-a", operation="monitor.control")


def test_reads_are_client_isolated_stateless_and_leave_database_bytes_unchanged(tmp_path) -> None:
    database = tmp_path / "monitor.db"
    writer = DurableOutbox(database)
    writer.append(_event("visible-1", "outbox:strategy-a", "risk.alert", level="warn"))
    writer.append(_event("other-scope", "outbox:strategy-b", "risk.alert", level="info"))
    writer.append(
        _event(
            "visible-2",
            "outbox:strategy-a",
            "risk.decision",
            decision="allow",
            facts=[{"source": "synthetic"}],
        )
    )
    writer.acknowledge("existing-consumer", "outbox:strategy-a", 1)
    service = MonitorReadService(
        DurableOutbox(database, read_only=True),
        {_scope(): MonitorReadTarget("outbox:strategy-a", ("risk.alert", "risk.decision"))},
    )

    database_hash_before = hashlib.sha256(database.read_bytes()).hexdigest()
    page_a = _handle(service, "principal-a", arguments={"limit": 10})
    page_b = _handle(service, "principal-b", arguments={"limit": 10})
    same_client_replay = _handle(service, "principal-a", arguments={"limit": 10})
    assert page_a == page_b == same_client_replay
    assert [event["event_id"] for event in page_a["events"]] == ["visible-1", "visible-2"]
    assert page_a["events"][1]["data"] == {
        "decision": "allow",
        "facts": [{"source": "synthetic"}],
    }
    # Returned values are ordinary JSON-compatible projections, detached from
    # the service and the outbox's immutable event data.
    serialized_page = json.loads(json.dumps(page_a))
    assert serialized_page["events"][1]["data"]["facts"] == [{"source": "synthetic"}]
    page_a["events"][1]["data"]["decision"] = "locally changed"
    assert (
        _handle(service, "principal-b", arguments={"limit": 10})["events"][1]["data"]["decision"]
        == "allow"
    )
    assert hashlib.sha256(database.read_bytes()).hexdigest() == database_hash_before
    assert writer.checkpoint("existing-consumer", "outbox:strategy-a") == 1
    assert (
        service.OPERATIONS
        == MONITOR_READ_OPERATIONS
        == frozenset({"monitor.query", "monitor.read_after"})
    )
    assert not hasattr(service, "close")


def test_targets_must_be_unambiguous_and_read_only_outbox_is_borrowed(tmp_path) -> None:
    database = tmp_path / "monitor.db"
    writer = DurableOutbox(database)
    with pytest.raises(MonitorReadServiceError, match="READ_ONLY_OUTBOX_REQUIRED"):
        MonitorReadService(writer, {_scope(): MonitorReadTarget("one", ("risk.alert",))})

    template = _scope()
    specific_run = _scope(run_id="run-one")
    readonly = DurableOutbox(database, read_only=True)
    with pytest.raises(MonitorReadServiceError, match="AMBIGUOUS_TARGET"):
        MonitorReadService(
            readonly,
            {
                template: MonitorReadTarget("strategy-wide", ("risk.alert",)),
                specific_run: MonitorReadTarget("strategy-run-one", ("risk.alert",)),
            },
        )
    service = MonitorReadService(
        readonly,
        {template: MonitorReadTarget("strategy-wide", ("risk.alert",))},
    )
    _handle(service, "principal-a")
    assert readonly.is_read_only
    # The caller still owns and can use the borrowed outbox after each call.
    assert readonly.read_page_types("strategy-wide", ("risk.alert",), 0, 1) == ([], False)


def test_service_component_import_is_lazy_and_does_not_start_monitoring(tmp_path) -> None:
    package_root = Path(__file__).resolve().parents[1]
    package_source = package_root / "src"
    base_source = package_root.parent / "bt_api_base" / "src"
    program = r"""
import asyncio
import os
import pathlib
import sys
import threading

sys.dont_write_bytecode = True
sys.path[:0] = [sys.argv[1], sys.argv[2]]
before_threads = tuple(threading.enumerate())
before_entries = set(pathlib.Path.cwd().rglob('*'))

from bt_api_base.functions.log_message import SpdLogManager
def forbidden_logger(*args, **kwargs):
    raise AssertionError('pure service import attempted logger/file creation')
SpdLogManager.create_logger = forbidden_logger

def forbidden_thread_start(*args, **kwargs):
    raise AssertionError('pure service import started a thread')
threading.Thread.start = forbidden_thread_start

def forbidden_task(*args, **kwargs):
    raise AssertionError('pure service import started async monitoring')
asyncio.create_task = forbidden_task

from bt_api_monitor.service_component import validate_service_options
assert dict(validate_service_options({}, ('service.monitor_query',))) == {}
assert tuple(threading.enumerate()) == before_threads
assert set(pathlib.Path.cwd().rglob('*')) == before_entries
assert 'bt_api_monitor.elk' not in sys.modules
assert 'bt_api_monitor.prometheus' not in sys.modules
assert 'bt_api_monitor.system_metrics' not in sys.modules
assert 'psutil' not in sys.modules

# Existing explicit exports still resolve lazily to their defining objects.
from bt_api_monitor import DurableOutbox, get_logger
from bt_api_monitor.durable import DurableOutbox as DirectOutbox
from bt_api_base.logging_factory import get_logger as direct_get_logger
import bt_api_monitor
import hashlib
assert DurableOutbox is DirectOutbox
assert get_logger is direct_get_logger
assert 'DurableOutbox' in dir(bt_api_monitor)
assert 'DurableOutbox' in bt_api_monitor.__all__
assert set(bt_api_monitor.__all__) == set(bt_api_monitor._EXPORT_MODULES)
assert len(bt_api_monitor.__all__) == 95
assert hashlib.sha256((chr(10).join(bt_api_monitor.__all__)).encode()).hexdigest() == '3d8fa6ce3844ff16648e9eb3123241ea7b8d483eb1ea7b988a642a107635aa87'
"""
    environment = os.environ.copy()
    environment.pop("PYTHONPATH", None)
    result = subprocess.run(  # noqa: S603 -- fixed import probe, no provider or shell.
        [sys.executable, "-c", program, str(package_source), str(base_source)],
        cwd=tmp_path,
        env=environment,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert result.returncode == 0, result.stderr
