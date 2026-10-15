"""Focused Gateway-to-Monitor system market observation tests."""

from __future__ import annotations

from itertools import count
from typing import Any

import pytest
from bt_api_base.market_protocol import MarketInstrumentKey, MarketSubscriptionKey
from bt_api_base.service_protocol import WireIdentity, WireRole, WireScope
from bt_api_gateway.market_hub import GatewayMarketHub

from bt_api_monitor.durable import DurableOutbox
from bt_api_monitor.market_observation import (
    GATEWAY_MARKET_OBSERVATION_EVENT_TYPE,
    MONITOR_MARKET_OBSERVATION_SCHEMA,
    MonitorMarketObservationError,
    MonitorMarketObservationProjector,
)
from bt_api_monitor.service_component import (
    MonitorReadService,
    MonitorReadServiceError,
    MonitorReadTarget,
)
from bt_api_monitor.service_ingress import MonitorIngressService, MonitorIngressTarget


class _Provider:
    def __init__(self) -> None:
        self.generations: dict[MarketSubscriptionKey, str] = {}

    def subscribe(self, key: MarketSubscriptionKey, *, generation: str) -> object:
        self.generations[key] = generation
        return object()

    def unsubscribe(self, handle: object) -> bool:
        del handle
        return True


def _key() -> MarketSubscriptionKey:
    return MarketSubscriptionKey(
        source_ref="source:public",
        entitlement_ref="entitlement:public",
        instrument=MarketInstrumentKey(
            provider="synthetic",
            venue="test-venue",
            environment="paper",
            product_type="spot",
            instrument_id="instrument-1",
            native_symbol="TST-USD",
        ),
        channel="trades",
    )


def _identity() -> WireIdentity:
    return WireIdentity(
        role=WireRole.SERVICE,
        principal_ref="service:gateway",
        actor_ref="gateway:market-hub",
    )


def _scope(**changes: Any) -> WireScope:
    values: dict[str, Any] = {"execution_domain_ref": "paper:demo"}
    values.update(changes)
    return WireScope(**values)


def _hub_events(count_events: int = 1) -> tuple[GatewayMarketHub, _Provider, list[object]]:
    key = _key()
    provider = _Provider()
    published: list[object] = []
    epochs = count(1)
    hub = GatewayMarketHub(
        provider,
        key_universe=(key,),
        principal_allowed_keys={"market-reader": (key,)},
        service_identity=_identity(),
        service_scope=_scope(),
        epoch_factory=lambda: f"gateway-epoch-{next(epochs)}",
    )
    hub.set_publisher(published.append)
    hub.subscribe("market-reader", key, "registration:one")
    for index in range(1, count_events + 1):
        hub.publish(
            key,
            {"price": 100 + index, "symbol": key.instrument.native_symbol},
            f"2026-10-15T10:00:{index:02d}Z",
            generation=provider.generations[key],
        )
    return hub, provider, published


def _projector(
    *,
    identity: WireIdentity | None = None,
    scope: WireScope | None = None,
    system_ref: str = "system:paper",
    process_ref: str = "process:market-monitor",
) -> MonitorMarketObservationProjector:
    return MonitorMarketObservationProjector(
        _identity() if identity is None else identity,
        _scope() if scope is None else scope,
        system_ref=system_ref,
        process_ref=process_ref,
    )


def test_gateway_hub_frame_projects_to_redacted_system_observation_with_retry_id() -> None:
    _, _, published = _hub_events(count_events=2)
    projector = _projector()

    first = projector.project(published[0])  # type: ignore[arg-type]
    retry = projector.project(published[0])  # type: ignore[arg-type]
    second = projector.project(published[1])  # type: ignore[arg-type]

    assert first == retry
    assert first["event_type"] == GATEWAY_MARKET_OBSERVATION_EVENT_TYPE
    assert first["event_id"].startswith("gateway-market-observation-v1:")
    assert first["event_id"] != second["event_id"]
    assert first["schema_version"] == 1
    assert first["occurred_at"] == 1_792_058_401.0
    data = first["data"]
    assert data == {
        "schema": MONITOR_MARKET_OBSERVATION_SCHEMA,
        "scope_type": "system",
        "system_ref": "system:paper",
        "process_ref": "process:market-monitor",
        "observation_kind": "consumer_received_frame",
        "source": {
            "service_ref": "service:gateway",
            "stream_epoch": "gateway-epoch-1",
            "sequence": 1,
            "gateway_sent_at_utc": "2026-10-15T10:00:01Z",
        },
        "market": {
            "instrument": _key().instrument.to_dict(),
            "channel": "trades",
            "depth": None,
            "timeframe": None,
        },
    }
    encoded = repr(data)
    assert "account_ref" not in encoded
    assert "strategy_ref" not in encoded
    assert "source_ref" not in encoded
    assert "entitlement_ref" not in encoded
    assert "price" not in encoded
    assert published[0].header.stream_id not in encoded  # type: ignore[attr-defined]


def test_market_projection_persists_once_and_exposes_only_the_system_view(
    tmp_path,
) -> None:
    _, _, published = _hub_events()
    system_scope = _scope()
    account_scope = _scope(account_ref="account-a")
    strategy_scope = _scope(account_ref="account-a", strategy_ref="strategy-a")
    outbox_path = tmp_path / "monitor.sqlite"
    writer = DurableOutbox(outbox_path)
    relay_identity = WireIdentity(
        role=WireRole.SERVICE,
        principal_ref="service:monitor-market-relay",
        actor_ref="monitor-market-relay:one",
    )
    ingress = MonitorIngressService(
        writer,
        {
            system_scope: MonitorIngressTarget(
                "monitor:system", (GATEWAY_MARKET_OBSERVATION_EVENT_TYPE,)
            )
        },
    )
    arguments = _projector().project(published[0])  # type: ignore[arg-type]
    appended = ingress.handle(
        "events.append",
        principal_ref=relay_identity.principal_ref,
        identity=relay_identity,
        scope=system_scope,
        arguments=arguments,
    )
    retried = ingress.handle(
        "events.append",
        principal_ref=relay_identity.principal_ref,
        identity=relay_identity,
        scope=system_scope,
        arguments=arguments,
    )
    assert appended == retried

    reader = DurableOutbox(outbox_path, read_only=True)
    query = MonitorReadService(
        reader,
        {
            system_scope: MonitorReadTarget(
                "monitor:system", (GATEWAY_MARKET_OBSERVATION_EVENT_TYPE,)
            ),
            account_scope: MonitorReadTarget(
                "monitor:account-a", (GATEWAY_MARKET_OBSERVATION_EVENT_TYPE,)
            ),
            strategy_scope: MonitorReadTarget(
                "monitor:strategy-a", (GATEWAY_MARKET_OBSERVATION_EVENT_TYPE,)
            ),
        },
    )

    system_page = query.handle(
        "monitor.query", principal_ref="operator:one", scope=system_scope, arguments={}
    )
    account_page = query.handle(
        "monitor.query", principal_ref="account-user:a", scope=account_scope, arguments={}
    )
    strategy_page = query.handle(
        "monitor.query", principal_ref="strategy-user:a", scope=strategy_scope, arguments={}
    )
    assert len(system_page["events"]) == 1
    assert account_page["events"] == strategy_page["events"] == ()
    assert system_page["events"][0]["data"]["payload"]["scope_type"] == "system"

    with pytest.raises(MonitorMarketObservationError, match="INVALID_TRUSTED_BINDING"):
        _projector(scope=account_scope)
    with pytest.raises(MonitorMarketObservationError, match="INVALID_TRUSTED_BINDING"):
        _projector(
            identity=WireIdentity(
                role=WireRole.SERVICE,
                principal_ref="service:gateway",
                actor_ref="gateway:market-hub",
                delegate_ref="unexpected-delegate",
            )
        )
    with pytest.raises(MonitorReadServiceError) as denied:
        query.handle(
            "monitor.query",
            principal_ref="account-user:b",
            scope=_scope(account_ref="account-b"),
            arguments={},
        )
    assert denied.value.code == "SCOPE_NOT_GRANTED"


def test_projector_rejects_wrong_gateway_identity_scope_and_stream_key() -> None:
    from dataclasses import replace

    _, _, published = _hub_events()
    event = published[0]
    projector = _projector()

    wrong_identity = replace(
        event,
        header=replace(
            event.header,
            identity=WireIdentity(
                role=WireRole.SERVICE,
                principal_ref="service:other",
                actor_ref="gateway:other",
            ),
        ),
    )
    with pytest.raises(MonitorMarketObservationError) as identity_error:
        projector.project(wrong_identity)
    assert identity_error.value.code == "IDENTITY_MISMATCH"

    wrong_scope = replace(
        event,
        header=replace(event.header, scope=_scope(execution_domain_ref="live:other")),
    )
    with pytest.raises(MonitorMarketObservationError) as scope_error:
        projector.project(wrong_scope)
    assert scope_error.value.code == "SCOPE_MISMATCH"

    wrong_stream = replace(
        event,
        header=replace(event.header, stream_id="market-not-the-payload-key"),
    )
    with pytest.raises(MonitorMarketObservationError) as stream_error:
        projector.project(wrong_stream)
    assert stream_error.value.code == "STREAM_KEY_MISMATCH"

    unsupported_schema = replace(
        event,
        header=replace(event.header, schema_id="sdk.market.event.v2"),
    )
    with pytest.raises(MonitorMarketObservationError) as schema_error:
        projector.project(unsupported_schema)
    assert schema_error.value.code == "UNSUPPORTED_GATEWAY_EVENT"

    invalid_payload = type(event)(
        header=event.header,
        payload={"key": event.payload["key"], "data": ["not", "a", "mapping"]},
    )
    with pytest.raises(MonitorMarketObservationError) as payload_error:
        projector.project(invalid_payload)
    assert payload_error.value.code == "INVALID_MARKET_EVENT"
