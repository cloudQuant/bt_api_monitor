"""Bounded fact projections accept only the execution package's scalar wire."""

from __future__ import annotations

import json

import pytest

from bt_api_monitor import (
    DurableOutbox,
    EconomicFactReadModel,
    FactCursorError,
    FactPage,
    FactReadError,
    OutboxConflictError,
    export_fact_page,
)

_SCOPE = {
    "provider": "SIM",
    "environment": "simulation",
    "account_fingerprint": "a" * 64,
    "generation": "generation-7",
    "trading_day": "20260926",
    "epoch": 3,
    "strategy_id": None,
}
_QUALITY_SCOPE = {**_SCOPE, "strategy_id": "strategy.alpha"}
_ACCOUNT_VALUES = (
    "equity",
    "cash",
    "available_margin",
    "margin",
    "realized_pnl",
    "unrealized_pnl",
    "fee",
    "funding",
    "net_cashflow",
    "fx_rate",
    "settlement_price",
)
_QUALITY_VALUES = (
    "arrival_bid",
    "arrival_ask",
    "arrival_mid",
    "native_quantity",
    "contract_multiplier",
    "vwap",
    "fee",
    "slippage_amount",
    "slippage_bps",
    "stage_durations_ns",
)


def _evidence(fields: tuple[str, ...]) -> dict[str, dict[str, object]]:
    return {
        field: {
            "completeness": "INCOMPLETE",
            "coverage_start_ns": None,
            "coverage_end_ns": None,
            "source_refs": [],
        }
        for field in fields
    }


def _account_fact(
    *, scope: dict[str, object] | None = None, as_of_ns: int = 200, **overrides
) -> dict[str, object]:
    fact: dict[str, object] = {
        "schema": "bt_api.execution.account_snapshot.v1",
        "fact_type": "account_snapshot",
        "scope": dict(_SCOPE if scope is None else scope),
        "as_of_ns": as_of_ns,
        "source": "provider.account.snapshot",
        "currency": "USD",
        "reporting_currency": "USD",
        "fx_rate_direction": "reporting_currency_units_per_currency_unit",
        "completeness": "INCOMPLETE",
        "values": dict.fromkeys(_ACCOUNT_VALUES),
        "field_evidence": _evidence(_ACCOUNT_VALUES),
        "external_activity_attribution": "INCOMPLETE",
        "external_activity_evidence": {
            "coverage_start_ns": None,
            "coverage_end_ns": None,
            "source_refs": [],
        },
        "equity_includes_fees": True,
    }
    fact["values"].update({"equity": "1000.00", "fee": "2.50"})  # type: ignore[union-attr]
    fact.update(overrides)
    return fact


def _quality_fact(
    *, scope: dict[str, object] | None = None, as_of_ns: int = 200, **overrides
) -> dict[str, object]:
    fact: dict[str, object] = {
        "schema": "bt_api.execution.execution_quality.v1",
        "fact_type": "execution_quality",
        "scope": dict(_QUALITY_SCOPE if scope is None else scope),
        "intent_id": "intent-1",
        "as_of_ns": as_of_ns,
        "source": "provider.execution.observation",
        "currency": "USD",
        "completeness": "INCOMPLETE",
        "lineage": {
            "signal_id": "signal-1",
            "intent_id": "intent-1",
            "child_id": None,
            "order_id": None,
            "trade_id": None,
        },
        "arrival": {
            "bid": None,
            "ask": None,
            "mid": None,
            "as_of_ns": None,
            "freshness_ns": None,
            "source": None,
        },
        "execution": {
            "side": None,
            "native_quantity": None,
            "contract_multiplier": None,
            "vwap": None,
            "fee": None,
            "fee_currency": None,
            "slippage_amount": None,
            "slippage_bps": None,
            "slippage_sign_convention": "positive_is_adverse",
            "stage_durations_ns": {},
            "stage_durations_clock": "monotonic",
            "rejection_reason": None,
            "legacy_metrics": {"latency_ms_unscoped": None, "slippage_untyped": None},
        },
        "field_evidence": _evidence(_QUALITY_VALUES),
    }
    fact.update(overrides)
    return fact


def _complete_quality_fact() -> dict[str, object]:
    fact = _quality_fact(completeness="COMPLETE")
    fact["lineage"] = {
        "signal_id": "signal-1",
        "intent_id": "intent-1",
        "child_id": "child-1",
        "order_id": "order-1",
        "trade_id": "trade-1",
    }
    fact["arrival"] = {
        "bid": "99.50",
        "ask": "100.50",
        "mid": "100.00",
        "as_of_ns": 190,
        "freshness_ns": 10,
        "source": "market.depth.snapshot",
    }
    fact["execution"] = {
        "side": "BUY",
        "native_quantity": "2.00",
        "contract_multiplier": "1",
        "vwap": "100.10",
        "fee": "0.03",
        "fee_currency": "USD",
        "slippage_amount": "0.20",
        "slippage_bps": "10",
        "slippage_sign_convention": "positive_is_adverse",
        "stage_durations_ns": {"admission": 20, "dispatch": 50},
        "stage_durations_clock": "monotonic",
        "rejection_reason": None,
        "legacy_metrics": {"latency_ms_unscoped": None, "slippage_untyped": None},
    }
    fact["field_evidence"] = {
        field: {
            "completeness": "COMPLETE",
            "coverage_start_ns": 100,
            "coverage_end_ns": 200,
            "source_refs": [f"source-{field}"],
        }
        for field in _QUALITY_VALUES
    }
    return fact


@pytest.fixture
def read_model(tmp_path):
    return EconomicFactReadModel(DurableOutbox(tmp_path / "monitor.db"))


@pytest.mark.unit
def test_account_facts_page_by_full_account_scope_without_strategy_attribution(read_model):
    first = read_model.append_account_snapshot("account-1", _account_fact(), 1_700_000_000.0)
    read_model.append_account_snapshot("account-2", _account_fact(as_of_ns=201), 1_700_000_001.0)
    other_scope = {**_SCOPE, "generation": "generation-8"}
    read_model.append_account_snapshot(
        "account-other-generation", _account_fact(scope=other_scope), 1_700_000_002.0
    )

    page = read_model.read_account_snapshots(_SCOPE, limit=1)

    assert [record.sequence for record in page.records] == [first.sequence]
    assert page.has_more is True
    assert page.records[0].fact["scope"]["strategy_id"] is None
    assert page.records[0].fact["values"]["fee"] == "2.50"
    assert page.records[0].fact["values"]["funding"] is None
    assert page.records[0].fact["field_evidence"]["funding"]["completeness"] == "INCOMPLETE"
    next_page = read_model.read_account_snapshots(_SCOPE, cursor=page.next_cursor, limit=10)
    assert [record.event_id for record in next_page.records] == ["account-2"]
    assert next_page.has_more is False


@pytest.mark.unit
def test_cursor_is_bound_to_scope_and_fact_type_and_pages_do_not_ack(read_model):
    item = read_model.append_account_snapshot("account-1", _account_fact(), 1_700_000_000.0)
    quality = read_model.append_execution_quality("quality-1", _quality_fact(), 1_700_000_001.0)
    page = read_model.read_account_snapshots(_SCOPE, limit=10)
    assert page.records[0].sequence == item.sequence

    with pytest.raises(FactCursorError, match="scope or fact type"):
        read_model.read_account_snapshots({**_SCOPE, "epoch": 4}, cursor=page.next_cursor, limit=10)
    quality_page = read_model.read_execution_quality(_QUALITY_SCOPE, limit=10)
    assert quality_page.records[0].sequence == quality.sequence
    with pytest.raises(FactCursorError, match="scope or fact type"):
        read_model.read_execution_quality(_QUALITY_SCOPE, cursor=page.next_cursor, limit=10)

    assert (
        read_model._outbox.checkpoint("unrelated-consumer", "economic-fact:account_snapshot") == 0
    )


@pytest.mark.unit
@pytest.mark.parametrize("limit", [True, 0, 501, -1])
def test_page_limit_requires_bounded_exact_positive_integer(read_model, limit):
    with pytest.raises(FactReadError, match="limit"):
        read_model.read_account_snapshots(_SCOPE, limit=limit)


@pytest.mark.unit
def test_export_is_one_bounded_page_and_does_not_claim_complete_history(read_model):
    read_model.append_account_snapshot("account-1", _account_fact(), 1_700_000_000.0)
    read_model.append_account_snapshot("account-2", _account_fact(as_of_ns=201), 1_700_000_001.0)

    payload = json.loads(read_model.export_account_snapshots(_SCOPE, limit=1))

    assert payload["schema"] == "bt_api.monitor.economic_fact_page.v1"
    assert payload["complete_export"] is False
    assert payload["export_kind"] == "bounded_page"
    assert payload["has_more"] is True
    assert len(payload["records"]) == 1
    assert payload["records"][0]["fact"]["values"]["equity"] == "1000.00"
    assert "raw-account-ref" not in export_fact_page(read_model.read_account_snapshots(_SCOPE))


@pytest.mark.unit
def test_export_revalidates_public_fact_page_size(read_model):
    read_model.append_account_snapshot("account-1", _account_fact(), 1_700_000_000.0)
    page = read_model.read_account_snapshots(_SCOPE, limit=1)
    oversized = FactPage(
        fact_type=page.fact_type,
        scope=page.scope,
        scope_digest=page.scope_digest,
        records=page.records * 501,
        next_cursor=page.next_cursor,
        has_more=False,
    )

    with pytest.raises(FactReadError, match="bounded export size"):
        export_fact_page(oversized)


@pytest.mark.unit
def test_retries_dedupe_by_event_identity_and_conflicting_revision_is_rejected(read_model):
    fact = _account_fact()
    first = read_model.append_account_snapshot("same-event", fact, 1_700_000_000.0)
    repeated = read_model.append_account_snapshot("same-event", fact, 1_700_000_000.0)
    assert repeated.sequence == first.sequence

    changed = _account_fact(as_of_ns=201)
    with pytest.raises(OutboxConflictError, match="event_id was reused"):
        read_model.append_account_snapshot("same-event", changed, 1_700_000_001.0)


@pytest.mark.unit
def test_quality_facts_keep_strategy_scope_lineage_and_missing_arrival_null(read_model):
    read_model.append_execution_quality("quality-1", _quality_fact(), 1_700_000_000.0)

    page = read_model.read_execution_quality(_QUALITY_SCOPE)
    fact = page.records[0].fact

    assert fact["scope"]["strategy_id"] == "strategy.alpha"
    assert fact["lineage"]["intent_id"] == "intent-1"
    assert fact["arrival"]["mid"] is None
    assert fact["execution"]["slippage_amount"] is None
    assert fact["field_evidence"]["arrival_mid"]["completeness"] == "INCOMPLETE"


@pytest.mark.unit
def test_complete_quality_fact_requires_execution_side(read_model):
    fact = _complete_quality_fact()
    read_model.append_execution_quality("complete-quality", fact, 1_700_000_000.0)

    missing_side = _complete_quality_fact()
    missing_side["execution"]["side"] = None  # type: ignore[index]
    with pytest.raises(FactReadError, match="quality fact claims COMPLETE"):
        read_model.append_execution_quality("quality-without-side", missing_side, 1_700_000_001.0)


@pytest.mark.unit
@pytest.mark.parametrize(
    ("fact_factory", "mutate"),
    [
        (_account_fact, lambda fact: fact.update(extra_required_field="unexpected")),
        (_account_fact, lambda fact: fact.update(as_of_ns=True)),
        (_account_fact, lambda fact: fact["values"].update(equity=float("nan"))),
        (_quality_fact, lambda fact: fact["execution"].update(side=[])),
    ],
)
def test_unknown_fields_bool_integer_decimal_and_wrong_scalar_types_reject(
    read_model, fact_factory, mutate
):
    fact = fact_factory()
    mutate(fact)
    with pytest.raises(FactReadError):
        if fact["fact_type"] == "account_snapshot":
            read_model.append_account_snapshot("invalid-fact", fact, 1_700_000_000.0)
        else:
            read_model.append_execution_quality("invalid-fact", fact, 1_700_000_000.0)


@pytest.mark.unit
def test_complete_claim_needs_full_field_coverage_and_external_attribution(read_model):
    fact = _account_fact(completeness="COMPLETE")
    with pytest.raises(FactReadError, match="COMPLETE with missing evidence"):
        read_model.append_account_snapshot("false-complete", fact, 1_700_000_000.0)


@pytest.mark.unit
def test_complete_external_activity_claim_needs_its_own_coverage_and_sources(read_model):
    fact = _account_fact(
        external_activity_attribution="COMPLETE",
        external_activity_evidence={
            "coverage_start_ns": None,
            "coverage_end_ns": None,
            "source_refs": [],
        },
    )
    with pytest.raises(FactReadError, match="external activity attribution requires as_of"):
        read_model.append_account_snapshot("false-external-complete", fact, 1_700_000_000.0)


@pytest.mark.unit
def test_complete_external_activity_coverage_must_reach_snapshot_as_of(read_model):
    fact = _account_fact(
        external_activity_attribution="COMPLETE",
        external_activity_evidence={
            "coverage_start_ns": 100,
            "coverage_end_ns": 150,
            "source_refs": ["external-ledger-snapshot"],
        },
    )
    with pytest.raises(FactReadError, match="as_of coverage"):
        read_model.append_account_snapshot("stale-external-coverage", fact, 1_700_000_000.0)


@pytest.mark.unit
def test_cursor_and_scope_reject_boolean_integer_fields(read_model):
    invalid_scope = {**_SCOPE, "epoch": True}
    with pytest.raises(FactReadError, match="epoch"):
        read_model.read_account_snapshots(invalid_scope)

    with pytest.raises(FactCursorError):
        read_model.read_account_snapshots(_SCOPE, cursor=True)  # type: ignore[arg-type]
