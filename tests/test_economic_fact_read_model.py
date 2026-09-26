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
    "generation_kind": "EXECUTION_JOURNAL",
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
        "schema": "bt_api.execution.account_snapshot.v2",
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
        "schema": "bt_api.execution.execution_quality.v2",
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
            "native_quantity_basis": None,
            "contract_multiplier": None,
            "vwap": None,
            "vwap_basis": None,
            "fee": None,
            "fee_basis": None,
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
        "native_quantity_basis": "ORDER_CUMULATIVE",
        "contract_multiplier": "1",
        "vwap": "100.10",
        "vwap_basis": "ORDER_CUMULATIVE",
        "fee": "0.03",
        "fee_basis": "ORDER_CUMULATIVE",
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


def _complete_account_fact_v1(scope: dict[str, object]) -> dict[str, object]:
    fact = _account_fact(scope=scope, completeness="COMPLETE")
    fact["values"] = dict.fromkeys(_ACCOUNT_VALUES, "1.00")
    fact["field_evidence"] = {
        field: {
            "completeness": "COMPLETE",
            "coverage_start_ns": 100,
            "coverage_end_ns": 200,
            "source_refs": [f"source-{field}"],
        }
        for field in _ACCOUNT_VALUES
    }
    fact["external_activity_attribution"] = "COMPLETE"
    fact["external_activity_evidence"] = {
        "coverage_start_ns": 100,
        "coverage_end_ns": 200,
        "source_refs": ["external-activity-source"],
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

    assert payload["schema"] == "bt_api.monitor.economic_fact_page.v2"
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
def test_complete_quality_fact_requires_explicit_measurement_bases(read_model):
    fact = _complete_quality_fact()
    fact["execution"]["fee_basis"] = None  # type: ignore[index]
    with pytest.raises(FactReadError, match="explicit measurement basis|claims COMPLETE"):
        read_model.append_execution_quality("quality-without-basis", fact, 1_700_000_000.0)


@pytest.mark.unit
@pytest.mark.parametrize(
    ("field_name", "basis_name", "value"),
    (
        ("native_quantity", "native_quantity_basis", "2.00"),
        ("vwap", "vwap_basis", "100.10"),
        ("fee", "fee_basis", "0.03"),
    ),
)
def test_quality_field_cannot_claim_complete_without_measurement_basis(
    read_model, field_name, basis_name, value
):
    fact = _quality_fact()
    fact["execution"][field_name] = value  # type: ignore[index]
    fact["execution"][basis_name] = None  # type: ignore[index]
    fact["field_evidence"][field_name] = {  # type: ignore[index]
        "completeness": "COMPLETE",
        "coverage_start_ns": 100,
        "coverage_end_ns": 200,
        "source_refs": [f"source-{field_name}"],
    }

    with pytest.raises(FactReadError, match="requires an explicit measurement basis"):
        read_model.append_execution_quality(
            f"quality-field-without-{basis_name}", fact, 1_700_000_000.0
        )


@pytest.mark.unit
@pytest.mark.parametrize("schema_version", ("v1", "v2"))
@pytest.mark.parametrize(
    ("section", "field_name", "value"),
    (
        ("arrival", "bid", "0"),
        ("arrival", "ask", "-1"),
        ("arrival", "mid", "0"),
        ("execution", "native_quantity", "-1"),
        ("execution", "native_quantity", "0"),
        ("execution", "contract_multiplier", "0"),
        ("execution", "vwap", "0"),
    ),
)
def test_nonpositive_quality_measurements_reject_even_when_incomplete(
    read_model, schema_version, section, field_name, value
):
    fact = _quality_fact()
    fact["schema"] = f"bt_api.execution.execution_quality.{schema_version}"
    if schema_version == "v1":
        fact["scope"].pop("generation_kind")  # type: ignore[union-attr]
        for basis_name in ("native_quantity_basis", "vwap_basis", "fee_basis"):
            fact["execution"].pop(basis_name)  # type: ignore[union-attr]
    fact[section][field_name] = value  # type: ignore[index]

    with pytest.raises(FactReadError, match="invalid execution"):
        read_model.append_execution_quality(
            f"quality-nonpositive-{schema_version}-{section}-{field_name}-{value}",
            fact,
            1_700_000_000.0,
        )


@pytest.mark.unit
@pytest.mark.parametrize("schema_version", ("v1", "v2"))
def test_signed_cumulative_fee_remains_valid_for_maker_rebate(read_model, schema_version):
    fact = _quality_fact()
    fact["schema"] = f"bt_api.execution.execution_quality.{schema_version}"
    if schema_version == "v1":
        fact["scope"].pop("generation_kind")  # type: ignore[union-attr]
        for basis_name in ("native_quantity_basis", "vwap_basis", "fee_basis"):
            fact["execution"].pop(basis_name)  # type: ignore[union-attr]
    else:
        fact["execution"]["fee_basis"] = "ORDER_CUMULATIVE"  # type: ignore[index]
    fact["execution"]["fee"] = "-0.03"  # type: ignore[index]

    read_model.append_execution_quality(
        f"quality-negative-fee-{schema_version}", fact, 1_700_000_000.0
    )


@pytest.mark.unit
def test_legacy_v1_complete_fact_is_rejected_on_append_and_downgraded_on_read(read_model):
    from bt_api_monitor.durable import OutboxEvent
    from bt_api_monitor.facts import _outbox_scope, _scope_digest

    legacy_scope = {key: value for key, value in _SCOPE.items() if key != "generation_kind"}
    legacy = _complete_account_fact_v1(legacy_scope)
    legacy["schema"] = "bt_api.execution.account_snapshot.v1"
    with pytest.raises(FactReadError, match="legacy v1 COMPLETE"):
        read_model.append_account_snapshot("legacy-complete-new", legacy, 1_700_000_000.0)

    legacy_complete = legacy
    scope_digest = _scope_digest(legacy_scope)
    read_model._outbox.append(
        OutboxEvent(
            event_id="legacy-complete-stored",
            scope=_outbox_scope("account_snapshot", scope_digest),
            event_type="account_snapshot",
            data=legacy_complete,
            occurred_at=1_700_000_000.0,
        )
    )
    page = read_model.read_account_snapshots(legacy_scope)
    record = page.records[0]
    assert record.stored_schema == "bt_api.execution.account_snapshot.v1"
    assert record.stored_completeness == "COMPLETE"
    assert record.effective_completeness == "INCOMPLETE"
    assert record.fact["completeness"] == "INCOMPLETE"
    exported = json.loads(export_fact_page(page))
    assert exported["schema"] == "bt_api.monitor.economic_fact_page.v2"
    assert exported["records"][0]["stored_completeness"] == "COMPLETE"
    assert exported["records"][0]["effective_completeness"] == "INCOMPLETE"


@pytest.mark.unit
def test_legacy_v1_quality_read_downgrades_basis_ambiguous_scalar_fields(read_model):
    from bt_api_monitor.durable import OutboxEvent
    from bt_api_monitor.facts import _outbox_scope, _scope_digest

    legacy_scope = {key: value for key, value in _QUALITY_SCOPE.items() if key != "generation_kind"}
    legacy = _complete_quality_fact()
    legacy["schema"] = "bt_api.execution.execution_quality.v1"
    legacy["scope"] = legacy_scope
    for basis_name in ("native_quantity_basis", "vwap_basis", "fee_basis"):
        legacy["execution"].pop(basis_name)  # type: ignore[union-attr]
    with pytest.raises(FactReadError, match="legacy v1 COMPLETE"):
        read_model.append_execution_quality("legacy-quality-complete-new", legacy, 1_700_000_000.0)

    scope_digest = _scope_digest(legacy_scope)
    partition = _outbox_scope("execution_quality", scope_digest)
    read_model._outbox.append(
        OutboxEvent(
            event_id="legacy-quality-complete-stored",
            scope=partition,
            event_type="execution_quality",
            data=legacy,
            occurred_at=1_700_000_000.0,
        )
    )
    page = read_model.read_execution_quality(legacy_scope)
    record = page.records[0]
    assert record.stored_schema == "bt_api.execution.execution_quality.v1"
    assert record.stored_completeness == "COMPLETE"
    assert record.effective_completeness == "INCOMPLETE"
    assert record.fact["completeness"] == "INCOMPLETE"
    for field_name in ("native_quantity", "vwap", "fee"):
        assert record.fact["field_evidence"][field_name]["completeness"] == "INCOMPLETE"
    assert record.fact["field_evidence"]["arrival_mid"]["completeness"] == "COMPLETE"
    exported = json.loads(export_fact_page(page))
    exported_fact = exported["records"][0]["fact"]
    assert exported_fact["completeness"] == "INCOMPLETE"
    assert exported_fact["field_evidence"]["native_quantity"]["completeness"] == "INCOMPLETE"


@pytest.mark.unit
def test_v1_cursor_cannot_be_replayed_in_v2_page(read_model):
    read_model.append_account_snapshot("account-1", _account_fact(), 1_700_000_000.0)
    with pytest.raises(FactCursorError, match="invalid cursor"):
        read_model.read_account_snapshots(_SCOPE, cursor=f"mf1:account_snapshot:{'a' * 64}:1")


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
