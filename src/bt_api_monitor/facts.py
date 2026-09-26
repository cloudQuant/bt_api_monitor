"""Bounded, read-only projections for versioned execution economic facts.

This module accepts the execution package's explicit scalar wire mappings. It
does not import execution code, normalize provider observations, calculate PnL,
or create strategy attribution. Facts are persisted through the existing
immutable outbox and read in scope-bound pages without changing consumer
checkpoints.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
from collections.abc import Mapping
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from types import MappingProxyType
from typing import Any

from .durable import DurableOutbox, OutboxEvent, SequencedOutboxEvent

_ACCOUNT_SCHEMA = "bt_api.execution.account_snapshot.v1"
_QUALITY_SCHEMA = "bt_api.execution.execution_quality.v1"
_PAGE_SCHEMA = "bt_api.monitor.economic_fact_page.v1"
_ACCOUNT_FACT = "account_snapshot"
_QUALITY_FACT = "execution_quality"
_FACT_TYPES = frozenset({_ACCOUNT_FACT, _QUALITY_FACT})
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
_COMPLETENESS = frozenset({"COMPLETE", "PARTIAL", "INCOMPLETE", "UNAVAILABLE", "UNKNOWN"})
_IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_FINGERPRINT_RE = re.compile(r"^[0-9a-f]{64}$")
_CURRENCY_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,15}$")
_MAX_PAGE_SIZE = 500
_MAX_CURSOR_SEQUENCE = (1 << 63) - 1


class FactReadError(ValueError):
    """A fact mapping or bounded read request failed closed validation."""


class FactCursorError(FactReadError):
    """A cursor is malformed or bound to a different scope/fact type."""


@dataclass(frozen=True, slots=True)
class FactRecord:
    """One immutable wire fact in outbox sequence order."""

    sequence: int
    event_id: str
    occurred_at: float
    fact: Mapping[str, Any]


@dataclass(frozen=True, slots=True)
class FactPage:
    """A single bounded page; it never claims to be a whole-history export."""

    fact_type: str
    scope: Mapping[str, Any]
    scope_digest: str
    records: tuple[FactRecord, ...]
    next_cursor: str | None
    has_more: bool


class EconomicFactReadModel:
    """Persist and page versioned account/quality mappings via a durable outbox."""

    def __init__(self, outbox: DurableOutbox) -> None:
        if not isinstance(outbox, DurableOutbox):
            raise FactReadError("outbox must be a DurableOutbox")
        self._outbox = outbox

    def append_account_snapshot(
        self, event_id: str, fact: Mapping[str, Any], occurred_at: float
    ) -> SequencedOutboxEvent:
        """Append one immutable account fact; exact event retries are idempotent."""

        normalized = _validate_fact_wire(fact, _ACCOUNT_FACT)
        return self._append(event_id, normalized, occurred_at, _ACCOUNT_FACT)

    def append_execution_quality(
        self, event_id: str, fact: Mapping[str, Any], occurred_at: float
    ) -> SequencedOutboxEvent:
        """Append one immutable strategy execution fact without attribution math."""

        normalized = _validate_fact_wire(fact, _QUALITY_FACT)
        return self._append(event_id, normalized, occurred_at, _QUALITY_FACT)

    def read_account_snapshots(
        self, scope: Mapping[str, Any], *, cursor: str | None = None, limit: int = 100
    ) -> FactPage:
        """Read one bounded account-level page for the exact account scope."""

        return self._read_page(_ACCOUNT_FACT, scope, cursor, limit)

    def read_execution_quality(
        self, scope: Mapping[str, Any], *, cursor: str | None = None, limit: int = 100
    ) -> FactPage:
        """Read one bounded strategy-attributed page for the exact scope."""

        return self._read_page(_QUALITY_FACT, scope, cursor, limit)

    def export_account_snapshots(
        self, scope: Mapping[str, Any], *, cursor: str | None = None, limit: int = 100
    ) -> str:
        """Return canonical JSON for exactly one bounded account page."""

        return export_fact_page(self.read_account_snapshots(scope, cursor=cursor, limit=limit))

    def export_execution_quality(
        self, scope: Mapping[str, Any], *, cursor: str | None = None, limit: int = 100
    ) -> str:
        """Return canonical JSON for exactly one bounded quality page."""

        return export_fact_page(self.read_execution_quality(scope, cursor=cursor, limit=limit))

    def _append(
        self, event_id: str, fact: dict[str, Any], occurred_at: float, fact_type: str
    ) -> SequencedOutboxEvent:
        _identifier(event_id, "event_id")
        if isinstance(occurred_at, bool) or not isinstance(occurred_at, (int, float)):
            raise FactReadError("occurred_at must be a finite timestamp")
        if not math.isfinite(float(occurred_at)):
            raise FactReadError("occurred_at must be a finite timestamp")
        scope = fact["scope"]
        scope_digest = _scope_digest(scope)
        event = OutboxEvent(
            event_id=event_id,
            scope=_outbox_scope(fact_type, scope_digest),
            event_type=fact_type,
            data=fact,
            occurred_at=float(occurred_at),
        )
        return self._outbox.append(event)

    def _read_page(
        self,
        fact_type: str,
        scope: Mapping[str, Any],
        cursor: str | None,
        limit: int,
    ) -> FactPage:
        normalized_scope = _validate_scope(scope, fact_type)
        if type(limit) is not int or not 1 <= limit <= _MAX_PAGE_SIZE:
            raise FactReadError("limit is outside the bounded page range")
        scope_digest = _scope_digest(normalized_scope)
        after_sequence = _decode_cursor(cursor, scope_digest, fact_type)
        items, has_more = self._outbox.read_page(
            _outbox_scope(fact_type, scope_digest), fact_type, after_sequence, limit
        )
        records: list[FactRecord] = []
        for item in items:
            normalized_fact = _validate_fact_wire(item.event.data, fact_type)
            if normalized_fact["scope"] != normalized_scope:
                raise FactReadError("stored fact scope does not match its outbox partition")
            records.append(
                FactRecord(
                    sequence=item.sequence,
                    event_id=item.event.event_id,
                    occurred_at=item.event.occurred_at,
                    fact=_freeze_json(normalized_fact),
                )
            )
        next_cursor = cursor
        if records:
            next_cursor = _encode_cursor(scope_digest, fact_type, records[-1].sequence)
        return FactPage(
            fact_type=fact_type,
            scope=_freeze_json(normalized_scope),
            scope_digest=scope_digest,
            records=tuple(records),
            next_cursor=next_cursor,
            has_more=has_more,
        )


def export_fact_page(page: FactPage) -> str:
    """Serialize one bounded page; callers chain ``next_cursor`` themselves."""

    if not isinstance(page, FactPage):
        raise FactReadError("page must be a FactPage")
    if page.fact_type not in _FACT_TYPES:
        raise FactReadError("unknown fact type")
    if not isinstance(page.records, (tuple, list)):
        raise FactReadError("page records must be a sequence")
    if len(page.records) > _MAX_PAGE_SIZE:
        raise FactReadError("page exceeds the bounded export size")
    if type(page.has_more) is not bool:
        raise FactReadError("has_more must be bool")
    scope = _validate_scope(page.scope, page.fact_type)
    scope_digest = _scope_digest(scope)
    if page.scope_digest != scope_digest:
        raise FactReadError("page scope digest mismatch")
    cursor_sequence = (
        _decode_cursor(page.next_cursor, scope_digest, page.fact_type)
        if page.next_cursor is not None
        else None
    )
    if page.has_more and cursor_sequence is None:
        raise FactReadError("a continuing page requires its scope-bound cursor")
    normalized_records: list[dict[str, Any]] = []
    previous_sequence = 0
    for record in page.records:
        if not isinstance(record, FactRecord):
            raise FactReadError("page contains an invalid fact record")
        sequence = _exact_positive_int(record.sequence, "record sequence")
        if sequence <= previous_sequence:
            raise FactReadError("page record sequences must be strictly increasing")
        previous_sequence = sequence
        event_id = _identifier(record.event_id, "event_id")
        occurred_at = record.occurred_at
        if (
            isinstance(occurred_at, bool)
            or not isinstance(occurred_at, (int, float))
            or not math.isfinite(float(occurred_at))
        ):
            raise FactReadError("record occurred_at must be a finite timestamp")
        fact = _validate_fact_wire(record.fact, page.fact_type)
        if fact["scope"] != scope:
            raise FactReadError("record scope does not match exported page scope")
        normalized_records.append(
            {
                "sequence": sequence,
                "event_id": event_id,
                "occurred_at": float(occurred_at),
                "fact": fact,
            }
        )
    if normalized_records and (cursor_sequence is None or cursor_sequence != previous_sequence):
        raise FactReadError("page cursor must match the final record sequence")
    return _canonical_json(
        {
            "schema": _PAGE_SCHEMA,
            "fact_type": page.fact_type,
            "scope": scope,
            "scope_digest": scope_digest,
            "records": normalized_records,
            "next_cursor": page.next_cursor,
            "has_more": page.has_more,
            "complete_export": False,
            "export_kind": "bounded_page",
        }
    )


def _validate_fact_wire(value: Mapping[str, Any], expected_fact: str) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise FactReadError("fact must be a mapping")
    if expected_fact == _ACCOUNT_FACT:
        expected_schema = _ACCOUNT_SCHEMA
        expected_keys = {
            "schema",
            "fact_type",
            "scope",
            "as_of_ns",
            "source",
            "currency",
            "reporting_currency",
            "fx_rate_direction",
            "completeness",
            "values",
            "field_evidence",
            "external_activity_attribution",
            "external_activity_evidence",
            "equity_includes_fees",
        }
    elif expected_fact == _QUALITY_FACT:
        expected_schema = _QUALITY_SCHEMA
        expected_keys = {
            "schema",
            "fact_type",
            "scope",
            "intent_id",
            "as_of_ns",
            "source",
            "currency",
            "completeness",
            "lineage",
            "arrival",
            "execution",
            "field_evidence",
        }
    else:
        raise FactReadError("unknown fact type")
    _exact_keys(value, expected_keys, "fact")
    if value["schema"] != expected_schema or value["fact_type"] != expected_fact:
        raise FactReadError("fact schema/version mismatch")
    as_of_ns = _exact_positive_int(value["as_of_ns"], "as_of_ns")
    _identifier(value["source"], "source")
    _validate_completeness(value["completeness"], "completeness")
    scope = _validate_scope(value["scope"], expected_fact)
    if expected_fact == _ACCOUNT_FACT:
        _validate_account_wire(value, scope, as_of_ns)
    else:
        _validate_quality_wire(value, scope, as_of_ns)
    return _plain_json(value)


def _validate_account_wire(value: Mapping[str, Any], scope: dict[str, Any], as_of_ns: int) -> None:
    _currency_or_none(value["currency"], "currency")
    _currency_or_none(value["reporting_currency"], "reporting_currency")
    direction = value["fx_rate_direction"]
    if direction is not None and direction != "reporting_currency_units_per_currency_unit":
        raise FactReadError("unsupported FX rate direction")
    if (
        value["equity_includes_fees"] is not None
        and type(value["equity_includes_fees"]) is not bool
    ):
        raise FactReadError("equity_includes_fees must be bool or null")
    external = _validate_completeness(
        value["external_activity_attribution"], "external_activity_attribution"
    )
    external_evidence = _mapping(value["external_activity_evidence"], "external_activity_evidence")
    _exact_keys(
        external_evidence,
        {"coverage_start_ns", "coverage_end_ns", "source_refs"},
        "external_activity_evidence",
    )
    external_start = _nullable_positive_int(
        external_evidence["coverage_start_ns"], "external activity coverage start"
    )
    external_end = _nullable_positive_int(
        external_evidence["coverage_end_ns"], "external activity coverage end"
    )
    if (
        (external_start is None) != (external_end is None)
        or (external_start is not None and external_end < external_start)
        or (external_end is not None and external_end > as_of_ns)
    ):
        raise FactReadError("invalid external activity coverage interval")
    external_refs = external_evidence["source_refs"]
    if not isinstance(external_refs, (list, tuple)):
        raise FactReadError("external activity source_refs must be an array")
    external_refs = [
        _identifier(ref, "external activity source reference") for ref in external_refs
    ]
    if len(set(external_refs)) != len(external_refs):
        raise FactReadError("duplicate external activity source reference")
    if external == "COMPLETE" and (
        external_start is None or external_end != as_of_ns or not external_refs
    ):
        raise FactReadError(
            "complete external activity attribution requires as_of coverage and sources"
        )
    values = _mapping(value["values"], "values")
    _exact_keys(values, set(_ACCOUNT_VALUES), "values")
    parsed_values = {
        name: _decimal_wire(values[name], f"values.{name}") for name in _ACCOUNT_VALUES
    }
    evidence = _validate_field_evidence(
        value["field_evidence"], _ACCOUNT_VALUES, parsed_values, as_of_ns
    )
    if value["completeness"] == "COMPLETE" and (
        any(parsed_values[name] is None for name in _ACCOUNT_VALUES)
        or any(evidence[name]["completeness"] != "COMPLETE" for name in _ACCOUNT_VALUES)
        or value["currency"] is None
        or value["reporting_currency"] is None
        or direction is None
        or scope["trading_day"] is None
        or external != "COMPLETE"
        or value["equity_includes_fees"] is None
    ):
        raise FactReadError("account fact claims COMPLETE with missing evidence")


def _validate_quality_wire(value: Mapping[str, Any], scope: dict[str, Any], as_of_ns: int) -> None:
    _identifier(value["intent_id"], "intent_id")
    _currency_or_none(value["currency"], "currency")
    lineage = _mapping(value["lineage"], "lineage")
    lineage_keys = {"signal_id", "intent_id", "child_id", "order_id", "trade_id"}
    _exact_keys(lineage, lineage_keys, "lineage")
    for name, item in lineage.items():
        if item is not None:
            _identifier(item, f"lineage.{name}")
    if lineage["intent_id"] != value["intent_id"]:
        raise FactReadError("quality lineage intent mismatch")

    arrival = _mapping(value["arrival"], "arrival")
    _exact_keys(arrival, {"bid", "ask", "mid", "as_of_ns", "freshness_ns", "source"}, "arrival")
    for name in ("bid", "ask", "mid"):
        _decimal_wire(arrival[name], f"arrival.{name}")
    arrival_as_of = _nullable_positive_int(arrival["as_of_ns"], "arrival.as_of_ns")
    if arrival_as_of is not None and arrival_as_of > as_of_ns:
        raise FactReadError("arrival timestamp follows the quality fact")
    freshness = arrival["freshness_ns"]
    if freshness is not None and (type(freshness) is not int or freshness < 0):
        raise FactReadError("invalid arrival freshness")
    if arrival["source"] is not None:
        _identifier(arrival["source"], "arrival.source")

    execution = _mapping(value["execution"], "execution")
    execution_keys = {
        "side",
        "native_quantity",
        "contract_multiplier",
        "vwap",
        "fee",
        "fee_currency",
        "slippage_amount",
        "slippage_bps",
        "slippage_sign_convention",
        "stage_durations_ns",
        "stage_durations_clock",
        "rejection_reason",
        "legacy_metrics",
    }
    _exact_keys(execution, execution_keys, "execution")
    side = execution["side"]
    if side is not None and (not isinstance(side, str) or side not in {"BUY", "SELL"}):
        raise FactReadError("invalid execution side")
    execution_values = {
        "arrival_bid": arrival["bid"],
        "arrival_ask": arrival["ask"],
        "arrival_mid": arrival["mid"],
        "native_quantity": execution["native_quantity"],
        "contract_multiplier": execution["contract_multiplier"],
        "vwap": execution["vwap"],
        "fee": execution["fee"],
        "slippage_amount": execution["slippage_amount"],
        "slippage_bps": execution["slippage_bps"],
        "stage_durations_ns": execution["stage_durations_ns"],
    }
    parsed_values: dict[str, Decimal | dict[str, int] | None] = {}
    for name in _QUALITY_VALUES:
        raw = execution_values[name]
        if name == "stage_durations_ns":
            parsed_values[name] = _durations(raw)
        else:
            parsed_values[name] = _decimal_wire(raw, f"execution.{name}")
    if execution["slippage_sign_convention"] != "positive_is_adverse":
        raise FactReadError("unsupported slippage sign convention")
    if execution["stage_durations_clock"] != "monotonic":
        raise FactReadError("stage durations must use monotonic intervals")
    fee_currency = _currency_or_none(execution["fee_currency"], "execution.fee_currency")
    reason = execution["rejection_reason"]
    if reason is not None:
        _identifier(reason, "execution.rejection_reason")
    legacy = _mapping(execution["legacy_metrics"], "execution.legacy_metrics")
    _exact_keys(legacy, {"latency_ms_unscoped", "slippage_untyped"}, "execution.legacy_metrics")
    legacy_latency = _decimal_wire(legacy["latency_ms_unscoped"], "legacy latency")
    legacy_slippage = _decimal_wire(legacy["slippage_untyped"], "legacy slippage")
    if (
        parsed_values["slippage_amount"] is not None or parsed_values["slippage_bps"] is not None
    ) and (parsed_values["arrival_mid"] is None or parsed_values["vwap"] is None):
        raise FactReadError("slippage requires arrival mid and VWAP")
    evidence = _validate_field_evidence(
        value["field_evidence"], _QUALITY_VALUES, parsed_values, as_of_ns
    )
    if value["completeness"] == "COMPLETE" and (
        any(parsed_values[name] is None for name in _QUALITY_VALUES)
        or any(evidence[name]["completeness"] != "COMPLETE" for name in _QUALITY_VALUES)
        or value["currency"] is None
        or (parsed_values["fee"] is not None and fee_currency is None)
        or side is None
        or scope["trading_day"] is None
        or any(lineage[name] is None for name in ("signal_id", "child_id", "order_id"))
        or (lineage["trade_id"] is None and reason is None)
        or arrival_as_of is None
        or freshness is None
        or arrival["source"] is None
        or not parsed_values["stage_durations_ns"]
        or legacy_latency is not None
        or legacy_slippage is not None
    ):
        raise FactReadError("quality fact claims COMPLETE with missing evidence")


def _validate_field_evidence(
    raw: Any, fields: tuple[str, ...], values: Mapping[str, Any], as_of_ns: int
) -> dict[str, dict[str, Any]]:
    evidence = _mapping(raw, "field_evidence")
    _exact_keys(evidence, set(fields), "field_evidence")
    normalized: dict[str, dict[str, Any]] = {}
    for name in fields:
        item = _mapping(evidence[name], f"field_evidence.{name}")
        _exact_keys(
            item,
            {"completeness", "coverage_start_ns", "coverage_end_ns", "source_refs"},
            f"field_evidence.{name}",
        )
        status = _validate_completeness(item["completeness"], f"{name} completeness")
        start = _nullable_positive_int(item["coverage_start_ns"], f"{name} coverage start")
        end = _nullable_positive_int(item["coverage_end_ns"], f"{name} coverage end")
        if (start is None) != (end is None) or (start is not None and end < start):
            raise FactReadError(f"invalid {name} coverage interval")
        if end is not None and end > as_of_ns:
            raise FactReadError(f"{name} coverage extends beyond as_of")
        refs = item["source_refs"]
        # DurableOutbox restores JSON arrays as immutable tuples; at the API
        # boundary JSON decoders still supply lists.
        if not isinstance(refs, (list, tuple)):
            raise FactReadError(f"{name} source_refs must be an array")
        normalized_refs = [_identifier(ref, f"{name} source reference") for ref in refs]
        if len(set(normalized_refs)) != len(normalized_refs):
            raise FactReadError(f"duplicate {name} source reference")
        if status == "COMPLETE" and (values[name] is None or start is None or not normalized_refs):
            raise FactReadError(f"complete {name} is missing value, coverage, or source")
        normalized[name] = {
            "completeness": status,
            "coverage_start_ns": start,
            "coverage_end_ns": end,
            "source_refs": normalized_refs,
        }
    return normalized


def _validate_scope(raw: Any, fact_type: str) -> dict[str, Any]:
    scope = _mapping(raw, "scope")
    _exact_keys(
        scope,
        {
            "provider",
            "environment",
            "account_fingerprint",
            "generation",
            "trading_day",
            "epoch",
            "strategy_id",
        },
        "scope",
    )
    _identifier(scope["provider"], "scope.provider")
    _identifier(scope["environment"], "scope.environment")
    if not isinstance(scope["account_fingerprint"], str) or not _FINGERPRINT_RE.fullmatch(
        scope["account_fingerprint"]
    ):
        raise FactReadError("invalid account fingerprint")
    _identifier(scope["generation"], "scope.generation")
    if scope["trading_day"] is not None:
        _identifier(scope["trading_day"], "scope.trading_day")
    _exact_positive_int(scope["epoch"], "scope.epoch")
    strategy_id = scope["strategy_id"]
    if fact_type == _ACCOUNT_FACT:
        if strategy_id is not None:
            raise FactReadError("account facts must not carry strategy attribution")
    elif fact_type == _QUALITY_FACT:
        _identifier(strategy_id, "scope.strategy_id")
    else:
        raise FactReadError("unknown fact type")
    return _plain_json(scope)


def _currency_or_none(value: Any, name: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or not _CURRENCY_RE.fullmatch(value):
        raise FactReadError(f"invalid {name}")
    return value


def _decimal_wire(value: Any, name: str) -> Decimal | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise FactReadError(f"{name} must be a Decimal string or null")
    try:
        parsed = Decimal(value)
    except (InvalidOperation, ValueError):
        raise FactReadError(f"invalid {name}") from None
    if not parsed.is_finite() or format(parsed, "f") != value:
        raise FactReadError(f"invalid canonical Decimal {name}")
    return parsed


def _durations(value: Any) -> dict[str, int] | None:
    if not isinstance(value, Mapping):
        raise FactReadError("stage_durations_ns must be a mapping")
    durations: dict[str, int] = {}
    for name, duration in value.items():
        _identifier(name, "stage duration name")
        if type(duration) is not int or duration < 0:
            raise FactReadError("invalid stage duration")
        durations[name] = duration
    return durations or None


def _validate_completeness(value: Any, name: str) -> str:
    if not isinstance(value, str) or value not in _COMPLETENESS:
        raise FactReadError(f"invalid {name}")
    return value


def _identifier(value: Any, name: str) -> str:
    if not isinstance(value, str) or not _IDENTIFIER_RE.fullmatch(value):
        raise FactReadError(f"invalid {name}")
    return value


def _exact_positive_int(value: Any, name: str) -> int:
    if type(value) is not int or value <= 0:
        raise FactReadError(f"invalid {name}")
    return value


def _nullable_positive_int(value: Any, name: str) -> int | None:
    return None if value is None else _exact_positive_int(value, name)


def _mapping(value: Any, name: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or any(not isinstance(key, str) for key in value):
        raise FactReadError(f"{name} must be a string-keyed mapping")
    return value


def _exact_keys(value: Mapping[str, Any], expected: set[str], name: str) -> None:
    if set(value) != expected:
        missing = expected - set(value)
        extra = set(value) - expected
        raise FactReadError(
            f"{name} keys invalid (missing={sorted(missing)}, extra={sorted(extra)})"
        )


def _scope_digest(scope: Mapping[str, Any]) -> str:
    return hashlib.sha256(_canonical_json(scope).encode("utf-8")).hexdigest()


def _outbox_scope(fact_type: str, scope_digest: str) -> str:
    return f"economic-fact:{fact_type}:{scope_digest}"


def _encode_cursor(scope_digest: str, fact_type: str, sequence: int) -> str:
    if type(sequence) is not int or not 0 < sequence <= _MAX_CURSOR_SEQUENCE:
        raise FactCursorError("cursor sequence is outside the supported range")
    return f"mf1:{fact_type}:{scope_digest}:{sequence}"


def _decode_cursor(cursor: str | None, scope_digest: str, fact_type: str) -> int:
    if cursor is None:
        return 0
    if not isinstance(cursor, str) or len(cursor) > 256:
        raise FactCursorError("invalid cursor")
    match = re.fullmatch(
        r"mf1:(account_snapshot|execution_quality):([0-9a-f]{64}):([1-9][0-9]{0,18})", cursor
    )
    if match is None:
        raise FactCursorError("invalid cursor")
    if match.group(1) != fact_type or match.group(2) != scope_digest:
        raise FactCursorError("cursor scope or fact type mismatch")
    sequence = int(match.group(3))
    if sequence > _MAX_CURSOR_SEQUENCE:
        raise FactCursorError("cursor sequence is outside the supported range")
    return sequence


def _plain_json(value: Any) -> Any:
    if isinstance(value, Mapping):
        if any(not isinstance(key, str) for key in value):
            raise FactReadError("JSON object keys must be strings")
        return {key: _plain_json(item) for key, item in value.items()}
    if isinstance(value, (tuple, list)):
        return [_plain_json(item) for item in value]
    if isinstance(value, float) and not math.isfinite(value):
        raise FactReadError("nonfinite JSON number")
    if value is None or type(value) in (str, bool, int, float):
        return value
    raise FactReadError(f"unsupported wire scalar {type(value).__name__}")


def _freeze_json(value: Any) -> Any:
    if isinstance(value, dict):
        return MappingProxyType({key: _freeze_json(item) for key, item in value.items()})
    if isinstance(value, list):
        return tuple(_freeze_json(item) for item in value)
    return value


def _canonical_json(value: Any) -> str:
    return json.dumps(
        _plain_json(value),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    )


__all__ = [
    "EconomicFactReadModel",
    "FactCursorError",
    "FactPage",
    "FactReadError",
    "FactRecord",
    "export_fact_page",
]
