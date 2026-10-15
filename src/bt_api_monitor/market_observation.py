"""Project trusted Gateway market frames into a system Monitor observation.

The projected event records that a Monitor consumer received a Gateway frame.
It does not assert that the Gateway retained the frame durably, that the data
is current, or that the market data is an authoritative exchange fact. The
append timestamp comes from Gateway ``sent_at_utc``; it is not a measured local
receipt time. The source quote payload and source/entitlement references are
deliberately omitted. Header identity and scope are claims; callers must pass
only frames received on an authenticated Gateway ``ServiceMarketClient``
subscription, because this projector does not authenticate arbitrary envelopes.
"""

from __future__ import annotations

import hashlib
import json
import math
from collections.abc import Mapping
from datetime import datetime
from typing import Any

from bt_api_base.market_protocol import (
    MARKET_EVENT_OPERATION,
    MARKET_EVENT_SCHEMA,
    MARKET_EVENT_SCHEMA_VERSION,
    MarketSubscriptionKey,
)
from bt_api_base.service_protocol import (
    MAX_REFERENCE_BYTES,
    WireEnvelope,
    WireIdentity,
    WireRole,
    WireScope,
    validate_event,
)

GATEWAY_MARKET_OBSERVATION_EVENT_TYPE = "gateway.market_observation"
MONITOR_MARKET_OBSERVATION_SCHEMA = "bt_api.monitor.market_observation.v1"
_EVENT_ID_PREFIX = "gateway-market-observation-v1:"


class MonitorMarketObservationError(ValueError):
    """A finite validation error for one trusted Gateway observation."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class MonitorMarketObservationProjector:
    """Convert one exact Gateway market event to bounded Monitor append args.

    ``expected_identity`` and ``expected_scope`` must come from trusted SDK
    service composition. The scope is required to be account-free; projected
    events are always system observations. The caller may retry the returned
    append request because its event ID binds the Gateway service, stream,
    epoch, sequence, and configured Monitor system/process.
    """

    def __init__(
        self,
        expected_identity: WireIdentity,
        expected_scope: WireScope,
        *,
        system_ref: str,
        process_ref: str,
    ) -> None:
        if (
            type(expected_identity) is not WireIdentity
            or expected_identity.role is not WireRole.SERVICE
            or expected_identity.delegate_ref is not None
            or type(expected_scope) is not WireScope
            or not _is_system_scope(expected_scope)
        ):
            raise MonitorMarketObservationError("INVALID_TRUSTED_BINDING")
        _validate_reference(system_ref)
        _validate_reference(process_ref)

        self._expected_identity = expected_identity
        self._expected_scope = expected_scope
        self._system_ref = system_ref
        self._process_ref = process_ref

    def project(self, event: WireEnvelope) -> dict[str, object]:
        """Return one JSON-ready ``events.append`` request or a finite error."""

        if type(event) is not WireEnvelope:
            raise MonitorMarketObservationError("INVALID_EVENT")
        header = event.header
        if header.identity != self._expected_identity:
            raise MonitorMarketObservationError("IDENTITY_MISMATCH")
        if header.scope != self._expected_scope:
            raise MonitorMarketObservationError("SCOPE_MISMATCH")
        try:
            validate_event(event, expected_scope=self._expected_scope)
        except Exception:
            raise MonitorMarketObservationError("INVALID_EVENT") from None
        if (
            header.operation != MARKET_EVENT_OPERATION
            or header.schema_id != MARKET_EVENT_SCHEMA
            or header.schema_version != MARKET_EVENT_SCHEMA_VERSION
        ):
            raise MonitorMarketObservationError("UNSUPPORTED_GATEWAY_EVENT")

        if set(event.payload) != {"key", "data"}:
            raise MonitorMarketObservationError("INVALID_MARKET_EVENT")
        raw_key = event.payload["key"]
        raw_data = event.payload["data"]
        if not isinstance(raw_key, Mapping) or not isinstance(raw_data, Mapping):
            raise MonitorMarketObservationError("INVALID_MARKET_EVENT")
        try:
            key = MarketSubscriptionKey.from_dict(raw_key)
        except (TypeError, ValueError):
            raise MonitorMarketObservationError("INVALID_MARKET_EVENT") from None
        if header.stream_id != key.stream_id:
            raise MonitorMarketObservationError("STREAM_KEY_MISMATCH")
        if type(header.stream_epoch) is not str or type(header.sequence) is not int:
            raise MonitorMarketObservationError("INVALID_EVENT")

        occurred_at = _timestamp_seconds(header.sent_at_utc)
        source = {
            "service_ref": header.identity.principal_ref,
            "stream_epoch": header.stream_epoch,
            "sequence": header.sequence,
            "gateway_sent_at_utc": header.sent_at_utc,
        }
        event_id = _stable_event_id(
            header.identity,
            header.stream_id,
            header.stream_epoch,
            header.sequence,
            self._system_ref,
            self._process_ref,
        )
        return {
            "schema_version": 1,
            "event_id": event_id,
            "event_type": GATEWAY_MARKET_OBSERVATION_EVENT_TYPE,
            "occurred_at": occurred_at,
            "data": {
                "schema": MONITOR_MARKET_OBSERVATION_SCHEMA,
                "scope_type": "system",
                "system_ref": self._system_ref,
                "process_ref": self._process_ref,
                "observation_kind": "consumer_received_frame",
                "source": source,
                "market": {
                    "instrument": key.instrument.to_dict(),
                    "channel": key.channel,
                    "depth": key.depth,
                    "timeframe": key.timeframe,
                },
            },
        }


def _is_system_scope(scope: WireScope) -> bool:
    return (
        scope.account_ref is None
        and not scope.account_refs
        and scope.strategy_ref is None
        and scope.run_id is None
        and scope.manual_book_ref is None
        and scope.portfolio_ref is None
        and scope.group_id is None
        and scope.leg_id is None
    )


def _validate_reference(value: Any) -> None:
    if type(value) is not str:
        raise MonitorMarketObservationError("INVALID_TRUSTED_BINDING")
    try:
        encoded = value.encode("utf-8", errors="strict")
    except UnicodeEncodeError:
        raise MonitorMarketObservationError("INVALID_TRUSTED_BINDING") from None
    if (
        not encoded
        or len(encoded) > MAX_REFERENCE_BYTES
        or value != value.strip()
        or not value.isprintable()
    ):
        raise MonitorMarketObservationError("INVALID_TRUSTED_BINDING")


def _timestamp_seconds(value: str) -> float:
    try:
        result = datetime.fromisoformat(value[:-1] + "+00:00").timestamp()
    except (OverflowError, OSError, ValueError):
        raise MonitorMarketObservationError("INVALID_SOURCE_TIME") from None
    if not math.isfinite(result):
        raise MonitorMarketObservationError("INVALID_SOURCE_TIME")
    return result


def _stable_event_id(
    identity: WireIdentity,
    stream_id: str,
    stream_epoch: str,
    sequence: int,
    system_ref: str,
    process_ref: str,
) -> str:
    canonical_identity = json.dumps(
        [
            identity.role.value,
            identity.principal_ref,
            identity.actor_ref,
            identity.delegate_ref,
            stream_id,
            stream_epoch,
            sequence,
            system_ref,
            process_ref,
        ],
        ensure_ascii=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("ascii")
    return _EVENT_ID_PREFIX + hashlib.sha256(canonical_identity).hexdigest()


__all__ = [
    "GATEWAY_MARKET_OBSERVATION_EVENT_TYPE",
    "MONITOR_MARKET_OBSERVATION_SCHEMA",
    "MonitorMarketObservationError",
    "MonitorMarketObservationProjector",
]
