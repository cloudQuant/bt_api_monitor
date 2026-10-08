"""Authenticated, read-only pages over the durable monitor outbox.

The service is intended to live inside a separately supervised process.  It
does not start a server, write events, acknowledge deliveries, or log event
content.  Its only storage operation is ``DurableOutbox.read_page_types``.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import math
import re
import secrets
import time
from collections.abc import Mapping
from dataclasses import dataclass, field
from threading import Lock
from types import MappingProxyType
from typing import Any, Union

from .durable import DurableOutbox, OutboxEvent, SequencedOutboxEvent, _is_sensitive_key

EVENT_READ_HMAC_DOMAIN = "bt_api.monitor.event_read.v1"
MAX_EVENT_READ_PAGE_SIZE = 100
_MAX_CURSOR = (1 << 63) - 1
_MAX_GENERATION = (1 << 31) - 1
_MAX_EVENT_TYPES = 16
_MAX_DATA_BYTES = 64 * 1024
_MAX_DATA_NODES = 2048
_MAX_DATA_DEPTH = 16
_OPAQUE_RE = re.compile(r"^[A-Za-z0-9_-]{16,128}$")


class EventReadError(ValueError):
    """A request, response, or durable row failed closed validation."""


class EventReadAuthenticationError(EventReadError):
    """An event-read request or page did not authenticate."""


class EventReadReplayError(EventReadError):
    """A request identifier or nonce was already used in this generation."""


class EventReadCursorError(EventReadError):
    """A request cursor regressed or advanced beyond the service cursor."""


@dataclass(frozen=True)
class EventReadRequestV1:
    """A signed request for one exact scope and configured event-type set."""

    service_instance_ref: str
    generation: int
    scope: str
    event_types: tuple[str, ...]
    after_sequence: int
    limit: int
    request_ref: str
    nonce: str
    issued_at: float
    signature: bytes = field(repr=False, compare=False)

    def __post_init__(self) -> None:
        _validate_request_fields(self, check_signature=True)


@dataclass(frozen=True)
class EventReadItemV1:
    """One immutable, bounded event in a read page."""

    sequence: int
    event_id: str
    event_type: str
    data: Mapping[str, Any]
    occurred_at: float

    def __post_init__(self) -> None:
        _validate_event_fields(self)
        object.__setattr__(self, "data", _freeze_json(self.data))


@dataclass(frozen=True)
class EventReadPageV1:
    """An authenticated receipt and one bounded page of event facts."""

    service_instance_ref: str
    generation: int
    scope: str
    event_types: tuple[str, ...]
    request_ref: str
    nonce: str
    issued_at: float
    after_sequence: int
    limit: int
    cursor: int
    has_more: bool
    observed_at: float
    events: tuple[EventReadItemV1, ...]
    signature: bytes = field(repr=False, compare=False)

    def __post_init__(self) -> None:
        _validate_page_fields(self, check_signature=True)


class ReadOnlyEventService:
    """Serve signed pages from one exact ``DurableOutbox`` binding.

    ``initial_cursor`` is supplied by the process owner when resuming a
    previously accepted cursor.  Each request in this service generation
    must then use the current cursor exactly; the service never accepts a
    caller-selected skip.
    """

    def __init__(
        self,
        outbox: DurableOutbox,
        scope: str,
        event_types: Union[str, tuple[str, ...]],  # noqa: UP007 -- Python 3.9 is supported.
        *,
        generation: int,
        hmac_key: bytes,
        service_instance_ref: str | None = None,
        initial_cursor: int = 0,
    ) -> None:
        if type(outbox) is not DurableOutbox or outbox.is_read_only is not True:
            raise EventReadError("outbox must be a read-only DurableOutbox")
        _validate_text("scope", scope, 256)
        normalized_types = _normalize_event_types(event_types)
        if type(generation) is not int or not 1 <= generation <= _MAX_GENERATION:
            raise EventReadError("generation is outside the supported range")
        _validate_key(hmac_key)
        if service_instance_ref is None:
            service_instance_ref = secrets.token_urlsafe(24)
        _validate_opaque("service_instance_ref", service_instance_ref)
        _validate_cursor(initial_cursor, "initial_cursor")

        self._outbox = outbox
        self._scope = scope
        self._event_types = normalized_types
        self._generation = generation
        self._service_instance_ref = service_instance_ref
        self._hmac_key = hmac_key
        self._cursor = initial_cursor
        self._used_request_refs: set[str] = set()
        self._used_nonces: set[str] = set()
        self._lock = Lock()

    @property
    def service_instance_ref(self) -> str:
        """Opaque identity for this separately supervised service instance."""

        return self._service_instance_ref

    @property
    def generation(self) -> int:
        """Owner-assigned generation number bound into every request and page."""

        return self._generation

    def read_page(self, request: EventReadRequestV1) -> EventReadPageV1:
        """Authenticate and serve one page without changing any checkpoint."""

        if type(request) is not EventReadRequestV1:
            raise EventReadError("request must be an EventReadRequestV1")
        _validate_request_fields(request, check_signature=True)
        _validate_fresh_timestamp(request.issued_at, time.time())
        if not hmac.compare_digest(request.signature, _request_signature(self._hmac_key, request)):
            raise EventReadAuthenticationError("request signature is invalid")
        if (
            request.service_instance_ref != self._service_instance_ref
            or request.generation != self._generation
            or request.scope != self._scope
            or request.event_types != self._event_types
        ):
            raise EventReadAuthenticationError("request binding does not match this service")

        with self._lock:
            if request.request_ref in self._used_request_refs or request.nonce in self._used_nonces:
                raise EventReadReplayError("request reference or nonce was already used")
            if request.after_sequence < self._cursor:
                raise EventReadCursorError("request cursor regressed")
            if request.after_sequence > self._cursor:
                raise EventReadCursorError("request cursor is ahead of the service cursor")
            if len(self._used_request_refs) >= 100_000:
                raise EventReadReplayError("request replay window is full")

            # Consume both identifiers before touching storage.  A storage
            # failure therefore cannot make an accepted nonce reusable.
            self._used_request_refs.add(request.request_ref)
            self._used_nonces.add(request.nonce)
            try:
                rows, has_more = self._outbox.read_page_types(
                    self._scope, self._event_types, request.after_sequence, request.limit
                )
                if type(rows) is not list or type(has_more) is not bool:
                    raise EventReadError("outbox returned a malformed page")
                if len(rows) > request.limit or (has_more and len(rows) != request.limit):
                    raise EventReadError("outbox page exceeded its bound")
                raw_events: list[SequencedOutboxEvent] = []
                for row in rows:
                    if type(row) is not SequencedOutboxEvent or type(row.event) is not OutboxEvent:
                        raise EventReadError("outbox returned a malformed event row")
                    if row.event.event_type not in self._event_types:
                        raise EventReadError("outbox returned an event outside the bound type set")
                    raw_events.append(
                        _validate_durable_row(
                            row, self._scope, row.event.event_type, request.after_sequence
                        )
                    )
                _validate_sequence_order(raw_events, request.after_sequence)
                selected = raw_events[: request.limit]
                if not selected and has_more:
                    raise EventReadError("outbox returned an invalid continuation marker")
                items = tuple(
                    EventReadItemV1(
                        sequence=row.sequence,
                        event_id=row.event.event_id,
                        event_type=row.event.event_type,
                        data=row.event.data,
                        occurred_at=row.event.occurred_at,
                    )
                    for row in selected
                )
                cursor = items[-1].sequence if items else request.after_sequence
                observed_at = time.time()
                unsigned_page = EventReadPageV1(
                    service_instance_ref=self._service_instance_ref,
                    generation=self._generation,
                    scope=self._scope,
                    event_types=self._event_types,
                    request_ref=request.request_ref,
                    nonce=request.nonce,
                    issued_at=request.issued_at,
                    after_sequence=request.after_sequence,
                    limit=request.limit,
                    cursor=cursor,
                    has_more=has_more,
                    observed_at=observed_at,
                    events=items,
                    signature=bytes(32),
                )
                page = EventReadPageV1(
                    service_instance_ref=unsigned_page.service_instance_ref,
                    generation=unsigned_page.generation,
                    scope=unsigned_page.scope,
                    event_types=unsigned_page.event_types,
                    request_ref=unsigned_page.request_ref,
                    nonce=unsigned_page.nonce,
                    issued_at=unsigned_page.issued_at,
                    after_sequence=unsigned_page.after_sequence,
                    limit=unsigned_page.limit,
                    cursor=unsigned_page.cursor,
                    has_more=unsigned_page.has_more,
                    observed_at=unsigned_page.observed_at,
                    events=unsigned_page.events,
                    signature=_page_signature(self._hmac_key, unsigned_page),
                )
                self._cursor = cursor
                return page
            except EventReadError:
                raise
            except Exception:
                # Do not expose database diagnostics that might contain event
                # content or storage details to the remote caller.
                raise EventReadError("outbox page read failed") from None


def sign_event_read_request(
    *,
    key: bytes,
    service_instance_ref: str,
    generation: int,
    scope: str,
    event_types: Union[str, tuple[str, ...]],  # noqa: UP007 -- Python 3.9 is supported.
    after_sequence: int,
    limit: int,
    request_ref: str,
    nonce: str,
    issued_at: float,
) -> EventReadRequestV1:
    """Build a deterministic signed request from explicit binding fields."""

    _validate_key(key)
    normalized_types = _normalize_event_types(event_types)
    unsigned_request = EventReadRequestV1(
        service_instance_ref=service_instance_ref,
        generation=generation,
        scope=scope,
        event_types=normalized_types,
        after_sequence=after_sequence,
        limit=limit,
        request_ref=request_ref,
        nonce=nonce,
        issued_at=issued_at,
        signature=bytes(32),
    )
    return EventReadRequestV1(
        service_instance_ref=unsigned_request.service_instance_ref,
        generation=unsigned_request.generation,
        scope=unsigned_request.scope,
        event_types=unsigned_request.event_types,
        after_sequence=unsigned_request.after_sequence,
        limit=unsigned_request.limit,
        request_ref=unsigned_request.request_ref,
        nonce=unsigned_request.nonce,
        issued_at=unsigned_request.issued_at,
        signature=_request_signature(key, unsigned_request),
    )


def verify_event_read_page(
    request: EventReadRequestV1, page: EventReadPageV1, *, key: bytes
) -> bool:
    """Verify the request and its exact authenticated page binding.

    Returns ``True`` for a valid page and raises ``EventReadError`` for any
    malformed, mismatched, replay-shaped, or unauthenticated response.
    """

    _validate_key(key)
    if type(request) is not EventReadRequestV1 or type(page) is not EventReadPageV1:
        raise EventReadError("request and page must use the versioned event-read types")
    _validate_request_fields(request, check_signature=True)
    _validate_page_fields(page, check_signature=True)
    if not hmac.compare_digest(request.signature, _request_signature(key, request)):
        raise EventReadAuthenticationError("request signature is invalid")
    bound_fields = (
        page.service_instance_ref == request.service_instance_ref,
        page.generation == request.generation,
        page.scope == request.scope,
        page.event_types == request.event_types,
        page.request_ref == request.request_ref,
        page.nonce == request.nonce,
        page.issued_at == request.issued_at,
        page.after_sequence == request.after_sequence,
        page.limit == request.limit,
    )
    if not all(bound_fields):
        raise EventReadAuthenticationError("page does not match its signed request")
    if page.observed_at < request.issued_at - 5.0:
        raise EventReadAuthenticationError("page observation predates its request")
    if not hmac.compare_digest(page.signature, _page_signature(key, page)):
        raise EventReadAuthenticationError("page signature is invalid")
    return True


def _validate_request_fields(request: EventReadRequestV1, *, check_signature: bool) -> None:
    _validate_opaque("service_instance_ref", request.service_instance_ref)
    if type(request.generation) is not int or not 1 <= request.generation <= _MAX_GENERATION:
        raise EventReadError("generation is outside the supported range")
    _validate_text("scope", request.scope, 256)
    if type(request.event_types) is not tuple:
        raise EventReadError("event_types must be a tuple")
    if _normalize_event_types(request.event_types) != request.event_types:
        raise EventReadError("event_types are not in canonical order")
    _validate_cursor(request.after_sequence, "after_sequence")
    if type(request.limit) is not int or not 1 <= request.limit <= MAX_EVENT_READ_PAGE_SIZE:
        raise EventReadError("limit is outside the bounded page range")
    _validate_opaque("request_ref", request.request_ref)
    _validate_opaque("nonce", request.nonce)
    if request.request_ref == request.nonce:
        raise EventReadError("request_ref and nonce must be distinct")
    if type(request.issued_at) is not float or not math.isfinite(request.issued_at):
        raise EventReadError("issued_at must be a finite float timestamp")
    if check_signature and (type(request.signature) is not bytes or len(request.signature) != 32):
        raise EventReadError("request signature has an invalid shape")


def _validate_page_fields(page: EventReadPageV1, *, check_signature: bool) -> None:
    _validate_opaque("service_instance_ref", page.service_instance_ref)
    if type(page.generation) is not int or not 1 <= page.generation <= _MAX_GENERATION:
        raise EventReadError("generation is outside the supported range")
    _validate_text("scope", page.scope, 256)
    if type(page.event_types) is not tuple:
        raise EventReadError("event_types must be a tuple")
    if _normalize_event_types(page.event_types) != page.event_types:
        raise EventReadError("event_types are not in canonical order")
    _validate_opaque("request_ref", page.request_ref)
    _validate_opaque("nonce", page.nonce)
    if page.request_ref == page.nonce:
        raise EventReadError("request_ref and nonce must be distinct")
    if type(page.issued_at) is not float or not math.isfinite(page.issued_at):
        raise EventReadError("issued_at must be a finite float timestamp")
    _validate_cursor(page.after_sequence, "after_sequence")
    if type(page.limit) is not int or not 1 <= page.limit <= MAX_EVENT_READ_PAGE_SIZE:
        raise EventReadError("limit is outside the bounded page range")
    _validate_cursor(page.cursor, "cursor")
    if page.cursor < page.after_sequence:
        raise EventReadCursorError("page cursor regressed")
    if type(page.has_more) is not bool:
        raise EventReadError("has_more must be a boolean")
    if type(page.observed_at) is not float or not math.isfinite(page.observed_at):
        raise EventReadError("observed_at must be a finite float timestamp")
    if type(page.events) is not tuple or len(page.events) > page.limit:
        raise EventReadError("events exceed the bounded page shape")
    previous = page.after_sequence
    for item in page.events:
        if type(item) is not EventReadItemV1:
            raise EventReadError("page contains a malformed event")
        _validate_event_fields(item)
        if item.sequence <= previous:
            raise EventReadCursorError("page events are not strictly ordered")
        if item.event_type not in page.event_types:
            raise EventReadError("page contains an unbound event type")
        previous = item.sequence
    expected_cursor = page.events[-1].sequence if page.events else page.after_sequence
    if page.cursor != expected_cursor:
        raise EventReadCursorError("page cursor is ahead of its event content")
    if page.has_more and len(page.events) != page.limit:
        raise EventReadError("continuation page is not full")
    if check_signature and (type(page.signature) is not bytes or len(page.signature) != 32):
        raise EventReadError("page signature has an invalid shape")


def _validate_event_fields(item: EventReadItemV1) -> None:
    _validate_cursor(item.sequence, "event sequence")
    if item.sequence == 0:
        raise EventReadError("event sequence must be positive")
    _validate_text("event_id", item.event_id, 256)
    _validate_text("event_type", item.event_type, 128)
    if type(item.occurred_at) is not float or not math.isfinite(item.occurred_at):
        raise EventReadError("occurred_at must be a finite float timestamp")
    if not isinstance(item.data, Mapping):
        raise EventReadError("event data must be a mapping")
    _validate_json_mapping(item.data)


def _validate_durable_row(
    row: Any, scope: str, event_type: str, after_sequence: int
) -> SequencedOutboxEvent:
    if type(row) is not SequencedOutboxEvent or type(row.event) is not OutboxEvent:
        raise EventReadError("outbox returned a malformed event row")
    if type(row.sequence) is not int or row.sequence <= after_sequence or row.sequence > _MAX_CURSOR:
        raise EventReadCursorError("outbox returned a sequence outside the requested cursor")
    event = row.event
    if event.scope != scope or event.event_type != event_type:
        raise EventReadError("outbox returned an event outside the bound scope or type")
    candidate = EventReadItemV1(
        sequence=row.sequence,
        event_id=event.event_id,
        event_type=event.event_type,
        data=event.data,
        occurred_at=event.occurred_at,
    )
    # Reconstruct the public durable value to reapply its redaction and JSON
    # invariants in case a malformed or monkeypatched row bypassed normal load.
    try:
        OutboxEvent(
            event_id=event.event_id,
            scope=event.scope,
            event_type=event.event_type,
            data=candidate.data,
            occurred_at=event.occurred_at,
        )
    except Exception:
        raise EventReadError("outbox event content failed validation") from None
    return row


def _validate_sequence_order(rows: list[SequencedOutboxEvent], after_sequence: int) -> None:
    previous = after_sequence
    for row in rows:
        if row.sequence <= previous:
            raise EventReadCursorError("outbox sequences are not strictly increasing")
        previous = row.sequence


def _normalize_event_types(
    value: Union[str, tuple[str, ...]],  # noqa: UP007 -- Python 3.9 is supported.
) -> tuple[str, ...]:
    if isinstance(value, str):
        values = (value,)
    elif type(value) is tuple:
        values = value
    else:
        raise EventReadError("event_types must be a string or tuple of strings")
    if not 1 <= len(values) <= _MAX_EVENT_TYPES:
        raise EventReadError("event_types count is outside the supported range")
    for event_type in values:
        _validate_text("event_type", event_type, 128)
    if len(set(values)) != len(values):
        raise EventReadError("event_types must be unique")
    return tuple(sorted(values))


def _validate_text(name: str, value: Any, max_bytes: int) -> None:
    if type(value) is not str or not value or value != value.strip():
        raise EventReadError(name + " is invalid")
    try:
        encoded = value.encode("utf-8", "strict")
    except UnicodeError:
        raise EventReadError(name + " is invalid") from None
    if len(encoded) > max_bytes or any(ord(char) < 32 or ord(char) == 127 for char in value):
        raise EventReadError(name + " is invalid")


def _validate_opaque(name: str, value: Any) -> None:
    if type(value) is not str or _OPAQUE_RE.fullmatch(value) is None:
        raise EventReadError(name + " must be a bounded opaque token")


def _validate_cursor(value: Any, name: str) -> None:
    if type(value) is not int or not 0 <= value <= _MAX_CURSOR:
        raise EventReadCursorError(name + " is outside the supported cursor range")


def _validate_key(key: Any) -> None:
    if type(key) is not bytes or not 32 <= len(key) <= 128:
        raise EventReadError("HMAC key must be 32 to 128 bytes")


def _validate_fresh_timestamp(issued_at: float, now: float) -> None:
    if issued_at > now + 5.0 or now - issued_at > 120.0:
        raise EventReadAuthenticationError("request timestamp is outside the freshness window")


def _validate_json_mapping(value: Mapping[str, Any]) -> None:
    nodes = 0

    def visit(item: Any, depth: int) -> Any:
        nonlocal nodes
        nodes += 1
        if nodes > _MAX_DATA_NODES or depth > _MAX_DATA_DEPTH:
            raise EventReadError("event data exceeds structural bounds")
        if isinstance(item, Mapping):
            normalized: dict[str, Any] = {}
            for key, nested in item.items():
                if type(key) is not str:
                    raise EventReadError("event data mapping keys must be strings")
                _validate_text("event data key", key, 128)
                if _is_sensitive_key(key):
                    raise EventReadError("event data contains a non-redacted field")
                normalized[key] = visit(nested, depth + 1)
            return normalized
        if isinstance(item, (list, tuple)):
            return [visit(nested, depth + 1) for nested in item]
        if item is None or type(item) is bool:
            return item
        if type(item) is str:
            try:
                if len(item.encode("utf-8", "strict")) > 8192:
                    raise EventReadError("event data string exceeds its bound")
            except UnicodeError:
                raise EventReadError("event data string is invalid") from None
            return item
        if type(item) is int:
            if item.bit_length() > 128:
                raise EventReadError("event data integer exceeds its bound")
            return item
        if type(item) is float:
            if not math.isfinite(item):
                raise EventReadError("event data number must be finite")
            return item
        raise EventReadError("event data contains a non-JSON value")

    normalized = visit(value, 0)
    try:
        encoded = json.dumps(
            normalized,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
    except (TypeError, ValueError):
        raise EventReadError("event data is not canonical JSON") from None
    if len(encoded) > _MAX_DATA_BYTES:
        raise EventReadError("event data exceeds its byte bound")


def _freeze_json(value: Any) -> Any:
    if isinstance(value, Mapping):
        return MappingProxyType({key: _freeze_json(nested) for key, nested in value.items()})
    if isinstance(value, (list, tuple)):
        return tuple(_freeze_json(nested) for nested in value)
    return value


def _json_value(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {key: _json_value(nested) for key, nested in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_value(nested) for nested in value]
    return value


def _request_payload(request: EventReadRequestV1) -> dict[str, Any]:
    return {
        "domain": EVENT_READ_HMAC_DOMAIN + ".request",
        "service_instance_ref": request.service_instance_ref,
        "generation": request.generation,
        "scope": request.scope,
        "event_types": list(request.event_types),
        "after_sequence": request.after_sequence,
        "limit": request.limit,
        "request_ref": request.request_ref,
        "nonce": request.nonce,
        "issued_at": request.issued_at,
    }


def _page_payload(page: EventReadPageV1) -> dict[str, Any]:
    return {
        "domain": EVENT_READ_HMAC_DOMAIN + ".response",
        "service_instance_ref": page.service_instance_ref,
        "generation": page.generation,
        "scope": page.scope,
        "event_types": list(page.event_types),
        "request_ref": page.request_ref,
        "nonce": page.nonce,
        "issued_at": page.issued_at,
        "after_sequence": page.after_sequence,
        "limit": page.limit,
        "cursor": page.cursor,
        "has_more": page.has_more,
        "observed_at": page.observed_at,
        "events": [
            {
                "sequence": item.sequence,
                "event_id": item.event_id,
                "event_type": item.event_type,
                "data": _json_value(item.data),
                "occurred_at": item.occurred_at,
            }
            for item in page.events
        ],
    }


def _canonical_payload(payload: Mapping[str, Any]) -> bytes:
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")


def _request_signature(key: bytes, request: EventReadRequestV1) -> bytes:
    return hmac.new(key, _canonical_payload(_request_payload(request)), hashlib.sha256).digest()


def _page_signature(key: bytes, page: EventReadPageV1) -> bytes:
    return hmac.new(key, _canonical_payload(_page_payload(page)), hashlib.sha256).digest()


__all__ = [
    "EVENT_READ_HMAC_DOMAIN",
    "MAX_EVENT_READ_PAGE_SIZE",
    "EventReadAuthenticationError",
    "EventReadCursorError",
    "EventReadError",
    "EventReadItemV1",
    "EventReadPageV1",
    "EventReadReplayError",
    "EventReadRequestV1",
    "ReadOnlyEventService",
    "sign_event_read_request",
    "verify_event_read_page",
]
