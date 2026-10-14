"""Local durable event delivery primitives for monitor consumers.

This module deliberately does not connect to a provider, start a worker, or
make execution decisions.  It gives execution/direct adapters a small SQLite
outbox with deterministic event de-duplication and per-scope consumer
checkpoints.  A monitor can therefore restart and replay facts without
inventing a second order ledger.
"""

from __future__ import annotations

import hashlib
import json
import math
import sqlite3
import stat
import time
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Any, Callable, Optional, Union


class OutboxError(RuntimeError):
    """Base error for durable outbox validation and persistence failures."""


class OutboxConflictError(OutboxError):
    """An event id was reused with different immutable content."""


class OutboxCapacityError(OutboxError):
    """A new event would exceed a bounded outbox's retained event capacity."""


class CheckpointError(OutboxError):
    """A consumer tried to skip, regress, or acknowledge another scope's event."""


class OutboxDeliveryError(OutboxError):
    """A consumer delivery was not durably checkpointed.

    A successful handler call followed by a checkpoint failure is deliberately
    reported as an error: the fact will be delivered again on the next pass.
    Monitor sinks must therefore de-duplicate by ``event_id`` and tolerate
    at-least-once delivery.  The outbox itself never assumes a network sink or
    turns a failed delivery into an acknowledged event.
    """


@dataclass(frozen=True)
class OutboxEvent:
    """A redacted domain fact ready for local durable delivery."""

    event_id: str
    scope: str
    event_type: str
    data: Mapping[str, Any]
    occurred_at: float

    def __post_init__(self) -> None:
        if not self.event_id.strip() or not self.scope.strip() or not self.event_type.strip():
            raise ValueError("event_id, scope, and event_type are required")
        if isinstance(self.occurred_at, bool) or not math.isfinite(self.occurred_at):
            raise ValueError("occurred_at must be finite")
        if not isinstance(self.data, Mapping):
            raise ValueError("data must be a mapping")
        _validate_redacted_mapping(self.data)
        object.__setattr__(self, "data", _freeze_json(json.loads(_canonical_json(self.data))))

    @property
    def data_json(self) -> str:
        return _canonical_json(self.data)

    @property
    def fingerprint(self) -> str:
        return _sha256(
            _canonical_json(
                {
                    "data": json.loads(self.data_json),
                    "event_type": self.event_type,
                    "occurred_at": self.occurred_at,
                    "scope": self.scope,
                }
            )
        )


@dataclass(frozen=True)
class SequencedOutboxEvent:
    """An event plus the monotonic sequence used for one consumer checkpoint."""

    sequence: int
    event: OutboxEvent


OutboxDeliveryCallable = Callable[[SequencedOutboxEvent], None]
_MAX_READ_PAGE_SIZE = 1000
_MAX_READ_PAGE_TYPES = 16
MAX_OUTBOX_CAPACITY_EVENTS = 1_000_000
MAX_OUTBOX_CAPACITY_BYTES = 1_073_741_824


class DurableOutbox:
    """SQLite outbox with idempotent append and contiguous scoped checkpoints."""

    def __init__(
        self,
        database_path: Union[Path, str],  # noqa: UP007 -- Python 3.9 is supported.
        clock: Optional[Callable[[], float]] = None,  # noqa: UP045 -- Python 3.9 is supported.
        timeout_seconds: float = 5.0,
        *,
        read_only: bool = False,
    ) -> None:
        self._database_path = Path(database_path)
        self._clock = clock or time.time
        self._timeout_seconds = timeout_seconds
        if type(read_only) is not bool:
            raise ValueError("read_only must be a boolean")
        self._read_only = read_only
        if read_only:
            try:
                info = self._database_path.lstat()
            except OSError as exc:
                raise OutboxError("read-only outbox database is unavailable") from exc
            if not stat.S_ISREG(info.st_mode):
                raise OutboxError("read-only outbox database must be a regular file")
        else:
            self._database_path.parent.mkdir(parents=True, exist_ok=True)
            self._initialize_schema()

    @property
    def is_read_only(self) -> bool:
        """Whether this instance is permanently bound to SQLite read-only mode."""

        return self._read_only

    def append(self, event: OutboxEvent) -> SequencedOutboxEvent:
        """Persist an event or return its existing sequence for an exact retry."""
        self._require_writable()
        with self._transaction() as connection:
            return self._append_on_connection(connection, event)

    def append_bounded(
        self,
        event: OutboxEvent,
        *,
        max_events: int,
        max_bytes: int,
    ) -> SequencedOutboxEvent:
        """Append idempotently while bounding retained logical event count and bytes.

        Byte accounting covers UTF-8 bytes for each retained event's ID, scope,
        type, and canonical ``data_json``. It describes logical event content,
        not SQLite file size or other database overhead. Capacity checks and the
        insert run under the same ``BEGIN IMMEDIATE`` transaction.
        """

        self._require_writable()
        _validate_capacity_limits(max_events, max_bytes)
        with self._transaction() as connection:
            return self._append_on_connection(
                connection,
                event,
                max_events=max_events,
                max_bytes=max_bytes,
            )

    def read_pending(
        self, consumer_id: str, scope: str, limit: int = 100
    ) -> list[SequencedOutboxEvent]:
        """Return unacknowledged events for a consumer/scope in sequence order."""
        if not consumer_id.strip() or not scope.strip():
            raise ValueError("consumer_id and scope are required")
        if limit <= 0:
            raise ValueError("limit must be positive")
        with self._connection() as connection:
            return self._read_pending_on_connection(connection, consumer_id, scope, limit)

    def _read_pending_on_connection(
        self,
        connection: sqlite3.Connection,
        consumer_id: str,
        scope: str,
        limit: int,
    ) -> list[SequencedOutboxEvent]:
        """Read pending rows on a caller-owned, non-transactional connection."""
        if not consumer_id.strip() or not scope.strip():
            raise ValueError("consumer_id and scope are required")
        if limit <= 0:
            raise ValueError("limit must be positive")
        checkpoint = self._checkpoint(connection, consumer_id, scope)
        rows = connection.execute(
            """
            SELECT sequence, event_id, scope, event_type, data_json, occurred_at
            FROM monitor_outbox_events
            WHERE scope = ? AND sequence > ?
            ORDER BY sequence ASC LIMIT ?
            """,
            (scope, checkpoint, limit),
        ).fetchall()
        return [self._sequenced_from_row(row) for row in rows]

    def read_page(
        self, scope: str, event_type: str, after_sequence: int, limit: int
    ) -> tuple[list[SequencedOutboxEvent], bool]:
        """Read a bounded, unacknowledged-independent page for one event scope.

        Unlike :meth:`read_pending`, this read-only projection does not consult
        or advance a consumer checkpoint.  The caller owns a scope-bound cursor
        and must validate it before passing its sequence here.
        """

        if not isinstance(scope, str) or not scope.strip():
            raise ValueError("scope is required")
        if not isinstance(event_type, str) or not event_type.strip():
            raise ValueError("event_type is required")
        if type(after_sequence) is not int or after_sequence < 0:
            raise ValueError("after_sequence must be a nonnegative exact integer")
        if type(limit) is not int or not 1 <= limit <= _MAX_READ_PAGE_SIZE:
            raise ValueError("limit is outside the bounded page range")
        with self._connection() as connection:
            rows = connection.execute(
                """
                SELECT sequence, event_id, scope, event_type, data_json, occurred_at
                FROM monitor_outbox_events
                WHERE scope = ? AND event_type = ? AND sequence > ?
                ORDER BY sequence ASC LIMIT ?
                """,
                (scope, event_type, after_sequence, limit + 1),
            ).fetchall()
        has_more = len(rows) > limit
        return [self._sequenced_from_row(row) for row in rows[:limit]], has_more

    def read_page_types(
        self, scope: str, event_types: tuple[str, ...], after_sequence: int, limit: int
    ) -> tuple[list[SequencedOutboxEvent], bool]:
        """Read one globally ordered page across a bounded event-type set.

        A single SQL statement gives every configured type the same SQLite
        snapshot.  Separate per-type reads can observe concurrent appends at
        different times and let a later sequence advance the cursor past an
        event inserted for an earlier type.
        """

        if not isinstance(scope, str) or not scope.strip():
            raise ValueError("scope is required")
        if (
            type(event_types) is not tuple
            or not 1 <= len(event_types) <= _MAX_READ_PAGE_TYPES
            or any(not isinstance(event_type, str) or not event_type.strip() for event_type in event_types)
            or len(set(event_types)) != len(event_types)
        ):
            raise ValueError("event_types must be a bounded tuple of unique names")
        if type(after_sequence) is not int or after_sequence < 0:
            raise ValueError("after_sequence must be a nonnegative exact integer")
        if type(limit) is not int or not 1 <= limit <= _MAX_READ_PAGE_SIZE:
            raise ValueError("limit is outside the bounded page range")

        parameters = (
            scope,
            *event_types,
            *(None for _ in range(_MAX_READ_PAGE_TYPES - len(event_types))),
            after_sequence,
            limit + 1,
        )
        with self._connection() as connection:
            rows = connection.execute(
                """
                SELECT sequence, event_id, scope, event_type, data_json, occurred_at
                FROM monitor_outbox_events
                WHERE scope = ? AND event_type IN (
                    ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
                ) AND sequence > ?
                ORDER BY sequence ASC LIMIT ?
                """,
                parameters,
            ).fetchall()
        has_more = len(rows) > limit
        return [self._sequenced_from_row(row) for row in rows[:limit]], has_more

    def acknowledge(self, consumer_id: str, scope: str, sequence: int) -> None:
        """Advance one consumer by exactly its next event in this scope."""
        self._require_writable()
        if not consumer_id.strip() or not scope.strip() or sequence <= 0:
            raise ValueError("consumer_id, scope, and positive sequence are required")
        with self._connection() as connection:
            self._acknowledge_on_connection(connection, consumer_id, scope, sequence)

    def _acknowledge_on_connection(
        self,
        connection: sqlite3.Connection,
        consumer_id: str,
        scope: str,
        sequence: int,
    ) -> None:
        """Commit one acknowledgement on a caller-owned connection.

        The caller must not hold a transaction across delivery callbacks. Each
        invocation owns one independent ``BEGIN IMMEDIATE``/``COMMIT`` pair.
        """
        if not consumer_id.strip() or not scope.strip() or sequence <= 0:
            raise ValueError("consumer_id, scope, and positive sequence are required")
        connection.execute("BEGIN IMMEDIATE")
        try:
            checkpoint = self._checkpoint(connection, consumer_id, scope)
            if sequence <= checkpoint:
                if sequence == checkpoint:
                    connection.execute("COMMIT")
                    return
                raise CheckpointError("consumer checkpoint cannot regress")
            next_row = connection.execute(
                """
                SELECT sequence FROM monitor_outbox_events
                WHERE scope = ? AND sequence > ? ORDER BY sequence ASC LIMIT 1
                """,
                (scope, checkpoint),
            ).fetchone()
            if next_row is None or int(next_row["sequence"]) != sequence:
                raise CheckpointError("consumer checkpoint must acknowledge the next scoped event")
            connection.execute(
                """
                INSERT INTO monitor_consumer_checkpoints (consumer_id, scope, sequence, updated_at)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(consumer_id, scope) DO UPDATE SET
                    sequence = excluded.sequence, updated_at = excluded.updated_at
                """,
                (consumer_id, scope, sequence, self._clock()),
            )
            connection.execute("COMMIT")
        except BaseException:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise

    def _can_reuse_consumer_connection(self) -> bool:
        """Whether the consumer may use the built-in read/ack implementations.

        ``read_pending`` and ``acknowledge`` remain dynamically dispatched
        extension points. If a subclass or instance overrides either public
        method, the consumer preserves that behavior through the original
        public-call path instead of bypassing the override with these helpers.
        """
        return (
            type(self).read_pending is _DURABLE_OUTBOX_READ_PENDING
            and type(self).acknowledge is _DURABLE_OUTBOX_ACKNOWLEDGE
            and "read_pending" not in self.__dict__
            and "acknowledge" not in self.__dict__
        )

    def _append_on_connection(
        self,
        connection: sqlite3.Connection,
        event: OutboxEvent,
        *,
        max_events: Optional[int] = None,  # noqa: UP045 -- Python 3.9 compatibility.
        max_bytes: Optional[int] = None,  # noqa: UP045 -- Python 3.9 compatibility.
    ) -> SequencedOutboxEvent:
        existing = connection.execute(
            "SELECT sequence, event_id, fingerprint, scope, event_type, data_json, occurred_at "
            "FROM monitor_outbox_events WHERE event_id = ?",
            (event.event_id,),
        ).fetchone()
        if existing is not None:
            if str(existing["fingerprint"]) != event.fingerprint:
                raise OutboxConflictError("event_id was reused with different content")
            return self._sequenced_from_row(existing)

        if max_events is not None and max_bytes is not None:
            new_event_bytes = _event_logical_bytes(event)
            if new_event_bytes > max_bytes:
                raise OutboxCapacityError("bounded outbox capacity would be exceeded")

            logical_bytes = 0
            retained_rows = connection.execute(
                """
                SELECT length(CAST(event_id AS BLOB)) +
                       length(CAST(scope AS BLOB)) +
                       length(CAST(event_type AS BLOB)) +
                       length(CAST(data_json AS BLOB)) AS logical_bytes
                FROM monitor_outbox_events
                LIMIT ?
                """,
                (max_events,),
            )
            for event_count, retained in enumerate(retained_rows, start=1):
                if event_count >= max_events:
                    raise OutboxCapacityError("bounded outbox capacity would be exceeded")
                logical_bytes += int(retained["logical_bytes"])
                if logical_bytes + new_event_bytes > max_bytes:
                    raise OutboxCapacityError("bounded outbox capacity would be exceeded")

        cursor = connection.execute(
            """
            INSERT INTO monitor_outbox_events
                (event_id, fingerprint, scope, event_type, data_json, occurred_at, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                event.event_id,
                event.fingerprint,
                event.scope,
                event.event_type,
                event.data_json,
                event.occurred_at,
                self._clock(),
            ),
        )
        return SequencedOutboxEvent(sequence=int(cursor.lastrowid), event=event)

    def checkpoint(self, consumer_id: str, scope: str) -> int:
        """Return the last durably acknowledged sequence for a consumer and scope."""
        with self._connection() as connection:
            return self._checkpoint(connection, consumer_id, scope)

    def _checkpoint(self, connection: sqlite3.Connection, consumer_id: str, scope: str) -> int:
        row = connection.execute(
            "SELECT sequence FROM monitor_consumer_checkpoints WHERE consumer_id = ? AND scope = ?",
            (consumer_id, scope),
        ).fetchone()
        return int(row["sequence"]) if row is not None else 0

    def _initialize_schema(self) -> None:
        self._require_writable()
        with self._connection() as connection:
            connection.execute("PRAGMA journal_mode = WAL")
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS monitor_outbox_events (
                    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_id TEXT NOT NULL UNIQUE,
                    fingerprint TEXT NOT NULL,
                    scope TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    data_json TEXT NOT NULL,
                    occurred_at REAL NOT NULL,
                    created_at REAL NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_monitor_outbox_scope_sequence
                    ON monitor_outbox_events(scope, sequence);
                CREATE TABLE IF NOT EXISTS monitor_consumer_checkpoints (
                    consumer_id TEXT NOT NULL,
                    scope TEXT NOT NULL,
                    sequence INTEGER NOT NULL,
                    updated_at REAL NOT NULL,
                    PRIMARY KEY(consumer_id, scope)
                );
                """
            )

    def _sequenced_from_row(self, row: sqlite3.Row) -> SequencedOutboxEvent:
        return SequencedOutboxEvent(
            sequence=int(row["sequence"]),
            event=OutboxEvent(
                event_id=str(row["event_id"]),
                scope=str(row["scope"]),
                event_type=str(row["event_type"]),
                data=json.loads(str(row["data_json"])),
                occurred_at=float(row["occurred_at"]),
            ),
        )

    @contextmanager
    def _connection(self) -> Iterator[sqlite3.Connection]:
        if self._read_only:
            connection = sqlite3.connect(
                self._database_path.absolute().as_uri() + "?mode=ro",
                uri=True,
                timeout=self._timeout_seconds,
                isolation_level=None,
            )
        else:
            connection = sqlite3.connect(
                str(self._database_path), timeout=self._timeout_seconds, isolation_level=None
            )
        connection.row_factory = sqlite3.Row
        try:
            if self._read_only:
                connection.execute("PRAGMA query_only = ON")
                row = connection.execute("PRAGMA query_only").fetchone()
                if row is None or int(row[0]) != 1:
                    raise OutboxError("read-only SQLite mode could not be verified")
            else:
                connection.execute("PRAGMA synchronous = FULL")
            yield connection
        finally:
            connection.close()

    @contextmanager
    def _transaction(self) -> Iterator[sqlite3.Connection]:
        self._require_writable()
        with self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                yield connection
            except BaseException:
                connection.execute("ROLLBACK")
                raise
            else:
                connection.execute("COMMIT")

    def _require_writable(self) -> None:
        if self._read_only:
            raise OutboxError("read-only outbox cannot perform writes")


# Keep references to the original methods so monkeypatching the class itself
# remains visible to the consumer's extension-point detection.
_DURABLE_OUTBOX_READ_PENDING = DurableOutbox.read_pending
_DURABLE_OUTBOX_ACKNOWLEDGE = DurableOutbox.acknowledge


class DurableOutboxConsumer:
    """Consume one scoped outbox cursor with explicit at-least-once semantics.

    The consumer is intentionally synchronous and contains no network client,
    worker thread, scheduler, or retry loop.  A deployment injects a redacted
    sink callback and calls :meth:`consume` from its own supervised lifecycle.
    The checkpoint advances only after that callback returns normally.  If the
    callback or acknowledgement fails, the current fact remains pending and a
    later invocation replays it.  This makes crash recovery deterministic
    without treating a local callback as proof of remote monitor delivery.
    """

    def __init__(
        self,
        outbox: DurableOutbox,
        consumer_id: str,
        scope: str,
        deliver: OutboxDeliveryCallable,
    ) -> None:
        if not isinstance(outbox, DurableOutbox):
            raise ValueError("outbox must be a DurableOutbox")
        if outbox.is_read_only:
            raise ValueError("outbox consumer requires a writable DurableOutbox")
        if not isinstance(consumer_id, str) or not consumer_id.strip():
            raise ValueError("consumer_id is required")
        if not isinstance(scope, str) or not scope.strip():
            raise ValueError("scope is required")
        if not callable(deliver):
            raise ValueError("deliver callback is required")
        self._outbox = outbox
        self._consumer_id = consumer_id
        self._scope = scope
        self._deliver = deliver

    @property
    def consumer_id(self) -> str:
        """Return the durable cursor identity used by this consumer."""

        return self._consumer_id

    @property
    def scope(self) -> str:
        """Return the sole scope this consumer is allowed to acknowledge."""

        return self._scope

    def checkpoint(self) -> int:
        """Return the consumer's last durable scoped acknowledgement."""

        return self._outbox.checkpoint(self._consumer_id, self._scope)

    def consume(self, limit: int = 100) -> list[SequencedOutboxEvent]:
        """Deliver up to ``limit`` pending facts and checkpoint each in order.

        This method intentionally does not swallow callback or SQLite failures.
        The caller can record health/freeze policy separately while the durable
        cursor remains at the last known acknowledgement.
        """

        if self._outbox._can_reuse_consumer_connection():
            with self._outbox._connection() as connection:
                pending = self._outbox._read_pending_on_connection(
                    connection, self._consumer_id, self._scope, limit
                )
                return self._deliver_and_ack(
                    pending,
                    lambda item: self._outbox._acknowledge_on_connection(
                        connection, self._consumer_id, self._scope, item.sequence
                    ),
                )

        # Preserve dynamic public method overrides on subclasses and instances.
        # Such overrides may add behavior to the documented read/ack API, so
        # they keep the original one-operation-per-connection path.
        pending = self._outbox.read_pending(self._consumer_id, self._scope, limit)
        return self._deliver_and_ack(
            pending,
            lambda item: self._outbox.acknowledge(self._consumer_id, self._scope, item.sequence),
        )

    def _deliver_and_ack(
        self,
        pending: list[SequencedOutboxEvent],
        acknowledge: Callable[[SequencedOutboxEvent], None],
    ) -> list[SequencedOutboxEvent]:
        delivered: list[SequencedOutboxEvent] = []
        for item in pending:
            try:
                self._deliver(item)
            except Exception as error:
                raise OutboxDeliveryError(
                    "outbox delivery failed; event remains pending for replay"
                ) from error
            try:
                acknowledge(item)
            except Exception as error:
                raise OutboxDeliveryError(
                    "outbox delivery was not checkpointed; event may be delivered again"
                ) from error
            delivered.append(item)
        return delivered


_SENSITIVE_KEY_PARTS = (
    "password",
    "passphrase",
    "secret",
    "token",
    "credential",
    "privatekey",
    "apikey",
)


def _is_sensitive_key(value: str) -> bool:
    """Reject secret field names despite case or common separator changes."""

    if type(value) is not str or len(value.encode("utf-8", "strict")) > 128:
        raise ValueError("outbox event data field name is invalid")
    normalized = "".join(
        character for character in value.casefold() if character.isascii() and character.isalnum()
    )
    return any(part in normalized for part in _SENSITIVE_KEY_PARTS)


def _validate_redacted_mapping(value: Mapping[str, Any]) -> None:
    """Reject known secret-bearing keys and non-canonical JSON before persistence."""

    def visit(item: Any, path: str = "") -> None:
        if isinstance(item, Mapping):
            for key, nested in item.items():
                if type(key) is not str:
                    raise ValueError("outbox event data mapping keys must be strings")
                if _is_sensitive_key(key):
                    raise ValueError("outbox event data must be redacted: " + (path + str(key)))
                visit(nested, path + str(key) + ".")
        elif isinstance(item, (list, tuple)):
            for nested in item:
                visit(nested, path)

    visit(value)
    try:
        _canonical_json(value)
    except (TypeError, ValueError) as exc:
        raise ValueError("outbox event data must be JSON serializable") from exc


def _canonical_json(value: object) -> str:
    return json.dumps(
        _json_value(value),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    )


def _json_value(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {key: _json_value(nested) for key, nested in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_value(nested) for nested in value]
    return value


def _freeze_json(value: Any) -> Any:
    if isinstance(value, dict):
        return MappingProxyType({key: _freeze_json(nested) for key, nested in value.items()})
    if isinstance(value, list):
        return tuple(_freeze_json(nested) for nested in value)
    return value


def _sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _validate_capacity_limits(max_events: int, max_bytes: int) -> None:
    if type(max_events) is not int or not 1 <= max_events <= MAX_OUTBOX_CAPACITY_EVENTS:
        raise ValueError("max_events is outside the bounded capacity range")
    if type(max_bytes) is not int or not 1 <= max_bytes <= MAX_OUTBOX_CAPACITY_BYTES:
        raise ValueError("max_bytes is outside the bounded capacity range")


def _event_logical_bytes(event: OutboxEvent) -> int:
    """Count the UTF-8 bytes retained for the event's logical text fields."""

    return _logical_text_bytes(
        event.event_id,
        event.scope,
        event.event_type,
        event.data_json,
    )


def _logical_text_bytes(*values: str) -> int:
    return sum(len(value.encode("utf-8", errors="strict")) for value in values)


__all__ = [
    "CheckpointError",
    "DurableOutbox",
    "DurableOutboxConsumer",
    "MAX_OUTBOX_CAPACITY_BYTES",
    "MAX_OUTBOX_CAPACITY_EVENTS",
    "OutboxCapacityError",
    "OutboxConflictError",
    "OutboxDeliveryCallable",
    "OutboxDeliveryError",
    "OutboxError",
    "OutboxEvent",
    "SequencedOutboxEvent",
]
