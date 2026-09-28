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


class DurableOutbox:
    """SQLite outbox with idempotent append and contiguous scoped checkpoints."""

    def __init__(
        self,
        database_path: Union[Path, str],  # noqa: UP007 -- Python 3.9 is supported.
        clock: Optional[Callable[[], float]] = None,  # noqa: UP045 -- Python 3.9 is supported.
        timeout_seconds: float = 5.0,
    ) -> None:
        self._database_path = Path(database_path)
        self._clock = clock or time.time
        self._timeout_seconds = timeout_seconds
        self._database_path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize_schema()

    def append(self, event: OutboxEvent) -> SequencedOutboxEvent:
        """Persist an event or return its existing sequence for an exact retry."""
        with self._transaction() as connection:
            existing = connection.execute(
                "SELECT sequence, event_id, fingerprint, scope, event_type, data_json, occurred_at "
                "FROM monitor_outbox_events WHERE event_id = ?",
                (event.event_id,),
            ).fetchone()
            if existing is not None:
                if str(existing["fingerprint"]) != event.fingerprint:
                    raise OutboxConflictError("event_id was reused with different content")
                return self._sequenced_from_row(existing)

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

    def read_pending(
        self, consumer_id: str, scope: str, limit: int = 100
    ) -> list[SequencedOutboxEvent]:
        """Return unacknowledged events for a consumer/scope in sequence order."""
        if not consumer_id.strip() or not scope.strip():
            raise ValueError("consumer_id and scope are required")
        if limit <= 0:
            raise ValueError("limit must be positive")
        with self._connection() as connection:
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

    def acknowledge(self, consumer_id: str, scope: str, sequence: int) -> None:
        """Advance one consumer by exactly its next event in this scope."""
        if not consumer_id.strip() or not scope.strip() or sequence <= 0:
            raise ValueError("consumer_id, scope, and positive sequence are required")
        with self._transaction() as connection:
            checkpoint = self._checkpoint(connection, consumer_id, scope)
            if sequence <= checkpoint:
                if sequence == checkpoint:
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
        connection = sqlite3.connect(
            str(self._database_path), timeout=self._timeout_seconds, isolation_level=None
        )
        connection.row_factory = sqlite3.Row
        try:
            connection.execute("PRAGMA synchronous = FULL")
            yield connection
        finally:
            connection.close()

    @contextmanager
    def _transaction(self) -> Iterator[sqlite3.Connection]:
        with self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                yield connection
            except BaseException:
                connection.execute("ROLLBACK")
                raise
            else:
                connection.execute("COMMIT")


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

        pending = self._outbox.read_pending(self._consumer_id, self._scope, limit)
        delivered: list[SequencedOutboxEvent] = []
        for item in pending:
            try:
                self._deliver(item)
            except Exception as error:
                raise OutboxDeliveryError(
                    "outbox delivery failed; event remains pending for replay"
                ) from error
            try:
                self._outbox.acknowledge(self._consumer_id, self._scope, item.sequence)
            except Exception as error:
                raise OutboxDeliveryError(
                    "outbox delivery was not checkpointed; event may be delivered again"
                ) from error
            delivered.append(item)
        return delivered


_SENSITIVE_KEY_PARTS = ("password", "secret", "token", "credential", "private_key", "api_key")


def _validate_redacted_mapping(value: Mapping[str, Any]) -> None:
    """Reject known secret-bearing keys and non-canonical JSON before persistence."""

    def visit(item: Any, path: str = "") -> None:
        if isinstance(item, Mapping):
            for key, nested in item.items():
                normalized_key = str(key).lower()
                if any(part in normalized_key for part in _SENSITIVE_KEY_PARTS):
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


__all__ = [
    "CheckpointError",
    "DurableOutbox",
    "DurableOutboxConsumer",
    "OutboxConflictError",
    "OutboxDeliveryCallable",
    "OutboxDeliveryError",
    "OutboxError",
    "OutboxEvent",
    "SequencedOutboxEvent",
]
