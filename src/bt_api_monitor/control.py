"""Durable monitor control-command ledger.

The ledger records a command before any account owner acts on it.  It has no
provider client and does not claim a command has executed merely because it
was accepted.  A supervisor, gateway, or Broker adapter must claim and then
acknowledge/reject its own command after performing its independently guarded
operation.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
import sqlite3
import time
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Callable, Optional, Protocol, Union


class ControlLedgerError(RuntimeError):
    """Base error for control-command validation and delivery."""


class ControlConflictError(ControlLedgerError):
    """A command id was reused with different content."""


class ControlClaimError(ControlLedgerError):
    """An executor attempted an invalid claim or outcome transition."""


class ControlAuthorizationError(ControlLedgerError):
    """A control request was not authenticated and authorized by a verifier."""

    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(reason.replace("_", " "))


class ControlSequenceError(ControlAuthorizationError):
    """A verified issuer sequence was replayed, skipped, or reordered."""


class ControlAction(str, Enum):
    """The supported monitor-to-owner commands."""

    FREEZE = "freeze"
    DRAIN = "drain"
    RESUME = "resume"


class ControlStatus(str, Enum):
    """Persisted state of one command, never inferred from a client response."""

    PENDING = "pending"
    CLAIMED = "claimed"
    ACKNOWLEDGED = "acknowledged"
    REJECTED = "rejected"
    EXPIRED = "expired"
    UNKNOWN = "unknown"


_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_CONTROL_ENVELOPE_DOMAIN = b"bt-api-monitor-control-envelope-v1\0"
_INGRESS_PROOF = object()
_MAX_CONTROL_PAYLOAD_BYTES = 64 * 1024
_MAX_CONTROL_SIGNATURE_BYTES = 16 * 1024


@dataclass(frozen=True)
class ControlCommandEnvelope:
    """Opaque signed input accepted by the control ingress.

    The envelope deliberately contains no caller-trusted issuer, receipt, or
    resume-authorization fields. A code-owned verifier must decode and verify
    its signed payload before any claims are converted to a ledger command.
    """

    payload: bytes
    signature: bytes

    def __post_init__(self) -> None:
        if type(self.payload) is not bytes or not self.payload:
            raise ValueError("control payload must be non-empty bytes")
        if len(self.payload) > _MAX_CONTROL_PAYLOAD_BYTES:
            raise ValueError("control payload is too large")
        if type(self.signature) is not bytes or not self.signature:
            raise ValueError("control signature must be non-empty bytes")
        if len(self.signature) > _MAX_CONTROL_SIGNATURE_BYTES:
            raise ValueError("control signature is too large")

    @property
    def digest(self) -> str:
        payload_length = len(self.payload).to_bytes(8, "big")
        signature_length = len(self.signature).to_bytes(8, "big")
        return hashlib.sha256(
            _CONTROL_ENVELOPE_DOMAIN
            + payload_length
            + self.payload
            + signature_length
            + self.signature
        ).hexdigest()


@dataclass(frozen=True)
class VerifiedControlCommand:
    """Normalized claims returned only after a verifier accepts an envelope.

    ``HmacControlCommandVerifier`` supplies the offline verification contract;
    the injected key and issuer-policy resolvers remain the authority boundary.
    This DTO is an audit result, not a production key source or route.
    """

    command_id: str
    account_id: str
    mode: str
    scope: str
    action: ControlAction
    issuer: str
    key_id: str
    reason: str
    receipt_digest: str
    issued_at: float
    expires_at: float
    issuer_sequence: int
    manual_resume_authorized: bool
    envelope_digest: str
    verification_digest: str

    def __post_init__(self) -> None:
        _validated_command(
            command_id=self.command_id,
            account_id=self.account_id,
            mode=self.mode,
            scope=self.scope,
            action=self.action,
            issuer=self.issuer,
            key_id=self.key_id,
            reason=self.reason,
            receipt_digest=self.receipt_digest,
            issued_at=self.issued_at,
            expires_at=self.expires_at,
            manual_resume_authorized=self.manual_resume_authorized,
            require_receipt_digest=True,
        )
        if type(self.issuer_sequence) is not int or self.issuer_sequence <= 0:
            raise ValueError("issuer_sequence must be a positive integer")
        for name in ("envelope_digest", "verification_digest"):
            value = getattr(self, name)
            if type(value) is not str or _SHA256_RE.fullmatch(value) is None:
                raise ValueError(name + " must be a lowercase SHA-256 digest")


class ControlCommandVerifier(Protocol):
    """Trusted composition seam for signature, issuer, receipt, and policy checks."""

    def verify(self, envelope: ControlCommandEnvelope, *, now_utc: float) -> VerifiedControlCommand:
        """Return claims bound to this exact envelope or raise to reject it."""


def _validated_command(
    *,
    command_id: str,
    account_id: str,
    mode: str,
    scope: str,
    action: ControlAction,
    issuer: str,
    key_id: str,
    reason: str,
    receipt_digest: str,
    issued_at: float,
    expires_at: float,
    manual_resume_authorized: bool,
    require_receipt_digest: bool = False,
) -> None:
    if not isinstance(action, ControlAction):
        raise ValueError("action must be a ControlAction")
    if type(manual_resume_authorized) is not bool:
        raise ValueError("manual_resume_authorized must be a boolean")
    for name, value in (
        ("command_id", command_id),
        ("account_id", account_id),
        ("mode", mode),
        ("scope", scope),
        ("issuer", issuer),
        ("key_id", key_id),
        ("reason", reason),
    ):
        if type(value) is not str or not value.strip() or value != value.strip():
            raise ValueError(name + " is required")
    if type(receipt_digest) is not str or not receipt_digest.strip():
        raise ValueError("receipt_digest is required")
    if require_receipt_digest and _SHA256_RE.fullmatch(receipt_digest) is None:
        raise ValueError("receipt_digest must be a lowercase SHA-256 digest")
    if any(
        isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value)
        for value in (issued_at, expires_at)
    ):
        raise ValueError("command timestamps must be finite")
    if expires_at <= issued_at:
        raise ValueError("expires_at must be after issued_at")
    if action is ControlAction.RESUME and not manual_resume_authorized:
        raise ValueError("resume requires explicit verified manual authorization")
    if action is not ControlAction.RESUME and manual_resume_authorized:
        raise ValueError("manual resume authorization is only valid for resume")


@dataclass(frozen=True)
class ControlCommand:
    """Validated command facts reconstructed from verifier output or the ledger."""

    command_id: str
    account_id: str
    mode: str
    scope: str
    action: ControlAction
    issuer: str
    key_id: str
    reason: str
    receipt_digest: str
    issued_at: float
    expires_at: float
    manual_resume_authorized: bool = False

    def __post_init__(self) -> None:
        _validated_command(
            command_id=self.command_id,
            account_id=self.account_id,
            mode=self.mode,
            scope=self.scope,
            action=self.action,
            issuer=self.issuer,
            key_id=self.key_id,
            reason=self.reason,
            receipt_digest=self.receipt_digest,
            issued_at=self.issued_at,
            expires_at=self.expires_at,
            manual_resume_authorized=self.manual_resume_authorized,
        )

    @property
    def fingerprint(self) -> str:
        return _sha256(
            _canonical_json(
                {
                    "action": self.action.value,
                    "account_id": self.account_id,
                    "expires_at": self.expires_at,
                    "issued_at": self.issued_at,
                    "issuer": self.issuer,
                    "key_id": self.key_id,
                    "manual_resume_authorized": self.manual_resume_authorized,
                    "mode": self.mode,
                    "reason": self.reason,
                    "receipt_digest": self.receipt_digest,
                    "scope": self.scope,
                }
            )
        )


@dataclass(frozen=True, repr=False)
class _IngressAcceptedCommand:
    """Private ledger input constructed only by :class:`ControlIngress`."""

    command: ControlCommand
    issuer_sequence: int
    envelope_digest: str
    verification_digest: str
    _proof: object

    def __post_init__(self) -> None:
        if self._proof is not _INGRESS_PROOF:
            raise ControlAuthorizationError("verified_control_ingress_required")
        if type(self.command) is not ControlCommand:
            raise ControlAuthorizationError("control_command_required")
        if type(self.issuer_sequence) is not int or self.issuer_sequence <= 0:
            raise ControlAuthorizationError("invalid_verified_issuer_sequence")
        for name in ("envelope_digest", "verification_digest"):
            value = getattr(self, name)
            if type(value) is not str or _SHA256_RE.fullmatch(value) is None:
                raise ControlAuthorizationError("invalid_verified_control_digest")

    @property
    def fingerprint(self) -> str:
        return _sha256(
            _canonical_json(
                {
                    "command_fingerprint": self.command.fingerprint,
                    "envelope_digest": self.envelope_digest,
                    "issuer_sequence": self.issuer_sequence,
                    "verification_digest": self.verification_digest,
                }
            )
        )


@dataclass(frozen=True)
class ClaimedControlCommand:
    """A command leased to exactly one account owner."""

    command: ControlCommand
    status: ControlStatus
    executor_id: Optional[str]  # noqa: UP045 -- Python 3.9 is supported.
    outcome: Optional[str] = None  # noqa: UP045 -- Python 3.9 is supported.


class DurableControlLedger:
    """SQLite command ledger with idempotent submit and one-executor claiming."""

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

    def submit(self, command: object) -> ClaimedControlCommand:
        """Persist only an ingress-verified command; exact retry is idempotent.

        A caller-created :class:`ControlCommand` is descriptive input, not
        authority. Requiring the private ingress result here prevents direct
        ledger submissions from treating its issuer, receipt, or manual
        resume flag as verified facts.
        """
        if type(command) is not _IngressAcceptedCommand or command._proof is not _INGRESS_PROOF:
            raise ControlAuthorizationError("verified_control_ingress_required")
        accepted = command
        durable_command = accepted.command
        with self._transaction() as connection:
            now = self._clock()
            self._expire_pending(connection, now)
            existing = connection.execute(
                "SELECT * FROM monitor_control_commands WHERE command_id = ?",
                (durable_command.command_id,),
            ).fetchone()
            if existing is not None:
                if str(existing["fingerprint"]) != accepted.fingerprint:
                    raise ControlConflictError("command_id was reused with different content")
                return self._claimed_from_row(existing)

            latest = connection.execute(
                "SELECT MAX(issuer_sequence) FROM monitor_control_commands WHERE issuer = ?",
                (durable_command.issuer,),
            ).fetchone()[0]
            if latest is not None and accepted.issuer_sequence != int(latest) + 1:
                raise ControlSequenceError("issuer_sequence_replayed_or_out_of_order")

            status = (
                ControlStatus.EXPIRED
                if durable_command.expires_at <= now
                else ControlStatus.PENDING
            )
            outcome = "command_ttl_elapsed" if status is ControlStatus.EXPIRED else None
            connection.execute(
                """
                INSERT INTO monitor_control_commands (
                    command_id, fingerprint, account_id, mode, scope, action, issuer, key_id,
                    reason, receipt_digest,
                    issued_at, expires_at, manual_resume_authorized, issuer_sequence,
                    envelope_digest, verification_digest, status, executor_id, outcome, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, ?, ?)
                """,
                (
                    durable_command.command_id,
                    accepted.fingerprint,
                    durable_command.account_id,
                    durable_command.mode,
                    durable_command.scope,
                    durable_command.action.value,
                    durable_command.issuer,
                    durable_command.key_id,
                    durable_command.reason,
                    durable_command.receipt_digest,
                    durable_command.issued_at,
                    durable_command.expires_at,
                    int(durable_command.manual_resume_authorized),
                    accepted.issuer_sequence,
                    accepted.envelope_digest,
                    accepted.verification_digest,
                    status.value,
                    outcome,
                    now,
                ),
            )
            return ClaimedControlCommand(durable_command, status, None)

    def claim_next(self, scope: str, executor_id: str) -> Optional[ClaimedControlCommand]:  # noqa: UP045 -- Python 3.9 is supported.
        """Lease the oldest pending unexpired command in the requested scope."""
        if not scope.strip() or not executor_id.strip():
            raise ValueError("scope and executor_id are required")
        now = self._clock()
        with self._transaction() as connection:
            self._expire_pending(connection, now)
            row = connection.execute(
                """
                SELECT * FROM monitor_control_commands
                WHERE scope = ? AND status = ? AND issued_at <= ?
                    AND issuer_sequence IS NOT NULL
                    AND account_id IS NOT NULL AND account_id <> ''
                    AND mode IS NOT NULL AND mode <> ''
                    AND key_id IS NOT NULL AND key_id <> ''
                    AND envelope_digest IS NOT NULL AND envelope_digest <> ''
                    AND verification_digest IS NOT NULL AND verification_digest <> ''
                ORDER BY issued_at ASC, command_id ASC LIMIT 1
                """,
                (scope, ControlStatus.PENDING.value, now),
            ).fetchone()
            if row is None:
                return None
            connection.execute(
                """
                UPDATE monitor_control_commands
                SET status = ?, executor_id = ?, updated_at = ? WHERE command_id = ?
                """,
                (ControlStatus.CLAIMED.value, executor_id, now, row["command_id"]),
            )
            claimed = dict(row)
            claimed["status"] = ControlStatus.CLAIMED.value
            claimed["executor_id"] = executor_id
            return self._claimed_from_mapping(claimed)

    def finish(self, command_id: str, executor_id: str, succeeded: bool, outcome: str) -> None:
        """Record a final owner outcome after the external action has actually completed."""
        if not command_id.strip() or not executor_id.strip() or not outcome.strip():
            raise ValueError("command_id, executor_id, and outcome are required")
        if type(succeeded) is not bool:
            raise ValueError("succeeded must be a boolean")
        now = self._clock()
        failure = None
        status = ControlStatus.ACKNOWLEDGED if succeeded else ControlStatus.REJECTED
        with self._transaction() as connection:
            self._expire_pending(connection, now)
            row = connection.execute(
                "SELECT * FROM monitor_control_commands WHERE command_id = ?", (command_id,)
            ).fetchone()
            if row is None:
                failure = ControlClaimError("command does not exist")
            elif row["executor_id"] != executor_id:
                failure = ControlClaimError("command is owned by another executor")
            elif row["status"] == status.value and row["outcome"] == outcome:
                return
            elif row["status"] != ControlStatus.CLAIMED.value:
                failure = ControlClaimError(
                    "command is not claimed; reconciliation may be required"
                )
            else:
                connection.execute(
                    """
                    UPDATE monitor_control_commands SET status = ?, outcome = ?, updated_at = ?
                    WHERE command_id = ?
                    """,
                    (status.value, outcome, now, command_id),
                )
        # Commit timeout/unknown facts even when the attempted ACK is rejected.
        if failure is not None:
            raise failure

    def get(self, command_id: str) -> Optional[ClaimedControlCommand]:  # noqa: UP045 -- Python 3.9 is supported.
        """Return the durable command state without changing it."""
        with self._connection() as connection:
            row = connection.execute(
                "SELECT * FROM monitor_control_commands WHERE command_id = ?", (command_id,)
            ).fetchone()
        return self._claimed_from_row(row) if row is not None else None

    def _expire_pending(self, connection: sqlite3.Connection, now: float) -> None:
        connection.execute(
            """
            UPDATE monitor_control_commands
            SET status = ?, outcome = ?, updated_at = ?
            WHERE status = ? AND expires_at <= ?
            """,
            (
                ControlStatus.EXPIRED.value,
                "command_ttl_elapsed",
                now,
                ControlStatus.PENDING.value,
                now,
            ),
        )
        connection.execute(
            """
            UPDATE monitor_control_commands SET status = ?, outcome = ?, updated_at = ?
            WHERE status = ? AND expires_at <= ?
            """,
            (
                ControlStatus.UNKNOWN.value,
                "claimed_command_reconciliation_required",
                now,
                ControlStatus.CLAIMED.value,
                now,
            ),
        )

    def _claimed_from_row(self, row: sqlite3.Row) -> ClaimedControlCommand:
        return self._claimed_from_mapping(dict(row))

    def _claimed_from_mapping(self, row: dict[str, object]) -> ClaimedControlCommand:
        command = ControlCommand(
            command_id=str(row["command_id"]),
            account_id=str(row["account_id"]),
            mode=str(row["mode"]),
            scope=str(row["scope"]),
            action=ControlAction(str(row["action"])),
            issuer=str(row["issuer"]),
            key_id=str(row["key_id"]),
            reason=str(row["reason"]),
            receipt_digest=str(row["receipt_digest"]),
            issued_at=_persisted_timestamp("issued_at", row["issued_at"]),
            expires_at=_persisted_timestamp("expires_at", row["expires_at"]),
            manual_resume_authorized=bool(row["manual_resume_authorized"]),
        )
        executor_id = row.get("executor_id")
        return ClaimedControlCommand(
            command=command,
            status=ControlStatus(str(row["status"])),
            executor_id=str(executor_id) if executor_id is not None else None,
            outcome=str(row["outcome"]) if row.get("outcome") is not None else None,
        )

    def _initialize_schema(self) -> None:
        with self._connection() as connection:
            connection.execute("PRAGMA journal_mode = WAL")
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS monitor_control_commands (
                    command_id TEXT PRIMARY KEY,
                    fingerprint TEXT NOT NULL,
                    account_id TEXT NOT NULL,
                    mode TEXT NOT NULL,
                    scope TEXT NOT NULL,
                    action TEXT NOT NULL,
                    issuer TEXT NOT NULL,
                    key_id TEXT NOT NULL,
                    reason TEXT NOT NULL,
                    receipt_digest TEXT NOT NULL,
                    issued_at REAL NOT NULL,
                    expires_at REAL NOT NULL,
                    manual_resume_authorized INTEGER NOT NULL,
                    issuer_sequence INTEGER,
                    envelope_digest TEXT,
                    verification_digest TEXT,
                    status TEXT NOT NULL,
                    executor_id TEXT,
                    outcome TEXT,
                    updated_at REAL NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_monitor_control_scope_status
                    ON monitor_control_commands(scope, status, issued_at);
                """
            )
            columns = {
                str(row["name"])
                for row in connection.execute("PRAGMA table_info(monitor_control_commands)")
            }
            migrations = {
                "account_id": "TEXT",
                "mode": "TEXT",
                "key_id": "TEXT",
                "issuer_sequence": "INTEGER",
                "envelope_digest": "TEXT",
                "verification_digest": "TEXT",
            }
            for name, declaration in migrations.items():
                if name not in columns:
                    connection.execute(
                        "ALTER TABLE monitor_control_commands ADD COLUMN "
                        + name
                        + " "
                        + declaration
                    )
            connection.execute(
                """
                UPDATE monitor_control_commands
                SET status = ?, outcome = ?
                WHERE status IN (?, ?) AND (
                    account_id IS NULL OR account_id = '' OR mode IS NULL OR mode = ''
                    OR key_id IS NULL OR key_id = '' OR issuer_sequence IS NULL
                    OR envelope_digest IS NULL OR envelope_digest = ''
                    OR verification_digest IS NULL OR verification_digest = ''
                )
                """,
                (
                    ControlStatus.UNKNOWN.value,
                    "legacy_unverified_control_command_requires_reconciliation",
                    ControlStatus.PENDING.value,
                    ControlStatus.CLAIMED.value,
                ),
            )
            connection.execute(
                """
                CREATE UNIQUE INDEX IF NOT EXISTS idx_monitor_control_issuer_sequence
                ON monitor_control_commands(issuer, issuer_sequence)
                WHERE issuer_sequence IS NOT NULL
                """
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


class ControlIngress:
    """Verify signed control envelopes before persisting any command facts.

    There is intentionally no default verifier. A deployment must construct
    this object with its reviewed verifier; without one, submissions fail
    before the durable ledger is called. The package includes an HMAC verifier
    implementation but provides no trusted production key source or policy.
    """

    def __init__(
        self,
        ledger: DurableControlLedger,
        verifier: ControlCommandVerifier | None = None,
        clock: Callable[[], float] | None = None,
    ) -> None:
        if type(ledger) is not DurableControlLedger:
            raise TypeError("a DurableControlLedger is required")
        self._ledger = ledger
        self._verifier = verifier
        self._clock = clock or ledger._clock

    def submit(self, envelope: ControlCommandEnvelope) -> ClaimedControlCommand:
        """Authenticate, normalize and persist exactly one control command."""

        if type(envelope) is not ControlCommandEnvelope:
            raise ControlAuthorizationError("control_envelope_required")
        verifier = self._verifier
        verify = getattr(verifier, "verify", None)
        if not callable(verify):
            raise ControlAuthorizationError("trusted_control_verifier_required")

        now = self._clock()
        if isinstance(now, bool) or not isinstance(now, (int, float)) or not math.isfinite(now):
            raise ControlAuthorizationError("control_ingress_clock_invalid")
        try:
            verified = verify(envelope, now_utc=float(now))
            if type(verified) is not VerifiedControlCommand:
                raise ValueError("verifier returned an unsupported result")
            # Reconstruct to rerun validation even if a verifier mutated a
            # frozen dataclass through low-level reflection.
            verified = VerifiedControlCommand(
                command_id=verified.command_id,
                account_id=verified.account_id,
                mode=verified.mode,
                scope=verified.scope,
                action=verified.action,
                issuer=verified.issuer,
                key_id=verified.key_id,
                reason=verified.reason,
                receipt_digest=verified.receipt_digest,
                issued_at=verified.issued_at,
                expires_at=verified.expires_at,
                issuer_sequence=verified.issuer_sequence,
                manual_resume_authorized=verified.manual_resume_authorized,
                envelope_digest=verified.envelope_digest,
                verification_digest=verified.verification_digest,
            )
        except Exception:
            raise ControlAuthorizationError("control_verification_failed") from None

        if verified.envelope_digest != envelope.digest:
            raise ControlAuthorizationError("verified_envelope_digest_mismatch")

        command = ControlCommand(
            command_id=verified.command_id,
            account_id=verified.account_id,
            mode=verified.mode,
            scope=verified.scope,
            action=verified.action,
            issuer=verified.issuer,
            key_id=verified.key_id,
            reason=verified.reason,
            receipt_digest=verified.receipt_digest,
            issued_at=verified.issued_at,
            expires_at=verified.expires_at,
            manual_resume_authorized=verified.manual_resume_authorized,
        )
        accepted = _IngressAcceptedCommand(
            command=command,
            issuer_sequence=verified.issuer_sequence,
            envelope_digest=verified.envelope_digest,
            verification_digest=verified.verification_digest,
            _proof=_INGRESS_PROOF,
        )
        return self._ledger.submit(accepted)


def _canonical_json(value: object) -> str:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    )


def _sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _persisted_timestamp(name: str, value: object) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
        raise ControlLedgerError("persisted " + name + " is invalid")
    return float(value)


__all__ = [
    "ClaimedControlCommand",
    "ControlAction",
    "ControlAuthorizationError",
    "ControlClaimError",
    "ControlCommand",
    "ControlCommandEnvelope",
    "ControlCommandVerifier",
    "ControlConflictError",
    "ControlIngress",
    "ControlLedgerError",
    "ControlSequenceError",
    "ControlStatus",
    "DurableControlLedger",
    "VerifiedControlCommand",
]
