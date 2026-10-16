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
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from types import MappingProxyType
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
    STOP_NEW = "stop_new"
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


class ControlOwnerOutcome(str, Enum):
    """Finite outcomes an authenticated owner may persist for a claimed command."""

    APPLIED = "applied"
    REJECTED = "rejected"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class ControlCommandBinding:
    """Trusted service-side binding for one verified control submission.

    The HMAC verifier proves the issuer's signed claims. This additional binding
    ties those claims to the authenticated wire caller and the configured
    account/mode/scope route before the ledger is changed.
    """

    issuer: str
    account_id: str
    mode: str
    scope: str
    actions: frozenset[ControlAction]

    def __post_init__(self) -> None:
        for name, value in (
            ("issuer", self.issuer),
            ("account_id", self.account_id),
            ("mode", self.mode),
            ("scope", self.scope),
        ):
            if type(value) is not str or not value.strip() or value != value.strip():
                raise ValueError(name + " is required")
        if (
            type(self.actions) is not frozenset
            or not self.actions
            or any(type(action) is not ControlAction for action in self.actions)
        ):
            raise ValueError("actions must be a non-empty set of ControlAction values")


_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_MONITOR_FREEZE_CAUSE_RE = re.compile(r"^monitor-freeze-v1:[0-9a-f]{64}$")
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
    schema_version: int = 1
    target_freeze_cause_id: str | None = None

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
            schema_version=self.schema_version,
            target_freeze_cause_id=self.target_freeze_cause_id,
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
    schema_version: int = 1,
    target_freeze_cause_id: str | None = None,
    require_receipt_digest: bool = False,
) -> None:
    if not isinstance(action, ControlAction):
        raise ValueError("action must be a ControlAction")
    if type(manual_resume_authorized) is not bool:
        raise ValueError("manual_resume_authorized must be a boolean")
    if type(schema_version) is not int or schema_version not in (1, 2):
        raise ValueError("schema_version must be 1 or 2")
    if target_freeze_cause_id is not None and (
        type(target_freeze_cause_id) is not str
        or _MONITOR_FREEZE_CAUSE_RE.fullmatch(target_freeze_cause_id) is None
    ):
        raise ValueError("target_freeze_cause_id is invalid")
    if schema_version == 1 and target_freeze_cause_id is not None:
        raise ValueError("schema version 1 cannot name a target freeze cause")
    if schema_version == 2 and action is ControlAction.RESUME and target_freeze_cause_id is None:
        raise ValueError("schema version 2 resume requires an exact target freeze cause")
    if schema_version == 2 and action is not ControlAction.RESUME and target_freeze_cause_id is not None:
        raise ValueError("only resume may name a target freeze cause")
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
    schema_version: int = 1
    target_freeze_cause_id: str | None = None

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
            schema_version=self.schema_version,
            target_freeze_cause_id=self.target_freeze_cause_id,
        )

    @property
    def fingerprint(self) -> str:
        values: dict[str, object] = {
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
        # Preserve the original v1 fingerprint so exact historical retries
        # remain idempotent after a ledger is opened by this version.
        if self.schema_version >= 2:
            values["schema_version"] = self.schema_version
            values["target_freeze_cause_id"] = self.target_freeze_cause_id
        return _sha256(_canonical_json(values))


def monitor_freeze_cause_id(command: ControlCommand) -> str:
    """Return the stable Risk cause identifier produced by one verified FREEZE.

    The account, mode and command scope are included so a cause id cannot be
    reused across a different monitor route. This function only derives an
    identifier; Risk remains the authority for whether a cause exists or is
    active.
    """

    if type(command) is not ControlCommand or command.action is not ControlAction.FREEZE:
        raise ValueError("a verified FREEZE command is required")
    facts = {
        "account_id": command.account_id,
        "command_id": command.command_id,
        "issuer": command.issuer,
        "mode": command.mode,
        "schema": "bt-api-monitor-freeze-cause-v1",
        "scope": command.scope,
    }
    digest = hashlib.sha256(_canonical_json(facts).encode("utf-8")).hexdigest()
    return "monitor-freeze-v1:" + digest


def _encode_effect_result(value: Mapping[str, object] | None) -> str | None:
    if value is None:
        return None
    if not isinstance(value, Mapping) or any(type(key) is not str for key in value):
        raise ValueError("effect_result must be a flat string-keyed mapping")
    copied: dict[str, object] = {}
    for key, item in value.items():
        if not key or key != key.strip() or type(item) not in (str, bool, int, type(None)):
            raise ValueError("effect_result contains an unsupported value")
        if type(item) is str and len(item.encode("utf-8", errors="strict")) > 256:
            raise ValueError("effect_result text is too long")
        copied[key] = item
    encoded = _canonical_json(copied)
    if len(encoded.encode("utf-8")) > 4096:
        raise ValueError("effect_result is too large")
    return encoded


def _decode_effect_result(value: object) -> Mapping[str, object] | None:
    if value is None:
        return None
    if type(value) is not str or len(value.encode("utf-8", errors="strict")) > 4096:
        raise ValueError("persisted effect_result is malformed")
    try:
        decoded = json.loads(value, object_pairs_hook=_reject_duplicate_json_keys)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError, RecursionError):
        raise ValueError("persisted effect_result is malformed") from None
    if type(decoded) is not dict or _encode_effect_result(decoded) != value:
        raise ValueError("persisted effect_result is malformed")
    return MappingProxyType(decoded)


def _reject_duplicate_json_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate key")
        result[key] = value
    return result


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
    effect_ref: Optional[str] = None  # noqa: UP045 -- Python 3.9 is supported.
    effect_result: Optional[Mapping[str, object]] = None  # noqa: UP045 -- Python 3.9 is supported.


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
            ledger_sequence = int(
                connection.execute(
                    "SELECT COALESCE(MAX(ledger_sequence), 0) + 1 "
                    "FROM monitor_control_commands"
                ).fetchone()[0]
            )
            connection.execute(
                """
                INSERT INTO monitor_control_commands (
                    command_id, fingerprint, account_id, mode, scope, action, issuer, key_id,
                    reason, receipt_digest,
                    issued_at, expires_at, manual_resume_authorized, issuer_sequence,
                    envelope_digest, verification_digest, schema_version,
                    target_freeze_cause_id, effect_ref, status, executor_id, outcome, updated_at,
                    ledger_sequence
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, ?, NULL, ?, ?, ?)
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
                    durable_command.schema_version,
                    durable_command.target_freeze_cause_id,
                    status.value,
                    outcome,
                    now,
                    ledger_sequence,
                ),
            )
            return ClaimedControlCommand(durable_command, status, None)

    def claim_command(
        self,
        command_id: str,
        scope: str,
        executor_id: str,
        *,
        account_id: str,
        mode: str,
    ) -> Optional[ClaimedControlCommand]:  # noqa: UP045 -- Python 3.9 is supported.
        """Claim the exact next command, or recover its v2 UNKNOWN effect.

        A recovery stays bound to the executor that made the original claim.
        Commands are serialized per account/mode/scope so an uncertain earlier
        FREEZE cannot be replayed after a later RESUME has already completed.
        """

        for value in (command_id, scope, executor_id, account_id, mode):
            if type(value) is not str or not value.strip() or value != value.strip():
                raise ValueError("command and owner route values are required")
        now = self._clock()
        with self._transaction() as connection:
            self._expire_pending(connection, now)
            row = connection.execute(
                """
                SELECT * FROM monitor_control_commands
                WHERE command_id = ? AND scope = ? AND account_id = ? AND mode = ?
                    AND status IN (?, ?) AND issued_at <= ?
                    AND issuer_sequence IS NOT NULL
                    AND key_id IS NOT NULL AND key_id <> ''
                    AND envelope_digest IS NOT NULL AND envelope_digest <> ''
                    AND verification_digest IS NOT NULL AND verification_digest <> ''
                """,
                (
                    command_id,
                    scope,
                    account_id,
                    mode,
                    ControlStatus.PENDING.value,
                    ControlStatus.UNKNOWN.value,
                    now,
                ),
            ).fetchone()
            if row is None:
                return None
            status = ControlStatus(str(row["status"]))
            if status is ControlStatus.PENDING and float(row["expires_at"]) <= now:
                return None
            if status is ControlStatus.UNKNOWN and (
                row["executor_id"] != executor_id
                or int(row["schema_version"] or 1) < 2
            ):
                return None
            if self._has_earlier_unresolved(connection, row):
                return None
            updated = connection.execute(
                """
                UPDATE monitor_control_commands
                SET status = ?, executor_id = ?, outcome = NULL, effect_ref = NULL,
                    effect_result = NULL, updated_at = ?
                WHERE command_id = ? AND status = ?
                """,
                (
                    ControlStatus.CLAIMED.value,
                    executor_id,
                    now,
                    command_id,
                    status.value,
                ),
            )
            if updated.rowcount != 1:
                return None
            claimed = dict(row)
            claimed["status"] = ControlStatus.CLAIMED.value
            claimed["executor_id"] = executor_id
            claimed["outcome"] = None
            claimed["effect_ref"] = None
            claimed["effect_result"] = None
            return self._claimed_from_mapping(claimed)

    def claim_next(
        self,
        scope: str,
        executor_id: str,
        *,
        account_id: str | None = None,
        mode: str | None = None,
    ) -> Optional[ClaimedControlCommand]:  # noqa: UP045 -- Python 3.9 is supported.
        """Lease the oldest command or recover its exact v2 UNKNOWN effect.

        An unresolved older command blocks all later commands for the same
        account, mode and scope. An UNKNOWN v1 RESUME has no cause identity and
        is deliberately not replayable.
        """
        if (
            type(scope) is not str
            or not scope.strip()
            or type(executor_id) is not str
            or not executor_id.strip()
        ):
            raise ValueError("scope and executor_id are required")
        if (account_id is None) != (mode is None):
            raise ValueError("account_id and mode must be provided together")
        if account_id is not None and (
            type(account_id) is not str
            or not account_id.strip()
            or type(mode) is not str
            or not mode.strip()
        ):
            raise ValueError("account_id and mode must be non-empty strings")
        now = self._clock()
        with self._transaction() as connection:
            self._expire_pending(connection, now)
            row = connection.execute(
                """
                SELECT * FROM monitor_control_commands
                WHERE scope = ? AND status IN (?, ?) AND issued_at <= ?
                    AND issuer_sequence IS NOT NULL
                    AND account_id IS NOT NULL AND account_id <> ''
                    AND mode IS NOT NULL AND mode <> ''
                    AND key_id IS NOT NULL AND key_id <> ''
                    AND envelope_digest IS NOT NULL AND envelope_digest <> ''
                    AND verification_digest IS NOT NULL AND verification_digest <> ''
                    AND (? IS NULL OR account_id = ?)
                    AND (? IS NULL OR mode = ?)
                ORDER BY ledger_sequence ASC LIMIT 1
                """,
                (
                    scope,
                    ControlStatus.PENDING.value,
                    ControlStatus.UNKNOWN.value,
                    now,
                    account_id,
                    account_id,
                    mode,
                    mode,
                ),
            ).fetchone()
            if row is None:
                return None
            status = ControlStatus(str(row["status"]))
            if status is ControlStatus.UNKNOWN and (
                row["executor_id"] != executor_id
                or int(row["schema_version"] or 1) < 2
            ):
                return None
            if self._has_earlier_unresolved(connection, row):
                return None
            updated = connection.execute(
                """
                UPDATE monitor_control_commands
                SET status = ?, executor_id = ?, outcome = NULL, effect_ref = NULL,
                    effect_result = NULL, updated_at = ?
                WHERE command_id = ? AND status = ?
                """,
                (
                    ControlStatus.CLAIMED.value,
                    executor_id,
                    now,
                    row["command_id"],
                    status.value,
                ),
            )
            if updated.rowcount != 1:
                return None
            claimed = dict(row)
            claimed["status"] = ControlStatus.CLAIMED.value
            claimed["executor_id"] = executor_id
            claimed["outcome"] = None
            claimed["effect_ref"] = None
            claimed["effect_result"] = None
            return self._claimed_from_mapping(claimed)

    @staticmethod
    def _has_earlier_unresolved(
        connection: sqlite3.Connection, row: sqlite3.Row
    ) -> bool:
        earlier = connection.execute(
            """
            SELECT 1 FROM monitor_control_commands
            WHERE scope = ? AND account_id = ? AND mode = ?
                AND status IN (?, ?, ?)
                AND ledger_sequence < ?
            LIMIT 1
            """,
            (
                str(row["scope"]),
                str(row["account_id"]),
                str(row["mode"]),
                ControlStatus.PENDING.value,
                ControlStatus.CLAIMED.value,
                ControlStatus.UNKNOWN.value,
                int(row["ledger_sequence"]),
            ),
        ).fetchone()
        return earlier is not None

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
            elif int(row["schema_version"] or 1) >= 2:
                failure = ControlClaimError("typed owner outcome is required for schema v2")
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

    def finish_owner_outcome(
        self,
        command_id: str,
        executor_id: str,
        outcome: ControlOwnerOutcome,
        *,
        effect_ref: str | None = None,
        effect_result: Mapping[str, object] | None = None,
    ) -> None:
        """Persist a finite owner result, keeping uncertain effects UNKNOWN.

        This operation is for an owner that already claimed the command. An
        unknown result remains unresolved and cannot be converted into an
        acknowledgement by choosing a success boolean.
        """

        if (
            type(command_id) is not str
            or not command_id.strip()
            or type(executor_id) is not str
            or not executor_id.strip()
        ):
            raise ValueError("command_id and executor_id are required")
        if type(outcome) is not ControlOwnerOutcome:
            raise ValueError("a ControlOwnerOutcome is required")
        if effect_ref is not None and (
            type(effect_ref) is not str
            or not effect_ref
            or effect_ref != effect_ref.strip()
        ):
            raise ValueError("effect_ref must be trimmed non-empty text")
        encoded_effect_result = _encode_effect_result(effect_result)
        if outcome is ControlOwnerOutcome.UNKNOWN and (
            effect_ref is not None or encoded_effect_result is not None
        ):
            raise ValueError("unknown outcomes cannot assert an effect result")
        status = {
            ControlOwnerOutcome.APPLIED: ControlStatus.ACKNOWLEDGED,
            ControlOwnerOutcome.REJECTED: ControlStatus.REJECTED,
            ControlOwnerOutcome.UNKNOWN: ControlStatus.UNKNOWN,
        }[outcome]
        failure = None
        with self._transaction() as connection:
            now = self._clock()
            # A v2 UNKNOWN can be reclaimed after the original signed command
            # expires. Once that recovery claim is in flight, its final Risk
            # result must be allowed to persist even though the command's
            # original expires_at remains in the past. Keep expiring all
            # unrelated stale rows while excluding this exact finalization.
            self._expire_pending(connection, now, exclude_claimed_command_id=command_id)
            row = connection.execute(
                "SELECT * FROM monitor_control_commands WHERE command_id = ?", (command_id,)
            ).fetchone()
            if row is None:
                failure = ControlClaimError("command does not exist")
            elif row["executor_id"] != executor_id:
                failure = ControlClaimError("command is owned by another executor")
            elif (
                row["status"] == status.value
                and row["outcome"] == outcome.value
                and row["effect_ref"] == effect_ref
                and row["effect_result"] == encoded_effect_result
            ):
                return
            elif row["status"] != ControlStatus.CLAIMED.value:
                failure = ControlClaimError(
                    "command is not claimed; reconciliation may be required"
                )
            else:
                connection.execute(
                    """
                    UPDATE monitor_control_commands
                    SET status = ?, outcome = ?, effect_ref = ?, effect_result = ?, updated_at = ?
                    WHERE command_id = ?
                    """,
                    (
                        status.value,
                        outcome.value,
                        effect_ref,
                        encoded_effect_result,
                        now,
                        command_id,
                    ),
                )
        if failure is not None:
            raise failure

    def get(self, command_id: str) -> Optional[ClaimedControlCommand]:  # noqa: UP045 -- Python 3.9 is supported.
        """Return the durable command state without changing it."""
        with self._connection() as connection:
            row = connection.execute(
                "SELECT * FROM monitor_control_commands WHERE command_id = ?", (command_id,)
            ).fetchone()
        return self._claimed_from_row(row) if row is not None else None

    def _expire_pending(
        self,
        connection: sqlite3.Connection,
        now: float,
        *,
        exclude_claimed_command_id: str | None = None,
    ) -> None:
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
                AND (? IS NULL OR command_id <> ?)
            """,
            (
                ControlStatus.UNKNOWN.value,
                "claimed_command_reconciliation_required",
                now,
                ControlStatus.CLAIMED.value,
                now,
                exclude_claimed_command_id,
                exclude_claimed_command_id,
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
            schema_version=int(row.get("schema_version") or 1),
            target_freeze_cause_id=(
                str(row["target_freeze_cause_id"])
                if row.get("target_freeze_cause_id") is not None
                else None
            ),
        )
        executor_id = row.get("executor_id")
        return ClaimedControlCommand(
            command=command,
            status=ControlStatus(str(row["status"])),
            executor_id=str(executor_id) if executor_id is not None else None,
            outcome=str(row["outcome"]) if row.get("outcome") is not None else None,
            effect_ref=str(row["effect_ref"]) if row.get("effect_ref") is not None else None,
            effect_result=_decode_effect_result(row.get("effect_result")),
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
                    schema_version INTEGER NOT NULL DEFAULT 1,
                    target_freeze_cause_id TEXT,
                    effect_ref TEXT,
                    effect_result TEXT,
                    ledger_sequence INTEGER,
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
                "schema_version": "INTEGER",
                "target_freeze_cause_id": "TEXT",
                "effect_ref": "TEXT",
                "effect_result": "TEXT",
                "ledger_sequence": "INTEGER",
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
                "UPDATE monitor_control_commands SET schema_version = 1 WHERE schema_version IS NULL"
            )
            connection.execute(
                "UPDATE monitor_control_commands SET ledger_sequence = rowid "
                "WHERE ledger_sequence IS NULL"
            )
            connection.execute(
                "CREATE UNIQUE INDEX IF NOT EXISTS idx_monitor_control_ledger_sequence "
                "ON monitor_control_commands(ledger_sequence)"
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
                UPDATE monitor_control_commands
                SET status = ?, outcome = ?
                WHERE status IN (?, ?) AND action = ?
                    AND (schema_version < 2 OR target_freeze_cause_id IS NULL
                        OR target_freeze_cause_id = '')
                """,
                (
                    ControlStatus.UNKNOWN.value,
                    "legacy_resume_target_cause_unavailable",
                    ControlStatus.PENDING.value,
                    ControlStatus.CLAIMED.value,
                    ControlAction.RESUME.value,
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

    @property
    def ledger(self) -> DurableControlLedger:
        """Return the exact durable ledger owned by this ingress composition."""

        return self._ledger

    def submit(
        self,
        envelope: ControlCommandEnvelope,
        *,
        binding: ControlCommandBinding | None = None,
    ) -> ClaimedControlCommand:
        """Authenticate, normalize and persist exactly one control command."""

        if type(envelope) is not ControlCommandEnvelope:
            raise ControlAuthorizationError("control_envelope_required")
        if binding is not None and type(binding) is not ControlCommandBinding:
            raise ControlAuthorizationError("control_binding_invalid")
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
                schema_version=verified.schema_version,
                target_freeze_cause_id=verified.target_freeze_cause_id,
            )
        except Exception:
            raise ControlAuthorizationError("control_verification_failed") from None

        if verified.envelope_digest != envelope.digest:
            raise ControlAuthorizationError("verified_envelope_digest_mismatch")
        if binding is not None and (
            verified.issuer != binding.issuer
            or verified.account_id != binding.account_id
            or verified.mode != binding.mode
            or verified.scope != binding.scope
            or verified.action not in binding.actions
        ):
            raise ControlAuthorizationError("verified_control_binding_mismatch")

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
            schema_version=verified.schema_version,
            target_freeze_cause_id=verified.target_freeze_cause_id,
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
    "ControlCommandBinding",
    "ControlClaimError",
    "ControlCommand",
    "ControlCommandEnvelope",
    "ControlCommandVerifier",
    "ControlConflictError",
    "ControlIngress",
    "ControlLedgerError",
    "ControlOwnerOutcome",
    "ControlSequenceError",
    "ControlStatus",
    "DurableControlLedger",
    "VerifiedControlCommand",
    "monitor_freeze_cause_id",
]
