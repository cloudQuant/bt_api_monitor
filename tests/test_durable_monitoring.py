"""Tests for the no-provider-I/O monitor durability primitives."""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier

import pytest

from bt_api_monitor import (
    CheckpointError,
    ClaimedControlCommand,
    ControlAction,
    ControlAuthorizationError,
    ControlClaimError,
    ControlCommand,
    ControlCommandEnvelope,
    ControlConflictError,
    ControlIngress,
    ControlSequenceError,
    ControlStatus,
    DurableControlLedger,
    DurableOutbox,
    DurableOutboxConsumer,
    OutboxConflictError,
    OutboxDeliveryError,
    OutboxEvent,
    VerifiedControlCommand,
)


class MutableClock:
    def __init__(self, value: float = 1_700_000_000.0) -> None:
        self.value = value

    def __call__(self) -> float:
        return self.value


def event(event_id: str, scope: str = "account:1", data=None) -> OutboxEvent:
    return OutboxEvent(
        event_id=event_id,
        scope=scope,
        event_type="risk.decision",
        data=data if data is not None else {"decision": "allow", "notional": "10"},
        occurred_at=1_700_000_000.0,
    )


def command(
    command_id: str,
    action: ControlAction = ControlAction.FREEZE,
    manual_resume_authorized: bool = False,
    expires_at: float = 1_700_000_010.0,
) -> ControlCommand:
    return ControlCommand(
        command_id=command_id,
        account_id="account-id-1",
        mode="simulation",
        scope="account:1",
        action=action,
        issuer="monitor",
        key_id="unit-test-key",
        reason="unit test",
        receipt_digest="a" * 64,
        issued_at=1_700_000_000.0,
        expires_at=expires_at,
        manual_resume_authorized=manual_resume_authorized,
    )


def envelope(value: ControlCommand) -> ControlCommandEnvelope:
    payload = json.dumps(
        {
            "action": value.action.value,
            "command_id": value.command_id,
            "expires_at": value.expires_at,
            "issued_at": value.issued_at,
            "reason": value.reason,
            "scope": value.scope,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return ControlCommandEnvelope(payload=payload, signature=b"offline-test-signature")


def verified_command(
    value: ControlCommand,
    signed: ControlCommandEnvelope,
    issuer_sequence: int = 1,
    **overrides,
) -> VerifiedControlCommand:
    facts = {
        "command_id": value.command_id,
        "account_id": value.account_id,
        "mode": value.mode,
        "scope": value.scope,
        "action": value.action,
        "issuer": value.issuer,
        "key_id": value.key_id,
        "reason": value.reason,
        "receipt_digest": value.receipt_digest,
        "issued_at": value.issued_at,
        "expires_at": value.expires_at,
        "issuer_sequence": issuer_sequence,
        "manual_resume_authorized": value.manual_resume_authorized,
        "envelope_digest": signed.digest,
        "verification_digest": hashlib.sha256(
            (value.command_id + ":" + str(issuer_sequence)).encode("ascii")
        ).hexdigest(),
    }
    facts.update(overrides)
    return VerifiedControlCommand(**facts)


class FakeControlVerifier:
    """Offline-only verifier fake; it does not establish deployment authority."""

    def __init__(self, result, error: Exception | None = None) -> None:
        self.result = result
        self.error = error
        self.calls: list[tuple[ControlCommandEnvelope, float]] = []

    def verify(self, signed: ControlCommandEnvelope, *, now_utc: float):
        self.calls.append((signed, now_utc))
        if self.error is not None:
            raise self.error
        return self.result


def submit(
    ledger: DurableControlLedger,
    value: ControlCommand,
    issuer_sequence: int = 1,
    *,
    verified_overrides=None,
    verifier=None,
):
    signed = envelope(value)
    if verifier is None:
        result = verified_command(value, signed, issuer_sequence, **(verified_overrides or {}))
        verifier = FakeControlVerifier(result)
    return ControlIngress(ledger, verifier).submit(signed)


def test_outbox_idempotency_checkpoint_and_cross_instance_replay(tmp_path) -> None:
    database = tmp_path / "monitor.db"
    writer = DurableOutbox(database)
    reader = DurableOutbox(database)
    first = writer.append(event("event-1"))
    duplicate = writer.append(event("event-1"))
    second = writer.append(event("event-2"))
    assert duplicate.sequence == first.sequence

    pending = reader.read_pending("consumer", "account:1")
    assert [item.sequence for item in pending] == [first.sequence, second.sequence]
    with pytest.raises(CheckpointError):
        reader.acknowledge("consumer", "account:1", second.sequence)
    reader.acknowledge("consumer", "account:1", first.sequence)
    reader.acknowledge("consumer", "account:1", second.sequence)
    assert reader.checkpoint("consumer", "account:1") == second.sequence
    assert reader.read_pending("consumer", "account:1") == []


def test_outbox_rejects_conflicting_event_or_sensitive_data(tmp_path) -> None:
    outbox = DurableOutbox(tmp_path / "monitor.db")
    outbox.append(event("event-1"))
    with pytest.raises(OutboxConflictError):
        outbox.append(event("event-1", data={"decision": "deny"}))
    with pytest.raises(ValueError, match="redacted"):
        event("event-secret", data={"api_token": "never-store-this"})


def test_outbox_consumer_checkpoints_only_after_delivery_and_recovers_cursor(tmp_path) -> None:
    database = tmp_path / "monitor.db"
    writer = DurableOutbox(database)
    first = writer.append(event("consume-1"))
    second = writer.append(event("consume-2"))
    delivered: list[tuple[int, str]] = []

    consumer = DurableOutboxConsumer(
        DurableOutbox(database),
        "monitor.sink",
        "account:1",
        lambda item: delivered.append((item.sequence, item.event.event_id)),
    )
    assert [item.sequence for item in consumer.consume(limit=1)] == [first.sequence]
    assert consumer.checkpoint() == first.sequence

    # A replacement process with the same reviewed consumer identity resumes
    # from the durable cursor rather than replaying acknowledged facts.
    replacement = DurableOutboxConsumer(
        DurableOutbox(database),
        "monitor.sink",
        "account:1",
        lambda item: delivered.append((item.sequence, item.event.event_id)),
    )
    assert [item.sequence for item in replacement.consume()] == [second.sequence]
    assert replacement.checkpoint() == second.sequence
    assert delivered == [(first.sequence, "consume-1"), (second.sequence, "consume-2")]


def test_outbox_consumer_replays_after_sink_or_checkpoint_failure(tmp_path, monkeypatch) -> None:
    database = tmp_path / "monitor.db"
    outbox = DurableOutbox(database)
    item = outbox.append(event("consume-retry"))
    calls: list[str] = []

    def unavailable(entry) -> None:
        calls.append(entry.event.event_id)
        raise OSError("monitor sink unavailable")

    consumer = DurableOutboxConsumer(outbox, "monitor.sink", "account:1", unavailable)
    with pytest.raises(OutboxDeliveryError, match="remains pending"):
        consumer.consume()
    assert consumer.checkpoint() == 0

    acknowledged_calls: list[str] = []
    recovering = DurableOutboxConsumer(
        outbox,
        "monitor.sink",
        "account:1",
        lambda entry: acknowledged_calls.append(entry.event.event_id),
    )
    original_acknowledge = outbox.acknowledge

    def lose_checkpoint(*args, **kwargs) -> None:
        raise OSError("database unavailable after sink accepted the fact")

    monkeypatch.setattr(outbox, "acknowledge", lose_checkpoint)
    with pytest.raises(OutboxDeliveryError, match="not checkpointed"):
        recovering.consume()
    assert recovering.checkpoint() == 0
    assert acknowledged_calls == ["consume-retry"]

    monkeypatch.setattr(outbox, "acknowledge", original_acknowledge)
    assert [entry.sequence for entry in recovering.consume()] == [item.sequence]
    assert recovering.checkpoint() == item.sequence
    # The sink sees at-least-once delivery after the checkpoint failure; only a
    # durable acknowledgement can suppress the next replay.
    assert calls == ["consume-retry"]
    assert acknowledged_calls == ["consume-retry", "consume-retry"]


def test_control_ledger_is_idempotent_and_single_executor(tmp_path) -> None:
    ledger = DurableControlLedger(tmp_path / "monitor.db", clock=MutableClock())
    submitted = submit(ledger, command("freeze-1"))
    repeated = submit(ledger, command("freeze-1"))
    assert submitted.status is ControlStatus.PENDING
    assert repeated.command.command_id == "freeze-1"

    claimed = ledger.claim_next("account:1", "owner-a")
    assert isinstance(claimed, ClaimedControlCommand)
    assert claimed.executor_id == "owner-a"
    assert ledger.claim_next("account:1", "owner-b") is None
    with pytest.raises(ControlClaimError):
        ledger.finish("freeze-1", "owner-b", True, "should not happen")
    ledger.finish("freeze-1", "owner-a", True, "freeze completed")
    assert ledger.get("freeze-1").status is ControlStatus.ACKNOWLEDGED


def test_unverified_command_and_missing_verifier_fail_before_ledger_write(tmp_path) -> None:
    ledger = DurableControlLedger(tmp_path / "monitor.db", clock=MutableClock())
    caller_claims = command("caller-asserted", action=ControlAction.FREEZE)
    signed = envelope(caller_claims)

    with pytest.raises(ControlAuthorizationError, match="verified control ingress"):
        ledger.submit(caller_claims)
    with pytest.raises(ControlAuthorizationError, match="trusted control verifier"):
        ControlIngress(ledger).submit(signed)

    assert ledger.get(caller_claims.command_id) is None


def test_verifier_error_or_envelope_mismatch_fails_before_ledger_write(tmp_path) -> None:
    ledger = DurableControlLedger(tmp_path / "monitor.db", clock=MutableClock())
    caller_claims = command("bad-verification")
    signed = envelope(caller_claims)
    valid_facts = verified_command(caller_claims, signed)

    verifier = FakeControlVerifier(valid_facts, error=RuntimeError("secret verifier detail"))
    with pytest.raises(ControlAuthorizationError, match="verification failed"):
        ControlIngress(ledger, verifier).submit(signed)
    assert ledger.get(caller_claims.command_id) is None

    wrong_binding = verified_command(caller_claims, signed, envelope_digest="b" * 64)
    with pytest.raises(ControlAuthorizationError, match="envelope digest mismatch"):
        ControlIngress(ledger, FakeControlVerifier(wrong_binding)).submit(signed)
    assert ledger.get(caller_claims.command_id) is None


def test_resume_authority_must_come_from_revalidated_verifier_output(tmp_path) -> None:
    ledger = DurableControlLedger(tmp_path / "monitor.db", clock=MutableClock())
    caller_claims = command(
        "resume-from-claim", action=ControlAction.RESUME, manual_resume_authorized=True
    )
    signed = envelope(caller_claims)
    verifier_output = verified_command(caller_claims, signed)
    # Simulate an invalid/mutated result from an incorrectly wired verifier.
    object.__setattr__(verifier_output, "manual_resume_authorized", False)

    with pytest.raises(ControlAuthorizationError, match="verification failed"):
        ControlIngress(ledger, FakeControlVerifier(verifier_output)).submit(signed)
    assert ledger.get(caller_claims.command_id) is None


def test_issuer_sequence_is_durable_strict_and_exact_retry_is_idempotent(tmp_path) -> None:
    ledger = DurableControlLedger(tmp_path / "monitor.db", clock=MutableClock())
    first = command("sequence-10")
    assert submit(ledger, first, issuer_sequence=10).status is ControlStatus.PENDING
    assert submit(ledger, first, issuer_sequence=10).command.command_id == "sequence-10"

    with pytest.raises(ControlSequenceError, match="replayed or out of order"):
        submit(ledger, command("sequence-gap"), issuer_sequence=12)
    with pytest.raises(ControlSequenceError, match="replayed or out of order"):
        submit(ledger, command("sequence-replay"), issuer_sequence=10)

    assert (
        submit(ledger, command("sequence-11"), issuer_sequence=11).status is ControlStatus.PENDING
    )
    assert ledger.claim_next("account:1", "owner").command.command_id == "sequence-10"


def test_legacy_unverified_pending_commands_are_quarantined_on_schema_upgrade(tmp_path) -> None:
    database = tmp_path / "monitor.db"
    with sqlite3.connect(database) as connection:
        connection.execute(
            """
            CREATE TABLE monitor_control_commands (
                command_id TEXT PRIMARY KEY, fingerprint TEXT NOT NULL, scope TEXT NOT NULL,
                action TEXT NOT NULL, issuer TEXT NOT NULL, reason TEXT NOT NULL,
                receipt_digest TEXT NOT NULL, issued_at REAL NOT NULL, expires_at REAL NOT NULL,
                manual_resume_authorized INTEGER NOT NULL, status TEXT NOT NULL,
                executor_id TEXT, outcome TEXT, updated_at REAL NOT NULL
            )
            """
        )
        connection.execute(
            """INSERT INTO monitor_control_commands VALUES
               ('legacy', 'old-fingerprint', 'account:1', 'freeze', 'caller', 'legacy',
                'caller-receipt', 1700000000, 1700000100, 0, 'pending', NULL, NULL, 1700000000)"""
        )

    ledger = DurableControlLedger(database, clock=MutableClock())

    assert ledger.get("legacy").status is ControlStatus.UNKNOWN
    assert (
        ledger.get("legacy").outcome == "legacy_unverified_control_command_requires_reconciliation"
    )
    assert ledger.claim_next("account:1", "owner") is None


def test_resume_requires_manual_authorization_and_commands_expire(tmp_path) -> None:
    clock = MutableClock()
    ledger = DurableControlLedger(tmp_path / "monitor.db", clock=clock)
    with pytest.raises(ValueError, match="manual authorization"):
        command("resume-unsafe", action=ControlAction.RESUME)
    submit(ledger, command("resume-safe", ControlAction.RESUME, manual_resume_authorized=True))
    assert ledger.claim_next("account:1", "owner").command.action is ControlAction.RESUME

    submit(ledger, command("freeze-expired", expires_at=1_700_000_002.0), issuer_sequence=2)
    clock.value += 3.0
    assert ledger.claim_next("account:1", "owner") is None
    assert ledger.get("freeze-expired").status is ControlStatus.EXPIRED


def test_control_command_id_conflict_is_rejected(tmp_path) -> None:
    ledger = DurableControlLedger(tmp_path / "monitor.db", clock=MutableClock())
    submit(ledger, command("freeze-1"))
    conflicting = ControlCommand(
        command_id="freeze-1",
        account_id="account-id-1",
        mode="simulation",
        scope="account:1",
        action=ControlAction.DRAIN,
        issuer="monitor",
        key_id="unit-test-key",
        reason="different action",
        receipt_digest="a" * 64,
        issued_at=1_700_000_000.0,
        expires_at=1_700_000_010.0,
    )
    with pytest.raises(ControlConflictError):
        submit(ledger, conflicting, issuer_sequence=2)


def test_outbox_captures_immutable_data_before_persistence(tmp_path):
    data = {"facts": [{"quantity": "1"}]}
    fact = event("immutable", data=data)
    fingerprint = fact.fingerprint
    data["facts"][0]["quantity"] = "999"
    data["password"] = "must-not-enter-outbox"
    with pytest.raises(TypeError):
        fact.data["facts"][0]["quantity"] = "888"
    assert fact.fingerprint == fingerprint
    outbox = DurableOutbox(tmp_path / "monitor.db")
    outbox.append(fact)
    restored = outbox.read_pending("consumer", "account:1")[0].event
    assert restored.data["facts"][0]["quantity"] == "1"
    assert "password" not in restored.data


def test_outbox_checks_secrets_in_tuple_and_rejects_nonfinite_json():
    with pytest.raises(ValueError, match="redacted"):
        event("tuple-secret", data={"facts": ({"api_key": "never-store"},)})
    with pytest.raises(ValueError, match="serializable"):
        event("nonfinite", data={"quantity": float("nan")})


@pytest.mark.parametrize("value", [float("nan"), float("inf"), True])
def test_control_deadline_must_be_finite(value):
    with pytest.raises(ValueError):
        command("invalid-time", expires_at=value)


def test_claimed_timeout_is_unknown_and_survives_rejected_late_ack(tmp_path):
    clock = MutableClock()
    database = tmp_path / "monitor.db"
    ledger = DurableControlLedger(database, clock=clock)
    submit(ledger, command("uncertain-freeze"))
    ledger.claim_next("account:1", "owner")
    clock.value += 11
    with pytest.raises(ControlClaimError, match="reconciliation"):
        ledger.finish("uncertain-freeze", "owner", True, "late local response")
    restored = DurableControlLedger(database, clock=clock)
    result = restored.get("uncertain-freeze")
    assert result.status is ControlStatus.UNKNOWN
    assert result.outcome == "claimed_command_reconciliation_required"
    assert restored.claim_next("account:1", "another-owner") is None


def test_control_ack_retry_is_idempotent_but_conflicting_result_is_rejected(tmp_path):
    ledger = DurableControlLedger(tmp_path / "monitor.db", clock=MutableClock())
    submit(ledger, command("freeze"))
    ledger.claim_next("account:1", "owner")
    ledger.finish("freeze", "owner", True, "freeze persisted")
    ledger.finish("freeze", "owner", True, "freeze persisted")
    with pytest.raises(ControlClaimError):
        ledger.finish("freeze", "owner", False, "conflicting result")
    assert ledger.get("freeze").status is ControlStatus.ACKNOWLEDGED
    assert ledger.get("freeze").outcome == "freeze persisted"


def test_expired_submit_and_future_issue_cannot_be_claimed(tmp_path):
    clock = MutableClock(1_700_000_011.0)
    ledger = DurableControlLedger(tmp_path / "monitor.db", clock=clock)
    assert submit(ledger, command("already-expired")).status is ControlStatus.EXPIRED
    assert ledger.get("already-expired").outcome == "command_ttl_elapsed"
    clock.value = 1_699_999_999.0
    assert submit(ledger, command("future"), issuer_sequence=2).status is ControlStatus.PENDING
    assert ledger.claim_next("account:1", "owner") is None


def test_concurrent_control_owners_receive_only_one_claim(tmp_path):
    database = tmp_path / "monitor.db"
    ledgers = [DurableControlLedger(database, clock=MutableClock()) for _ in range(2)]
    submit(ledgers[0], command("single-owner"))
    barrier = Barrier(2)

    def claim(index):
        barrier.wait(timeout=10)
        return ledgers[index].claim_next("account:1", "owner-" + str(index))

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(claim, range(2)))
    assert sum(result is not None for result in results) == 1


def test_scoped_checkpoint_handles_interleaved_accounts(tmp_path):
    outbox = DurableOutbox(tmp_path / "monitor.db")
    first = outbox.append(event("a1", scope="a"))
    foreign = outbox.append(event("b1", scope="b"))
    second = outbox.append(event("a2", scope="a"))
    outbox.acknowledge("consumer", "a", first.sequence)
    with pytest.raises(CheckpointError):
        outbox.acknowledge("consumer", "a", foreign.sequence)
    outbox.acknowledge("consumer", "a", second.sequence)
    assert [entry.event.event_id for entry in outbox.read_pending("consumer", "b")] == ["b1"]


def test_process_exit_preserves_outbox_fact_and_unresolved_control_claim(tmp_path):
    database = tmp_path / "monitor.db"
    program = """
import os
import socket
import sys
def no_network(*args, **kwargs):
    raise AssertionError('monitor worker attempted external I/O')
socket.create_connection = no_network
socket.socket.connect = no_network
from bt_api_monitor import (
    ControlAction, ControlCommand, ControlCommandEnvelope, ControlIngress,
    DurableControlLedger, DurableOutbox, OutboxEvent, VerifiedControlCommand,
)
outbox = DurableOutbox(sys.argv[1])
outbox.append(OutboxEvent('before-crash', 'account:1', 'control.requested', {'command': 'freeze'}, 1700000000.0))
ledger = DurableControlLedger(sys.argv[1], clock=lambda: 1700000000.0)
command = ControlCommand('crashed', 'account-id-1', 'simulation', 'account:1', ControlAction.FREEZE, 'monitor', 'unit-test-key', 'test', 'a' * 64, 1700000000.0, 1700000010.0)
envelope = ControlCommandEnvelope(command.fingerprint.encode(), b'offline-test-signature')
facts = VerifiedControlCommand(
    command.command_id, command.account_id, command.mode, command.scope, command.action,
    command.issuer, command.key_id, command.reason, command.receipt_digest,
    command.issued_at, command.expires_at, 1, False,
    envelope.digest, 'b' * 64,
)
class FakeVerifier:
    def verify(self, signed, *, now_utc):
        return facts
ControlIngress(ledger, FakeVerifier()).submit(envelope)
assert ledger.claim_next('account:1', 'owner') is not None
os._exit(7)
"""
    environment = os.environ.copy()
    environment["PYTHONPATH"] = os.pathsep.join(sys.path)
    result = subprocess.run(  # noqa: S603 -- fixed crash worker, no provider or shell.
        [sys.executable, "-c", program, str(database)],
        env=environment,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert result.returncode == 7, result.stderr
    restored = DurableControlLedger(database, clock=MutableClock(1_700_000_011.0))
    assert restored.claim_next("account:1", "another-owner") is None
    assert restored.get("crashed").status is ControlStatus.UNKNOWN
    facts = DurableOutbox(database).read_pending("consumer", "account:1")
    assert [fact.event.event_id for fact in facts] == ["before-crash"]
