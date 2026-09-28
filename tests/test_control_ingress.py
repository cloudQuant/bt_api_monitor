"""Offline contract tests for the injected HMAC control verifier."""

from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import replace

import pytest

from bt_api_monitor import (
    CONTROL_COMMAND_HMAC_DOMAIN,
    ControlAction,
    ControlAuthorizationError,
    ControlCommandEnvelope,
    ControlIngress,
    ControlIssuerPolicy,
    ControlScopeGrant,
    ControlSequenceError,
    ControlStatus,
    DurableControlLedger,
    HmacControlCommandVerifier,
    HmacControlKey,
)

NOW = 1_700_000_000.0
KEY_ID = "unit-test-key"
ISSUER = "offline-operator"
ACCOUNT_ID = "paper-account-17"
MODE = "simulation"
SCOPE = "account:17"
RECEIPT = "a" * 64
SECRET = b"offline-test-only-secret-32-bytes!"


class MutableClock:
    def __init__(self, value: float = NOW) -> None:
        self.value = value

    def __call__(self) -> float:
        return self.value


class FakeKeyResolver:
    def __init__(self, key: HmacControlKey | None) -> None:
        self.key = key

    def resolve(self, key_id: str) -> HmacControlKey | None:
        return self.key if self.key is not None and self.key.key_id == key_id else None


class FakePolicyResolver:
    def __init__(self, policy: ControlIssuerPolicy | None) -> None:
        self.policy = policy

    def resolve(self, issuer: str) -> ControlIssuerPolicy | None:
        return self.policy if self.policy is not None and self.policy.issuer == issuer else None


def make_key() -> HmacControlKey:
    return HmacControlKey(
        key_id=KEY_ID,
        issuer=ISSUER,
        secret=SECRET,
        not_before_utc=NOW - 100,
        expires_at_utc=NOW + 100,
    )


def make_policy(
    *,
    actions: tuple[ControlAction, ...] = (ControlAction.FREEZE,),
    account_id: str = ACCOUNT_ID,
    mode: str = MODE,
    scope: str = SCOPE,
    receipt_digests: tuple[str, ...] = (RECEIPT,),
    manual_resume_allowed: bool = False,
) -> ControlIssuerPolicy:
    return ControlIssuerPolicy(
        issuer=ISSUER,
        policy_id="offline-test-policy-v1",
        grants=(
            ControlScopeGrant(
                account_id=account_id,
                mode=mode,
                scope=scope,
                actions=actions,
                receipt_digests=receipt_digests,
                manual_resume_allowed=manual_resume_allowed,
            ),
        ),
        not_before_utc=NOW - 100,
        expires_at_utc=NOW + 100,
    )


def verifier(
    *,
    key: HmacControlKey | None = None,
    policy: ControlIssuerPolicy | None = None,
) -> HmacControlCommandVerifier:
    return HmacControlCommandVerifier(
        FakeKeyResolver(make_key() if key is None else key),
        FakePolicyResolver(make_policy() if policy is None else policy),
        max_command_ttl_seconds=60,
    )


def signed_envelope(**overrides: object) -> ControlCommandEnvelope:
    claims: dict[str, object] = {
        "schema_version": 1,
        "key_id": KEY_ID,
        "issuer": ISSUER,
        "command_id": "freeze-001",
        "account_id": ACCOUNT_ID,
        "mode": MODE,
        "scope": SCOPE,
        "action": ControlAction.FREEZE.value,
        "reason": "approved offline test",
        "receipt_digest": RECEIPT,
        "issued_at": NOW - 1.0,
        "expires_at": NOW + 20.0,
        "issuer_sequence": 1,
        "manual_resume_authorized": False,
    }
    claims.update(overrides)
    payload = json.dumps(
        claims,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")
    encoded_key_id = KEY_ID.encode("ascii")
    mac_input = (
        CONTROL_COMMAND_HMAC_DOMAIN
        + len(encoded_key_id).to_bytes(2, "big")
        + encoded_key_id
        + payload
    )
    signature = hmac.new(SECRET, mac_input, hashlib.sha256).digest()
    return ControlCommandEnvelope(payload=payload, signature=signature)


def test_hmac_verifier_accepts_exact_signed_scope_and_persists_binding(tmp_path) -> None:
    clock = MutableClock()
    ledger = DurableControlLedger(tmp_path / "monitor.db", clock=clock)
    ingress = ControlIngress(ledger, verifier(), clock=clock)

    accepted = ingress.submit(signed_envelope())
    assert accepted.status is ControlStatus.PENDING
    assert accepted.command.account_id == ACCOUNT_ID
    assert accepted.command.mode == MODE
    assert accepted.command.key_id == KEY_ID
    assert ledger.claim_next(SCOPE, "offline-test-owner").command == accepted.command


def test_hmac_verifier_fails_closed_without_trusted_key_or_policy(tmp_path) -> None:
    clock = MutableClock()
    ledger = DurableControlLedger(tmp_path / "monitor.db", clock=clock)
    signed = signed_envelope()
    ingress = ControlIngress(
        ledger,
        HmacControlCommandVerifier(max_command_ttl_seconds=60),
        clock=clock,
    )
    with pytest.raises(ControlAuthorizationError, match="verification failed"):
        ingress.submit(signed)
    assert ledger.get("freeze-001") is None

    no_key = HmacControlCommandVerifier(FakeKeyResolver(None), FakePolicyResolver(make_policy()))
    with pytest.raises(ControlAuthorizationError):
        no_key.verify(signed, now_utc=NOW)


@pytest.mark.parametrize(
    "field, replacement",
    [
        ("command_id", "freeze-for-another-command"),
        ("account_id", "live-account-17"),
        ("mode", "live"),
        ("scope", "account:other"),
        ("action", ControlAction.DRAIN.value),
        ("receipt_digest", "b" * 64),
    ],
)
def test_signed_payload_tampering_is_rejected(field: str, replacement: str) -> None:
    original = signed_envelope()
    changed = (
        original.payload.replace(
            b'"command_id":"freeze-001"',
            b'"command_id":"freeze-for-another-command"',
        )
        if field == "command_id"
        else original.payload
    )
    if field != "command_id":
        claims = json.loads(original.payload)
        claims[field] = replacement
        changed = json.dumps(
            claims, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode("utf-8")
    with pytest.raises(ControlAuthorizationError):
        verifier().verify(
            ControlCommandEnvelope(payload=changed, signature=original.signature),
            now_utc=NOW,
        )


@pytest.mark.parametrize(
    "field, value",
    [
        ("account_id", "other-account"),
        ("mode", "live"),
        ("scope", "account:other"),
    ],
)
def test_policy_requires_exact_account_mode_and_scope(field: str, value: str) -> None:
    with pytest.raises(ControlAuthorizationError, match="verification failed"):
        ControlIngress(
            DurableControlLedger(":memory:"),
            verifier(policy=make_policy(**{field: value})),
            clock=MutableClock(),
        ).submit(signed_envelope())


def test_policy_rejects_wildcard_scopes() -> None:
    with pytest.raises(ValueError, match="wildcard"):
        make_policy(scope="account:*")


def test_issuer_action_receipt_and_resume_permissions_are_exact() -> None:
    with pytest.raises(ControlAuthorizationError, match="verification failed"):
        ControlIngress(
            DurableControlLedger(":memory:"),
            verifier(policy=make_policy(actions=(ControlAction.DRAIN,))),
            clock=MutableClock(),
        ).submit(signed_envelope())

    with pytest.raises(ControlAuthorizationError, match="verification failed"):
        ControlIngress(
            DurableControlLedger(":memory:"),
            verifier(policy=make_policy(receipt_digests=("b" * 64,))),
            clock=MutableClock(),
        ).submit(signed_envelope())

    resume = signed_envelope(
        command_id="resume-001",
        action=ControlAction.RESUME.value,
        manual_resume_authorized=True,
        issuer_sequence=2,
    )
    resume_policy = make_policy(
        actions=(ControlAction.FREEZE, ControlAction.RESUME),
        manual_resume_allowed=False,
    )
    with pytest.raises(ControlAuthorizationError, match="verification failed"):
        ControlIngress(
            DurableControlLedger(":memory:"),
            verifier(policy=resume_policy),
            clock=MutableClock(),
        ).submit(resume)


@pytest.mark.parametrize(
    "claims",
    [
        {"issued_at": NOW - 20.0, "expires_at": NOW - 1.0},
        {"issued_at": NOW + 1.0, "expires_at": NOW + 20.0},
        {"issued_at": NOW - 100.0, "expires_at": NOW + 20.0},
    ],
)
def test_expired_future_and_overlong_commands_are_rejected(claims: dict[str, float]) -> None:
    with pytest.raises(ControlAuthorizationError):
        verifier().verify(signed_envelope(**claims), now_utc=NOW)


def test_revoked_key_and_issuer_mismatch_are_rejected() -> None:
    with pytest.raises(ControlAuthorizationError):
        verifier(key=replace(make_key(), revoked=True)).verify(signed_envelope(), now_utc=NOW)

    with pytest.raises(ControlAuthorizationError):
        verifier(key=replace(make_key(), issuer="different-issuer")).verify(
            signed_envelope(), now_utc=NOW
        )

    mismatched_policy = replace(make_policy(), revoked=True)
    with pytest.raises(ControlAuthorizationError):
        verifier(policy=mismatched_policy).verify(signed_envelope(), now_utc=NOW)

    with pytest.raises(ControlAuthorizationError):
        verifier(key=replace(make_key(), expires_at_utc=NOW - 1)).verify(
            signed_envelope(), now_utc=NOW
        )

    with pytest.raises(ControlAuthorizationError):
        verifier(policy=replace(make_policy(), expires_at_utc=NOW - 1)).verify(
            signed_envelope(), now_utc=NOW
        )


def test_issuer_sequence_replay_is_rejected_by_durable_ledger(tmp_path) -> None:
    clock = MutableClock()
    ledger = DurableControlLedger(tmp_path / "monitor.db", clock=clock)
    ingress = ControlIngress(ledger, verifier(), clock=clock)
    ingress.submit(signed_envelope())
    replay = signed_envelope(command_id="freeze-002", issuer_sequence=1)
    with pytest.raises(ControlSequenceError, match="replayed or out of order"):
        ingress.submit(replay)
    assert ledger.get("freeze-002") is None


def test_canonical_json_and_signature_bytes_are_required() -> None:
    valid = signed_envelope()
    with pytest.raises(ControlAuthorizationError):
        verifier().verify(
            ControlCommandEnvelope(
                payload=b" " + valid.payload,
                signature=valid.signature,
            ),
            now_utc=NOW,
        )
    with pytest.raises(ControlAuthorizationError):
        verifier().verify(
            ControlCommandEnvelope(
                payload=valid.payload,
                signature=valid.signature[:-1] + bytes([valid.signature[-1] ^ 1]),
            ),
            now_utc=NOW,
        )
