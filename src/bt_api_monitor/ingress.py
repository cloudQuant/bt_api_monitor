"""Offline-verifiable HMAC control ingress contracts.

This module implements cryptographic envelope verification, but intentionally
ships no keys, issuer policy, resolver implementation, or provider integration.
Deployments must inject reviewed, trusted resolvers before this verifier can
authorize a command.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import math
import re
from dataclasses import dataclass, field
from typing import Protocol, TypedDict

from .control import (
    ControlAction,
    ControlAuthorizationError,
    ControlCommandEnvelope,
    VerifiedControlCommand,
)

CONTROL_COMMAND_HMAC_DOMAIN = b"bt-api-monitor.control-command.hmac.v1\0"
_VERIFICATION_RECEIPT_DOMAIN = b"bt-api-monitor.control-command.verified.v1\0"
_PAYLOAD_FIELDS = frozenset(
    {
        "schema_version",
        "key_id",
        "issuer",
        "command_id",
        "account_id",
        "mode",
        "scope",
        "action",
        "reason",
        "receipt_digest",
        "issued_at",
        "expires_at",
        "issuer_sequence",
        "manual_resume_authorized",
    }
)
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_KEY_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")


class _NormalizedClaims(TypedDict):
    schema_version: int
    key_id: str
    issuer: str
    command_id: str
    account_id: str
    mode: str
    scope: str
    action: ControlAction
    reason: str
    receipt_digest: str
    issued_at: float
    expires_at: float
    issuer_sequence: int
    manual_resume_authorized: bool


class ControlKeyResolver(Protocol):
    """Resolve a key from a trusted local key store, including revocation state."""

    def resolve(self, key_id: str) -> HmacControlKey | None:
        """Return the current key record, or ``None`` when absent/revoked away."""


class ControlIssuerPolicyResolver(Protocol):
    """Resolve current, code-owned issuer authorization policy."""

    def resolve(self, issuer: str) -> ControlIssuerPolicy | None:
        """Return issuer policy or ``None`` when no authority is configured."""


def _finite_timestamp(name: str, value: object) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(name + " must be a finite timestamp")
    try:
        normalized = float(value)
    except OverflowError:
        raise ValueError(name + " must be a finite timestamp") from None
    if not math.isfinite(normalized):
        raise ValueError(name + " must be a finite timestamp")
    return normalized


def _required_text(name: str, value: object) -> str:
    if type(value) is not str or not value or value != value.strip():
        raise ValueError(name + " is required and must be trimmed text")
    return value


@dataclass(frozen=True, repr=False)
class HmacControlKey:
    """Key metadata returned by a trusted resolver; never persist its secret."""

    key_id: str
    issuer: str
    secret: bytes = field(repr=False)
    not_before_utc: float
    expires_at_utc: float
    revoked: bool = False

    def __post_init__(self) -> None:
        if _KEY_ID_RE.fullmatch(_required_text("key_id", self.key_id)) is None:
            raise ValueError("key_id has an invalid format")
        _required_text("issuer", self.issuer)
        if type(self.secret) is not bytes or len(self.secret) < 32:
            raise ValueError("HMAC key material must contain at least 32 bytes")
        start = _finite_timestamp("not_before_utc", self.not_before_utc)
        end = _finite_timestamp("expires_at_utc", self.expires_at_utc)
        if end <= start:
            raise ValueError("key expiry must be after key activation")
        if type(self.revoked) is not bool:
            raise ValueError("revoked must be a boolean")


@dataclass(frozen=True)
class ControlScopeGrant:
    """One exact account/mode/scope grant; wildcards are not supported."""

    account_id: str
    mode: str
    scope: str
    actions: tuple[ControlAction, ...]
    receipt_digests: tuple[str, ...]
    manual_resume_allowed: bool = False

    def __post_init__(self) -> None:
        for name, value in (
            ("account_id", self.account_id),
            ("mode", self.mode),
            ("scope", self.scope),
        ):
            if "*" in _required_text(name, value):
                raise ValueError("wildcard scope grants are not supported")
        if type(self.actions) is not tuple or not self.actions:
            raise ValueError("actions must be a non-empty tuple")
        if any(type(action) is not ControlAction for action in self.actions):
            raise ValueError("actions must contain ControlAction values")
        if len(set(self.actions)) != len(self.actions):
            raise ValueError("actions cannot contain duplicates")
        if type(self.receipt_digests) is not tuple or not self.receipt_digests:
            raise ValueError("receipt_digests must be a non-empty tuple")
        if any(
            type(value) is not str or _SHA256_RE.fullmatch(value) is None
            for value in self.receipt_digests
        ):
            raise ValueError("receipt_digests must contain lowercase SHA-256 digests")
        if len(set(self.receipt_digests)) != len(self.receipt_digests):
            raise ValueError("receipt_digests cannot contain duplicates")
        if type(self.manual_resume_allowed) is not bool:
            raise ValueError("manual_resume_allowed must be a boolean")
        if self.manual_resume_allowed and ControlAction.RESUME not in self.actions:
            raise ValueError("manual resume requires RESUME in the grant actions")


@dataclass(frozen=True)
class ControlIssuerPolicy:
    """Current issuer authority and its exact, non-wildcard grants."""

    issuer: str
    policy_id: str
    grants: tuple[ControlScopeGrant, ...]
    not_before_utc: float
    expires_at_utc: float
    revoked: bool = False

    def __post_init__(self) -> None:
        _required_text("issuer", self.issuer)
        _required_text("policy_id", self.policy_id)
        if type(self.grants) is not tuple or not self.grants:
            raise ValueError("grants must be a non-empty tuple")
        if any(type(grant) is not ControlScopeGrant for grant in self.grants):
            raise ValueError("grants must contain ControlScopeGrant values")
        exact_scopes = [(g.account_id, g.mode, g.scope) for g in self.grants]
        if len(set(exact_scopes)) != len(exact_scopes):
            raise ValueError("duplicate account/mode/scope grants are not allowed")
        start = _finite_timestamp("not_before_utc", self.not_before_utc)
        end = _finite_timestamp("expires_at_utc", self.expires_at_utc)
        if end <= start:
            raise ValueError("policy expiry must be after policy activation")
        if type(self.revoked) is not bool:
            raise ValueError("revoked must be a boolean")


class HmacControlCommandVerifier:
    """Verify canonical HMAC command envelopes against injected trust records.

    A payload is canonical UTF-8 JSON with an exact versioned field set. Its
    MAC covers a fixed domain, length-prefixed key ID, and the exact payload
    bytes. Every claim is then checked against the key's issuer and a current
    exact issuer grant. Missing resolvers, keys, or policies always reject.
    """

    def __init__(
        self,
        key_resolver: ControlKeyResolver | None = None,
        policy_resolver: ControlIssuerPolicyResolver | None = None,
        *,
        max_command_ttl_seconds: float = 60.0,
    ) -> None:
        ttl = _finite_timestamp("max_command_ttl_seconds", max_command_ttl_seconds)
        if ttl <= 0:
            raise ValueError("max_command_ttl_seconds must be positive")
        self._key_resolver = key_resolver
        self._policy_resolver = policy_resolver
        self._max_command_ttl_seconds = ttl

    def verify(self, envelope: ControlCommandEnvelope, *, now_utc: float) -> VerifiedControlCommand:
        if type(envelope) is not ControlCommandEnvelope:
            raise ControlAuthorizationError("control_envelope_required")
        now = _finite_timestamp("now_utc", now_utc)
        key_resolver = self._key_resolver
        policy_resolver = self._policy_resolver
        if key_resolver is None or policy_resolver is None:
            raise ControlAuthorizationError("trusted_control_key_and_policy_required")

        claims = self._decode_payload(envelope.payload)
        key_id = claims["key_id"]
        issuer = claims["issuer"]
        if type(key_id) is not str or _KEY_ID_RE.fullmatch(key_id) is None:
            raise ControlAuthorizationError("control_key_id_invalid")
        if type(issuer) is not str or not issuer or issuer != issuer.strip():
            raise ControlAuthorizationError("control_issuer_invalid")

        try:
            resolved_key = key_resolver.resolve(key_id)
        except Exception:
            raise ControlAuthorizationError("trusted_control_key_resolution_failed") from None
        if type(resolved_key) is not HmacControlKey:
            raise ControlAuthorizationError("trusted_control_key_unavailable")
        try:
            key = HmacControlKey(
                key_id=resolved_key.key_id,
                issuer=resolved_key.issuer,
                secret=resolved_key.secret,
                not_before_utc=resolved_key.not_before_utc,
                expires_at_utc=resolved_key.expires_at_utc,
                revoked=resolved_key.revoked,
            )
        except (TypeError, ValueError):
            raise ControlAuthorizationError("trusted_control_key_invalid") from None
        if key.key_id != key_id or key.revoked:
            raise ControlAuthorizationError("trusted_control_key_unavailable")

        parsed = self._validate_claims(claims)
        if key.issuer != parsed["issuer"]:
            raise ControlAuthorizationError("control_key_issuer_mismatch")
        issued_at = parsed["issued_at"]
        expires_at = parsed["expires_at"]
        if not (key.not_before_utc <= issued_at < key.expires_at_utc):
            raise ControlAuthorizationError("control_key_outside_validity")
        if not (key.not_before_utc <= now < key.expires_at_utc):
            raise ControlAuthorizationError("control_key_inactive_or_expired")

        if type(envelope.signature) is not bytes or len(envelope.signature) != 32:
            raise ControlAuthorizationError("control_signature_invalid")
        expected = self._signature(key.secret, key_id, envelope.payload)
        if not hmac.compare_digest(envelope.signature, expected):
            raise ControlAuthorizationError("control_signature_invalid")

        try:
            resolved_policy = policy_resolver.resolve(issuer)
        except Exception:
            raise ControlAuthorizationError("trusted_control_policy_resolution_failed") from None
        if type(resolved_policy) is not ControlIssuerPolicy:
            raise ControlAuthorizationError("trusted_control_issuer_unavailable")
        try:
            grants = tuple(
                ControlScopeGrant(
                    account_id=grant.account_id,
                    mode=grant.mode,
                    scope=grant.scope,
                    actions=grant.actions,
                    receipt_digests=grant.receipt_digests,
                    manual_resume_allowed=grant.manual_resume_allowed,
                )
                for grant in resolved_policy.grants
            )
            policy = ControlIssuerPolicy(
                issuer=resolved_policy.issuer,
                policy_id=resolved_policy.policy_id,
                grants=grants,
                not_before_utc=resolved_policy.not_before_utc,
                expires_at_utc=resolved_policy.expires_at_utc,
                revoked=resolved_policy.revoked,
            )
        except (AttributeError, TypeError, ValueError):
            raise ControlAuthorizationError("trusted_control_policy_invalid") from None
        if policy.issuer != issuer or policy.revoked:
            raise ControlAuthorizationError("trusted_control_issuer_unavailable")
        if not (policy.not_before_utc <= issued_at < policy.expires_at_utc):
            raise ControlAuthorizationError("control_policy_outside_validity")
        if not (policy.not_before_utc <= now < policy.expires_at_utc):
            raise ControlAuthorizationError("control_policy_inactive_or_expired")
        if issued_at > now:
            raise ControlAuthorizationError("control_command_not_yet_valid")
        if expires_at <= now:
            raise ControlAuthorizationError("control_command_expired")
        if expires_at - issued_at > self._max_command_ttl_seconds:
            raise ControlAuthorizationError("control_command_ttl_exceeds_limit")

        action = parsed["action"]
        grant = next(
            (
                candidate
                for candidate in policy.grants
                if candidate.account_id == parsed["account_id"]
                and candidate.mode == parsed["mode"]
                and candidate.scope == parsed["scope"]
            ),
            None,
        )
        if grant is None:
            raise ControlAuthorizationError("control_scope_not_authorized")
        if action not in grant.actions:
            raise ControlAuthorizationError("control_action_not_authorized")
        if parsed["receipt_digest"] not in grant.receipt_digests:
            raise ControlAuthorizationError("control_receipt_not_authorized")
        manual_resume = parsed["manual_resume_authorized"]
        if action is ControlAction.RESUME:
            if not manual_resume or not grant.manual_resume_allowed:
                raise ControlAuthorizationError("manual_resume_not_authorized")
        elif manual_resume:
            raise ControlAuthorizationError("manual_resume_flag_not_applicable")

        verification_digest = self._verification_digest(
            envelope=envelope,
            key_id=key_id,
            issuer=issuer,
            policy=policy,
            grant=grant,
        )
        return VerifiedControlCommand(
            command_id=parsed["command_id"],
            account_id=parsed["account_id"],
            mode=parsed["mode"],
            scope=parsed["scope"],
            action=action,
            issuer=issuer,
            key_id=key_id,
            reason=parsed["reason"],
            receipt_digest=parsed["receipt_digest"],
            issued_at=issued_at,
            expires_at=expires_at,
            issuer_sequence=parsed["issuer_sequence"],
            manual_resume_authorized=manual_resume,
            envelope_digest=envelope.digest,
            verification_digest=verification_digest,
        )

    @staticmethod
    def _signature(secret: bytes, key_id: str, payload: bytes) -> bytes:
        encoded_key_id = key_id.encode("ascii")
        message = (
            CONTROL_COMMAND_HMAC_DOMAIN
            + len(encoded_key_id).to_bytes(2, "big")
            + encoded_key_id
            + payload
        )
        return hmac.new(secret, message, hashlib.sha256).digest()

    @staticmethod
    def _decode_payload(payload: bytes) -> dict[str, object]:
        try:
            decoded = payload.decode("utf-8", errors="strict")
            value = json.loads(
                decoded,
                object_pairs_hook=HmacControlCommandVerifier._reject_duplicate_keys,
                parse_constant=HmacControlCommandVerifier._reject_constant,
            )
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError, RecursionError):
            raise ControlAuthorizationError("control_payload_invalid") from None
        if type(value) is not dict or set(value) != _PAYLOAD_FIELDS:
            raise ControlAuthorizationError("control_payload_schema_invalid")
        try:
            canonical = json.dumps(
                value,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=True,
                allow_nan=False,
            ).encode("utf-8")
        except (TypeError, ValueError):
            raise ControlAuthorizationError("control_payload_invalid") from None
        if canonical != payload:
            raise ControlAuthorizationError("control_payload_not_canonical")
        return value

    @staticmethod
    def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate JSON key")
            result[key] = value
        return result

    @staticmethod
    def _reject_constant(value: str) -> object:
        raise ValueError("non-standard JSON number: " + value)

    @staticmethod
    def _validate_claims(claims: dict[str, object]) -> _NormalizedClaims:
        if type(claims["schema_version"]) is not int or claims["schema_version"] != 1:
            raise ControlAuthorizationError("control_payload_version_unsupported")
        text_claims: dict[str, str] = {}
        for name in (
            "key_id",
            "issuer",
            "command_id",
            "account_id",
            "mode",
            "scope",
            "reason",
        ):
            value = claims[name]
            if type(value) is not str or not value or value != value.strip():
                raise ControlAuthorizationError("control_" + name + "_invalid")
            if name in {"account_id", "mode", "scope"} and "*" in value:
                raise ControlAuthorizationError("control_wildcards_not_supported")
            text_claims[name] = value
        if _KEY_ID_RE.fullmatch(text_claims["key_id"]) is None:
            raise ControlAuthorizationError("control_key_id_invalid")
        receipt_digest = claims["receipt_digest"]
        if type(receipt_digest) is not str or _SHA256_RE.fullmatch(receipt_digest) is None:
            raise ControlAuthorizationError("control_receipt_digest_invalid")
        action_value = claims["action"]
        if type(action_value) is not str:
            raise ControlAuthorizationError("control_action_invalid")
        try:
            action = ControlAction(action_value)
        except ValueError:
            raise ControlAuthorizationError("control_action_invalid") from None
        try:
            issued_at = _finite_timestamp("issued_at", claims["issued_at"])
            expires_at = _finite_timestamp("expires_at", claims["expires_at"])
        except ValueError:
            raise ControlAuthorizationError("control_timestamp_invalid") from None
        if expires_at <= issued_at:
            raise ControlAuthorizationError("control_deadline_invalid")
        sequence = claims["issuer_sequence"]
        if type(sequence) is not int or sequence <= 0:
            raise ControlAuthorizationError("control_issuer_sequence_invalid")
        manual_resume = claims["manual_resume_authorized"]
        if type(manual_resume) is not bool:
            raise ControlAuthorizationError("control_manual_resume_flag_invalid")
        return {
            "schema_version": 1,
            "key_id": text_claims["key_id"],
            "issuer": text_claims["issuer"],
            "command_id": text_claims["command_id"],
            "account_id": text_claims["account_id"],
            "mode": text_claims["mode"],
            "scope": text_claims["scope"],
            "action": action,
            "reason": text_claims["reason"],
            "receipt_digest": receipt_digest,
            "issued_at": issued_at,
            "expires_at": expires_at,
            "issuer_sequence": sequence,
            "manual_resume_authorized": manual_resume,
        }

    @staticmethod
    def _verification_digest(
        *,
        envelope: ControlCommandEnvelope,
        key_id: str,
        issuer: str,
        policy: ControlIssuerPolicy,
        grant: ControlScopeGrant,
    ) -> str:
        audit_facts = {
            "account_id": grant.account_id,
            "actions": sorted(action.value for action in grant.actions),
            "issuer": issuer,
            "key_id": key_id,
            "mode": grant.mode,
            "policy_id": policy.policy_id,
            "receipt_digests": sorted(grant.receipt_digests),
            "scope": grant.scope,
        }
        return hashlib.sha256(
            _VERIFICATION_RECEIPT_DOMAIN
            + envelope.digest.encode("ascii")
            + json.dumps(audit_facts, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()


__all__ = [
    "CONTROL_COMMAND_HMAC_DOMAIN",
    "ControlIssuerPolicy",
    "ControlIssuerPolicyResolver",
    "ControlKeyResolver",
    "ControlScopeGrant",
    "HmacControlCommandVerifier",
    "HmacControlKey",
]
