"""Stage 45: signed provider-acknowledgement consistency, REVIEW-ONLY.

No TPM, external provider, protected key enrollment, storage, network, owner
approval or execution. Both the "pinned" key and replay history are supplied
by the caller; a self-generated signed reply can satisfy this verifier.
Actual provider provenance, durable replay defense, CAS and monitoring remain
UNVERIFIED even if every signature and requested field is consistent.
"""
from __future__ import annotations

import hashlib
import json
import re

from .v3_policy import PolicyBlocked
from .v3_stage44_witness_protocol_review import _check_request
from .v3_portfolio_health_rollup import MAX_EPOCH

CLAIM_SCHEMA = "upab.watcher-v3.synthetic-provider-ack-claim.v1"
ENVELOPE_SCHEMA = "upab.watcher-v3.synthetic-provider-ack-envelope.v1"
RECEIPT_SCHEMA = "upab.watcher-v3.synthetic-provider-ack-review.v1"
DOMAIN = b"UPAB-WATCHER-V3-PROVIDER-ACK-REVIEW-ONLY-v1\x00"
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
HEX128 = re.compile(r"[0-9a-f]{128}\Z")
CLAIM_FIELDS = frozenset({
    "schema", "provider_kind", "witness_id", "request_id",
    "request_sha256", "operation", "transition_kind",
    "claimed_status", "claimed_epoch", "claimed_commitment",
    "issued_at_epoch_s", "expires_at_epoch_s",
})
ENVELOPE_FIELDS = frozenset({"schema", "claim", "public_key_hex", "signature_hex"})
PROVIDERS = frozenset({"TPM_NV_CANDIDATE", "EXTERNAL_WITNESS_CANDIDATE"})
CLAIM_STATUSES = frozenset({"APPLIED", "SNAPSHOT", "DENIED", "RECOVERY_REVIEW_REQUIRED"})
MAX_HISTORY = 128
MAX_RESPONSE_AGE = 600


def _hex(value: object, regex: re.Pattern) -> bool:
    return type(value) is str and regex.fullmatch(value) is not None


def _epoch(value: object) -> bool:
    return type(value) is int and 0 <= value <= MAX_EPOCH


def _canonical(obj: object) -> bytes:
    try:
        payload = json.dumps(obj, sort_keys=True, separators=(",", ":"),
                             ensure_ascii=True, allow_nan=False).encode("ascii")
    except (TypeError, ValueError, UnicodeError, OverflowError) as exc:
        raise PolicyBlocked("synthetic provider claim not canonicalizable") from exc
    if not 1 <= len(payload) <= 2048:
        raise PolicyBlocked("synthetic provider claim oversized")
    return payload


def canonical_provider_claim(claim: object) -> bytes:
    """Domain-safe signing payload for ephemeral, non-enrolled test keys."""
    if type(claim) is not dict or set(claim) != CLAIM_FIELDS:
        raise PolicyBlocked("invalid synthetic provider claim shape")
    if (claim["schema"] != CLAIM_SCHEMA
            or type(claim["provider_kind"]) is not str
            or claim["provider_kind"] not in PROVIDERS
            or not _hex(claim["witness_id"], HEX64) and not (
                type(claim["witness_id"]) is str and
                re.fullmatch(r"[0-9a-f]{32}", claim["witness_id"]) is not None
            )
            or type(claim["operation"]) is not str
            or claim["operation"] not in ("READ_SNAPSHOT", "COMPARE_ADVANCE")
            or not _hex(claim["request_id"], HEX64) and not (
                type(claim["request_id"]) is str and
                re.fullmatch(r"[0-9a-f]{32}", claim["request_id"]) is not None
            )
            or not _hex(claim["request_sha256"], HEX64)
            or not _hex(claim["claimed_commitment"], HEX64)
            or not _epoch(claim["claimed_epoch"])
            or type(claim["claimed_status"]) is not str
            or claim["claimed_status"] not in CLAIM_STATUSES
            or type(claim["transition_kind"]) not in (type(None), str)
            or not _epoch(claim["issued_at_epoch_s"])
            or not _epoch(claim["expires_at_epoch_s"])
            or claim["expires_at_epoch_s"] < claim["issued_at_epoch_s"]
            or claim["expires_at_epoch_s"] - claim["issued_at_epoch_s"] > MAX_RESPONSE_AGE):
        raise PolicyBlocked("invalid synthetic provider claim values")
    if claim["operation"] == "READ_SNAPSHOT":
        if claim["transition_kind"] is not None:
            raise PolicyBlocked("provider read claim cannot carry mutation")
    elif claim["transition_kind"] not in ("HEALTH", "ENROLL", "ROTATE", "REVOKE", "RECOVER"):
        raise PolicyBlocked("provider transition kind not supported")
    return _canonical(claim)


def _receipt(status: str) -> dict[str, object]:
    return {
        "schema": RECEIPT_SCHEMA,
        "status": status,
        "evidence_trust": "CALLER_SELECTED_PROVIDER_PIN_AND_REPLAY_HISTORY",
        "signature_consistency_demonstrated": status not in (
            "BLOCKED_SYNTHETIC_ACK_EXPIRED_OR_FUTURE",
            "QUARANTINED_SYNTHETIC_ACK_REPLAY",
        ),
        "provider_independently_authenticated": False,
        "pin_independently_enrolled": False,
        "genuine_tpm_or_external_service_verified": False,
        "durable_replay_history_verified": False,
        "protected_monotonicity_verified": False,
        "remote_cas_verified": False,
        "actual_recovery_verified": False,
        "owner_approval_verified": False,
        "collector_identity_verified": False,
        "real_monitoring_enabled": False,
        "task_execution_authorized": False,
        "project_roster_modified": False,
    }


def review_untrusted_provider_ack(
    *, request: object, envelope: object,
    caller_selected_public_key_sha256: object,
    seen_ack_claim_sha256: object,
    now_epoch_s: int,
) -> dict[str, object]:
    """Verify signature and correspondence ONLY against untrusted inputs."""
    _check_request(request)
    if type(envelope) is not dict or set(envelope) != ENVELOPE_FIELDS:
        raise PolicyBlocked("invalid provider envelope fields")
    if envelope["schema"] != ENVELOPE_SCHEMA:
        raise PolicyBlocked("invalid provider envelope schema")
    if not _hex(envelope["public_key_hex"], HEX64):
        raise PolicyBlocked("invalid candidate provider public key")
    if not _hex(envelope["signature_hex"], HEX128):
        raise PolicyBlocked("invalid candidate provider signature")
    if not _hex(caller_selected_public_key_sha256, HEX64):
        raise PolicyBlocked("invalid caller-selected pin")
    if (type(seen_ack_claim_sha256) is not list or len(seen_ack_claim_sha256) > MAX_HISTORY
            or any(not _hex(v, HEX64) for v in seen_ack_claim_sha256)
            or len(set(seen_ack_claim_sha256)) != len(seen_ack_claim_sha256)):
        raise PolicyBlocked("untrusted acknowledgement history invalid")
    if not _epoch(now_epoch_s):
        raise PolicyBlocked("invalid provider evidence review time")
    claim = envelope["claim"]
    wire = canonical_provider_claim(claim)
    if hashlib.sha256(bytes.fromhex(envelope["public_key_hex"])).hexdigest() != caller_selected_public_key_sha256:
        raise PolicyBlocked("provider public key differs from caller pin")
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    except ImportError as exc:
        raise PolicyBlocked("maintained provider signature backend unavailable") from exc
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(envelope["public_key_hex"])).verify(
            bytes.fromhex(envelope["signature_hex"]), DOMAIN + wire)
    except (InvalidSignature, TypeError, ValueError) as exc:
        raise PolicyBlocked("provider signature consistency failure") from exc
    if (claim["issued_at_epoch_s"] > now_epoch_s
            or claim["expires_at_epoch_s"] < now_epoch_s):
        return _receipt("BLOCKED_SYNTHETIC_ACK_EXPIRED_OR_FUTURE")

    ack_hash = hashlib.sha256(wire).hexdigest()
    if ack_hash in seen_ack_claim_sha256:
        return _receipt("QUARANTINED_SYNTHETIC_ACK_REPLAY")
    if (claim["request_id"] != request["request_id"]
            or claim["witness_id"] != request["witness_id"]
            or claim["operation"] != request["operation"]
            or claim["request_sha256"] != hashlib.sha256(_canonical(request)).hexdigest()
            or claim["transition_kind"] != request["transition_kind"]):
        return _receipt("QUARANTINED_SYNTHETIC_ACK_REQUEST_MISMATCH")

    status = claim["claimed_status"]
    if status == "DENIED":
        return _receipt("BLOCKED_PROVIDER_REPORTED_DENIAL_NO_RETRY_AUTHORITY")
    if status == "RECOVERY_REVIEW_REQUIRED":
        if request["transition_kind"] != "RECOVER":
            return _receipt("QUARANTINED_SYNTHETIC_RECOVERY_SCOPE_MISMATCH")
        return _receipt("SYNTHETIC_RECOVERY_HUMAN_REVIEW_REQUIRED")
    if request["operation"] == "READ_SNAPSHOT":
        if (status != "SNAPSHOT" or
                claim["claimed_epoch"] != request["expected_epoch"] or
                claim["claimed_commitment"] != request["expected_commitment"]):
            return _receipt("QUARANTINED_SYNTHETIC_READ_STATE_MISMATCH")
    elif (status != "APPLIED"
            or claim["claimed_epoch"] != request["next_epoch"]
            or claim["claimed_commitment"] != request["next_commitment"]
            or request["transition_kind"] == "RECOVER"):
        return _receipt("QUARANTINED_SYNTHETIC_ADVANCE_STATE_MISMATCH")
    return _receipt("SYNTHETIC_SIGNED_ACK_CONSISTENT_NO_PROVIDER_TRUST")
