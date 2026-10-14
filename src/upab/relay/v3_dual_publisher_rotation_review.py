"""Stage 32: dual-Ed25519 publisher key rotation signature REVIEW only.

Verifies signatures from the old and new *caller-supplied* keys over the
same versioned domain-separated rotation statement. The statement binds
the entire prior (UNTRUSTED) lifecycle state, the complete proposed
transition, and the fixed repository identity. Genuine Ed25519 cryptography
is performed only when the optional maintained 'cryptography' backend
is available. No custom signature algorithm and no private key material.

IMPORTANT: Anyone can generate two new keys and produce two valid
signatures. Neither signature authenticates a trusted OWNER nor that the
'old' key was previously enrolled in protected storage. This module
cannot enroll, revoke, persist, authenticate Windows Hello, install,
migrate, approve or execute a task. It does not prevent physical rollback;
the old state and epoch supplied by a caller are forgeable.
"""
from __future__ import annotations

import hashlib
import json
import re

from .v3_policy import PolicyBlocked
from .v3_publisher_key_lifecycle import review_publisher_transition

SCHEMA = "upab.watcher-v3.dual-publisher-rotation-review.v1"
STATEMENT_SCHEMA = "upab.watcher-v3.publisher-rotation-statement.v1"
REPOSITORY = "blazinsoulja420-ops/powershell-connection"
DOMAIN = b"UPAB-WATCHER-V3-PUBLISHER-ROTATION-REVIEW-ONLY-v1\x00"
_HEX_KEY = re.compile(r"[0-9a-f]{64}\Z")
_HEX_SIGNATURE = re.compile(r"[0-9a-f]{128}\Z")


def _canonical(obj: object) -> bytes:
    """No arbitrary file or executable; strict bounded canonical JSON."""
    try:
        wire = json.dumps(obj, sort_keys=True, separators=(",", ":"),
                          ensure_ascii=True, allow_nan=False).encode("ascii")
    except (TypeError, ValueError, OverflowError) as exc:
        raise PolicyBlocked("publisher rotation input not canonical JSON") from exc
    if not 1 <= len(wire) <= 4096:
        raise PolicyBlocked("publisher rotation input exceeds bound")
    return wire


def rotation_statement(prior: object, proposal: object) -> bytes:
    """Canonical public REVIEW statement, never a trusted state record."""
    reviewed = review_publisher_transition(prior, proposal)
    if reviewed["proposed_action"] != "ROTATE":
        raise PolicyBlocked("dual publisher signature review only supports ROTATE")
    # Bind all historical revocations, old key and old release floor into
    # the old-state digest. A caller cannot swap these without resigning.
    return _canonical({
        "schema": STATEMENT_SCHEMA,
        "repository": REPOSITORY,
        "action": "ROTATE",
        "prior_state_sha256": hashlib.sha256(_canonical(prior)).hexdigest(),
        "proposed_transition_sha256": hashlib.sha256(_canonical(proposal)).hexdigest(),
        "next_epoch": reviewed["proposed_epoch"],
        "next_minimum_release_sequence":
            reviewed["proposed_minimum_release_sequence"],
    })


def verify_dual_rotation_review(
    *,
    prior: object,
    proposal: object,
    old_public_key_hex: str,
    new_public_key_hex: str,
    old_signature_hex: str,
    new_signature_hex: str,
) -> dict[str, object]:
    """Verify both signatures but ALWAYS deny enrollment/authorization."""
    for key in (old_public_key_hex, new_public_key_hex):
        if type(key) is not str or not _HEX_KEY.fullmatch(key):
            raise PolicyBlocked("publisher rotation public key malformed")
    for signature in (old_signature_hex, new_signature_hex):
        if type(signature) is not str or not _HEX_SIGNATURE.fullmatch(signature):
            raise PolicyBlocked("publisher rotation signature malformed")
    if old_public_key_hex == new_public_key_hex:
        raise PolicyBlocked("publisher rotation keys must differ")

    # Stage 31 checks syntax, exactly sequential epoch, nondecreasing
    # release floor, revoked key reuse and no re-enrollment.
    statement = rotation_statement(prior, proposal)
    old_key = bytes.fromhex(old_public_key_hex)
    new_key = bytes.fromhex(new_public_key_hex)
    if (hashlib.sha256(old_key).hexdigest() != prior["active_key_sha256"]
            or hashlib.sha256(new_key).hexdigest() != proposal["new_key_sha256"]):
        raise PolicyBlocked("publisher public keys mismatch proposed pins")

    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PublicKey,
        )
    except ImportError as exc:
        raise PolicyBlocked("maintained Ed25519 verification backend missing") from exc
    message = DOMAIN + statement
    try:
        Ed25519PublicKey.from_public_bytes(old_key).verify(
            bytes.fromhex(old_signature_hex), message
        )
        Ed25519PublicKey.from_public_bytes(new_key).verify(
            bytes.fromhex(new_signature_hex), message
        )
    except (InvalidSignature, ValueError, TypeError) as exc:
        raise PolicyBlocked("dual publisher review signature invalid") from exc

    return {
        "schema": SCHEMA,
        "status": "DUAL_SIGNATURES_VALID_FOR_UNTRUSTED_KEYS_ONLY",
        "old_signature_cryptographically_valid_for_supplied_key": True,
        "new_signature_cryptographically_valid_for_supplied_key": True,
        "versioned_domain_separation_checked": True,
        "prior_state_and_proposal_bound_in_statement": True,
        "proposed_next_epoch": proposal["next_epoch"],
        "proposed_release_floor": proposal["minimum_release_sequence"],
        "previous_state_authenticated_by_protected_store": False,
        "publisher_key_pins_independently_enrolled": False,
        "trusted_publisher_identity_proven": False,
        "trusted_revocation_history_proven": False,
        "hardware_monotonic_counter_proven": False,
        "windows_hello_owner_verified": False,
        "owner_approved_rotation": False,
        "key_rotation_committed": False,
        "installation_authorized": False,
        "migration_authorized": False,
        "task_execution_authorized": False,
        "writes_performed": False,
    }
