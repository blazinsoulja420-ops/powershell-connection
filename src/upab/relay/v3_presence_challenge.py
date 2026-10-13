"""Stage 11: task-bound user-presence CHALLENGE PLAN, not an approval issuer.

This module only constructs a fresh, public, bounded, exact-context
challenge preview. There is NO relying-party credential enrollment,
signature verification, Windows Hello prompt, or successful authorization
path. A challenge, even if displayed, never grants execution authority.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import json
import re
import secrets

from .v3_policy import PolicyBlocked

SCHEMA = "upab.watcher-v3.owner-presence-challenge-preview.v1"
_ALLOWED_SCOPE = frozenset({"review_only"})
_HEX64 = re.compile(r"[a-fA-F0-9]{64}\Z")
_SLUG = re.compile(r"[a-z0-9][a-z0-9-]{0,63}\Z")
_ID = re.compile(r"[a-zA-Z0-9._:-]{1,128}\Z")
_ALLOWED_FIELDS = frozenset({
    "schema", "project_id", "task_id", "task_sha256", "scope",
    "requested_at_utc", "expires_at_utc", "challenge_hex",
    "context_sha256", "owner_verified", "execution_authorized",
    "credential_assertion_available",
})


def _utc(now: datetime | None) -> datetime:
    clock = datetime.now(timezone.utc) if now is None else now
    if not isinstance(clock, datetime) or clock.tzinfo is None:
        raise PolicyBlocked("challenge time requires timezone")
    return clock.astimezone(timezone.utc)


def _context(task_id: str, project_id: str, task_digest: str, scope: str) -> bytes:
    if not isinstance(project_id, str) or not _SLUG.fullmatch(project_id):
        raise PolicyBlocked("invalid project identifier")
    if not isinstance(task_id, str) or not _ID.fullmatch(task_id):
        raise PolicyBlocked("invalid task identifier")
    if not isinstance(task_digest, str) or not _HEX64.fullmatch(task_digest):
        raise PolicyBlocked("invalid task SHA-256")
    if not isinstance(scope, str) or scope not in _ALLOWED_SCOPE:
        raise PolicyBlocked("only review-only context is permitted")
    return json.dumps({
        "project_id": project_id,
        "task_id": task_id,
        "task_sha256": task_digest.upper(),
        "scope": scope,
    }, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def create_challenge_preview(
    *, project_id: str, task_id: str, task_sha256: str,
    scope: str = "review_only", now: datetime | None = None
) -> dict[str, object]:
    """Prepare a 90-second challenge and exact task binding for later review.

    No credential is requested, and no signature is checked. The caller must
    not treat this dictionary, or a copied edit of it, as an approval.
    """
    context = _context(task_id, project_id, task_sha256, scope)
    clock = _utc(now)
    nonce = secrets.token_bytes(32)
    created = clock.isoformat()
    expiry = (clock + timedelta(seconds=90)).isoformat()
    # Include the nonce AND the exact expiry in the digest; context is
    # immutable and context_sha256 cannot be transferred to another task.
    bound = hashlib.sha256(
        b"UPAB-WATCHER-V3-PRESENCE-PREVIEW\0" +
        context + b"\0" + nonce + b"\0" +
        created.encode("ascii") + b"\0" + expiry.encode("ascii")
    ).hexdigest().upper()
    return {
        "schema": SCHEMA,
        "project_id": project_id,
        "task_id": task_id,
        "task_sha256": task_sha256.upper(),
        "scope": scope,
        "requested_at_utc": created,
        "expires_at_utc": expiry,
        "challenge_hex": nonce.hex(),
        "context_sha256": bound,
        "owner_verified": False,
        "execution_authorized": False,
        "credential_assertion_available": False,
    }


def inspect_challenge_preview(proposal: object, *,
                              now: datetime | None = None) -> dict[str, object]:
    """Reject malformed/stale/tampered previews, always return deny-only.

    A copied preview is NOT a trusted owner assertion. Callers never receive
    a positive approval result even after a completely valid integrity check.
    """
    if not isinstance(proposal, dict) or set(proposal) != _ALLOWED_FIELDS:
        raise PolicyBlocked("unknown or missing presence challenge fields")
    if proposal["schema"] != SCHEMA:
        raise PolicyBlocked("challenge schema mismatch")
    context = _context(proposal["task_id"], proposal["project_id"],
                       proposal["task_sha256"], proposal["scope"])
    if (proposal["owner_verified"] is not False or
            proposal["execution_authorized"] is not False or
            proposal["credential_assertion_available"] is not False):
        raise PolicyBlocked("challenge illegally claims approval authority")
    raw_nonce = proposal["challenge_hex"]
    if (not isinstance(raw_nonce, str) or
            not re.fullmatch(r"[a-f0-9]{64}", raw_nonce)):
        raise PolicyBlocked("invalid challenge random bytes")
    times = []
    for field in ("requested_at_utc", "expires_at_utc"):
        value = proposal[field]
        if not isinstance(value, str) or len(value) > 48:
            raise PolicyBlocked("invalid challenge time")
        try:
            parsed = datetime.fromisoformat(value)
        except ValueError as exc:
            raise PolicyBlocked("unparseable challenge time") from exc
        if parsed.tzinfo is None:
            raise PolicyBlocked("challenge time must include timezone")
        times.append(parsed.astimezone(timezone.utc))
    issued, expires = times
    current = _utc(now)
    if not (issued <= current < expires) or (expires - issued) != timedelta(seconds=90):
        raise PolicyBlocked("challenge expired, premature or invalid duration")
    expected = hashlib.sha256(
        b"UPAB-WATCHER-V3-PRESENCE-PREVIEW\0" +
        context + b"\0" + bytes.fromhex(raw_nonce) + b"\0" +
        proposal["requested_at_utc"].encode("ascii") + b"\0" +
        proposal["expires_at_utc"].encode("ascii")
    ).hexdigest().upper()
    actual = proposal["context_sha256"]
    if not isinstance(actual, str) or not secrets.compare_digest(expected, actual):
        raise PolicyBlocked("challenge context binding mismatch")
    return {
        "status": "VALID_UNAUTHENTICATED_CHALLENGE_PREVIEW",
        "challenge_age_seconds": int((current - issued).total_seconds()),
        "owner_verified": False,
        "assertion_signature_verified": False,
        "execution_authorized": False,
        "changes_performed": False,
    }
