"""Watcher v3 authenticated-proof *verification preview* with atomic replay denial.

IMPORTANT: Does NOT authenticate a human, issue approval proofs, obtain keys,
grant execution authority, access project repositories, or invoke the runner.
The HMAC key must eventually come from an independently authenticated,
protected local approval broker. Bare chat/clipboard JSON can never approve.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import re
import secrets
import sqlite3
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path

from .v3_policy import PolicyBlocked

SCHEMA = "upab.watcher.v3.approval-proof.v1"
FIELDS = frozenset({
    "schema", "issuer", "task_id", "task_sha256", "channel_id",
    "repository", "expected_head", "scope", "issued_at_utc",
    "expires_at_utc", "nonce", "mac",
})
_ID = re.compile(r"^[a-zA-Z0-9._:-]{1,128}$")
_REPO = re.compile(r"^[a-zA-Z0-9_.-]+/[a-zA-Z0-9_.-]+$")
_SHA = re.compile(r"^[a-fA-F0-9]{64}$")
_HEAD = re.compile(r"^[a-fA-F0-9]{40}$")
_NONCE = re.compile(r"^[a-fA-F0-9]{32,128}$")


def canonical_proof_bytes(proof: dict) -> bytes:
    """Sign only the exact recognized envelope (excluding the MAC field)."""
    if not isinstance(proof, dict) or set(proof) != FIELDS:
        raise PolicyBlocked("unknown or missing approval-proof fields")
    return json.dumps(
        {k: proof[k] for k in sorted(FIELDS - {"mac"})},
        sort_keys=True, separators=(",", ":"), ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")


def _parse_time(value: object) -> datetime:
    if not isinstance(value, str) or len(value) > 48:
        raise PolicyBlocked("invalid proof time")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise PolicyBlocked("invalid proof timestamp") from exc
    if parsed.tzinfo is None:
        raise PolicyBlocked("proof timestamp must have time zone")
    return parsed.astimezone(timezone.utc)


def check_proof_format(proof: object, *, now: datetime | None = None) -> bytes:
    if not isinstance(proof, dict) or set(proof) != FIELDS:
        raise PolicyBlocked("malformed approval proof")
    for name in ("issuer", "task_id", "channel_id"):
        if not isinstance(proof[name], str) or not _ID.fullmatch(proof[name]):
            raise PolicyBlocked("invalid proof identity field")
    if proof["schema"] != SCHEMA:
        raise PolicyBlocked("unsupported approval proof schema")
    if not isinstance(proof["repository"], str) or not _REPO.fullmatch(proof["repository"]):
        raise PolicyBlocked("invalid repository binding")
    if not isinstance(proof["task_sha256"], str) or not _SHA.fullmatch(proof["task_sha256"]):
        raise PolicyBlocked("invalid task digest")
    if not isinstance(proof["expected_head"], str) or not _HEAD.fullmatch(proof["expected_head"]):
        raise PolicyBlocked("invalid expected Git HEAD")
    if proof["scope"] != "read_only":
        raise PolicyBlocked("mutation/other scopes not admitted by v3 preview")
    if not isinstance(proof["nonce"], str) or not _NONCE.fullmatch(proof["nonce"]):
        raise PolicyBlocked("invalid proof nonce")
    if not isinstance(proof["mac"], str) or not _SHA.fullmatch(proof["mac"]):
        raise PolicyBlocked("invalid proof MAC")
    issued = _parse_time(proof["issued_at_utc"])
    expires = _parse_time(proof["expires_at_utc"])
    current = now or datetime.now(timezone.utc)
    if current.tzinfo is None:
        raise PolicyBlocked("now requires time zone")
    current = current.astimezone(timezone.utc)
    if expires <= issued or (expires - issued).total_seconds() > 300:
        raise PolicyBlocked("invalid proof lifetime")
    if issued > current or current >= expires:
        raise PolicyBlocked("proof not currently valid")
    return canonical_proof_bytes(proof)


class ApprovalProofPreview:
    """MAC check and one-time admission of *metadata for REVIEW ONLY*.

    Never place the key in a file underneath the watched project or the
    watcher state directory. A caller-supplied key is NOT proof of protected
    storage or human authentication: those require independent integration.
    """

    def __init__(self, state_dir: str | Path, *, trusted_verifier_key: bytes):
        if (not isinstance(trusted_verifier_key, bytes) or
                len(trusted_verifier_key) < 32):
            raise PolicyBlocked("trusted verifier requires 32+ byte secret")
        self._key = trusted_verifier_key
        root = Path(state_dir).expanduser().resolve() / "relay"
        root.mkdir(parents=True, exist_ok=True)
        self.path = root / "v3_approval_preview.sqlite3"
        with closing(self._connect()) as db:
            db.execute(
                "CREATE TABLE IF NOT EXISTS spent_proofs "
                "(nonce_hash TEXT PRIMARY KEY, task_id TEXT NOT NULL, "
                "task_sha256 TEXT NOT NULL, consumed_at_utc TEXT NOT NULL)"
            )
            db.execute("CREATE INDEX IF NOT EXISTS spent_task ON spent_proofs(task_id)")

    def _connect(self) -> sqlite3.Connection:
        db = sqlite3.connect(str(self.path), timeout=10, isolation_level=None)
        db.execute("PRAGMA busy_timeout=10000")
        db.execute("PRAGMA synchronous=FULL")
        return db

    def admit_for_review(
        self, proof: dict, *,
        task_id: str, task_sha256: str, channel_id: str,
        repository: str, expected_head: str, issuer: str,
        now: datetime | None = None,
    ) -> dict[str, object]:
        payload = check_proof_format(proof, now=now)
        expected = {
            "task_id": task_id, "task_sha256": task_sha256,
            "channel_id": channel_id, "repository": repository,
            "expected_head": expected_head, "issuer": issuer,
        }
        # All bindings are supplied by the caller and must eventually be
        # obtained from a trusted preflight, never a model-produced task alone.
        for key, value in expected.items():
            actual = proof[key]
            if key in ("task_sha256", "expected_head"):
                if not isinstance(value, str) or not secrets.compare_digest(
                        actual.casefold(), value.casefold()):
                    raise PolicyBlocked("approval proof binding mismatch")
            elif actual != value:
                raise PolicyBlocked("approval proof binding mismatch")
        calculated = hmac.new(self._key, payload, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(calculated, proof["mac"].casefold()):
            raise PolicyBlocked("unverified approval proof")
        nonce_hash = hashlib.sha256(proof["nonce"].encode("ascii")).hexdigest()
        with closing(self._connect()) as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                if db.execute(
                    "SELECT 1 FROM spent_proofs WHERE nonce_hash=? OR task_id=? LIMIT 1",
                    (nonce_hash, task_id),
                ).fetchone():
                    raise PolicyBlocked("replayed approval proof or task ID")
                db.execute(
                    "INSERT INTO spent_proofs "
                    "(nonce_hash,task_id,task_sha256,consumed_at_utc) "
                    "VALUES (?,?,?,?)",
                    (nonce_hash, task_id, task_sha256.upper(),
                     datetime.now(timezone.utc).isoformat()),
                )
                db.execute("COMMIT")
            except BaseException:
                db.execute("ROLLBACK")
                raise
        return {
            "status": "PROOF_VERIFIED_FOR_REVIEW_ONLY",
            "task_id": task_id,
            "authenticated_owner": False,
            "execution_authorized": False,
            "proof_consumed": True,
        }
