"""Stage 14: disposable Windows WebAuthn registration *rehearsal*.

This NEVER registers an authenticator or marks a public key trusted. It
records a 90-second one-use synthetic enrollment challenge, then optionally
seals a FIXED PUBLIC development-key candidate with current-user DPAPI.
No caller-supplied key, private key, attestation, owner identity or permission
is accepted. The record is ALWAYS untrusted and cannot issue task approval.

The exclusive OS-temp upab-v3-lab-* root is for isolated CI fixtures only.
DPAPI protects ciphertext under the current Windows user but does not prove
human presence or prevent same-user modification.
"""
from __future__ import annotations

from contextlib import closing
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import secrets
import sqlite3
import stat
import tempfile

from .single_flight_v2 import SingleFlightLock
from .v3_assertion_crypto import inspect_es256_assertion
from .v3_policy import PolicyBlocked
from .v3_synthetic_assertion_journal import (
    PUBLIC_FIXTURE_RP, PUBLIC_FIXTURE_ORIGIN,
    PUBLIC_FIXTURE_X, PUBLIC_FIXTURE_Y,
)
from .v3_windows_dpapi import protect_for_current_user, unprotect_for_current_user

SCHEMA = "upab.watcher-v3.enrollment-rehearsal.v1"
FIXTURE_ID = "untrusted-public-registration-fixture-v1"
CAPACITY = 4


def _clock(now: datetime | None) -> datetime:
    clock = datetime.now(timezone.utc) if now is None else now
    if not isinstance(clock, datetime) or clock.tzinfo is None:
        raise PolicyBlocked("enrollment timestamp must be timezone aware")
    return clock.astimezone(timezone.utc)


def _reject_redirect(path: Path, *, is_dir: bool = False) -> None:
    try:
        meta = path.lstat()
    except FileNotFoundError:
        return
    if stat.S_ISLNK(meta.st_mode) or getattr(meta, "st_file_attributes", 0) & 0x400:
        raise PolicyBlocked("lab state path redirected")
    if is_dir and not stat.S_ISDIR(meta.st_mode):
        raise PolicyBlocked("lab state directory has invalid type")
    if not is_dir and not stat.S_ISREG(meta.st_mode):
        raise PolicyBlocked("lab state file has invalid type")


class SyntheticEnrollmentLab:
    """Durable registration *candidate* state machine, never an authenticator."""

    def __init__(self, root: str | Path):
        supplied = Path(root).expanduser()
        if (not supplied.name.startswith("upab-v3-lab-")
                or supplied.is_symlink() or not supplied.is_dir()):
            raise PolicyBlocked("enrollment lab requires an existing disposable root")
        self.root = supplied.resolve(strict=True)
        if (self.root.name != supplied.name
                or self.root.parent != Path(tempfile.gettempdir()).resolve()):
            raise PolicyBlocked("lab root must be a direct OS-temp child")
        self.relay = self.root / "relay"
        self.path = self.relay / "v3_synthetic_enrollment.sqlite3"
        _reject_redirect(self.relay, is_dir=True)
        _reject_redirect(self.relay / "watcher_v2.lock")
        _reject_redirect(self.path)
        with SingleFlightLock(self.root):
            _reject_redirect(self.path)
            with closing(self._db()) as db:
                db.execute(
                    "CREATE TABLE IF NOT EXISTS enrollment_challenges("
                    "nonce_hash TEXT PRIMARY KEY, issued TEXT NOT NULL, "
                    "expires TEXT NOT NULL, "
                    "phase TEXT NOT NULL CHECK(phase IN "
                    "('PENDING','CLAIMED','SEALED_UNTRUSTED','EXPIRED',"
                    "'INTERRUPTED','REJECTED')))"
                )
                db.execute(
                    "CREATE TABLE IF NOT EXISTS candidate("
                    "id TEXT PRIMARY KEY CHECK(id='untrusted-public-registration-fixture-v1'), "
                    "challenge_hash TEXT UNIQUE NOT NULL, "
                    "ciphertext BLOB NOT NULL CHECK(length(ciphertext) BETWEEN 1 AND 4096), "
                    "trusted INTEGER NOT NULL DEFAULT 0 CHECK(trusted=0))"
                )

    def _db(self) -> sqlite3.Connection:
        _reject_redirect(self.relay, is_dir=True)
        _reject_redirect(self.path)
        self.relay.mkdir(parents=True, exist_ok=True)
        db = sqlite3.connect(str(self.path), timeout=10, isolation_level=None)
        db.execute("PRAGMA busy_timeout=10000")
        db.execute("PRAGMA synchronous=FULL")
        return db

    @staticmethod
    def _nonce_hash(challenge_hex: str) -> str:
        if (not isinstance(challenge_hex, str) or len(challenge_hex) != 64
                or any(c not in "0123456789abcdef" for c in challenge_hex)):
            raise PolicyBlocked("invalid enrollment challenge")
        return hashlib.sha256(bytes.fromhex(challenge_hex)).hexdigest()

    def begin(self, *, now: datetime | None = None) -> dict[str, object]:
        instant = _clock(now)
        challenge_hex = secrets.token_hex(32)
        nonce_hash = self._nonce_hash(challenge_hex)
        with closing(self._db()) as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                db.execute(
                    "UPDATE enrollment_challenges SET phase='EXPIRED' "
                    "WHERE phase='PENDING' AND expires<=?", (instant.isoformat(),)
                )
                count = db.execute(
                    "SELECT count(*) FROM enrollment_challenges "
                    "WHERE phase IN ('PENDING','CLAIMED')"
                ).fetchone()[0]
                if count >= CAPACITY:
                    raise PolicyBlocked("bounded enrollment lab queue full")
                if db.execute("SELECT 1 FROM candidate LIMIT 1").fetchone():
                    raise PolicyBlocked("a synthetic candidate already exists")
                expires = (instant + timedelta(seconds=90)).isoformat()
                db.execute(
                    "INSERT INTO enrollment_challenges VALUES (?, ?, ?, 'PENDING')",
                    (nonce_hash, instant.isoformat(), expires),
                )
                db.execute("COMMIT")
            except BaseException:
                db.execute("ROLLBACK")
                raise
        return {
            "schema": SCHEMA,
            "challenge_hex": challenge_hex,
            "expires_at_utc": expires,
            "relying_party": PUBLIC_FIXTURE_RP,
            "origin": PUBLIC_FIXTURE_ORIGIN,
            "authenticator_prompted": False,
            "credential_enrolled": False,
            "owner_authenticated": False,
            "execution_authorized": False,
        }

    def seal_public_fixture(
        self, challenge_hex: str, *, now: datetime | None = None,
        synthetic_test_only: bool = False, inject_interruption: bool = False
    ) -> dict[str, object]:
        """Spend challenge before encrypting; interrupted claims never resume."""
        if synthetic_test_only is not True or type(inject_interruption) is not bool:
            raise PolicyBlocked("only explicit non-production fixture rehearsal allowed")
        instant = _clock(now)
        nonce_hash = self._nonce_hash(challenge_hex)
        with closing(self._db()) as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                row = db.execute(
                    "SELECT issued,expires,phase FROM enrollment_challenges "
                    "WHERE nonce_hash=?", (nonce_hash,),
                ).fetchone()
                if row is None or row[2] != "PENDING":
                    raise PolicyBlocked("unknown or spent enrollment challenge")
                issued = datetime.fromisoformat(row[0]).astimezone(timezone.utc)
                expires = datetime.fromisoformat(row[1]).astimezone(timezone.utc)
                if instant < issued:
                    raise PolicyBlocked("enrollment claim predates issue")
                if instant >= expires:
                    db.execute(
                        "UPDATE enrollment_challenges SET phase='EXPIRED' "
                        "WHERE nonce_hash=?", (nonce_hash,),
                    )
                    db.execute("COMMIT")
                    raise PolicyBlocked("enrollment challenge expired")
                if db.execute("SELECT 1 FROM candidate LIMIT 1").fetchone():
                    raise PolicyBlocked("synthetic enrollment already recorded")
                changed = db.execute(
                    "UPDATE enrollment_challenges SET phase='CLAIMED' "
                    "WHERE nonce_hash=? AND phase='PENDING'", (nonce_hash,),
                ).rowcount
                if changed != 1:
                    raise PolicyBlocked("enrollment claim raced")
                db.execute("COMMIT")
            except BaseException:
                if db.in_transaction:
                    db.execute("ROLLBACK")
                raise

        if inject_interruption:
            return self._report("CLAIMED_INTERRUPTED_FOR_TEST")
        # No attestation bytes or caller-supplied public keys: permanently
        # store a known PUBLIC fixture, not a trusted enrolled authenticator.
        candidate = {
            "schema": SCHEMA, "credential_id": FIXTURE_ID,
            "rp_id": PUBLIC_FIXTURE_RP, "origin": PUBLIC_FIXTURE_ORIGIN,
            "x": PUBLIC_FIXTURE_X.hex(), "y": PUBLIC_FIXTURE_Y.hex(),
            "nonce_sha256": nonce_hash, "trusted": False,
            "owner_enrollment_verified": False,
        }
        wire = json.dumps(candidate, sort_keys=True, separators=(",", ":")).encode()
        ciphertext = protect_for_current_user(wire)
        if not 1 <= len(ciphertext) <= 4096:
            raise PolicyBlocked("encrypted test credential exceeds bound")
        with closing(self._db()) as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                db.execute(
                    "INSERT INTO candidate (id,challenge_hash,ciphertext,trusted) "
                    "VALUES (?,?,?,0)", (FIXTURE_ID, nonce_hash, ciphertext),
                )
                changed = db.execute(
                    "UPDATE enrollment_challenges SET phase='SEALED_UNTRUSTED' "
                    "WHERE nonce_hash=? AND phase='CLAIMED'", (nonce_hash,),
                ).rowcount
                if changed != 1:
                    raise PolicyBlocked("enrollment claim lost before seal")
                db.execute("COMMIT")
            except sqlite3.IntegrityError as exc:
                db.execute("ROLLBACK")
                raise PolicyBlocked("duplicate synthetic enrollment") from exc
            except BaseException:
                db.execute("ROLLBACK")
                raise
        return self._report("SEALED_UNTRUSTED")

    @staticmethod
    def _report(status: str) -> dict[str, object]:
        return {
            "schema": SCHEMA,
            "status": status,
            "credential_enrolled": False,
            "test_candidate_sealed": status == "SEALED_UNTRUSTED",
            "attestation_verified": False,
            "owner_authenticated": False,
            "approval_issued": False,
            "execution_authorized": False,
        }

    def inspect_sealed_fixture(self) -> dict[str, object]:
        """Test DPAPI integrity and known fixture binding; export NO key bytes."""
        with closing(self._db()) as db:
            row = db.execute(
                "SELECT challenge_hash,ciphertext,trusted FROM candidate "
                "WHERE id=?", (FIXTURE_ID,),
            ).fetchone()
            if row is None or row[2] != 0:
                raise PolicyBlocked("synthetic candidate absent or untrusted schema broken")
            challenge = db.execute(
                "SELECT phase FROM enrollment_challenges WHERE nonce_hash=?", (row[0],)
            ).fetchone()
            if challenge is None or challenge[0] != "SEALED_UNTRUSTED":
                raise PolicyBlocked("synthetic registration journal inconsistent")
        plain = unprotect_for_current_user(row[1])
        try:
            record = json.loads(plain.decode("utf-8", "strict"))
        except (UnicodeError, ValueError) as exc:
            raise PolicyBlocked("synthetic credential record unreadable") from exc
        expected = {
            "schema": SCHEMA, "credential_id": FIXTURE_ID,
            "rp_id": PUBLIC_FIXTURE_RP, "origin": PUBLIC_FIXTURE_ORIGIN,
            "x": PUBLIC_FIXTURE_X.hex(), "y": PUBLIC_FIXTURE_Y.hex(),
            "nonce_sha256": row[0], "trusted": False,
            "owner_enrollment_verified": False,
        }
        if record != expected:
            raise PolicyBlocked("encrypted synthetic registration binding mismatch")
        return {
            "status": "UNTRUSTED_FIXTURE_INTEGRITY_OK",
            "encrypted_record_recovered": True,
            "credential_enrolled": False,
            "owner_authenticated": False,
            "approval_issued": False,
            "execution_authorized": False,
        }

    def reconcile(self) -> int:
        """Exclusive crash reconciliation; CLAIMED never returns to PENDING."""
        with SingleFlightLock(self.root):
            with closing(self._db()) as db:
                db.execute("BEGIN IMMEDIATE")
                try:
                    changed = db.execute(
                        "UPDATE enrollment_challenges SET phase='INTERRUPTED' "
                        "WHERE phase='CLAIMED'"
                    ).rowcount
                    db.execute("COMMIT")
                    return changed
                except BaseException:
                    db.execute("ROLLBACK")
                    raise

    def summary(self) -> dict[str, object]:
        with closing(self._db()) as db:
            counts = dict(db.execute(
                "SELECT phase,count(*) FROM enrollment_challenges GROUP BY phase"
            ))
            sealed = db.execute("SELECT count(*) FROM candidate").fetchone()[0]
        return {
            "schema": SCHEMA, "phases": counts, "sealed_fixture_count": sealed,
            "protected_owner_enrollment_complete": False,
            "trusted_credential_count": 0,
            "real_execution_authorized": False,
        }
