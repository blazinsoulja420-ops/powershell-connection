"""Stage 13 disposable WebAuthn credential+nonce journal (NO OWNER AUTHORITY).

Only a PUBLIC precomputed synthetic ES256 test credential is registered.
All state is restricted to existing upab-v3-lab-* directories directly
below the OS temporary directory. There is no real enrollment or Windows
Hello credential request. A valid signature advances a *synthetic* counter
and burns the one-use challenge, but NEVER approves or executes tasks.

A committed CLAIMED record is uncertain after a crash and is not replayed.
No caller-provided "verified"/"approved" flag is accepted.
"""
from __future__ import annotations

from contextlib import closing
from datetime import datetime, timedelta, timezone
import hashlib
from pathlib import Path
import secrets
import sqlite3
import stat
import tempfile

from .single_flight_v2 import SingleFlightLock
from .v3_assertion_crypto import inspect_es256_assertion
from .v3_policy import PolicyBlocked
from .v3_presence_challenge import _context

PUBLIC_FIXTURE_X = bytes.fromhex("1ee3e20b7836c44e865ec199a838e3944c724acfcb858fd6744459fb1c2f5722")
PUBLIC_FIXTURE_Y = bytes.fromhex("8c29c28c357150527a5f75b2a23194868f57a4c1191b2bd154b0306340986e80")
PUBLIC_FIXTURE_CHALLENGE = bytes.fromhex("cd"*32)
PUBLIC_FIXTURE_RP = "upab.example.test"
PUBLIC_FIXTURE_ORIGIN = "https://upab.example.test"
FIXTURE_ID = "public-es256-fixture-v1"
STATE_SCHEMA = "upab.watcher-v3.synthetic-assertion-journal.v1"
CAPACITY = 8


def _utc(now: datetime | None) -> datetime:
    value = datetime.now(timezone.utc) if now is None else now
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise PolicyBlocked("time must have a timezone")
    return value.astimezone(timezone.utc)


def _check_path(path: Path, *, directory: bool = False) -> None:
    try:
        mode = path.lstat()
    except FileNotFoundError:
        return
    if (stat.S_ISLNK(mode.st_mode) or
            getattr(mode, "st_file_attributes", 0) & 0x400):
        raise PolicyBlocked("synthetic state path redirected")
    if directory and not stat.S_ISDIR(mode.st_mode):
        raise PolicyBlocked("synthetic state parent is not a directory")
    if not directory and not stat.S_ISREG(mode.st_mode):
        raise PolicyBlocked("synthetic state file is not regular")


class SyntheticAssertionJournal:
    def __init__(self, root: str | Path):
        supplied = Path(root).expanduser()
        if (not supplied.name.startswith("upab-v3-lab-") or
                not supplied.is_dir() or supplied.is_symlink()):
            raise PolicyBlocked("requires an existing disposable fixture root")
        self.root = supplied.resolve(strict=True)
        if (self.root.parent != Path(tempfile.gettempdir()).resolve() or
                not self.root.name.startswith("upab-v3-lab-")):
            raise PolicyBlocked("fixture root must be directly inside OS temp")
        _check_path(self.root / "relay", directory=True)
        _check_path(self.root / "relay" / "watcher_v2.lock")
        self.path = self.root / "relay" / "v3_synthetic_assertions.sqlite3"
        _check_path(self.path)
        with SingleFlightLock(self.root):
            _check_path(self.path)
            with closing(self._db()) as db:
                db.execute("CREATE TABLE IF NOT EXISTS credential "
                           "(id TEXT PRIMARY KEY, x BLOB NOT NULL, y BLOB NOT NULL, "
                           "rp TEXT NOT NULL, origin TEXT NOT NULL, "
                           "counter INTEGER NOT NULL CHECK(counter>=0), "
                           "trusted INTEGER NOT NULL CHECK(trusted=0))")
                db.execute(
                    "INSERT OR IGNORE INTO credential VALUES (?,?,?,?,?,0,0)",
                    (FIXTURE_ID, PUBLIC_FIXTURE_X, PUBLIC_FIXTURE_Y,
                     PUBLIC_FIXTURE_RP, PUBLIC_FIXTURE_ORIGIN),
                )
                db.execute(
                    "CREATE TABLE IF NOT EXISTS challenges "
                    "(nonce_hash TEXT PRIMARY KEY, task_id TEXT NOT NULL, "
                    "project_id TEXT NOT NULL, digest TEXT NOT NULL, "
                    "context_hash TEXT NOT NULL, created TEXT NOT NULL, expiry TEXT NOT NULL, "
                    "phase TEXT NOT NULL CHECK(phase IN "
                    "('PENDING','CLAIMED','CRYPTO_VERIFIED_ONLY',"
                    "'REJECTED','INTERRUPTED','EXPIRED')), "
                    "is_fixed_fixture INTEGER NOT NULL CHECK(is_fixed_fixture IN (0,1)))"
                )
                db.execute("CREATE INDEX IF NOT EXISTS challenge_phase "
                           "ON challenges(phase,expiry)")

    def _db(self):
        _check_path(self.path.parent, directory=True)
        _check_path(self.path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        db = sqlite3.connect(str(self.path), timeout=10, isolation_level=None)
        db.execute("PRAGMA busy_timeout=10000")
        db.execute("PRAGMA synchronous=FULL")
        return db

    def issue(self, *, project_id: str, task_id: str, task_sha256: str,
              now: datetime | None = None, fixed_public_fixture: bool = False):
        if type(fixed_public_fixture) is not bool:
            raise PolicyBlocked("invalid synthetic fixture flag")
        context = _context(task_id, project_id, task_sha256, "review_only")
        instant = _utc(now)
        challenge = (PUBLIC_FIXTURE_CHALLENGE if fixed_public_fixture
                     else secrets.token_bytes(32))
        context_digest = hashlib.sha256(context).hexdigest()
        nonce_hash = hashlib.sha256(challenge).hexdigest()
        expiry = (instant + timedelta(seconds=90)).isoformat()
        with closing(self._db()) as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                db.execute(
                    "UPDATE challenges SET phase='EXPIRED' "
                    "WHERE phase='PENDING' AND expiry<=?", (instant.isoformat(),)
                )
                count = db.execute(
                    "SELECT count(*) FROM challenges WHERE phase IN ('PENDING','CLAIMED')"
                ).fetchone()[0]
                if count >= CAPACITY:
                    raise PolicyBlocked("bounded synthetic assertion queue full")
                db.execute(
                    "INSERT INTO challenges VALUES (?,?,?,?,?,?,?,?,?)",
                    (nonce_hash, task_id, project_id, task_sha256.upper(),
                     context_digest, instant.isoformat(), expiry, "PENDING",
                     1 if fixed_public_fixture else 0),
                )
                db.execute("COMMIT")
            except (sqlite3.IntegrityError, BaseException) as exc:
                db.execute("ROLLBACK")
                if isinstance(exc, sqlite3.IntegrityError):
                    raise PolicyBlocked("duplicate synthetic challenge") from exc
                raise
        return {
            "schema": STATE_SCHEMA,
            "challenge_hex": challenge.hex(),
            "task_id": task_id,
            "project_id": project_id,
            "task_sha256": task_sha256.upper(),
            "expires_at_utc": expiry,
            "scope": "review_only",
            "trusted_credential_enrolled": False,
            "owner_authenticated": False,
            "execution_authorized": False,
        }

    def inspect_fixture(self, *, challenge_hex: str, task_id: str,
                        project_id: str, task_sha256: str,
                        client_data_json: bytes, authenticator_data: bytes,
                        signature_der: bytes, now: datetime | None = None):
        """Consume nonce BEFORE cryptography. A crash leaves CLAIMED in doubt."""
        context = _context(task_id, project_id, task_sha256, "review_only")
        if (not isinstance(challenge_hex, str) or len(challenge_hex) != 64
                or not all(c in "0123456789abcdef" for c in challenge_hex)):
            raise PolicyBlocked("invalid synthetic challenge")
        supplied = bytes.fromhex(challenge_hex)
        nonce_hash = hashlib.sha256(supplied).hexdigest()
        instant = _utc(now)
        with closing(self._db()) as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                row = db.execute(
                    "SELECT task_id,project_id,digest,context_hash,created,expiry,phase,"
                    "is_fixed_fixture FROM challenges WHERE nonce_hash=?",
                    (nonce_hash,),
                ).fetchone()
                if (row is None or row[:4] !=
                        (task_id, project_id, task_sha256.upper(),
                         hashlib.sha256(context).hexdigest())
                        or row[6] != "PENDING"):
                    raise PolicyBlocked("unknown, reused, or incorrectly bound nonce")
                created = datetime.fromisoformat(row[4]).astimezone(timezone.utc)
                expiry = datetime.fromisoformat(row[5]).astimezone(timezone.utc)
                if instant < created:
                    raise PolicyBlocked("synthetic challenge time predates issue")
                if instant >= expiry:
                    db.execute("UPDATE challenges SET phase='EXPIRED' WHERE nonce_hash=?",
                               (nonce_hash,))
                    db.execute("COMMIT")
                    raise PolicyBlocked("synthetic challenge expired")
                # Only hardcoded public fixture can demonstrate a cryptographic
                # success; arbitrary key enrollment is intentionally impossible.
                if row[7] != 1 or supplied != PUBLIC_FIXTURE_CHALLENGE:
                    raise PolicyBlocked("random challenge lacks a fixture authenticator")
                db.execute("UPDATE challenges SET phase='CLAIMED' WHERE nonce_hash=?",
                           (nonce_hash,))
                db.execute("COMMIT")
            except BaseException:
                if db.in_transaction:
                    db.execute("ROLLBACK")
                raise
        with closing(self._db()) as db:
            credential = db.execute("SELECT x,y,rp,origin,counter,trusted "
                                    "FROM credential WHERE id=?", (FIXTURE_ID,)).fetchone()
        if (credential is None or credential[:4] !=
                (PUBLIC_FIXTURE_X, PUBLIC_FIXTURE_Y, PUBLIC_FIXTURE_RP,
                 PUBLIC_FIXTURE_ORIGIN) or credential[5] != 0):
            raise PolicyBlocked("synthetic credential registry changed")
        try:
            result = inspect_es256_assertion(
                expected_challenge=supplied, expected_origin=credential[3],
                expected_rp_id=credential[2], credential_public_x=credential[0],
                credential_public_y=credential[1], client_data_json=client_data_json,
                authenticator_data=authenticator_data, signature_der=signature_der,
                previous_sign_count=credential[4],
            )
            valid = result["signed_assertion_valid"]
            proposed_count = result["new_sign_count"]
        except (PolicyBlocked, ValueError, TypeError):
            valid = False
            proposed_count = None
        with closing(self._db()) as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                if valid:
                    # Counter and nonce disposition commit in ONE transaction.
                    updated = db.execute(
                        "UPDATE credential SET counter=? WHERE id=? "
                        "AND counter<? AND trusted=0",
                        (proposed_count, FIXTURE_ID, proposed_count),
                    ).rowcount
                    if updated != 1:
                        valid = False
                status = "CRYPTO_VERIFIED_ONLY" if valid else "REJECTED"
                changed = db.execute(
                    "UPDATE challenges SET phase=? WHERE nonce_hash=? "
                    "AND phase='CLAIMED'", (status, nonce_hash),
                ).rowcount
                if changed != 1:
                    raise PolicyBlocked("synthetic challenge transition interrupted")
                db.execute("COMMIT")
            except BaseException:
                db.execute("ROLLBACK")
                raise
        return {
            "schema": STATE_SCHEMA,
            "status": status,
            "public_fixture_signature_valid": bool(valid),
            "trusted_credential_enrolled": False,
            "challenge_spent": True,
            "owner_authenticated": False,
            "approval_issued": False,
            "execution_authorized": False,
            "real_task_executed": False,
        }

    def reconcile_after_restart(self) -> int:
        """Caller must have exclusive single-flight ownership before calling."""
        with SingleFlightLock(self.root):
            with closing(self._db()) as db:
                db.execute("BEGIN IMMEDIATE")
                try:
                    changed = db.execute(
                        "UPDATE challenges SET phase='INTERRUPTED' "
                        "WHERE phase='CLAIMED'"
                    ).rowcount
                    db.execute("COMMIT")
                    return changed
                except BaseException:
                    db.execute("ROLLBACK")
                    raise

    def summary(self):
        with closing(self._db()) as db:
            counts = dict(db.execute(
                "SELECT phase,count(*) FROM challenges GROUP BY phase"
            ))
            ctr = db.execute(
                "SELECT counter,trusted FROM credential WHERE id=?", (FIXTURE_ID,)
            ).fetchone()
        return {
            "schema": STATE_SCHEMA,
            "counts": counts,
            "synthetic_counter": ctr[0] if ctr else None,
            "trusted_enrollment": False,
            "execution_authorized": False,
            "persistent_replay_protection_is_synthetic_only": True,
        }
