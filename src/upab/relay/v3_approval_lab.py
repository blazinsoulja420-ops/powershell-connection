"""Stage 8 isolated approval ceremony simulator.

This is NOT owner authentication and never issues real execution permission.
It admits only a fixed public SHA-256 fixture in an existing disposable
upab-v3-lab-* root. The "approve" method is clearly a laboratory simulation,
not a Windows Hello/WebAuthn provider. A real broker MUST NOT import this.
"""
from __future__ import annotations

from contextlib import closing
from datetime import datetime, timedelta, timezone
import hashlib
from pathlib import Path
import tempfile
import secrets
import sqlite3
import stat
from typing import Callable

from .single_flight_v2 import SingleFlightLock
from .v3_policy import PolicyBlocked
from .v3_synthetic_worker import (
    FIXTURE_ID, FIXTURE_PAYLOAD, SyntheticSingleWorker
)

LAB_SCHEMA = "upab.watcher.v3.approval-lab.v1"
FIXTURE_SHA = hashlib.sha256(FIXTURE_PAYLOAD).hexdigest().upper()
LAB_SCOPE = "fixed_synthetic_hash_only"
MAX_PENDING = 8


def _time(now: datetime | None) -> datetime:
    point = datetime.now(timezone.utc) if now is None else now
    if not isinstance(point, datetime) or point.tzinfo is None:
        raise PolicyBlocked("lab approval time requires a timezone")
    return point.astimezone(timezone.utc)


class IsolatedApprovalLab:
    """Single-use challenge/approval/claim journal, no real authority."""

    def __init__(self, root: str | Path):
        user_path = Path(root).expanduser()
        if not user_path.name.startswith("upab-v3-lab-") or not user_path.is_dir():
            raise PolicyBlocked("approval lab requires existing disposable test root")
        if user_path.is_symlink():
            raise PolicyBlocked("approval lab root must not be a symlink")
        self.root = user_path.resolve(strict=True)
        if not self.root.name.startswith("upab-v3-lab-"):
            raise PolicyBlocked("approval lab root changed on canonicalization")
        if self.root.parent != Path(tempfile.gettempdir()).resolve():
            raise PolicyBlocked("approval lab must be direct child of OS temporary directory")
        relay = self.root / "relay"
        for path in (relay, relay / "approval_lab.sqlite3"):
            try:
                info = path.lstat()
            except FileNotFoundError:
                continue
            if (stat.S_ISLNK(info.st_mode) or
                    getattr(info, "st_file_attributes", 0) & 0x400):
                raise PolicyBlocked("approval lab state cannot be redirected")
        self.path = relay / "approval_lab.sqlite3"
        with SingleFlightLock(self.root):
            with closing(self._open()) as db:
                db.execute(
                    "CREATE TABLE IF NOT EXISTS challenges ("
                    "nonce_hash TEXT PRIMARY KEY, "
                    "task_id TEXT NOT NULL, task_digest TEXT NOT NULL, "
                    "scope TEXT NOT NULL, expires_at TEXT NOT NULL, "
                    "phase TEXT NOT NULL CHECK(phase IN "
                    "('PENDING','SIMULATED_APPROVED','CONSUMED')), "
                    "created_at TEXT NOT NULL)"
                )

    def _open(self) -> sqlite3.Connection:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        db = sqlite3.connect(self.path, timeout=10, isolation_level=None)
        db.execute("PRAGMA busy_timeout=10000")
        db.execute("PRAGMA synchronous=FULL")
        return db

    @staticmethod
    def _hash_nonce(challenge: str) -> str:
        if (not isinstance(challenge, str)
                or len(challenge) != 64
                or any(ch not in "0123456789abcdef" for ch in challenge)):
            raise PolicyBlocked("invalid lab challenge")
        return hashlib.sha256(challenge.encode("ascii")).hexdigest()

    def request(self, *, now: datetime | None = None) -> dict[str, object]:
        current = _time(now)
        nonce = secrets.token_hex(32)
        digest = self._hash_nonce(nonce)
        with SingleFlightLock(self.root):
            with closing(self._open()) as db:
                db.execute("BEGIN IMMEDIATE")
                try:
                    waiting = db.execute(
                        "SELECT count(*) FROM challenges WHERE phase IN "
                        "('PENDING','SIMULATED_APPROVED')"
                    ).fetchone()[0]
                    if waiting >= MAX_PENDING:
                        raise PolicyBlocked("bounded lab approval queue full")
                    db.execute(
                        "INSERT INTO challenges VALUES (?,?,?,?,?,?,?)",
                        (digest, FIXTURE_ID, FIXTURE_SHA, LAB_SCOPE,
                         (current + timedelta(seconds=90)).isoformat(),
                         "PENDING", current.isoformat()),
                    )
                    db.execute("COMMIT")
                except BaseException:
                    db.execute("ROLLBACK")
                    raise
        return {
            "schema": LAB_SCHEMA,
            "challenge": nonce,
            "fixture_id": FIXTURE_ID,
            "digest": FIXTURE_SHA,
            "scope": LAB_SCOPE,
            "expires_in_seconds": 90,
            "owner_authenticated": False,
            "execution_authorized": False,
            "synthetic_only": True,
        }

    def _transition(self, challenge: str, old: str, new: str,
                    *, now: datetime | None = None) -> None:
        digest = self._hash_nonce(challenge)
        current = _time(now)
        with SingleFlightLock(self.root):
            with closing(self._open()) as db:
                db.execute("BEGIN IMMEDIATE")
                try:
                    row = db.execute(
                        "SELECT task_id,task_digest,scope,expires_at,phase "
                        "FROM challenges WHERE nonce_hash=?", (digest,)
                    ).fetchone()
                    if (row is None or row[0] != FIXTURE_ID
                            or row[1] != FIXTURE_SHA
                            or row[2] != LAB_SCOPE
                            or row[4] != old):
                        raise PolicyBlocked("challenge mismatch or already spent")
                    expires = datetime.fromisoformat(row[3]).astimezone(timezone.utc)
                    if current >= expires:
                        raise PolicyBlocked("lab challenge expired")
                    db.execute(
                        "UPDATE challenges SET phase=? WHERE nonce_hash=? AND phase=?",
                        (new, digest, old),
                    )
                    db.execute("COMMIT")
                except BaseException:
                    db.execute("ROLLBACK")
                    raise

    def simulate_approval(self, challenge: str, *,
                          now: datetime | None = None,
                          test_simulation: bool = False) -> dict[str, object]:
        """Explicit non-production simulation: NO Windows user verification."""
        if test_simulation is not True:
            raise PolicyBlocked("only explicit fixture simulation is supported")
        self._transition(challenge, "PENDING", "SIMULATED_APPROVED", now=now)
        return {
            "schema": LAB_SCHEMA,
            "status": "LAB_SIMULATED_PRESENCE",
            "owner_authenticated": False,
            "execution_authorized": False,
            "synthetic_only": True,
        }

    def run_fixed_fixture(self, challenge: str, *,
                          now: datetime | None = None,
                          inject_interruption: bool = False) -> dict[str, object]:
        """Spend approval first; execute only fixed, harmless public hash."""
        if type(inject_interruption) is not bool:
            raise PolicyBlocked("invalid test fault")
        self._transition(challenge, "SIMULATED_APPROVED", "CONSUMED", now=now)
        result = SyntheticSingleWorker(self.root).run(
            inject_interruption=inject_interruption
        )
        return {
            "schema": LAB_SCHEMA,
            "lab_fixture_state": result["state"],
            "approval_simulated": True,
            "challenge_spent": True,
            "real_task_execution_enabled": False,
            "owner_authenticated": False,
        }
