"""Synthetic single-worker execution fixture: SHA-256 on a fixed public string.

Never accepts a user task, shell command, project path, clipboard payload,
provider model, approval proof, or arbitrary work item. The disposable
upab-v3-lab-* root is the only persistence target. This is NOT the
production executor. Crash injection leaves an uncertain fixture quarantined.
"""
from __future__ import annotations

from contextlib import closing
from datetime import datetime, timezone
import hashlib
from pathlib import Path
import stat
import sqlite3

from .single_flight_v2 import SingleFlightLock
from .v3_policy import PolicyBlocked

FIXTURE_ID = "upab-v3-safe-hash-fixture"
FIXTURE_PAYLOAD = b"UPAB WATCHER V3 FIXED SYNTHETIC WORKLOAD"
FIXTURE_RESULT = hashlib.sha256(FIXTURE_PAYLOAD).hexdigest().upper()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class SyntheticSingleWorker:
    """Persistent at-most-once fixture transitions (not real-world exactly once)."""

    @staticmethod
    def _refuse_redirected_path(path: Path, *, directory: bool = False) -> None:
        """Reject preexisting symlinks/reparse points before a disposable write.

        This is defense-in-depth for the synthetic fixture, NOT a secure
        production open-by-handle or Windows DACL verification.
        """
        try:
            info = path.lstat()
        except FileNotFoundError:
            return
        if stat.S_ISLNK(info.st_mode) or (
            getattr(info, "st_file_attributes", 0) & 0x400
        ):
            raise PolicyBlocked("fixture state path has a reparse point")
        if directory and not stat.S_ISDIR(info.st_mode):
            raise PolicyBlocked("fixture relay path is not a directory")
        if not directory and not stat.S_ISREG(info.st_mode):
            raise PolicyBlocked("fixture database/lock path is not a file")

    def __init__(self, root: str | Path):
        supplied = Path(root).expanduser()
        if (not supplied.name.startswith("upab-v3-lab-") or supplied.is_symlink()
                or not supplied.is_dir()):
            raise PolicyBlocked("worker requires existing disposable upab-v3-lab- root")
        self.root = supplied.resolve(strict=True)
        if not self.root.name.startswith("upab-v3-lab-"):
            raise PolicyBlocked("worker root changed on canonicalization")
        # Database creation happens only on a disposable fixture root.
        self.path = self.root / "relay" / "synthetic_worker.sqlite3"
        self._refuse_redirected_path(self.path.parent, directory=True)
        self._refuse_redirected_path(self.path.parent / "watcher_v2.lock")
        self._refuse_redirected_path(self.path)
        with SingleFlightLock(self.root):
            self._refuse_redirected_path(self.path.parent, directory=True)
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self._refuse_redirected_path(self.path)
            with closing(self._db()) as db:
                db.execute(
                    "CREATE TABLE IF NOT EXISTS fixture "
                    "(name TEXT PRIMARY KEY, state TEXT NOT NULL CHECK(state IN "
                    "('PENDING','RUNNING','DONE','INTERRUPTED')), "
                    "attempts INTEGER NOT NULL, result_digest TEXT, "
                    "updated_utc TEXT NOT NULL)"
                )
                db.execute(
                    "INSERT OR IGNORE INTO fixture "
                    "(name,state,attempts,result_digest,updated_utc) "
                    "VALUES (?,'PENDING',0,NULL,?)", (FIXTURE_ID, _now())
                )

    def _db(self):
        db = sqlite3.connect(str(self.path), timeout=10, isolation_level=None)
        db.execute("PRAGMA busy_timeout=10000")
        db.execute("PRAGMA synchronous=FULL")
        return db

    def _transition(self, expected: str, target: str,
                    result: str | None = None) -> bool:
        with closing(self._db()) as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                outcome = db.execute(
                    "UPDATE fixture SET state=?, "
                    "attempts=attempts+CASE WHEN ?='RUNNING' THEN 1 ELSE 0 END, "
                    "result_digest=?, updated_utc=? "
                    "WHERE name=? AND state=?",
                    (target, target, result, _now(), FIXTURE_ID, expected),
                ).rowcount
                db.execute("COMMIT")
                return outcome == 1
            except BaseException:
                db.execute("ROLLBACK")
                raise

    def status(self) -> dict[str, object]:
        with closing(self._db()) as db:
            row = db.execute(
                "SELECT state,attempts,result_digest FROM fixture WHERE name=?",
                (FIXTURE_ID,),
            ).fetchone()
        if row is None:
            raise PolicyBlocked("synthetic journal is missing")
        return {
            "fixture_id": FIXTURE_ID,
            "state": row[0],
            "attempts": row[1],
            "result_digest": row[2],
            "real_task_execution_enabled": False,
            "owner_authenticated": False,
        }

    def run(self, *, inject_interruption: bool = False) -> dict[str, object]:
        if type(inject_interruption) is not bool:
            raise PolicyBlocked("invalid test-only fault injection")
        self._refuse_redirected_path(self.path)
        with SingleFlightLock(self.root):
            self._refuse_redirected_path(self.path)
            current = self.status()
            if current["state"] != "PENDING":
                raise PolicyBlocked("fixture not pending; no replay allowed")
            if not self._transition("PENDING", "RUNNING"):
                raise PolicyBlocked("fixture claim failed")
            # Run-once checkpoint is durable before fixed computation.
            if inject_interruption:
                return {
                    "state": "RUNNING", "simulated_interruption": True,
                    "real_task_execution_enabled": False,
                }
            result = hashlib.sha256(FIXTURE_PAYLOAD).hexdigest().upper()
            if not self._transition("RUNNING", "DONE", result):
                raise PolicyBlocked("synthetic result commit failed")
            receipt = self.status()
            if receipt["result_digest"] != FIXTURE_RESULT:
                raise PolicyBlocked("unexpected public fixture result")
            return receipt

    def reconcile(self) -> dict[str, object]:
        """No automatic repeat after an uncertain RUNNING checkpoint."""
        self._refuse_redirected_path(self.path)
        with SingleFlightLock(self.root):
            self._refuse_redirected_path(self.path)
            self._transition("RUNNING", "INTERRUPTED")
            return self.status()
