"""Durable reviewer checkpoints for Watcher v3; non-executable by design.

A REVIEW_COMPLETED checkpoint is not a permit to execute anything. No task
payload, secret, repository path or clipboard text is stored.
"""
from __future__ import annotations

from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path
import sqlite3

from .v3_policy import PolicyBlocked, ReviewJob

_ALLOWED_TRANSITIONS = {
    "PROPOSED": frozenset({"REVIEW_STARTED", "DISMISSED"}),
    "REVIEW_STARTED": frozenset({"REVIEW_COMPLETED", "DISMISSED", "INTERRUPTED"}),
    "INTERRUPTED": frozenset({"DISMISSED"}),
    "REVIEW_COMPLETED": frozenset(),
    "DISMISSED": frozenset(),
}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class CheckpointStore:
    """Atomic non-authorizing review lifecycle, safe across process restarts."""

    def __init__(self, state_dir: str | Path, *, max_records: int = 4096):
        if type(max_records) is not int or not 1 <= max_records <= 65536:
            raise PolicyBlocked("invalid checkpoint row bound")
        self.max_records = max_records
        root = Path(state_dir).expanduser().resolve() / "relay"
        root.mkdir(parents=True, exist_ok=True)
        self.path = root / "v3_checkpoints.sqlite3"
        with closing(self._connect()) as db:
            db.execute(
                "CREATE TABLE IF NOT EXISTS reviews "
                "(task_id TEXT PRIMARY KEY, digest TEXT NOT NULL, "
                "phase TEXT NOT NULL CHECK(phase IN "
                "('PROPOSED','REVIEW_STARTED','REVIEW_COMPLETED','INTERRUPTED','DISMISSED')), "
                "created TEXT NOT NULL, updated TEXT NOT NULL)"
            )

    def _connect(self) -> sqlite3.Connection:
        db = sqlite3.connect(str(self.path), isolation_level=None, timeout=10)
        db.execute("PRAGMA busy_timeout=10000")
        db.execute("PRAGMA synchronous=FULL")
        return db

    def propose(self, task_id: str, digest: str) -> str:
        validated = ReviewJob(task_id=task_id, digest=digest)
        with closing(self._connect()) as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                if db.execute("SELECT 1 FROM reviews WHERE task_id=?", (task_id,)).fetchone():
                    raise PolicyBlocked("checkpoint identifier already exists")
                rows = db.execute("SELECT count(*) FROM reviews").fetchone()[0]
                if rows >= self.max_records:
                    raise PolicyBlocked("checkpoint store bound reached")
                ts = _now()
                db.execute(
                    "INSERT INTO reviews(task_id,digest,phase,created,updated) "
                    "VALUES (?,?,'PROPOSED',?,?)",
                    (validated.task_id, validated.digest.upper(), ts, ts),
                )
                db.execute("COMMIT")
                return "PROPOSED"
            except BaseException:
                db.execute("ROLLBACK")
                raise

    def transition(self, task_id: str, *, expected_digest: str, next_phase: str) -> str:
        validated = ReviewJob(task_id=task_id, digest=expected_digest)
        if next_phase not in _ALLOWED_TRANSITIONS:
            raise PolicyBlocked("unknown checkpoint phase")
        with closing(self._connect()) as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                row = db.execute(
                    "SELECT digest,phase FROM reviews WHERE task_id=?", (task_id,)
                ).fetchone()
                if row is None or row[0] != validated.digest.upper():
                    raise PolicyBlocked("checkpoint digest mismatch or missing record")
                if next_phase not in _ALLOWED_TRANSITIONS[row[1]]:
                    raise PolicyBlocked("checkpoint transition not allowed")
                db.execute(
                    "UPDATE reviews SET phase=?,updated=? WHERE task_id=?",
                    (next_phase, _now(), task_id),
                )
                db.execute("COMMIT")
                return next_phase
            except BaseException:
                db.execute("ROLLBACK")
                raise

    def reconcile_interrupted(self) -> int:
        """Call only after exclusive single-flight lock; never requeue or execute."""
        with closing(self._connect()) as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                changed = db.execute(
                    "UPDATE reviews SET phase='INTERRUPTED',updated=? "
                    "WHERE phase='REVIEW_STARTED'", (_now(),)
                ).rowcount
                db.execute("COMMIT")
                return changed
            except BaseException:
                db.execute("ROLLBACK")
                raise

    def status(self, task_id: str) -> dict[str, object] | None:
        if not isinstance(task_id, str) or not task_id:
            raise PolicyBlocked("invalid task identifier")
        with closing(self._connect()) as db:
            row = db.execute(
                "SELECT phase,digest FROM reviews WHERE task_id=?", (task_id,)
            ).fetchone()
        if row is None:
            return None
        return {
            "task_id": task_id,
            "phase": row[0],
            "digest": row[1],
            "execution_authorized": False,
            "can_auto_resume": False,
        }

    def summary(self) -> dict[str, object]:
        with closing(self._connect()) as db:
            counts = dict(db.execute("SELECT phase,count(*) FROM reviews GROUP BY phase"))
        return {
            "max_records": self.max_records,
            "counts": counts,
            "execution_enabled": False,
            "replay_enabled": False,
        }
