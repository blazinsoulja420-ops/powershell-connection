"""Watcher v2 metadata-only bounded review queue. NOT an executor.

Only task ID and digest are durable. There is no approval or execution API.
"""
from __future__ import annotations

import re
import sqlite3
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path

_TASK_ID = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
_DIGEST = re.compile(r"^[A-Fa-f0-9]{64}$")
ACTIVE = ("PENDING_REVIEW", "UNDER_REVIEW", "REVIEW_INTERRUPTED")


class QueueBlocked(ValueError):
    pass


class BoundedReviewQueue:
    def __init__(self, state_dir: str | Path, capacity: int = 8):
        if type(capacity) is not int or not 1 <= capacity <= 32:
            raise ValueError("capacity must be 1..32")
        self.capacity = capacity
        root = Path(state_dir).expanduser().resolve() / "relay"
        root.mkdir(parents=True, exist_ok=True)
        self.path = root / "review_queue_v2.sqlite3"
        with closing(self._connect()) as db:
            db.execute(
                "CREATE TABLE IF NOT EXISTS queue "
                "(task_id TEXT PRIMARY KEY, digest TEXT NOT NULL, "
                "status TEXT NOT NULL CHECK(status IN "
                "('PENDING_REVIEW','UNDER_REVIEW','REVIEW_INTERRUPTED',"
                "'DISMISSED','REVIEWED_UNAUTHORIZED')), "
                "added TEXT NOT NULL)"
            )
            db.execute("CREATE INDEX IF NOT EXISTS queue_status ON queue(status,added)")

    def _connect(self):
        db = sqlite3.connect(self.path, timeout=10, isolation_level=None)
        db.execute("PRAGMA busy_timeout=10000")
        db.execute("PRAGMA synchronous=FULL")
        return db

    def submit(self, task_id: str, digest: str) -> str:
        if not isinstance(task_id, str) or not _TASK_ID.fullmatch(task_id):
            raise QueueBlocked("invalid task id")
        if not isinstance(digest, str) or not _DIGEST.fullmatch(digest):
            raise QueueBlocked("invalid digest")
        with closing(self._connect()) as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                if db.execute("SELECT 1 FROM queue WHERE task_id=?", (task_id,)).fetchone():
                    raise QueueBlocked("duplicate task id")
                count = db.execute(
                    "SELECT count(*) FROM queue WHERE status IN (?,?,?)", ACTIVE
                ).fetchone()[0]
                if count >= self.capacity:
                    raise QueueBlocked("queue full")
                db.execute(
                    "INSERT INTO queue(task_id,digest,status,added) VALUES (?,?,?,?)",
                    (task_id, digest.upper(), "PENDING_REVIEW",
                     datetime.now(timezone.utc).isoformat()),
                )
                db.execute("COMMIT")
                return "PENDING_REVIEW"
            except BaseException:
                db.execute("ROLLBACK")
                raise

    def claim_for_review(self):
        """Claim one metadata record, not permission to run a task."""
        with closing(self._connect()) as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                if db.execute(
                    "SELECT 1 FROM queue WHERE status='UNDER_REVIEW'"
                ).fetchone():
                    db.execute("COMMIT")
                    return None
                row = db.execute(
                    "SELECT task_id,digest FROM queue "
                    "WHERE status='PENDING_REVIEW' ORDER BY added,rowid LIMIT 1"
                ).fetchone()
                if row:
                    db.execute(
                        "UPDATE queue SET status='UNDER_REVIEW' WHERE task_id=?", (row[0],)
                    )
                db.execute("COMMIT")
                return None if not row else {
                    "task_id": row[0], "digest": row[1], "execution_authorized": False
                }
            except BaseException:
                db.execute("ROLLBACK")
                raise

    def reconcile_after_exclusive_restart(self) -> int:
        """Caller MUST hold the exclusive v2 state lock before invoking."""
        with closing(self._connect()) as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                count = db.execute(
                    "UPDATE queue SET status='REVIEW_INTERRUPTED' "
                    "WHERE status='UNDER_REVIEW'"
                ).rowcount
                db.execute("COMMIT")
                return count
            except BaseException:
                db.execute("ROLLBACK")
                raise

    def dismiss(self, task_id: str) -> None:
        if not isinstance(task_id, str) or not _TASK_ID.fullmatch(task_id):
            raise QueueBlocked("invalid task id")
        with closing(self._connect()) as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                changed = db.execute(
                    "UPDATE queue SET status='DISMISSED' "
                    "WHERE task_id=? AND status IN (?,?,?)",
                    (task_id, *ACTIVE),
                ).rowcount
                if changed != 1:
                    raise QueueBlocked("task missing or already resolved")
                db.execute("COMMIT")
            except BaseException:
                db.execute("ROLLBACK")
                raise

    def summary(self):
        with closing(self._connect()) as db:
            rows = dict(db.execute("SELECT status,count(*) FROM queue GROUP BY status"))
        return {
            "capacity": self.capacity,
            "active": sum(rows.get(status, 0) for status in ACTIVE),
            "counts": rows,
            "execution_enabled": False,
            "stores_task_payload": False,
        }
