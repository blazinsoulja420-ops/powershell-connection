"""Transactional Exact Relay v2 ledger (candidate; NOT activated by v1).

SQLite is authoritative after migration. Never run a v1 watcher or relay-run
against the same state directory after v2 activation; the v1 text files do not
participate in v2's transaction and cannot enforce its replay guarantees.
"""
from __future__ import annotations

import hashlib
from contextlib import closing
import json
import secrets
import sqlite3
from datetime import datetime, timezone
from pathlib import Path


class RelayLedgerV2:
    """Durable, cross-process atomic consume/rotate using SQLite transactions."""

    def __init__(self, state_dir: str | Path):
        self.root = Path(state_dir).expanduser().resolve() / "relay"
        self.root.mkdir(parents=True, exist_ok=True)
        self.path = self.root / "relay_v2.sqlite3"
        self.legacy_nonce = self.root / "nonce.txt"
        self.legacy_seen = self.root / "seen_tasks.jsonl"
        self._initialize()

    @staticmethod
    def _new_nonce() -> str:
        return secrets.token_urlsafe(32)

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.path), timeout=30, isolation_level=None)
        conn.execute("PRAGMA busy_timeout=30000")
        conn.execute("PRAGMA synchronous=FULL")
        return conn

    def _initialize(self) -> None:
        with closing(self._connect()) as conn:
            conn.execute("BEGIN IMMEDIATE")
            try:
                conn.execute(
                    "CREATE TABLE IF NOT EXISTS state "
                    "(key TEXT PRIMARY KEY, value TEXT NOT NULL)"
                )
                conn.execute(
                    "CREATE TABLE IF NOT EXISTS consumed "
                    "(task_id TEXT PRIMARY KEY, sha256 TEXT NOT NULL, "
                    "nonce_sha256 TEXT UNIQUE, consumed_at_utc TEXT NOT NULL)"
                )
                initialized = conn.execute(
                    "SELECT value FROM state WHERE key='current_nonce'"
                ).fetchone()
                if initialized is None:
                    # One-time migration from a stopped v1 installation.
                    # Force a fresh nonce on first activation: a crashed v1
                    # process may have appended a task without rotating nonce.
                    # A copied v1 task must NEVER survive migration.
                    nonce = self._new_nonce()
                    if self.legacy_seen.exists():
                        with self.legacy_seen.open("r", encoding="utf-8") as source:
                            for line_number, line in enumerate(source, start=1):
                                try:
                                    record = json.loads(line)
                                except json.JSONDecodeError as exc:
                                    raise ValueError(
                                        f"corrupt legacy relay ledger at line {line_number}"
                                    ) from exc
                                if not isinstance(record, dict):
                                    raise ValueError("invalid legacy relay ledger record")
                                task_id = record.get("task_id")
                                if not isinstance(task_id, str) or not task_id:
                                    raise ValueError("invalid legacy relay ledger task ID")
                                digest = record.get("sha256", "")
                                if not isinstance(digest, str):
                                    raise ValueError("invalid legacy relay ledger digest")
                                conn.execute(
                                    "INSERT OR IGNORE INTO consumed "
                                    "(task_id, sha256, nonce_sha256, consumed_at_utc) "
                                    "VALUES (?, ?, NULL, ?)",
                                    (task_id, digest, str(record.get("consumed_at_utc", ""))),
                                )
                    conn.execute(
                        "INSERT INTO state (key, value) VALUES ('current_nonce', ?)",
                        (nonce,),
                    )
                conn.execute("COMMIT")
            except BaseException:
                conn.execute("ROLLBACK")
                raise

    def current_nonce(self) -> str:
        with closing(self._connect()) as conn:
            row = conn.execute(
                "SELECT value FROM state WHERE key='current_nonce'"
            ).fetchone()
        if row is None or not row[0]:
            raise RuntimeError("relay v2 state missing/empty: fail closed")
        return str(row[0])

    def seen_task_ids(self) -> set[str]:
        with closing(self._connect()) as conn:
            return {row[0] for row in conn.execute("SELECT task_id FROM consumed")}

    def has_seen(self, task_id: str) -> bool:
        """Indexed SQLite replay lookup, avoiding full-history scans/copies.

        Read-only precheck is advisory; consume() rechecks under BEGIN IMMEDIATE.
        """
        if not isinstance(task_id, str) or not task_id:
            raise ValueError("invalid task_id")
        with closing(self._connect()) as conn:
            row = conn.execute(
                "SELECT 1 FROM consumed WHERE task_id=? LIMIT 1", (task_id,)
            ).fetchone()
        return row is not None

    def consume(self, task_id: str, digest: str, supplied_nonce: str) -> str:
        if not isinstance(task_id, str) or not task_id:
            raise ValueError("invalid task_id")
        if not isinstance(supplied_nonce, str) or not supplied_nonce:
            raise ValueError("invalid relay nonce")
        with closing(self._connect()) as conn:
            conn.execute("BEGIN IMMEDIATE")
            try:
                row = conn.execute(
                    "SELECT value FROM state WHERE key='current_nonce'"
                ).fetchone()
                if row is None or not row[0]:
                    raise RuntimeError("relay v2 nonce unavailable: fail closed")
                if not secrets.compare_digest(supplied_nonce, row[0]):
                    raise ValueError("relay nonce changed before task consumption")
                if conn.execute(
                    "SELECT 1 FROM consumed WHERE task_id=?", (task_id,)
                ).fetchone():
                    raise ValueError(f"task_id replay detected: {task_id}")
                nonce_hash = hashlib.sha256(supplied_nonce.encode("utf-8")).hexdigest()
                next_nonce = self._new_nonce()
                conn.execute(
                    "INSERT INTO consumed "
                    "(task_id, sha256, nonce_sha256, consumed_at_utc) "
                    "VALUES (?, ?, ?, ?)",
                    (
                        task_id,
                        digest,
                        nonce_hash,
                        datetime.now(timezone.utc).isoformat(),
                    ),
                )
                conn.execute(
                    "UPDATE state SET value=? WHERE key='current_nonce'",
                    (next_nonce,),
                )
                conn.execute("COMMIT")
                return next_nonce
            except BaseException:
                conn.execute("ROLLBACK")
                raise
