from __future__ import annotations

import json
import secrets
from datetime import datetime, timezone
from pathlib import Path


class RelayLedger:
    def __init__(self, state_dir: str | Path):
        self.root = Path(state_dir).expanduser().resolve() / "relay"
        self.root.mkdir(parents=True, exist_ok=True)
        self.nonce_path = self.root / "nonce.txt"
        self.seen_path = self.root / "seen_tasks.jsonl"
        if not self.nonce_path.exists():
            self._write_nonce(self._new_nonce())

    @staticmethod
    def _new_nonce() -> str:
        return secrets.token_urlsafe(24)

    def _write_nonce(self, value: str) -> None:
        tmp = self.nonce_path.with_suffix(".tmp")
        tmp.write_text(value + "\n", encoding="utf-8")
        tmp.replace(self.nonce_path)

    def current_nonce(self) -> str:
        value = self.nonce_path.read_text(encoding="utf-8").strip()
        if not value:
            value = self._new_nonce()
            self._write_nonce(value)
        return value

    def seen_task_ids(self) -> set[str]:
        if not self.seen_path.exists():
            return set()
        seen: set[str] = set()
        for line in self.seen_path.read_text(encoding="utf-8").splitlines():
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue
            task_id = record.get("task_id")
            if isinstance(task_id, str):
                seen.add(task_id)
        return seen

    def consume(self, task_id: str, digest: str, supplied_nonce: str) -> str:
        if task_id in self.seen_task_ids():
            raise ValueError(f"task_id replay detected: {task_id}")
        current = self.current_nonce()
        if supplied_nonce != current:
            raise ValueError("relay nonce changed before task consumption")
        next_nonce = self._new_nonce()
        record = {
            "task_id": task_id,
            "sha256": digest,
            "consumed_at_utc": datetime.now(timezone.utc).isoformat(),
            "nonce_sha256_prefix": __import__("hashlib").sha256(current.encode()).hexdigest()[:16].upper(),
        }
        with self.seen_path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(record, sort_keys=True) + "\n")
        self._write_nonce(next_nonce)
        return next_nonce
