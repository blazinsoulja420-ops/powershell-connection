from __future__ import annotations

import json
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .security import redact


class EvidenceLog:
    def __init__(self, state_dir: str | Path, max_output_chars: int = 40000):
        self.state_dir = Path(state_dir).expanduser().resolve()
        self.session_id = uuid.uuid4().hex
        self.session_dir = self.state_dir / "sessions" / self.session_id
        self.backup_dir = self.session_dir / "backups"
        self.session_dir.mkdir(parents=True, exist_ok=True)
        self.backup_dir.mkdir(parents=True, exist_ok=True)
        self.log_path = self.session_dir / "evidence.jsonl"
        self.max_output_chars = max_output_chars

    def append(self, event: dict[str, Any]) -> None:
        safe = dict(event)
        safe["session_id"] = self.session_id
        safe["timestamp_utc"] = datetime.now(timezone.utc).isoformat()
        for key in ("stdout", "stderr", "output", "command"):
            if key in safe and isinstance(safe[key], str):
                safe[key] = redact(safe[key], self.max_output_chars)
        with self.log_path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(safe, ensure_ascii=False, sort_keys=True) + "\n")

    def backup_path_for(self, rel_path: str) -> Path:
        safe = rel_path.replace("\\", "/").strip("/")
        dest = self.backup_dir / safe
        dest.parent.mkdir(parents=True, exist_ok=True)
        return dest

    def backup_path_for_write(self, rel_path: str, sequence: int) -> Path:
        safe = rel_path.replace("\\", "/").strip("/")
        base = self.backup_dir / safe
        base.parent.mkdir(parents=True, exist_ok=True)
        return base.with_name(base.name + f".write-{sequence:04d}.bak")
