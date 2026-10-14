"""Structured, bounded diagnostic log writer. Candidate not connected to watcher.

The caller supplies an allowlisted event type and numeric duration only.
No task payloads, clipboard text, arbitrary messages or secrets can enter logs.
All multi-process users MUST hold the v2 single-flight state lock first.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import stat
import threading
from datetime import datetime, timezone

from .v3_policy import PolicyBlocked

EVENTS = frozenset({
    "observer_started", "observer_stopped", "review_queued",
    "review_dismissed", "review_interrupted", "capacity_blocked",
    "clipboard_read_retry", "watchdog_stale", "health_sample",
})


class BoundedDiagnosticLog:
    def __init__(
        self, state_dir: str | Path, *, max_bytes: int = 65536,
        archives: int = 3,
    ):
        if type(max_bytes) is not int or not 1024 <= max_bytes <= 1048576:
            raise PolicyBlocked("diagnostic log size out of range")
        if type(archives) is not int or not 1 <= archives <= 5:
            raise PolicyBlocked("diagnostic archive count out of range")
        root = Path(state_dir).expanduser().resolve() / "relay"
        root.mkdir(parents=True, exist_ok=True)
        self.path = root / "v3_diagnostics.jsonl"
        self.max_bytes = max_bytes
        self.archives = archives
        self._lock = threading.Lock()

    @staticmethod
    def _no_symlink(path: Path) -> None:
        try:
            info = path.lstat()
        except FileNotFoundError:
            return
        if stat.S_ISLNK(info.st_mode):
            raise PolicyBlocked("diagnostic target must not be a symlink")
        if not stat.S_ISREG(info.st_mode):
            raise PolicyBlocked("diagnostic target is not a regular file")

    def record(self, event: str, *, elapsed_ms: int | None = None) -> None:
        if not isinstance(event, str) or event not in EVENTS:
            raise PolicyBlocked("diagnostic event not allowlisted")
        if elapsed_ms is not None and (
            type(elapsed_ms) is not int or not 0 <= elapsed_ms <= 3600000
        ):
            raise PolicyBlocked("diagnostic latency out of range")
        item = {
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
            "event": event,
            "elapsed_ms": elapsed_ms,
        }
        wire = (json.dumps(item, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
        if len(wire) >= self.max_bytes:
            raise PolicyBlocked("log event exceeds configured bound")
        with self._lock:
            self._no_symlink(self.path)
            current = self.path.stat().st_size if self.path.exists() else 0
            if current + len(wire) > self.max_bytes:
                self._rotate()
            fd = os.open(str(self.path), os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
            try:
                with os.fdopen(fd, "ab", closefd=True) as handle:
                    handle.write(wire)
                    handle.flush()
                    os.fsync(handle.fileno())
            except BaseException:
                raise

    def _rotate(self) -> None:
        for number in range(self.archives, 0, -1):
            newer = self.path.with_name(self.path.name + "." + str(number))
            older = self.path if number == 1 else self.path.with_name(
                self.path.name + "." + str(number - 1)
            )
            self._no_symlink(newer)
            self._no_symlink(older)
            if older.exists():
                os.replace(older, newer)

    def inventory(self) -> dict[str, object]:
        files = [self.path] + [
            self.path.with_name(self.path.name + "." + str(n))
            for n in range(1, self.archives + 1)
        ]
        for item in files:
            self._no_symlink(item)
        return {
            "files": sum(int(p.exists()) for p in files),
            "total_bytes": sum(p.stat().st_size for p in files if p.exists()),
            "max_possible_bytes": self.max_bytes * (self.archives + 1),
            "content_logging_enabled": False,
        }
