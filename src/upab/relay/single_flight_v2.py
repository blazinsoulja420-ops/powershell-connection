"""Cross-process single-flight guard for a future Watcher v2 runtime.

Not connected to legacy v1, to any repo, or to a task execution entrypoint.
This guard prevents two cooperating v2 runtimes sharing the same state
directory from concurrently processing tasks. Non-cooperating v1 processes
do NOT respect it: v1 lockout remains a separate activation gate.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import BinaryIO


class WatcherAlreadyRunning(RuntimeError):
    pass


class SingleFlightLock:
    def __init__(self, state_dir: str | Path):
        self.root = Path(state_dir).expanduser().resolve() / "relay"
        self.path = self.root / "watcher_v2.lock"
        self._file: BinaryIO | None = None

    def __enter__(self) -> "SingleFlightLock":
        if self._file is not None:
            raise WatcherAlreadyRunning("single-flight lock already held")
        self.root.mkdir(parents=True, exist_ok=True)
        # Lock a distinct, persistent file inside the per-watcher state root.
        # The file is deliberately NOT deleted after release: removing a lock
        # pathname while another process races to open it breaks exclusivity.
        handle = self.path.open("a+b")
        try:
            handle.seek(0, os.SEEK_END)
            if handle.tell() == 0:
                handle.write(b"\x00")
                handle.flush()
            handle.seek(0)
            try:
                if sys.platform == "win32":
                    import msvcrt
                    msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
                else:
                    import fcntl
                    fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            except (OSError, BlockingIOError) as exc:
                raise WatcherAlreadyRunning("another v2 runtime holds the state lock") from exc
            self._file = handle
            return self
        except BaseException:
            handle.close()
            raise

    def close(self) -> None:
        handle = self._file
        self._file = None
        if handle is None:
            return
        try:
            handle.seek(0)
            if sys.platform == "win32":
                import msvcrt
                msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                import fcntl
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
        finally:
            handle.close()

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.close()
