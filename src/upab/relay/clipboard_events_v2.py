"""Passive, event-driven Windows Clipboard observation for Watcher v2 candidates.

IMPORTANT: Not a task runner. This module NEVER invokes the relay pipeline,
consumes a nonce, writes to the clipboard, or changes any repository.
"""
from __future__ import annotations

import argparse
import ctypes
import hashlib
import json
import sys
import time
from ctypes import wintypes
from dataclasses import dataclass
from typing import Any, Callable

from ..config import load_config
from .schema import TASK_BEGIN, TASK_END

WM_CLIPBOARDUPDATE = 0x031D
QS_ALLINPUT = 0x04FF
MWMO_INPUTAVAILABLE = 0x0004
PM_REMOVE = 1
WAIT_TIMEOUT = 258
ERROR_ALREADY_EXISTS = 183
_HWND_MESSAGE = -3
_MUTEX_NAME = r"Local\UPAB.WatcherV2.ClipboardEvents.Candidate"


class ClipboardEventError(RuntimeError):
    pass


class WindowsClipboardEvents:
    """Native clipboard notifications, no 500-ms content polling.

    Registration and pumping must happen on the SAME owning Windows thread.
    A per-session named mutex prevents competing instances of THIS candidate;
    it does not lock out legacy v1, so do not integrate task execution here.
    """

    def __init__(self):
        if sys.platform != "win32":
            raise ClipboardEventError("native clipboard events require Windows")
        self.user32 = ctypes.WinDLL("user32", use_last_error=True)
        self.kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        u, k = self.user32, self.kernel32
        k.CreateMutexW.argtypes = [wintypes.LPVOID, wintypes.BOOL, wintypes.LPCWSTR]
        k.CreateMutexW.restype = wintypes.HANDLE
        k.ReleaseMutex.argtypes = [wintypes.HANDLE]
        k.ReleaseMutex.restype = wintypes.BOOL
        k.CloseHandle.argtypes = [wintypes.HANDLE]
        k.CloseHandle.restype = wintypes.BOOL
        u.CreateWindowExW.argtypes = [
            wintypes.DWORD, wintypes.LPCWSTR, wintypes.LPCWSTR,
            wintypes.DWORD, ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_int,
            wintypes.HWND, wintypes.HMENU, wintypes.HINSTANCE, wintypes.LPVOID,
        ]
        u.CreateWindowExW.restype = wintypes.HWND
        u.DestroyWindow.argtypes = [wintypes.HWND]
        u.DestroyWindow.restype = wintypes.BOOL
        u.AddClipboardFormatListener.argtypes = [wintypes.HWND]
        u.AddClipboardFormatListener.restype = wintypes.BOOL
        u.RemoveClipboardFormatListener.argtypes = [wintypes.HWND]
        u.RemoveClipboardFormatListener.restype = wintypes.BOOL
        u.MsgWaitForMultipleObjectsEx.argtypes = [
            wintypes.DWORD, ctypes.c_void_p, wintypes.DWORD,
            wintypes.DWORD, wintypes.DWORD,
        ]
        u.MsgWaitForMultipleObjectsEx.restype = wintypes.DWORD
        u.PeekMessageW.argtypes = [
            ctypes.POINTER(wintypes.MSG), wintypes.HWND,
            wintypes.UINT, wintypes.UINT, wintypes.UINT,
        ]
        u.PeekMessageW.restype = wintypes.BOOL
        u.TranslateMessage.argtypes = [ctypes.POINTER(wintypes.MSG)]
        u.TranslateMessage.restype = wintypes.BOOL
        u.DispatchMessageW.argtypes = [ctypes.POINTER(wintypes.MSG)]
        u.DispatchMessageW.restype = wintypes.LPARAM

        self._hwnd = None
        self._mutex = None
        self._listening = False

    def __enter__(self) -> "WindowsClipboardEvents":
        if self._mutex or self._hwnd:
            raise ClipboardEventError("event source is already started")
        mutex = self.kernel32.CreateMutexW(None, True, _MUTEX_NAME)
        if not mutex:
            raise ClipboardEventError("could not claim the event-observer mutex")
        if ctypes.get_last_error() == ERROR_ALREADY_EXISTS:
            self.kernel32.CloseHandle(mutex)
            raise ClipboardEventError("another watcher v2 observer already exists")
        self._mutex = mutex
        try:
            # Built-in STATIC class; message-only window, never visible.
            hwnd = self.user32.CreateWindowExW(
                0, "STATIC", "UPAB_WATCHER_V2_PASSIVE", 0,
                0, 0, 0, 0, ctypes.c_void_p(_HWND_MESSAGE),
                None, None, None,
            )
            if not hwnd:
                raise ClipboardEventError("could not create clipboard event window")
            self._hwnd = hwnd
            if not self.user32.AddClipboardFormatListener(hwnd):
                raise ClipboardEventError("could not register clipboard notifications")
            self._listening = True
            return self
        except BaseException:
            self.close()
            raise

    def close(self) -> None:
        if self._hwnd:
            if self._listening:
                self.user32.RemoveClipboardFormatListener(self._hwnd)
            self.user32.DestroyWindow(self._hwnd)
            self._hwnd = None
            self._listening = False
        if self._mutex:
            self.kernel32.ReleaseMutex(self._mutex)
            self.kernel32.CloseHandle(self._mutex)
            self._mutex = None

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.close()

    def wait_for_change(self, timeout_ms: int = 1000) -> bool:
        if not self._listening:
            raise ClipboardEventError("clipboard event listener is not started")
        if type(timeout_ms) is not int or not 0 <= timeout_ms <= 10000:
            raise ValueError("timeout_ms must be 0..10000")
        result = self.user32.MsgWaitForMultipleObjectsEx(
            0, None, timeout_ms, QS_ALLINPUT, MWMO_INPUTAVAILABLE
        )
        if result == WAIT_TIMEOUT:
            return False
        if result != 0:
            raise ClipboardEventError("Win32 event wait failed")
        msg = wintypes.MSG()
        changed = False
        while self.user32.PeekMessageW(ctypes.byref(msg), self._hwnd, 0, 0, PM_REMOVE):
            if msg.message == WM_CLIPBOARDUPDATE:
                changed = True
            self.user32.TranslateMessage(ctypes.byref(msg))
            self.user32.DispatchMessageW(ctypes.byref(msg))
        return changed


@dataclass(frozen=True)
class Observation:
    kind: str
    retryable: bool = False


class PassiveClipboardObserver:
    """Digest-only observer with startup suppression and bounded reading.

    The event source signals a change. Caller injects the clipboard reader.
    A simple bounded retry handles transient OpenClipboard ownership contention.
    This is deliberately synchronous and has NO executor/command/callback.
    """

    def __init__(
        self, clipboard: Any, *, max_text_chars: int = 131072,
        attempts: int = 3, retry_delay_seconds: float = 0.025,
        sleep: Callable[[float], None] = time.sleep,
    ):
        if type(max_text_chars) is not int or not 256 <= max_text_chars <= 1048576:
            raise ValueError("max_text_chars must be 256..1048576")
        if type(attempts) is not int or not 1 <= attempts <= 5:
            raise ValueError("attempts must be 1..5")
        if not 0 <= retry_delay_seconds <= 0.2:
            raise ValueError("retry_delay_seconds must be 0..0.2")
        self.clipboard = clipboard
        self.max_text_chars = max_text_chars
        self.attempts = attempts
        self.retry_delay_seconds = retry_delay_seconds
        self.sleep = sleep
        self._last_digest: str | None = None
        self._started = False
        self.counts = {
            "events": 0,
            "duplicates": 0,
            "too_large": 0,
            "read_errors": 0,
            "ignored": 0,
            "candidates": 0,
        }

    def _snapshot(self) -> str:
        for i in range(self.attempts):
            try:
                # A read-limited clipboard adapter may fail before decoding
                # oversized payloads; an ordinary v1 clipboard reader isn't
                # memory-bounded until after the text has been returned.
                reader = getattr(self.clipboard, "get_text_limited", None)
                value = reader(self.max_text_chars) if reader is not None else self.clipboard.get_text()
                if not isinstance(value, str):
                    raise ClipboardEventError("clipboard returned non-text data")
                return value
            except Exception as exc:
                if isinstance(exc, ClipboardTooLarge):
                    raise
                if i == self.attempts - 1:
                    raise ClipboardEventError("clipboard read unavailable") from exc
                self.sleep(self.retry_delay_seconds * (i + 1))
        raise AssertionError("unreachable")

    def suppress_startup(self) -> Observation:
        if self._started:
            raise ClipboardEventError("startup snapshot already taken")
        # Fail closed if clipboard is inaccessible: do not arm with an
        # unknown startup clipboard, which might contain an old task.
        try:
            current = self._snapshot()
        except ClipboardTooLarge:
            current = None
        if current is not None and len(current) <= self.max_text_chars:
            self._last_digest = hashlib.sha256(current.encode("utf-8")).hexdigest()
        self._started = True
        return Observation("STARTUP_SUPPRESSED")

    def on_change(self) -> Observation:
        if not self._started:
            raise ClipboardEventError("startup snapshot is required")
        self.counts["events"] += 1
        try:
            current = self._snapshot()
        except ClipboardTooLarge:
            self.counts["too_large"] += 1
            return Observation("OVERSIZE_IGNORED")
        except ClipboardEventError:
            self.counts["read_errors"] += 1
            return Observation("READ_UNAVAILABLE", retryable=True)
        if len(current) > self.max_text_chars:
            self.counts["too_large"] += 1
            return Observation("OVERSIZE_IGNORED")
        digest = hashlib.sha256(current.encode("utf-8")).hexdigest()
        if digest == self._last_digest:
            self.counts["duplicates"] += 1
            return Observation("DUPLICATE_IGNORED")
        self._last_digest = digest
        stripped = current.strip()
        if stripped.startswith(TASK_BEGIN) and stripped.endswith(TASK_END):
            self.counts["candidates"] += 1
            return Observation("TASK_CANDIDATE_OBSERVED")
        self.counts["ignored"] += 1
        return Observation("NON_TASK_IGNORED")


class ClipboardTooLarge(ClipboardEventError):
    """A bounded clipboard adapter refused a large payload."""


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Observe clipboard task-candidate notifications; never execute"
    )
    parser.add_argument("--once", action="store_true")
    parser.add_argument("--max-events", type=int, default=0)
    args = parser.parse_args(argv)
    if args.max_events < 0 or args.max_events > 10000:
        parser.error("--max-events must be 0..10000")
    try:
        from .clipboard import WindowsClipboard

        with WindowsClipboardEvents() as source:
            observer = PassiveClipboardObserver(WindowsClipboard())
            observer.suppress_startup()
            print("UPAB_WATCHER_V2_PASSIVE_OBSERVER_STARTED", flush=True)
            while True:
                if source.wait_for_change(1000):
                    event = observer.on_change()
                    print(json.dumps({"event": event.kind, "retryable": event.retryable}), flush=True)
                    if args.once or (args.max_events and observer.counts["events"] >= args.max_events):
                        return 0
    except KeyboardInterrupt:
        return 130
    except (ClipboardEventError, OSError) as exc:
        print("WATCHER_V2_OBSERVER_BLOCKED: " + type(exc).__name__, file=sys.stderr)
        return 7


if __name__ == "__main__":
    raise SystemExit(main())
