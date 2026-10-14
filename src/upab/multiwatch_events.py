"""Windows native, read-only multi-project filesystem event listener.

Never reads the clipboard or invokes tasks. Windows change notifications name a
project, not file contents. The existing UPAB relay is not activated.
"""
from __future__ import annotations

import argparse
import ctypes
import json
import sys
from ctypes import wintypes

from .multiwatch import ProjectRegistry, RegistryError

_NOTIFY_MASK = 0x0001 | 0x0002 | 0x0008 | 0x0010
_WAIT_OBJECT_0 = 0
_WAIT_TIMEOUT = 258
_WAIT_FAILED = 0xFFFFFFFF
_ERROR_ALREADY_EXISTS = 183
_INVALID_HANDLE = ctypes.c_void_p(-1).value
_LOCK_NAME = r"Local\UPAB.MultiProject.ReadOnlyEvents.v1"


class EventWatcherError(RuntimeError):
    pass


class WindowsProjectEvents:
    """Exactly one observer per Windows interactive session; no task executor."""

    def __init__(self, registry: ProjectRegistry):
        if sys.platform != "win32":
            raise EventWatcherError("Windows filesystem events require Windows")
        # Validate ALL active project origins first. No partially armed observer.
        registry.preflight()
        active = [p for p in registry.projects if p.watch_enabled]
        if not active:
            raise EventWatcherError("no active project preflight profiles")
        if len(active) > 32:
            raise EventWatcherError("too many projects for bounded Windows observer")
        self._ids = tuple(profile.id for profile in active)
        self._paths = tuple(str(profile.root) for profile in active)
        self._kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        k = self._kernel
        k.CreateMutexW.argtypes = [wintypes.LPVOID, wintypes.BOOL, wintypes.LPCWSTR]
        k.CreateMutexW.restype = wintypes.HANDLE
        k.CloseHandle.argtypes = [wintypes.HANDLE]
        k.CloseHandle.restype = wintypes.BOOL
        k.FindFirstChangeNotificationW.argtypes = [
            wintypes.LPCWSTR, wintypes.BOOL, wintypes.DWORD
        ]
        k.FindFirstChangeNotificationW.restype = wintypes.HANDLE
        k.FindNextChangeNotification.argtypes = [wintypes.HANDLE]
        k.FindNextChangeNotification.restype = wintypes.BOOL
        k.FindCloseChangeNotification.argtypes = [wintypes.HANDLE]
        k.FindCloseChangeNotification.restype = wintypes.BOOL
        k.WaitForMultipleObjects.argtypes = [
            wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE),
            wintypes.BOOL, wintypes.DWORD,
        ]
        k.WaitForMultipleObjects.restype = wintypes.DWORD
        self._mutex = None
        self._handles: list[int] = []
        self._started = False
        self._cursor = 0

    def __enter__(self) -> "WindowsProjectEvents":
        if self._started:
            raise EventWatcherError("watcher already started")
        k = self._kernel
        mutex = k.CreateMutexW(None, True, _LOCK_NAME)
        if not mutex:
            raise EventWatcherError("unable to acquire Windows observer mutex")
        if ctypes.get_last_error() == _ERROR_ALREADY_EXISTS:
            k.CloseHandle(mutex)
            raise EventWatcherError("another read-only multi-project observer is running")
        self._mutex = mutex
        try:
            for root in self._paths:
                handle = k.FindFirstChangeNotificationW(root, True, _NOTIFY_MASK)
                if not handle or int(handle) == _INVALID_HANDLE:
                    raise EventWatcherError("failed to subscribe to a project folder")
                self._handles.append(handle)
            self._started = True
            return self
        except BaseException:
            self.close()
            raise

    def close(self) -> None:
        for handle in self._handles:
            self._kernel.FindCloseChangeNotification(handle)
        self._handles.clear()
        if self._mutex:
            self._kernel.ReleaseMutex.argtypes = [wintypes.HANDLE]
            self._kernel.ReleaseMutex.restype = wintypes.BOOL
            self._kernel.ReleaseMutex(self._mutex)
            self._kernel.CloseHandle(self._mutex)
            self._mutex = None
        self._started = False

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.close()

    def wait_once(self, timeout_ms: int = 1000) -> str | None:
        """Return the changed *project ID*, or None on timeout."""
        if not self._started:
            raise EventWatcherError("observer is not running")
        if type(timeout_ms) is not int or not 0 <= timeout_ms <= 10000:
            raise ValueError("timeout_ms must be within 0..10000")
        count = len(self._handles)
        # Round-robin ordering prevents one noisy project from starving others.
        ordered = self._handles[self._cursor:] + self._handles[:self._cursor]
        arr = (wintypes.HANDLE * count)(*ordered)
        outcome = self._kernel.WaitForMultipleObjects(count, arr, False, timeout_ms)
        if outcome == _WAIT_TIMEOUT:
            return None
        offset = int(outcome) - _WAIT_OBJECT_0
        if outcome == _WAIT_FAILED or not 0 <= offset < count:
            raise EventWatcherError("Windows change observer wait failed")
        index = (self._cursor + offset) % count
        self._cursor = (index + 1) % count
        if not self._kernel.FindNextChangeNotification(self._handles[index]):
            raise EventWatcherError("unable to rearm a Windows folder notification")
        return self._ids[index]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Read-only Windows five-project event observer")
    parser.add_argument("--config", required=True)
    parser.add_argument("--once", action="store_true", help="Return after one repository change")
    args = parser.parse_args(argv)
    try:
        registry = ProjectRegistry.from_file(args.config)
        with WindowsProjectEvents(registry) as watcher:
            print("MULTIPROJECT_READ_ONLY_EVENTS_STARTED", flush=True)
            while True:
                project = watcher.wait_once()
                if project:
                    print(json.dumps({"project_id": project, "event": "folder_changed"}), flush=True)
                    if args.once:
                        return 0
    except KeyboardInterrupt:
        return 130
    except (RegistryError, EventWatcherError) as exc:
        print(f"MULTIPROJECT_EVENTS_BLOCKED: {exc}", file=sys.stderr)
        return 7


if __name__ == "__main__":
    raise SystemExit(main())
