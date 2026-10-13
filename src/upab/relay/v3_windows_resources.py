"""Read-only Windows CPU/RAM sampler for the Watcher v3 admission policy.

No network, model, repository reads, task scheduling, privilege changes or
execution. A valid resource sample is a suggestion, not an approval.
"""
from __future__ import annotations

import ctypes
from ctypes import wintypes
import sys
import time
from typing import Callable

from .v3_policy import PolicyBlocked, ResourceSample, review_admission_allowed


class FILETIME(ctypes.Structure):
    _fields_ = [
        ("dwLowDateTime", wintypes.DWORD),
        ("dwHighDateTime", wintypes.DWORD),
    ]


class MEMORYSTATUSEX(ctypes.Structure):
    _fields_ = [
        ("dwLength", wintypes.DWORD),
        ("dwMemoryLoad", wintypes.DWORD),
        ("ullTotalPhys", ctypes.c_ulonglong),
        ("ullAvailPhys", ctypes.c_ulonglong),
        ("ullTotalPageFile", ctypes.c_ulonglong),
        ("ullAvailPageFile", ctypes.c_ulonglong),
        ("ullTotalVirtual", ctypes.c_ulonglong),
        ("ullAvailVirtual", ctypes.c_ulonglong),
        ("ullAvailExtendedVirtual", ctypes.c_ulonglong),
    ]


def _ticks(value: FILETIME) -> int:
    return (int(value.dwHighDateTime) << 32) | int(value.dwLowDateTime)


def compute_cpu_load(before: tuple[int, int, int], after: tuple[int, int, int]) -> float:
    """GetSystemTimes cumulative idle, kernel, user counters.

    Total system busy percentage = 100 * (1 - idle / (kernel + user)).
    Idle time is included in the Windows kernel time value.
    """
    if not all(type(x) is int and x >= 0 for x in (*before, *after)):
        raise PolicyBlocked("invalid CPU counters")
    diffs = tuple(b - a for a,b in zip(before, after))
    if min(diffs) < 0 or (diffs[1] + diffs[2]) <= 0 or diffs[0] > diffs[1]:
        raise PolicyBlocked("invalid CPU counter interval")
    return max(0.0, min(100.0, 100.0 * (1 - diffs[0] / (diffs[1] + diffs[2]))))


def sample_windows_resources(
    *, interval_seconds: float = 0.1,
    sleep: Callable[[float], None] = time.sleep,
) -> ResourceSample:
    """Bounded read-only sample of system-wide CPU and available physical RAM."""
    if sys.platform != "win32":
        raise PolicyBlocked("Windows resource sampler requires Windows")
    if (type(interval_seconds) not in (int, float)
            or not 0.05 <= interval_seconds <= 2.0):
        raise PolicyBlocked("sample interval must be 0.05..2.0 seconds")

    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.GetSystemTimes.argtypes = [
        ctypes.POINTER(FILETIME), ctypes.POINTER(FILETIME),
        ctypes.POINTER(FILETIME),
    ]
    kernel.GetSystemTimes.restype = wintypes.BOOL
    kernel.GlobalMemoryStatusEx.argtypes = [ctypes.POINTER(MEMORYSTATUSEX)]
    kernel.GlobalMemoryStatusEx.restype = wintypes.BOOL

    def counters() -> tuple[int, int, int]:
        idle, kernel_time, user_time = FILETIME(), FILETIME(), FILETIME()
        if not kernel.GetSystemTimes(
            ctypes.byref(idle), ctypes.byref(kernel_time), ctypes.byref(user_time)
        ):
            raise PolicyBlocked("Windows CPU counters unavailable")
        return _ticks(idle), _ticks(kernel_time), _ticks(user_time)

    before = counters()
    sleep(interval_seconds)
    after = counters()
    memory = MEMORYSTATUSEX()
    memory.dwLength = ctypes.sizeof(MEMORYSTATUSEX)
    if not kernel.GlobalMemoryStatusEx(ctypes.byref(memory)):
        raise PolicyBlocked("Windows memory counters unavailable")
    available_mb = int(memory.ullAvailPhys // (1024 * 1024))
    return ResourceSample(compute_cpu_load(before, after), available_mb)


def admission_snapshot() -> dict[str, object]:
    sample = sample_windows_resources()
    return {
        "schema": "upab.watcher-v3.resource-preview.v1",
        "cpu_percent": round(sample.cpu_percent, 2),
        "available_memory_mb": sample.available_memory_mb,
        "review_admission_suggested": review_admission_allowed(sample),
        "task_execution_enabled": False,
        "owner_authorized": False,
    }
