"""Stage 21 authoritative Windows service and scheduled-task *snapshots*.

The Service Control Manager API enumerates registered Win32 services and
their instant status. Windows schtasks.exe /Query reads the Task Scheduler's
registered task names (including hidden/system entries visible to caller).
No task definitions, actions or credentials are exported.

Snapshots are not atomic with execution, omit inaccessible entries and do NOT
prove all old watcher processes are stopped. Every answer DENIES migration
and execution. Never starts/stops a service, registers/edits a task, or
connects an external repository.
"""
from __future__ import annotations

import csv
import ctypes
from ctypes import wintypes
import io
from pathlib import Path
import re
import subprocess
import sys

from .v3_policy import PolicyBlocked

SC_MANAGER_ENUMERATE_SERVICE = 0x0004
SC_ENUM_PROCESS_INFO = 0
SERVICE_WIN32 = 0x00000030
SERVICE_STATE_ALL = 0x00000003
ERROR_MORE_DATA = 234
MAX_SERVICES = 12000
MAX_TASKS = 12000
MAX_CSV_CHARS = 2 * 1024 * 1024
MATCH = re.compile(r"(?:upab|exact[-_ ]?relay|powershell[-_ ]?connection)", re.I)


class SERVICE_STATUS_PROCESS(ctypes.Structure):
    _fields_ = [
        ("dwServiceType", wintypes.DWORD),
        ("dwCurrentState", wintypes.DWORD),
        ("dwControlsAccepted", wintypes.DWORD),
        ("dwWin32ExitCode", wintypes.DWORD),
        ("dwServiceSpecificExitCode", wintypes.DWORD),
        ("dwCheckPoint", wintypes.DWORD),
        ("dwWaitHint", wintypes.DWORD),
        ("dwProcessId", wintypes.DWORD),
        ("dwServiceFlags", wintypes.DWORD),
    ]


class ENUM_SERVICE_STATUS_PROCESSW(ctypes.Structure):
    _fields_ = [
        ("lpServiceName", wintypes.LPWSTR),
        ("lpDisplayName", wintypes.LPWSTR),
        ("ServiceStatusProcess", SERVICE_STATUS_PROCESS),
    ]


def observe_scm_services() -> dict[str, object]:
    """SCM enumeration, never a guarantee no service starts after the scan."""
    if sys.platform != "win32":
        raise PolicyBlocked("Windows Service Control Manager required")
    adv = ctypes.WinDLL("advapi32", use_last_error=True)
    adv.OpenSCManagerW.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD]
    adv.OpenSCManagerW.restype = wintypes.HANDLE
    adv.EnumServicesStatusExW.argtypes = [
        wintypes.HANDLE, wintypes.DWORD, wintypes.DWORD, wintypes.DWORD,
        ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD),
        ctypes.POINTER(wintypes.DWORD), ctypes.POINTER(wintypes.DWORD),
        wintypes.LPCWSTR,
    ]
    adv.EnumServicesStatusExW.restype = wintypes.BOOL
    adv.CloseServiceHandle.argtypes = [wintypes.HANDLE]
    adv.CloseServiceHandle.restype = wintypes.BOOL

    handle = adv.OpenSCManagerW(None, None, SC_MANAGER_ENUMERATE_SERVICE)
    if not handle:
        raise PolicyBlocked("SCM service inventory unavailable")
    try:
        # 2 MiB is the documented upper bound accepted by this Windows API.
        # Fail closed on a partial enumeration or any ERROR_MORE_DATA.
        buffer = ctypes.create_string_buffer(2 * 1024 * 1024)
        needed, count, resume = wintypes.DWORD(), wintypes.DWORD(), wintypes.DWORD()
        ctypes.set_last_error(0)
        ok = adv.EnumServicesStatusExW(
            handle, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_STATE_ALL,
            ctypes.cast(buffer, ctypes.c_void_p), ctypes.sizeof(buffer),
            ctypes.byref(needed), ctypes.byref(count), ctypes.byref(resume), None
        )
        if not ok:
            raise PolicyBlocked("SCM service inventory incomplete or not accessible")
        if count.value > MAX_SERVICES:
            raise PolicyBlocked("SCM service result exceeds bounded count")
        entries = ctypes.cast(
            buffer, ctypes.POINTER(ENUM_SERVICE_STATUS_PROCESSW)
        )
        probable = 0
        running_probable = 0
        for i in range(count.value):
            name, label = entries[i].lpServiceName, entries[i].lpDisplayName
            if (not isinstance(name, str) or not isinstance(label, str) or
                    len(name) > 512 or len(label) > 512):
                raise PolicyBlocked("SCM returned oversized/invalid service name")
            if MATCH.search(name) or MATCH.search(label):
                probable += 1
                if entries[i].ServiceStatusProcess.dwCurrentState == 4:  # SERVICE_RUNNING
                    running_probable += 1
        return {
            "schema": "upab.watcher-v3.scm-snapshot.v1",
            "scm_access_succeeded": True,
            "win32_service_entries_observed": int(count.value),
            "possible_watcher_services_observed": probable,
            "possible_watcher_services_running_at_sample": running_probable,
            "service_names_or_pids_exposed": False,
            "driver_services_included": False,
            "service_processes_proven_stopped": False,
            "all_watcher_launchers_known": False,
            "v1_quiescence_proven": False,
            "migration_authorized": False,
            "execution_authorized": False,
            "windows_changes_performed": False,
        }
    finally:
        adv.CloseServiceHandle(handle)


def _trusted_schtasks_binary() -> Path:
    """Resolve only from Win32-reported system directory, never PATH."""
    if sys.platform != "win32":
        raise PolicyBlocked("Windows Task Scheduler required")
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.GetSystemDirectoryW.argtypes = [wintypes.LPWSTR, wintypes.UINT]
    kernel.GetSystemDirectoryW.restype = wintypes.UINT
    output = ctypes.create_unicode_buffer(512)
    size = kernel.GetSystemDirectoryW(output, len(output))
    if not 1 <= size < len(output):
        raise PolicyBlocked("Windows system directory not available")
    binary = Path(output.value) / "schtasks.exe"
    if not binary.is_file():
        raise PolicyBlocked("native scheduler query executable missing")
    return binary


def _count_csv_task_names(wire: str) -> tuple[int, int]:
    if type(wire) is not str or len(wire) > MAX_CSV_CHARS:
        raise PolicyBlocked("Task Scheduler output exceeds bounded buffer")
    count = matches = 0
    try:
        rows = csv.reader(io.StringIO(wire), strict=True)
        for columns in rows:
            if not columns:
                continue
            if count >= MAX_TASKS or len(columns) > 20:
                raise PolicyBlocked("Task Scheduler rows exceed bound")
            name = columns[0]
            if not isinstance(name, str) or len(name) > 1024 or not name.startswith("\\"):
                raise PolicyBlocked("Task Scheduler returned unexpected CSV row")
            count += 1
            if MATCH.search(name):
                matches += 1
    except csv.Error as exc:
        raise PolicyBlocked("Task Scheduler CSV malformed") from exc
    return count, matches


def observe_registered_tasks() -> dict[str, object]:
    """Fixed signed OS-binary query; no shell, task actions or mutations."""
    binary = _trusted_schtasks_binary()
    try:
        # Never use a shell, PATH search, user command strings or user args.
        output = subprocess.run(
            [str(binary), "/Query", "/FO", "CSV", "/NH"],
            shell=False, stdin=subprocess.DEVNULL,
            capture_output=True, timeout=30,
            text=True, encoding="mbcs", errors="replace",
            check=False,
            creationflags=0x08000000,  # CREATE_NO_WINDOW
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise PolicyBlocked("Task Scheduler query did not complete") from exc
    if output.returncode != 0:
        raise PolicyBlocked("Task Scheduler query failed or access denied")
    tasks, matches = _count_csv_task_names(output.stdout)
    return {
        "schema": "upab.watcher-v3.scheduler-snapshot.v1",
        "registered_task_names_observed": tasks,
        "possible_watcher_task_names": matches,
        "task_actions_read_or_exported": False,
        "task_actions_absence_proven": False,
        "scheduler_access_scope_complete": False,
        "startup_disablement_proven": False,
        "running_task_instances_excluded": False,
        "v1_quiescence_proven": False,
        "migration_authorized": False,
        "execution_authorized": False,
        "windows_changes_performed": False,
    }
