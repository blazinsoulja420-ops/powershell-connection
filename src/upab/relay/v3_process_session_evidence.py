"""Stage 24 Windows process and session evidence: observation, NOT exclusion.

Enumerate candidates from the native Toolhelp32 process snapshot. For a
bounded set of exact executable names, open a read-only process handle and
validate that it still has retrievable process creation-time metadata and
a Windows session ID. Neither names nor PID, SID, process arguments, file
paths, access tokens or creation times are exported.

An old watcher can run from renamed executables, a generic host, a
different session, or start after inspection. An open process can exit
immediately. This evidence NEVER certifies absence, quiescence, consent,
Windows Hello authentication, or task-execution permission.
"""
from __future__ import annotations

import argparse
import ctypes
import json
from ctypes import wintypes
import sys

from .v3_policy import PolicyBlocked
from .v3_windows_cutover_preflight import (
    TH32CS_SNAPPROCESS, ERROR_NO_MORE_FILES, PROCESSENTRY32W,
    MAX_PROCESS_SNAPSHOT, PROGRAM_NAMES,
)

PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
INVALID_SESSION = 0xFFFFFFFF
MAX_RELEVANT = 4096
MAX_SESSION_PROBE_FAILURES = MAX_RELEVANT


class FILETIME(ctypes.Structure):
    _fields_ = [("dwLowDateTime", wintypes.DWORD),
                ("dwHighDateTime", wintypes.DWORD)]


def classify_host_sessions(
    *, candidates: object, current_session: int,
    active_console_session: int | None,
) -> dict[str, int | bool | None]:
    """Testable bounded count reduction; not an owner authentication."""
    if type(candidates) is not list or len(candidates) > MAX_RELEVANT:
        raise PolicyBlocked("bounded candidate session results required")
    if type(current_session) is not int or not 0 <= current_session < INVALID_SESSION:
        raise PolicyBlocked("invalid process session")
    if active_console_session is not None and (
        type(active_console_session) is not int
        or not 0 <= active_console_session < INVALID_SESSION
    ):
        raise PolicyBlocked("invalid console session")
    same = other = inaccessible = console = 0
    for session in candidates:
        if session is None:
            inaccessible += 1
        elif type(session) is not int or not 0 <= session < INVALID_SESSION:
            raise PolicyBlocked("untrusted candidate session value")
        else:
            if session == current_session:
                same += 1
            else:
                other += 1
            if active_console_session is not None and session == active_console_session:
                console += 1
    return {
        "candidate_host_instances_observed": len(candidates),
        "candidate_hosts_in_process_session": same,
        "candidate_hosts_in_other_sessions": other,
        "candidate_host_sessions_inaccessible": inaccessible,
        "candidate_hosts_in_active_console_session": console,
        "active_console_session_observed": active_console_session is not None,
        "current_session_is_active_console": (
            active_console_session is not None
            and active_console_session == current_session
        ),
        "old_watcher_process_absence_proven": False,
        "owner_interactive_presence_proven": False,
        "task_execution_authorized": False,
    }


def observe_process_sessions() -> dict[str, object]:
    if sys.platform != "win32":
        raise PolicyBlocked("Win32 process/session evidence requires Windows")
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
    kernel.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
    kernel.Process32FirstW.argtypes = [wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32W)]
    kernel.Process32FirstW.restype = wintypes.BOOL
    kernel.Process32NextW.argtypes = [wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32W)]
    kernel.Process32NextW.restype = wintypes.BOOL
    kernel.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel.OpenProcess.restype = wintypes.HANDLE
    kernel.GetProcessTimes.argtypes = [wintypes.HANDLE, ctypes.POINTER(FILETIME),
                                     ctypes.POINTER(FILETIME), ctypes.POINTER(FILETIME),
                                     ctypes.POINTER(FILETIME)]
    kernel.GetProcessTimes.restype = wintypes.BOOL
    kernel.GetCurrentProcessId.argtypes = []
    kernel.GetCurrentProcessId.restype = wintypes.DWORD
    kernel.ProcessIdToSessionId.argtypes = [wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
    kernel.ProcessIdToSessionId.restype = wintypes.BOOL
    kernel.WTSGetActiveConsoleSessionId.argtypes = []
    kernel.WTSGetActiveConsoleSessionId.restype = wintypes.DWORD
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel.CloseHandle.restype = wintypes.BOOL

    current = wintypes.DWORD()
    if not kernel.ProcessIdToSessionId(
        kernel.GetCurrentProcessId(), ctypes.byref(current)
    ) or current.value == INVALID_SESSION:
        raise PolicyBlocked("cannot identify inspector Windows session")
    console = int(kernel.WTSGetActiveConsoleSessionId())
    console_id = None if console == INVALID_SESSION else console

    handle = kernel.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if not handle or handle == ctypes.c_void_p(-1).value:
        raise PolicyBlocked("Windows process snapshot unavailable")
    candidates: list[int | None] = []
    observed = 0
    try:
        item = PROCESSENTRY32W()
        item.dwSize = ctypes.sizeof(PROCESSENTRY32W)
        if not kernel.Process32FirstW(handle, ctypes.byref(item)):
            raise PolicyBlocked("Windows process enumeration unavailable")
        while True:
            observed += 1
            if observed > MAX_PROCESS_SNAPSHOT:
                raise PolicyBlocked("Windows process snapshot exceeds bound")
            if item.szExeFile.casefold() in PROGRAM_NAMES:
                if len(candidates) >= MAX_RELEVANT:
                    raise PolicyBlocked("too many candidate host processes")
                proc = kernel.OpenProcess(
                    PROCESS_QUERY_LIMITED_INFORMATION, False,
                    item.th32ProcessID
                )
                if not proc:
                    candidates.append(None)
                else:
                    try:
                        created = FILETIME()
                        exited = FILETIME()
                        kernel_time = FILETIME()
                        user_time = FILETIME()
                        session = wintypes.DWORD()
                        # If the handle is unreadable or the PID stopped while
                        # observed, do not claim its session or liveness.
                        if (not kernel.GetProcessTimes(
                                proc, ctypes.byref(created), ctypes.byref(exited),
                                ctypes.byref(kernel_time), ctypes.byref(user_time))
                                or not kernel.ProcessIdToSessionId(
                                    item.th32ProcessID, ctypes.byref(session))
                                or session.value == INVALID_SESSION):
                            candidates.append(None)
                        else:
                            candidates.append(int(session.value))
                    finally:
                        kernel.CloseHandle(proc)
            ctypes.set_last_error(0)
            if not kernel.Process32NextW(handle, ctypes.byref(item)):
                if ctypes.get_last_error() != ERROR_NO_MORE_FILES:
                    raise PolicyBlocked("Windows process enumeration incomplete")
                break
    finally:
        kernel.CloseHandle(handle)
    summary = classify_host_sessions(
        candidates=candidates, current_session=int(current.value),
        active_console_session=console_id
    )
    return {
        "schema": "upab.watcher-v3.windows-process-session-evidence.v1",
        "total_process_entries_in_snapshot": observed,
        **summary,
        "session_evidence_sampled": True,
        "process_image_paths_or_args_exposed": False,
        "raw_pids_or_session_ids_exposed": False,
        "user_sid_or_tokens_exposed": False,
        "renamed_or_generic_hosts_exhaustively_identified": False,
        "in_flight_task_absence_proven": False,
        "v1_shutdown_and_restart_prevention_proven": False,
        "owner_windows_hello_verified": False,
        "deployment_authorized": False,
        "processes_stopped": False,
        "settings_changed": False,
    }


def main(argv: list[str] | None = None) -> int:
    """Explicit one-shot read-only Windows session summary."""
    parser = argparse.ArgumentParser(
        description="READ-ONLY Windows candidate-process/session evidence"
    )
    parser.parse_args(argv)
    try:
        report = observe_process_sessions()
    except (OSError, PolicyBlocked) as exc:
        # Do not print OS errors: they may contain private local paths.
        print("WATCHER_V3_SESSION_PREFLIGHT_BLOCKED: " +
              type(exc).__name__, file=sys.stderr)
        return 7
    print(json.dumps(report, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
