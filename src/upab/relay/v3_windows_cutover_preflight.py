"""Stage 19 READ-ONLY Windows cutover evidence; NEVER proof of quiescence.

Use documented Win32 Toolhelp32 process enumeration to observe potentially
relevant program *names*, not their command lines or full paths. Python and
PowerShell may host arbitrary workloads, and an old v1 process can continue
after process enumeration. This scan CANNOT certify watcher shutdown.

Optional source/backup comparison hashes ONLY the two explicit v1 ledger
files in existing user-selected ordinary relay state directories. Matching
checksums do NOT prove immutable backups, private ACLs, signed provenance,
or the right to migrate. No state creation, process launch/termination,
startup task disable, credential use, network call or authorization.
"""
from __future__ import annotations

import argparse
import ctypes
import hashlib
import json
from pathlib import Path
import stat
import sys
from ctypes import wintypes

from .v3_policy import PolicyBlocked

TH32CS_SNAPPROCESS = 0x00000002
ERROR_NO_MORE_FILES = 18
MAX_PROCESS_SNAPSHOT = 100000
MAX_LEDGER_BYTES = 8 * 1024 * 1024
PROGRAM_NAMES = frozenset({
    "python.exe", "pythonw.exe", "py.exe", "pwsh.exe",
    "powershell.exe", "cmd.exe", "upab.exe",
})
KNOWN_REPO_LAUNCHERS = (
    "scripts/Start-UPAB-ExactRelay.ps1",
    "scripts/Enable-UPAB-ExactRelay.ps1",
    "scripts/upab.ps1",
)
STATE_FILES = ("nonce.txt", "seen_tasks.jsonl")


class PROCESSENTRY32W(ctypes.Structure):
    _fields_ = [
        ("dwSize", wintypes.DWORD),
        ("cntUsage", wintypes.DWORD),
        ("th32ProcessID", wintypes.DWORD),
        ("th32DefaultHeapID", ctypes.c_size_t),
        ("th32ModuleID", wintypes.DWORD),
        ("cntThreads", wintypes.DWORD),
        ("th32ParentProcessID", wintypes.DWORD),
        ("pcPriClassBase", wintypes.LONG),
        ("dwFlags", wintypes.DWORD),
        ("szExeFile", wintypes.WCHAR * 260),
    ]


def snapshot_possible_host_processes() -> dict[str, object]:
    if sys.platform != "win32":
        raise PolicyBlocked("Windows process survey requires Windows")
    k = ctypes.WinDLL("kernel32", use_last_error=True)
    k.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
    k.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
    k.Process32FirstW.argtypes = [wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32W)]
    k.Process32FirstW.restype = wintypes.BOOL
    k.Process32NextW.argtypes = [wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32W)]
    k.Process32NextW.restype = wintypes.BOOL
    k.CloseHandle.argtypes = [wintypes.HANDLE]
    k.CloseHandle.restype = wintypes.BOOL
    handle = k.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if not handle or handle == ctypes.c_void_p(-1).value:
        raise PolicyBlocked("cannot enumerate Windows processes")
    counts = {name: 0 for name in sorted(PROGRAM_NAMES)}
    seen = 0
    try:
        entry = PROCESSENTRY32W()
        entry.dwSize = ctypes.sizeof(PROCESSENTRY32W)
        if not k.Process32FirstW(handle, ctypes.byref(entry)):
            raise PolicyBlocked("Windows process list unavailable")
        while True:
            seen += 1
            if seen > MAX_PROCESS_SNAPSHOT:
                raise PolicyBlocked("process count exceeds bounded scan")
            exe = entry.szExeFile.casefold()
            if exe in counts:
                counts[exe] += 1
            ctypes.set_last_error(0)
            if not k.Process32NextW(handle, ctypes.byref(entry)):
                if ctypes.get_last_error() != ERROR_NO_MORE_FILES:
                    raise PolicyBlocked("Windows process enumeration incomplete")
                break
    finally:
        k.CloseHandle(handle)
    return {
        "schema": "upab.watcher-v3.windows-cutover-survey.v1",
        "process_snapshot_completed": True,
        "total_process_entries_observed": seen,
        "possible_host_counts": counts,
        "known_repo_launcher_names": list(KNOWN_REPO_LAUNCHERS),
        "all_relevant_processes_identified": False,
        "candidate_process_absence_proven": False,
        "old_watcher_not_running_proven": False,
        "in_flight_v1_task_absence_proven": False,
        "scheduled_tasks_inventory_complete": False,
        "windows_services_inventory_complete": False,
        "registry_autostart_inventory_complete": False,
        "startup_shortcuts_inventory_complete": False,
        "old_launcher_paths_disabled_verified": False,
        "migration_authorized": False,
        "execution_authorized": False,
        "processes_stopped": False,
        "startup_modified": False,
    }


def _ordinary_directory(root: str | Path) -> Path:
    supplied = Path(root).expanduser()
    try:
        st = supplied.lstat()
    except (OSError, ValueError) as exc:
        raise PolicyBlocked("backup/source root not available") from exc
    if not stat.S_ISDIR(st.st_mode) or stat.S_ISLNK(st.st_mode) or (
        getattr(st, "st_file_attributes", 0) & 0x400
    ):
        raise PolicyBlocked("backup/source state root redirected or not directory")
    return supplied.resolve(strict=True)


def _hash_bounded(root: Path, name: str) -> tuple[int, str]:
    relay = root / "relay"
    try:
        d = relay.lstat()
        if not stat.S_ISDIR(d.st_mode) or stat.S_ISLNK(d.st_mode) or (
            getattr(d, "st_file_attributes", 0) & 0x400
        ):
            raise PolicyBlocked("state relay folder unsafe")
        target = relay / name
        st = target.lstat()
    except (OSError, ValueError) as exc:
        raise PolicyBlocked("expected backup/source state file is missing") from exc
    if not stat.S_ISREG(st.st_mode) or stat.S_ISLNK(st.st_mode) or (
        getattr(st, "st_file_attributes", 0) & 0x400
    ):
        raise PolicyBlocked("backup/source file is redirected or not regular")
    limit = 512 if name == "nonce.txt" else MAX_LEDGER_BYTES
    if not 1 <= st.st_size <= limit:
        raise PolicyBlocked("backup/source file exceeds bounded size")
    h = hashlib.sha256()
    total = 0
    with target.open("rb") as f:
        while True:
            chunk = f.read(65536)
            if not chunk:
                break
            total += len(chunk)
            if total > limit:
                raise PolicyBlocked("file grew during backup inspection")
            h.update(chunk)
    if total != st.st_size or target.stat().st_size != st.st_size:
        raise PolicyBlocked("backup/source state changed during inspection")
    return total, h.hexdigest()


def compare_existing_backup(
    *, source_state: str | Path, backup_state: str | Path
) -> dict[str, object]:
    """Match state file checksums without emitting their values or contents."""
    source = _ordinary_directory(source_state)
    backup = _ordinary_directory(backup_state)
    if source == backup or source in backup.parents or backup in source.parents:
        raise PolicyBlocked("source and backup must be distinct peer directories")
    matches = {}
    bytes_checked = 0
    for name in STATE_FILES:
        source_size, source_digest = _hash_bounded(source, name)
        backup_size, backup_digest = _hash_bounded(backup, name)
        matches[name] = source_size == backup_size and source_digest == backup_digest
        bytes_checked += source_size + backup_size
    return {
        "schema": "upab.watcher-v3.backup-comparison.v1",
        "expected_file_count": len(STATE_FILES),
        "bytes_hashed": bytes_checked,
        "matched_file_count": sum(matches.values()),
        "mismatched_file_count": len(matches) - sum(matches.values()),
        "files_identical_at_sample_time": all(matches.values()),
        "source_quiescence_proven": False,
        "backup_protected_by_verified_acl": False,
        "backup_authenticity_proven": False,
        "backup_immutable": False,
        "backup_restoration_test_passed": False,
        "migration_authorized": False,
        "file_changes_performed": False,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="READ-ONLY Windows cutover preview")
    modes = parser.add_mutually_exclusive_group(required=True)
    modes.add_argument("--processes", action="store_true")
    modes.add_argument("--compare-backup", action="store_true")
    parser.add_argument("--source-state")
    parser.add_argument("--backup-state")
    args = parser.parse_args(argv)
    try:
        if args.processes:
            if args.source_state is not None or args.backup_state is not None:
                raise PolicyBlocked("process survey takes no state path")
            output = snapshot_possible_host_processes()
        else:
            if args.source_state is None or args.backup_state is None:
                raise PolicyBlocked("explicit source and backup states required")
            output = compare_existing_backup(
                source_state=args.source_state, backup_state=args.backup_state
            )
    except (OSError, PolicyBlocked) as exc:
        print("UPAB_STAGE19_PREFLIGHT_BLOCKED: " + type(exc).__name__, file=sys.stderr)
        return 7
    print(json.dumps(output, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
