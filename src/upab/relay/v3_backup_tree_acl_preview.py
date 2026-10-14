"""Stage 21 bounded read-only backup directory + NTFS DACL tree audit.

Requires an explicitly selected existing backup *state root* consisting of
exactly relay/ and a narrow allowlist of known v1/v2 state files. No recursive
arbitrary filesystem traversal, file content or secret export. Evaluates DACL
observations on root/relay directories and every encountered state file,
including broad-principal write risks. No DACL snapshot proves protected
custody, immutability, correct effective access or permission to migrate.

A real state tree with unexpected files is BLOCKED, not silently excluded.
"""
from __future__ import annotations

import hashlib
from pathlib import Path
import stat
import sys

from .v3_policy import PolicyBlocked
from .v3_windows_backup_acl import (
    inspect_backup_directory_acl, inspect_backup_file_acl, _existing_directory
)

_ALLOWED = frozenset({
    "nonce.txt", "seen_tasks.jsonl", "relay_v2.sqlite3",
    "v2_active.marker", "watcher_v2.lock",
})
_REQUIRED = frozenset({"nonce.txt", "seen_tasks.jsonl"})
_MAX_FILE = {
    "nonce.txt": 512,
    "seen_tasks.jsonl": 8 * 1024 * 1024,
    "relay_v2.sqlite3": 64 * 1024 * 1024,
    "v2_active.marker": 512,
    "watcher_v2.lock": 512,
}


def _ordinary_file(path: Path, *, limit: int) -> None:
    try:
        entry = path.lstat()
    except OSError as exc:
        raise PolicyBlocked("backup state file not available") from exc
    if (not stat.S_ISREG(entry.st_mode) or stat.S_ISLNK(entry.st_mode)
            or getattr(entry, "st_file_attributes", 0) & 0x400):
        raise PolicyBlocked("backup contains a redirected or non-regular file")
    if not 0 <= entry.st_size <= limit:
        raise PolicyBlocked("backup file exceeds explicit bound")


def inspect_backup_tree(root: str | Path) -> dict[str, object]:
    """Only records aggregated counts; refuses all approval assertions."""
    if sys.platform != "win32":
        raise PolicyBlocked("Windows NTFS backup tree audit requires Windows")
    top = _existing_directory(root)
    relay = _existing_directory(top / "relay")
    # An explicit narrow root layout is needed; unrecognized files should
    # never be mistaken for a comprehensive backup.
    top_entries = list(top.iterdir())
    if len(top_entries) != 1 or top_entries[0].name != "relay":
        raise PolicyBlocked("backup root contains unexpected entries")
    entries = list(relay.iterdir())
    if not 2 <= len(entries) <= len(_ALLOWED):
        raise PolicyBlocked("backup relay file count unexpected")
    names = {p.name for p in entries}
    if (len(names) != len(entries)
            or not _REQUIRED.issubset(names)
            or not names.issubset(_ALLOWED)):
        raise PolicyBlocked("backup relay file set incomplete or unexpected")
    for p in entries:
        _ordinary_file(p, limit=_MAX_FILE[p.name])

    acl_checks = [
        inspect_backup_directory_acl(top),
        inspect_backup_directory_acl(relay),
    ]
    for path in sorted(entries, key=lambda p:p.name):
        acl_checks.append(inspect_backup_file_acl(path))

    null_dacls = sum(bool(a["null_or_missing_dacl"]) for a in acl_checks)
    broad = sum(bool(a["broad_write_allow_ace_observed"]) for a in acl_checks)
    unknown = sum(int(a["uninterpreted_ace_count"]) for a in acl_checks)
    unprotected = sum(not bool(a["dacl_inheritance_protected"])
                      for a in acl_checks)
    return {
        "schema": "upab.watcher-v3.backup-tree-acl-preview.v1",
        "expected_state_files_observed": len(entries),
        "state_directories_sampled": 2,
        "total_dacl_objects_sampled": len(acl_checks),
        "null_or_missing_dacl_objects": null_dacls,
        "broad_write_allow_objects": broad,
        "uninterpreted_ace_total": unknown,
        "dacl_inheritance_not_protected_objects": unprotected,
        "layout_contains_only_allowlisted_relay_files": True,
        "backup_bytes_read_or_exported": False,
        "backup_contents_proven_restorable": False,
        "acl_sampling_race_free": False,
        "effective_windows_rights_verified": False,
        "full_backup_integrity_proven": False,
        "tamper_protected_backup_proven": False,
        "owner_authenticated": False,
        "migration_authorized": False,
        "task_execution_authorized": False,
        "filesystem_changes_performed": False,
    }
