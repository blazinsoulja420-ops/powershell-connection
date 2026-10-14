"""Stage 17 legacy-to-v2 migration risk audit — READ ONLY, NEVER ACTIVATES.

Strict bounded inspection of existing v1 nonce/JSONL and optional v2 SQLite.
It can detect corrupt/duplicate history and missing imported replay records.
It CANNOT prove v1 has stopped or prevent a concurrent v1 process from
consuming a task. There is deliberately no success/authorization path.

Never creates a migration marker, database, backup, lock, task, repo link,
Windows service or new execution process.
"""
from __future__ import annotations

import argparse
from contextlib import closing
from datetime import datetime
import json
from pathlib import Path
import re
import sqlite3
import stat
import sys

from .v3_policy import PolicyBlocked

MAX_LEGACY_BYTES = 8 * 1024 * 1024
MAX_V2_BYTES = 64 * 1024 * 1024
MAX_RECORDS = 10000
_HEX64 = re.compile(r"[0-9A-Fa-f]{64}\Z")
_HEX16 = re.compile(r"[0-9A-Fa-f]{16}\Z")
_NONCE = re.compile(r"[A-Za-z0-9_-]{24,128}\Z")

BASE_BLOCKERS = (
    "UNVERIFIED_V1_PROCESS_QUIESCENCE",
    "UNVERIFIED_STOP_OF_OLD_LAUNCH_PATHS",
    "NO_OWNER_AUTHENTICATED_MIGRATION_APPROVAL",
    "NO_PROTECTED_BACKUP_OR_ROLLBACK_EVIDENCE",
    "NO_LAPTOP_ACCEPTANCE_EVIDENCE",
)


def _ordinary(path: Path, *, directory: bool = False) -> bool:
    try:
        info = path.lstat()
    except FileNotFoundError:
        return False
    if stat.S_ISLNK(info.st_mode) or (getattr(info, "st_file_attributes", 0) & 0x400):
        raise PolicyBlocked("watcher state contains redirected path")
    if directory and not stat.S_ISDIR(info.st_mode):
        raise PolicyBlocked("expected ordinary state directory")
    if not directory and not stat.S_ISREG(info.st_mode):
        raise PolicyBlocked("expected ordinary state file")
    return True


def _nonce_check(path: Path) -> None:
    if not _ordinary(path) or not 24 <= path.stat().st_size <= 130:
        raise PolicyBlocked("missing or malformed legacy nonce file")
    try:
        content = path.read_text("ascii")
    except (UnicodeError, OSError) as exc:
        raise PolicyBlocked("legacy nonce not readable") from exc
    if not _NONCE.fullmatch(content.strip()) or len(content.strip()) != len(content.rstrip("\r\n")):
        raise PolicyBlocked("legacy nonce format invalid")


def _strict_legacy(path: Path) -> set[str]:
    if not _ordinary(path):
        return set()
    if path.stat().st_size > MAX_LEGACY_BYTES:
        raise PolicyBlocked("legacy ledger exceeds bounded inspection")
    ids = set()
    with path.open("r", encoding="utf-8") as file:
        for line in file:
            if len(ids) >= MAX_RECORDS:
                raise PolicyBlocked("legacy record count exceeds audit bound")
            if len(line) > 4096:
                raise PolicyBlocked("legacy ledger line too large")
            try:
                item = json.loads(line)
            except (ValueError, TypeError) as exc:
                raise PolicyBlocked("legacy JSONL is malformed") from exc
            if not isinstance(item, dict) or set(item) != {
                "task_id", "sha256", "consumed_at_utc", "nonce_sha256_prefix"
            }:
                raise PolicyBlocked("legacy record missing canonical fields")
            task = item["task_id"]
            digest = item["sha256"]
            stamp = item["consumed_at_utc"]
            prefix = item["nonce_sha256_prefix"]
            if not isinstance(task, str) or not 1 <= len(task) <= 128 or (
                not re.fullmatch(r"[A-Za-z0-9._:-]+", task)
            ):
                raise PolicyBlocked("invalid legacy task identifier")
            if task in ids:
                raise PolicyBlocked("duplicate legacy task identifier")
            if (not isinstance(digest, str) or not _HEX64.fullmatch(digest)
                    or not isinstance(prefix, str) or not _HEX16.fullmatch(prefix)
                    or not isinstance(stamp, str) or len(stamp) > 64):
                raise PolicyBlocked("invalid legacy task hash or timestamp")
            try:
                point = datetime.fromisoformat(stamp)
            except ValueError as exc:
                raise PolicyBlocked("legacy timestamp malformed") from exc
            if point.tzinfo is None:
                raise PolicyBlocked("legacy timestamp must include timezone")
            ids.add(task)
    return ids


def _inspect_v2(path: Path, legacy_ids: set[str]) -> dict[str, int | bool]:
    if not _ordinary(path):
        return {"exists": False, "consumed_records": 0, "legacy_ids_missing": len(legacy_ids)}
    if not 4096 <= path.stat().st_size <= MAX_V2_BYTES:
        raise PolicyBlocked("v2 SQLite file size invalid")
    try:
        with closing(sqlite3.connect(path.as_uri() + "?mode=ro", uri=True, timeout=2)) as conn:
            conn.execute("PRAGMA query_only=ON")
            schema = {
                row[0] for row in conn.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                )
            }
            if not {"state", "consumed"}.issubset(schema):
                raise PolicyBlocked("v2 SQLite expected tables absent")
            row = conn.execute(
                "SELECT value FROM state WHERE key='current_nonce'"
            ).fetchone()
            if row is None or not isinstance(row[0], str) or not _NONCE.fullmatch(row[0]):
                raise PolicyBlocked("v2 ledger current nonce missing or invalid")
            count = conn.execute("SELECT count(*) FROM consumed").fetchone()[0]
            if type(count) is not int or not 0 <= count <= 1000000:
                raise PolicyBlocked("v2 ledger count unexpected")
            missing = sum(
                1 for task in legacy_ids
                if conn.execute(
                    "SELECT 1 FROM consumed WHERE task_id=? LIMIT 1", (task,)
                ).fetchone() is None
            )
    except (sqlite3.Error, OSError) as exc:
        raise PolicyBlocked("v2 SQLite cannot be verified read-only") from exc
    return {"exists": True, "consumed_records": count, "legacy_ids_missing": missing}


def audit_migration_risks(state_dir: str | Path) -> dict[str, object]:
    """Enumerate objective state issues, NEVER provide migration authority."""
    supplied = Path(state_dir).expanduser()
    if not _ordinary(supplied, directory=True):
        raise PolicyBlocked("existing ordinary state root required")
    state = supplied.resolve(strict=True)
    relay = state / "relay"
    if not _ordinary(relay, directory=True):
        raise PolicyBlocked("ordinary relay state directory required")
    marker = _ordinary(relay / "v2_active.marker")
    # Read the full old ledger even with a marker: a marker doesn't validate it.
    legacy_ids = _strict_legacy(relay / "seen_tasks.jsonl")
    nonce_present = _ordinary(relay / "nonce.txt")
    if nonce_present:
        _nonce_check(relay / "nonce.txt")
    v2 = _inspect_v2(relay / "relay_v2.sqlite3", legacy_ids)
    risks = list(BASE_BLOCKERS)
    if not nonce_present:
        risks.append("LEGACY_NONCE_MISSING")
    if marker:
        risks.append("MIGRATION_MARKER_NOT_PROOF_OF_V1_EXIT")
        if not v2["exists"]:
            risks.append("ACTIVATION_MARKER_WITHOUT_V2_LEDGER")
    elif v2["exists"]:
        risks.append("V2_LEDGER_PRESENT_WITHOUT_V1_LOCKOUT_MARKER")
    if v2["exists"] and v2["legacy_ids_missing"] > 0:
        risks.append("LEGACY_HISTORY_NOT_FULLY_IN_V2")
    return {
        "schema": "upab.watcher-v3.legacy-migration-risk-audit.v1",
        "status": "BLOCKED_NOT_AUTHORIZED",
        "legacy_nonce_present": nonce_present,
        "legacy_record_count": len(legacy_ids),
        "v2_database_present": v2["exists"],
        "v2_consumed_count": v2["consumed_records"],
        "missing_legacy_records_in_v2": v2["legacy_ids_missing"] if v2["exists"] else None,
        "activation_marker_present": marker,
        "blocked_reasons": risks,
        "v1_quiescence_proven": False,
        "owner_approval_proven": False,
        "migration_allowed": False,
        "task_execution_allowed": False,
        "writes_performed": False,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="READ-ONLY legacy watcher migration risk audit")
    parser.add_argument("--state", required=True)
    args = parser.parse_args(argv)
    try:
        report = audit_migration_risks(args.state)
    except (OSError, UnicodeError, PolicyBlocked) as exc:
        print("UPAB_MIGRATION_AUDIT_BLOCKED: " + type(exc).__name__, file=sys.stderr)
        return 7
    print(json.dumps(report, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
