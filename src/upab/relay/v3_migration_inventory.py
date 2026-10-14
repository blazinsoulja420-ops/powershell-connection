"""Watcher v3 READ-ONLY migration inventory; never enables, marks or migrates.

File existence cannot prove v1 has stopped. This gate always requires a
separate trusted process/approval ceremony before a migration could begin.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import stat
import sys

from .v3_policy import PolicyBlocked


def _plain_file(path: Path) -> bool:
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return False
    if (stat.S_ISLNK(metadata.st_mode)
            or (getattr(metadata, "st_file_attributes", 0) & 0x400)):
        raise PolicyBlocked("state contains a symlink/reparse point")
    if not stat.S_ISREG(metadata.st_mode):
        raise PolicyBlocked("state path is not a regular file")
    return True


def inspect_migration_state(state_dir: str | Path) -> dict[str, object]:
    state = Path(state_dir).expanduser().resolve(strict=True)
    if not state.is_dir():
        raise PolicyBlocked("state root must be an existing directory")
    relay = state / "relay"
    try:
        relay_info = relay.lstat()
    except FileNotFoundError:
        raise PolicyBlocked("relay state directory is absent")
    if (not stat.S_ISDIR(relay_info.st_mode)
            or (getattr(relay_info, "st_file_attributes", 0) & 0x400)):
        raise PolicyBlocked("relay directory is not an ordinary directory")
    marker = relay / "v2_active.marker"
    nonce = relay / "nonce.txt"
    legacy = relay / "seen_tasks.jsonl"
    v2 = relay / "relay_v2.sqlite3"
    marked = _plain_file(marker)
    nonce_found = _plain_file(nonce)
    legacy_found = _plain_file(legacy)
    v2_found = _plain_file(v2)
    if marked:
        return {
            "schema": "upab.watcher-v3.migration-inventory.v1",
            "status": "MIGRATION_MARKER_PRESENT_STOP",
            "legacy_nonce_present": nonce_found,
            "legacy_records": None,
            "v2_database_present": v2_found,
            "verified_v1_quiescent": False,
            "authorized_to_migrate": False,
            "changes_performed": False,
        }
    if not nonce_found:
        raise PolicyBlocked("legacy nonce missing: cannot establish baseline")
    if nonce.stat().st_size < 4 or nonce.stat().st_size > 512:
        raise PolicyBlocked("legacy nonce file has invalid size")
    if legacy_found and legacy.stat().st_size > 8 * 1024 * 1024:
        raise PolicyBlocked("legacy ledger exceeds inventory size limit")
    records = 0
    if legacy_found:
        with legacy.open("r", encoding="utf-8") as file:
            for line in file:
                try:
                    record = json.loads(line)
                except json.JSONDecodeError as exc:
                    raise PolicyBlocked("legacy ledger has unreadable records") from exc
                if (not isinstance(record, dict)
                        or not isinstance(record.get("task_id"), str)
                        or not record["task_id"]):
                    raise PolicyBlocked("legacy ledger record is malformed")
                records += 1
    return {
        "schema": "upab.watcher-v3.migration-inventory.v1",
        "status": "V2_STATE_PRESENT_REVIEW" if v2_found else "V1_INVENTORIED_NOT_READY",
        "legacy_nonce_present": True,
        "legacy_records": records,
        "v2_database_present": v2_found,
        "verified_v1_quiescent": False,
        "authorized_to_migrate": False,
        "changes_performed": False,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Inspect watcher state without migration")
    parser.add_argument("--state", required=True)
    args = parser.parse_args(argv)
    try:
        report = inspect_migration_state(args.state)
    except (OSError, UnicodeError, PolicyBlocked) as exc:
        print("WATCHER_MIGRATION_PREFLIGHT_BLOCKED: " + type(exc).__name__, file=sys.stderr)
        return 7
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
