"""Read-only console dashboard snapshot; no server, execution or authorization.

Optional local UI and authenticated inbox are future integration milestones.
"""
from __future__ import annotations

import argparse
from contextlib import closing
import json
from pathlib import Path
import sqlite3
import sys

from .v3_policy import PolicyBlocked


def status_snapshot(state_dir: str | Path) -> dict[str, object]:
    root = Path(state_dir).expanduser().resolve(strict=True)
    if not root.is_dir():
        raise PolicyBlocked("state directory is not a directory")
    database = root / "relay" / "v3_checkpoints.sqlite3"
    base = {
        "schema": "upab.watcher-v3.status-preview.v1",
        "checkpoint_state": "NOT_INITIALIZED",
        "review_counts": {},
        "observed_running_process": None,
        "is_live": None,
        "task_execution_enabled": False,
        "approval_gateway_connected": False,
        "changes_performed": False,
    }
    if not database.exists():
        return base
    if database.is_symlink() or not database.is_file():
        raise PolicyBlocked("checkpoint path is not a plain file")
    try:
        uri = database.as_uri() + "?mode=ro"
        with closing(sqlite3.connect(uri, uri=True, timeout=5)) as db:
            values = dict(db.execute("SELECT phase,count(*) FROM reviews GROUP BY phase"))
    except sqlite3.Error as exc:
        raise PolicyBlocked("checkpoint snapshot unreadable: " + type(exc).__name__) from exc
    allowed = frozenset({"PROPOSED", "REVIEW_STARTED", "REVIEW_COMPLETED", "INTERRUPTED", "DISMISSED"})
    if any(key not in allowed for key in values):
        raise PolicyBlocked("unexpected checkpoint phase")
    base["checkpoint_state"] = "AVAILABLE"
    base["review_counts"] = values
    return base


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Read-only Watcher v3 checkpoint dashboard")
    parser.add_argument("--state", required=True, help="Existing local watcher state directory")
    args = parser.parse_args(argv)
    try:
        report = status_snapshot(args.state)
    except (OSError, PolicyBlocked) as exc:
        print("WATCHER_V3_STATUS_BLOCKED: " + type(exc).__name__, file=sys.stderr)
        return 7
    print(json.dumps(report, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
