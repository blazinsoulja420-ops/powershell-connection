"""Stage 27: selected Windows watcher checkout shape inventory, READ ONLY.

Unlike Stage 26, a v1-only checkout is not rejected solely for missing v3
feature config. This collector checks only fixed source *metadata*, never
private config values, ledger/nonce contents, executable bytes, Git hooks,
other projects, process commands or arbitrary directory children.

No source-layout match is proof of a deployed watcher or trustworthy origin.
An empty directory is classified separately from a partial/source-like tree.
All observations are one-time, path-based and do not prove process shutdown.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import stat
import sys

from .v3_policy import PolicyBlocked

SCHEMA = "upab.watcher-v3.explicit-runtime-layout-preview.v1"
# Named source-layout sentinels only. No .git/config, secrets, private state
# or arbitrary recursive search is allowed.
MARKERS = (
    "scripts/Start-UPAB-ExactRelay.ps1",
    "scripts/Enable-UPAB-ExactRelay.ps1",
    "scripts/upab.ps1",
    "src/upab/__init__.py",
    "src/upab/relay/ledger.py",
    "src/upab/relay/ledger_v2.py",
    "config/watcher-v3-features.example.json",
    "pyproject.toml",
)
V1_ANCHORS = (
    "scripts/Start-UPAB-ExactRelay.ps1",
    "src/upab/relay/ledger.py",
)
V2_ANCHORS = ("src/upab/relay/ledger_v2.py",)
V3_ANCHORS = ("config/watcher-v3-features.example.json",)
MAX_ROOT_CHILDREN = 256
MAX_MARKER_BYTES = 1024 * 1024


def _plain(path: Path, *, directory: bool) -> bool:
    try:
        info = path.lstat()
    except FileNotFoundError:
        return False
    except (OSError, ValueError) as exc:
        raise PolicyBlocked("cannot inspect source-layout path") from exc
    if (stat.S_ISLNK(info.st_mode)
            or getattr(info, "st_file_attributes", 0) & 0x400):
        raise PolicyBlocked("source-layout redirection is unsupported")
    if directory:
        if not stat.S_ISDIR(info.st_mode):
            raise PolicyBlocked("source-layout component is not directory")
    else:
        if not stat.S_ISREG(info.st_mode):
            raise PolicyBlocked("source-layout component is not file")
        if not 0 <= info.st_size <= MAX_MARKER_BYTES:
            raise PolicyBlocked("source-layout marker exceeds size bound")
    return True


def inspect_explicit_layout(candidate: str | Path) -> dict[str, object]:
    """Only an existing absolute directory; return no paths or file values."""
    if not isinstance(candidate, (Path, str)):
        raise PolicyBlocked("explicit candidate directory required")
    root = Path(candidate).expanduser()
    if not root.is_absolute():
        raise PolicyBlocked("candidate directory must be absolute")
    for item in (root, *root.parents):
        if not _plain(item, directory=True):
            raise PolicyBlocked("candidate directory or parent is missing")
    # A directory count is deliberately bounded; do not recurse arbitrarily.
    count = 0
    for child in root.iterdir():
        count += 1
        if count > MAX_ROOT_CHILDREN:
            raise PolicyBlocked("candidate root exceeds enumeration bound")
        _plain(child, directory=child.is_dir())
    present: dict[str, bool] = {}
    for relative in MARKERS:
        cursor = root
        portions = relative.split("/")
        found = True
        for name in portions[:-1]:
            cursor = cursor / name
            if not _plain(cursor, directory=True):
                found = False
                break
        if found:
            found = _plain(cursor / portions[-1], directory=False)
        present[relative] = found
    matching = sum(present.values())
    if count == 0:
        category = "EMPTY_DIRECTORY_NOT_INSTALLATION"
    elif matching == 0:
        category = "NO_EXPECTED_WATCHER_SOURCE_MARKERS"
    elif all(present[name] for name in V1_ANCHORS):
        category = "POSSIBLE_SOURCE_LAYOUT_NOT_AUTHENTICATED"
    else:
        category = "PARTIAL_SOURCE_LAYOUT_NOT_AUTHENTICATED"
    return {
        "schema": SCHEMA,
        "status": category,
        "top_level_entries_observed": count,
        "expected_marker_count": len(MARKERS),
        "expected_markers_present": matching,
        "expected_markers_missing": len(MARKERS) - matching,
        "v1_source_anchors_present": all(present[name] for name in V1_ANCHORS),
        "v2_source_anchor_present": all(present[name] for name in V2_ANCHORS),
        "v3_example_feature_config_present": all(
            present[name] for name in V3_ANCHORS
        ),
        "private_config_or_replay_state_read": False,
        "source_file_content_read": False,
        "source_origin_authenticated": False,
        "all_installations_found": False,
        "installed_runtime_identified": False,
        "old_watcher_running_proven": False,
        "old_watcher_stopped_proven": False,
        "startup_launchers_disabled_proven": False,
        "owner_authenticated": False,
        "installation_authorized": False,
        "migration_authorized": False,
        "task_execution_authorized": False,
        "system_changes_performed": False,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="READ ONLY inspect a selected potential watcher folder"
    )
    parser.add_argument("--candidate", required=True)
    args = parser.parse_args(argv)
    try:
        report = inspect_explicit_layout(args.candidate)
    except (PolicyBlocked, OSError, ValueError, UnicodeError) as exc:
        print("WATCHER_V3_LAYOUT_PREVIEW_BLOCKED: " +
              type(exc).__name__, file=sys.stderr)
        return 7
    print(json.dumps(report, indent=2, sort_keys=True))
    # 0 means a report, not validation or installation approval.
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
