"""Stage 26 — READ-ONLY explicit checkout installation fingerprint preview.

Inspects a fixed allowlist of watcher code/launcher files and the example
disabled v3 feature catalog under one existing selected checkout. It never
discovers a checkout, reads local.json, identifies private state, runs
launchers, stages a release, installs software, or changes Windows startup.

A matching local SHA-256 fingerprint does NOT authenticate the source;
reviewer pins can be forged. Nor does it prove no unlisted files exist,
that a real watcher is running/stopped, or that this checkout is installed.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import stat
import sys

from .v3_features import FEATURES, STAGES, load_feature_catalog
from .v3_policy import PolicyBlocked

_SCHEMA = "upab.watcher-v3.existing-checkout-baseline.v1"
_FILES = (
    "scripts/Start-UPAB-ExactRelay.ps1",
    "scripts/Enable-UPAB-ExactRelay.ps1",
    "scripts/upab.ps1",
    "src/upab/relay/ledger.py",
    "src/upab/relay/ledger_v2.py",
    "config/watcher-v3-features.example.json",
)
_FILE_LIMIT = 1024 * 1024
_FINGERPRINT = re.compile(r"[0-9a-f]{64}\Z")


def _normal(path: Path, *, directory: bool) -> None:
    try:
        info = path.lstat()
    except (OSError, ValueError) as exc:
        raise PolicyBlocked("selected checkout file does not exist") from exc
    if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
        raise PolicyBlocked("selected checkout path is redirected")
    if directory:
        if not stat.S_ISDIR(info.st_mode):
            raise PolicyBlocked("expected ordinary directory")
    elif not stat.S_ISREG(info.st_mode):
        raise PolicyBlocked("expected ordinary file")


def _existing_root(selected: str | Path) -> Path:
    if not isinstance(selected, (Path, str)):
        raise PolicyBlocked("explicit checkout root required")
    root = Path(selected).expanduser()
    if not root.is_absolute():
        raise PolicyBlocked("checkout root must be absolute")
    for part in (root, *root.parents):
        _normal(part, directory=True)
    return root.resolve(strict=True)


def _read_digest(path: Path) -> tuple[int, str]:
    _normal(path, directory=False)
    before = path.stat()
    if not 1 <= before.st_size <= _FILE_LIMIT:
        raise PolicyBlocked("checkout file is empty or beyond inspection bound")
    total = 0
    sha = hashlib.sha256()
    with path.open("rb") as stream:
        while True:
            block = stream.read(65536)
            if not block:
                break
            total += len(block)
            if total > _FILE_LIMIT:
                raise PolicyBlocked("checkout file grew beyond inspection bound")
            sha.update(block)
    after = path.stat()
    if (total != before.st_size or after.st_size != before.st_size
            or after.st_mtime_ns != before.st_mtime_ns
            or after.st_ino != before.st_ino or after.st_dev != before.st_dev):
        raise PolicyBlocked("checkout file changed during inspection")
    return total, sha.hexdigest()


def inspect_checkout_baseline(
    checkout_root: str | Path, *,
    supplied_fingerprint: str | None = None
) -> dict[str, object]:
    """Observe explicitly selected candidate code; always DENY promotion."""
    if supplied_fingerprint is not None and (
        type(supplied_fingerprint) is not str
        or not _FINGERPRINT.fullmatch(supplied_fingerprint)
    ):
        raise PolicyBlocked("unexpected reference fingerprint format")
    root = _existing_root(checkout_root)
    entries = []
    for relative in _FILES:
        path = root
        pieces = relative.split("/")
        for part in pieces[:-1]:
            path = path / part
            _normal(path, directory=True)
        path = path / pieces[-1]
        size, digest = _read_digest(path)
        entries.append({"file": relative, "bytes": size, "sha256": digest})
    catalog = load_feature_catalog(root / _FILES[-1])
    if (type(catalog) is not dict
            or catalog.get("schema") != "upab.watcher-v3.features.v1"
            or type(catalog.get("registered_upgrades")) is not int
            or catalog["registered_upgrades"] != 12
            or type(catalog.get("activated_upgrades")) is not int
            or catalog["activated_upgrades"] != 0
            or catalog.get("execution_enabled") is not False
            or type(catalog.get("project_limit")) is not int
            or catalog["project_limit"] != 64
            or type(catalog.get("monitor_limit")) is not int
            or catalog["monitor_limit"] != 32):
        raise PolicyBlocked("candidate feature catalog deviates from disabled limits")
    stages = catalog.get("stages")
    if (type(stages) is not dict or set(stages) != set(FEATURES)
            or any(type(value) is not str or value not in STAGES
                   for value in stages.values())):
        raise PolicyBlocked("candidate feature identities or stage labels invalid")
    canonical = json.dumps(entries, sort_keys=True, separators=(",", ":")).encode("utf-8")
    aggregate = hashlib.sha256(canonical).hexdigest()
    return {
        "schema": _SCHEMA,
        "status": "READ_ONLY_CHECKOUT_FINGERPRINT_UNTRUSTED",
        "allowlisted_files_observed": len(entries),
        "total_source_bytes_hashed": sum(e["bytes"] for e in entries),
        "source_fingerprint_sha256": aggregate,
        "supplied_fingerprint_matches": (
            None if supplied_fingerprint is None else aggregate == supplied_fingerprint
        ),
        "feature_flags_enabled": 0,
        "registered_project_limit": 64,
        "active_monitored_folder_limit": 32,
        "all_possible_launchers_observed": False,
        "source_origin_authenticated": False,
        "external_fingerprint_owner_authenticated": False,
        "actual_installation_identified": False,
        "live_watcher_running_proven": False,
        "old_watcher_stopped_proven": False,
        "owner_approval_issued": False,
        "safe_to_install": False,
        "safe_to_migrate": False,
        "task_execution_authorized": False,
        "files_changed": False,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Read-only explicit watcher checkout baseline")
    parser.add_argument("--checkout", required=True)
    parser.add_argument("--expected-fingerprint", default=None)
    args = parser.parse_args(argv)
    try:
        output = inspect_checkout_baseline(
            args.checkout, supplied_fingerprint=args.expected_fingerprint
        )
    except (OSError, UnicodeError, ValueError, PolicyBlocked) as exc:
        print("WATCHER_V3_INSTALL_BASELINE_BLOCKED: " +
              type(exc).__name__, file=sys.stderr)
        return 7
    print(json.dumps(output, sort_keys=True, indent=2))
    # Report generation is not deployment approval.
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
