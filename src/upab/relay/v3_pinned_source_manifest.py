"""Stage 29: explicitly pinned watcher source-manifest consistency PREVIEW.

This observer compares only the six fixed Stage 26 source artifacts in a
caller-selected existing checkout to an EXTERNALLY PROVIDED reviewer manifest
and independent SHA-256 pin, tied to an explicitly named candidate commit.

There is NO authenticated publisher identity in a SHA digest; both the
manifest and its pin may have been forged by the same caller. This module
DOES NOT verify GitHub commit signatures, fetch repos, inspect .git, install,
make credentials, migrate state, execute tasks, or claim release readiness.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import stat
import sys

from .v3_installation_baseline import (
    _FILES, _FILE_LIMIT, _existing_root, _normal,
    _read_digest, inspect_checkout_baseline,
)
from .v3_policy import PolicyBlocked

SCHEMA = "upab.watcher-v3.pinned-source-manifest-preview.v1"
REPOSITORY = "blazinsoulja420-ops/powershell-connection"
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_COMMIT = re.compile(r"[0-9a-f]{40}\Z")
_MAX_MANIFEST = 8192


def canonical_manifest_bytes(manifest: object) -> bytes:
    if type(manifest) is not dict or set(manifest) != {
        "schema", "repository", "commit", "files"
    }:
        raise PolicyBlocked("source manifest has invalid top-level fields")
    if manifest["schema"] != SCHEMA or manifest["repository"] != REPOSITORY:
        raise PolicyBlocked("source manifest wrong identity or schema")
    if type(manifest["commit"]) is not str or not _COMMIT.fullmatch(
        manifest["commit"]
    ):
        raise PolicyBlocked("source manifest commit format invalid")
    files = manifest["files"]
    if type(files) is not dict or set(files) != set(_FILES):
        raise PolicyBlocked("source manifest missing or extra allowlist entries")
    for name in _FILES:
        record = files[name]
        if type(record) is not dict or set(record) != {"bytes", "sha256"}:
            raise PolicyBlocked("source manifest file entry malformed")
        if (type(record["bytes"]) is not int
                or not 1 <= record["bytes"] <= _FILE_LIMIT
                or type(record["sha256"]) is not str
                or not _SHA256.fullmatch(record["sha256"])):
            raise PolicyBlocked("source manifest file size or digest invalid")
    wire = json.dumps(
        manifest, sort_keys=True, ensure_ascii=True, separators=(",", ":")
    ).encode("ascii")
    if len(wire) > _MAX_MANIFEST:
        raise PolicyBlocked("source manifest exceeds fixed bound")
    return wire


def _load_explicit_manifest(source: str | Path) -> object:
    if not isinstance(source, (str, Path)):
        raise PolicyBlocked("explicit manifest file path required")
    path = Path(source).expanduser()
    if not path.is_absolute():
        raise PolicyBlocked("manifest file path must be absolute")
    for ancestor in path.parents:
        _normal(ancestor, directory=True)
    _normal(path, directory=False)
    before = path.stat()
    if not 1 <= before.st_size <= _MAX_MANIFEST:
        raise PolicyBlocked("manifest file exceeds bound")
    with path.open("rb") as f:
        data = f.read(_MAX_MANIFEST + 1)
    after = path.stat()
    if (len(data) != before.st_size or len(data) > _MAX_MANIFEST
            or after.st_size != before.st_size
            or after.st_mtime_ns != before.st_mtime_ns):
        raise PolicyBlocked("manifest file modified during inspection")
    try:
        return json.loads(data)
    except (ValueError, UnicodeError) as exc:
        raise PolicyBlocked("manifest JSON not valid") from exc


def compare_selected_checkout(
    *, checkout: str | Path, manifest: object, manifest_sha256: str,
    expected_commit: str
) -> dict[str, object]:
    """Strict equality check only; cannot issue a trust or approval proof."""
    if type(manifest_sha256) is not str or not _SHA256.fullmatch(manifest_sha256):
        raise PolicyBlocked("independent manifest fingerprint malformed")
    if type(expected_commit) is not str or not _COMMIT.fullmatch(expected_commit):
        raise PolicyBlocked("explicit reviewer commit malformed")
    wire = canonical_manifest_bytes(manifest)
    if hashlib.sha256(wire).hexdigest() != manifest_sha256:
        raise PolicyBlocked("source manifest does not match supplied pin")
    if manifest["commit"] != expected_commit:
        raise PolicyBlocked("manifest does not match explicitly expected commit")
    # In addition to per-file hashing, Stage 26 checks the disabled-v3
    # catalog (all 12 names + stages, zero activated, 64/32 caps).
    stage26 = inspect_checkout_baseline(checkout)
    root = _existing_root(checkout)
    size_total = 0
    for name in _FILES:
        path = root
        parts = name.split("/")
        for part in parts[:-1]:
            path = path / part
            _normal(path, directory=True)
        size, digest = _read_digest(path / parts[-1])
        record = manifest["files"][name]
        if record["bytes"] != size or record["sha256"] != digest:
            raise PolicyBlocked("candidate source bytes mismatch pinned manifest")
        size_total += size
    return {
        "schema": SCHEMA,
        "status": "FILE_MATCH_TO_UNAUTHENTICATED_REVIEWER_MANIFEST",
        "manifest_matches_provided_sha256": True,
        "manifest_matches_expected_commit_text": True,
        "file_bytes_match_manifest": True,
        "files_observed": len(_FILES),
        "bytes_observed": size_total,
        "twelve_upgrade_flags_enabled": stage26["feature_flags_enabled"],
        "project_registration_limit": stage26["registered_project_limit"],
        "active_monitor_limit": stage26["active_monitored_folder_limit"],
        "git_commit_object_validated": False,
        "github_commit_signature_verified": False,
        "reviewer_pin_cryptographically_authenticated": False,
        "owner_authenticated": False,
        "selected_checkout_is_active_installation_proven": False,
        "legacy_process_shutdown_proven": False,
        "safe_to_promote": False,
        "safe_to_install": False,
        "safe_to_migrate": False,
        "task_execution_authorized": False,
        "files_changed": False,
    }


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Read-only pinned source consistency")
    p.add_argument("--checkout", required=True)
    p.add_argument("--manifest", required=True)
    p.add_argument("--manifest-sha256", required=True)
    p.add_argument("--expected-commit", required=True)
    args = p.parse_args(argv)
    try:
        report = compare_selected_checkout(
            checkout=args.checkout,
            manifest=_load_explicit_manifest(args.manifest),
            manifest_sha256=args.manifest_sha256,
            expected_commit=args.expected_commit,
        )
    except (OSError, UnicodeError, ValueError, PolicyBlocked) as exc:
        print("WATCHER_V3_SOURCE_PIN_BLOCKED: " +
              type(exc).__name__, file=sys.stderr)
        return 7
    print(json.dumps(report, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
