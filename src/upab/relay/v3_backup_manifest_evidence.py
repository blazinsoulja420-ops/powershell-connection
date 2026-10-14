"""Stage 23: immutable-format, READ-ONLY backup manifest verification preview.

Consumes only an owner-SELECTED, pre-existing relay backup directory and an
explicit untrusted manifest plus independently supplied manifest fingerprint.
It NEVER CREATES a backup, manifest, signature, approval or trusted proof.
It cannot establish where a manifest came from, whether the external pin
was owner approved, whether an earlier backup was restored, or whether a
live v1 process changed the state during observation.

Only the narrow v1/v2 relay backup file allowlist is accepted. A matching
pin and matching file hashes provide evidence of consistency, NOT provenance,
authenticated backup, rollback authority, or safety to deploy.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
import stat

from .v3_policy import PolicyBlocked

SCHEMA = "upab.watcher-v3.backup-manifest-preview.v1"
ALLOWLIST = {
    "nonce.txt": 512,
    "seen_tasks.jsonl": 8 * 1024 * 1024,
    "relay_v2.sqlite3": 64 * 1024 * 1024,
    "v2_active.marker": 512,
    "watcher_v2.lock": 512,
}
REQUIRED = frozenset({"nonce.txt", "seen_tasks.jsonl"})
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
MAX_TOTAL_BYTES = 72 * 1024 * 1024


def _regular(path: Path, *, directory: bool) -> None:
    try:
        s = path.lstat()
    except (OSError, ValueError) as exc:
        raise PolicyBlocked("existing backup object missing") from exc
    if (stat.S_ISLNK(s.st_mode)
            or getattr(s, "st_file_attributes", 0) & 0x400):
        raise PolicyBlocked("backup object is redirected")
    if (directory and not stat.S_ISDIR(s.st_mode)
            or not directory and not stat.S_ISREG(s.st_mode)):
        raise PolicyBlocked("unexpected backup object type")


def _root(path: str | Path) -> Path:
    if not isinstance(path, (str, Path)):
        raise PolicyBlocked("explicit existing backup root required")
    source = Path(path).expanduser()
    if not source.is_absolute():
        raise PolicyBlocked("backup root must be absolute")
    # Guard *all* components, not just the final symlink. This is still a
    # path-based TOCTOU check, NOT secured Windows open-by-handle semantics.
    for part in [source, *source.parents]:
        _regular(part, directory=True)
    relay = source / "relay"
    _regular(relay, directory=True)
    if tuple(p.name for p in source.iterdir()) != ("relay",):
        raise PolicyBlocked("backup root has unexpected entries")
    return relay


def _manifest_bytes(manifest: object) -> bytes:
    if type(manifest) is not dict or set(manifest) != {"schema", "files"}:
        raise PolicyBlocked("backup manifest schema fields malformed")
    if manifest["schema"] != SCHEMA:
        raise PolicyBlocked("backup manifest schema version unknown")
    files = manifest["files"]
    if type(files) is not dict or not REQUIRED.issubset(files):
        raise PolicyBlocked("backup manifest lacks required files")
    if len(files) > len(ALLOWLIST) or not set(files).issubset(ALLOWLIST):
        raise PolicyBlocked("backup manifest includes unknown files")
    total = 0
    for name, record in files.items():
        if type(record) is not dict or set(record) != {"bytes", "sha256"}:
            raise PolicyBlocked("backup file manifest entry invalid")
        size = record["bytes"]
        digest = record["sha256"]
        if (type(size) is not int or not 0 <= size <= ALLOWLIST[name]
                or type(digest) is not str or not _SHA256.fullmatch(digest)):
            raise PolicyBlocked("backup file manifest bound or digest malformed")
        total += size
    if total > MAX_TOTAL_BYTES:
        raise PolicyBlocked("backup total file bytes exceed cap")
    return json.dumps(manifest, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True).encode("ascii")


def _hash_file(path: Path, bound: int) -> tuple[int, str]:
    _regular(path, directory=False)
    start = path.stat()
    if not 0 <= start.st_size <= bound:
        raise PolicyBlocked("backup file size exceeds cap")
    sha = hashlib.sha256()
    total = 0
    with path.open("rb") as stream:
        while True:
            block = stream.read(65536)
            if not block:
                break
            total += len(block)
            if total > bound:
                raise PolicyBlocked("backup file grew outside cap")
            sha.update(block)
        end = stream.seek(0, 2)
        if end != total:
            raise PolicyBlocked("backup file changed while hashing")
    after = path.stat()
    if (total != start.st_size or after.st_size != start.st_size
            or after.st_mtime_ns != start.st_mtime_ns):
        raise PolicyBlocked("backup file changed during observation")
    return total, sha.hexdigest()


def verify_existing_backup_manifest(
    *, backup_state: str | Path, manifest: object,
    pinned_manifest_sha256: str
) -> dict[str, object]:
    """Match fixed-format declared bytes; ALWAYS deny migration/restore."""
    if (type(pinned_manifest_sha256) is not str or
            not _SHA256.fullmatch(pinned_manifest_sha256)):
        raise PolicyBlocked("expected external manifest SHA-256 pin invalid")
    wire = _manifest_bytes(manifest)
    digest = hashlib.sha256(wire).hexdigest()
    if digest != pinned_manifest_sha256:
        raise PolicyBlocked("backup manifest does not match external pin")
    relay = _root(backup_state)
    entries = list(relay.iterdir())
    declared = manifest["files"]
    if len(entries) != len(declared) or {p.name for p in entries} != set(declared):
        raise PolicyBlocked("backup tree contains added or missing files")
    count = 0
    total = 0
    for name in sorted(declared):
        size, computed = _hash_file(relay / name, ALLOWLIST[name])
        record = declared[name]
        if size != record["bytes"] or computed != record["sha256"]:
            raise PolicyBlocked("backup bytes do not match declared evidence")
        count += 1
        total += size
    return {
        "schema": SCHEMA,
        "status": "MATCHED_UNTRUSTED_MANIFEST_ONLY",
        "checked_file_count": count,
        "checked_bytes": total,
        "external_pin_consistency_observed": True,
        "backup_snapshot_consistency_observed": True,
        "external_pin_owner_authenticated": False,
        "manifest_signed_by_trusted_authority": False,
        "backup_origin_authenticated": False,
        "backup_acls_and_immutability_verified": False,
        "atomic_snapshot_proven": False,
        "rollback_restore_demonstrated": False,
        "real_v1_quiescence_proven": False,
        "live_migration_authorized": False,
        "live_restore_authorized": False,
        "real_task_execution_authorized": False,
        "writes_performed": False,
    }
