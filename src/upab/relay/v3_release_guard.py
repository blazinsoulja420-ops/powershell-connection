"""Read-only release integrity and rollback planning for Watcher v3.

Matching hashes prove consistency with caller-supplied data, NOT authenticity,
security approval, permission to install, or authorization to roll back.
"""
from __future__ import annotations

import hashlib
from pathlib import Path
import re
import stat

from .v3_policy import PolicyBlocked

_SHA256 = re.compile(r"^[a-fA-F0-9]{64}$")
_COMPONENT = re.compile(r"^[A-Za-z0-9_.-]+$")
_SCHEMA = "upab.watcher.release-preview.v1"


def verify_release_preview(root_dir: str | Path, manifest: object) -> dict[str, object]:
    if not isinstance(manifest, dict) or set(manifest) != {"schema", "files"}:
        raise PolicyBlocked("manifest fields are invalid")
    if manifest["schema"] != _SCHEMA:
        raise PolicyBlocked("unknown release manifest schema")
    files = manifest["files"]
    if not isinstance(files, dict) or not 1 <= len(files) <= 512:
        raise PolicyBlocked("manifest must contain 1..512 files")
    root = Path(root_dir).expanduser().resolve(strict=True)
    if not root.is_dir():
        raise PolicyBlocked("release root is not a directory")
    passed = 0
    total = 0
    mismatched: list[str] = []
    for rel, digest in sorted(files.items()):
        if not isinstance(rel, str) or len(rel) > 256 or not rel:
            raise PolicyBlocked("invalid manifest path")
        if not isinstance(digest, str) or not _SHA256.fullmatch(digest):
            raise PolicyBlocked("invalid SHA-256 digest")
        pieces = rel.split("/")
        if any(not _COMPONENT.fullmatch(part) or part in {".", ".."} for part in pieces):
            raise PolicyBlocked("manifest path must be an ordinary relative path")
        location = root
        # Deny symlinks/reparse points in each component, not just final file.
        for part in pieces:
            location = location / part
            try:
                details = location.lstat()
            except FileNotFoundError:
                mismatched.append(rel)
                location = None
                break
            if stat.S_ISLNK(details.st_mode) or (hasattr(details, "st_file_attributes") and
                details.st_file_attributes & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)):
                raise PolicyBlocked("symlink/reparse point in release manifest path")
        if location is None:
            continue
        if not location.is_file() or not location.resolve().is_relative_to(root):
            raise PolicyBlocked("release manifest includes non-file or escaping path")
        size = location.stat().st_size
        if size > 32 * 1024 * 1024:
            raise PolicyBlocked("release file exceeds bounded verification size")
        total += size
        h = hashlib.sha256()
        with location.open("rb") as source:
            while True:
                chunk = source.read(65536)
                if not chunk:
                    break
                h.update(chunk)
        if h.hexdigest().casefold() == digest.casefold():
            passed += 1
        else:
            mismatched.append(rel)
    return {
        "schema": _SCHEMA,
        "verified_file_count": passed,
        "declared_file_count": len(files),
        "total_bytes_hashed": total,
        "mismatches": mismatched,
        "contents_match_manifest": passed == len(files) and not mismatched,
        "manifest_authenticated": False,
        "authorized_to_install": False,
        "authorized_to_rollback": False,
        "performed_changes": False,
    }


def rollback_preview() -> dict[str, object]:
    """Explicit checklist, no writes, scripts, file restoration or permissions."""
    return {
        "status": "REVIEW_ONLY",
        "requirements": [
            "Stop and verify all existing v1/v2 processes are quiescent.",
            "Validate an independently authenticated operator approval.",
            "Capture and integrity-check a private backup of prechange state.",
            "Verify proposed rollback bytes and repository baseline.",
            "Rotate or quarantine old nonces to prevent replay on restart.",
            "Verify state and launch-path mutual exclusion before promotion.",
            "Run negative-path Windows acceptance and log evidence.",
        ],
        "performed_changes": False,
        "rollback_authorized": False,
    }
