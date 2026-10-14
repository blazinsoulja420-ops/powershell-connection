"""Stage 30: cryptographic Ed25519 release-review signature verification.

This is a READ-ONLY review candidate. Ed25519 verification uses the audited
optional 'cryptography' package, never an improvised signature algorithm.
If unavailable, verification fails CLOSED.

Both public key AND its expected fingerprint arrive from the caller. Their
consistency is *not* an owner trust root, trusted publisher identity, GitHub
commit verification, hardware key enrollment or release approval. Signatures
bind the canonical Stage 29 manifest, NOT an authenticated Git commit object.
Nothing in this module installs, launches, connects a repo, approves a task,
makes a Windows Hello credential, migrates state, or enables the watcher.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import sys

from .v3_pinned_source_manifest import (
    SCHEMA as MANIFEST_SCHEMA,
    _load_explicit_manifest,
    canonical_manifest_bytes,
    compare_selected_checkout,
)
from .v3_policy import PolicyBlocked

SCHEMA = "upab.watcher-v3.signed-release-review.v1"
_ALGORITHM = "Ed25519"
_DOMAIN = b"UPAB-WATCHER-V3-RELEASE-REVIEW-ONLY-v1\x00"
_PUB_HEX = re.compile(r"[0-9a-f]{64}\Z")
_SIG_HEX = re.compile(r"[0-9a-f]{128}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_COMMIT = re.compile(r"[0-9a-f]{40}\Z")


def verify_signed_review(
    *,
    checkout: str | Path,
    manifest: object,
    manifest_sha256: str,
    expected_commit: str,
    public_key_hex: str,
    signature_hex: str,
    expected_public_key_sha256: str,
) -> dict[str, object]:
    """Check bytes and Ed25519 signature; always deny owner trust/activation."""
    if (type(public_key_hex) is not str or
            not _PUB_HEX.fullmatch(public_key_hex)
            or type(signature_hex) is not str or
            not _SIG_HEX.fullmatch(signature_hex)
            or type(expected_public_key_sha256) is not str or
            not _SHA256.fullmatch(expected_public_key_sha256)):
        raise PolicyBlocked("release review key/signature/pin malformed")
    pub = bytes.fromhex(public_key_hex)
    if hashlib.sha256(pub).hexdigest() != expected_public_key_sha256:
        raise PolicyBlocked("provided key does not match supplied pin")
    # Stage 29 checks expected repo, exact commit label and all six source
    # artifact digests; it NEVER claims Git object authenticity.
    checked = compare_selected_checkout(
        checkout=checkout, manifest=manifest,
        manifest_sha256=manifest_sha256, expected_commit=expected_commit
    )
    payload = _DOMAIN + canonical_manifest_bytes(manifest)
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    except ImportError as exc:
        raise PolicyBlocked("maintained Ed25519 verification backend unavailable") from exc
    try:
        key = Ed25519PublicKey.from_public_bytes(pub)
        key.verify(bytes.fromhex(signature_hex), payload)
    except (InvalidSignature, ValueError, TypeError) as exc:
        raise PolicyBlocked("release review signature invalid") from exc
    return {
        "schema": SCHEMA,
        "status": "SIGNATURE_VALID_SIGNER_TRUST_NOT_ESTABLISHED",
        "review_signature_algorithm": _ALGORITHM,
        "signature_cryptographically_valid_for_supplied_key": True,
        "source_bytes_match_signed_manifest": True,
        "source_files_observed": checked["files_observed"],
        "activated_upgrade_flags": checked["twelve_upgrade_flags_enabled"],
        "registered_project_limit": checked["project_registration_limit"],
        "active_monitor_limit": checked["active_monitor_limit"],
        "trusted_owner_root_enrolled": False,
        "public_key_fingerprint_independently_trusted": False,
        "key_custody_and_revocation_verified": False,
        "github_commit_object_verified": False,
        "github_commit_signature_verified": False,
        "reproducible_build_verified": False,
        "installed_runtime_identity_verified": False,
        "legacy_watcher_absence_proven": False,
        "owner_authenticated": False,
        "real_device_acceptance_passed": False,
        "safe_to_install": False,
        "safe_to_migrate": False,
        "task_execution_authorized": False,
        "files_or_settings_changed": False,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Read-only Ed25519 verification; no owner trust or execution"
    )
    parser.add_argument("--checkout", required=True)
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--manifest-sha256", required=True)
    parser.add_argument("--expected-commit", required=True)
    parser.add_argument("--public-key-hex", required=True)
    parser.add_argument("--signature-hex", required=True)
    parser.add_argument("--public-key-sha256", required=True)
    args = parser.parse_args(argv)
    try:
        result = verify_signed_review(
            checkout=args.checkout,
            manifest=_load_explicit_manifest(args.manifest),
            manifest_sha256=args.manifest_sha256,
            expected_commit=args.expected_commit,
            public_key_hex=args.public_key_hex,
            signature_hex=args.signature_hex,
            expected_public_key_sha256=args.public_key_sha256,
        )
    except (OSError, UnicodeError, ValueError, PolicyBlocked) as exc:
        # Do not log raw CLI args, local file paths, source bytes or keys.
        print("WATCHER_V3_SIGNED_REVIEW_BLOCKED: " +
              type(exc).__name__, file=sys.stderr)
        return 7
    print(json.dumps(result, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
