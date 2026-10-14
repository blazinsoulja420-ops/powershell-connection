"""Stage 30: fail-closed offline publisher trust boundary.

This is a *policy preflight*, not signature verification. No embedded key,
network call, certificate installation, Windows credential enrollment, or
approval capability is supplied by this module.
"""
from __future__ import annotations

import re

from .v3_policy import PolicyBlocked

_FINGERPRINT = re.compile(r"[0-9a-f]{64}\\Z")
_COMMIT = re.compile(r"[0-9a-f]{40}\\Z")
SCHEMA = "upab.watcher-v3.publisher-trust-preflight.v1"


def inspect_release_trust(*, expected_commit: str, publisher_key_sha256: str | None = None,
                          signed_release_verified: bool = False,
                          owner_authenticated: bool = False) -> dict[str, object]:
    if type(expected_commit) is not str or not _COMMIT.fullmatch(expected_commit):
        raise PolicyBlocked("explicit reviewed commit is required")
    if publisher_key_sha256 is not None and (
        type(publisher_key_sha256) is not str or not _FINGERPRINT.fullmatch(publisher_key_sha256)
    ):
        raise PolicyBlocked("publisher key fingerprint malformed")
    if type(signed_release_verified) is not bool or type(owner_authenticated) is not bool:
        raise PolicyBlocked("untrusted trust indicators")
    # Caller-provided booleans are assertions, not cryptographic evidence.
    return {
        "schema": SCHEMA,
        "status": "TRUST_ROOT_NOT_ENROLLED",
        "reviewed_commit_format_valid": True,
        "publisher_fingerprint_supplied": publisher_key_sha256 is not None,
        "signature_cryptographically_verified": False,
        "trusted_publisher_key_enrolled": False,
        "owner_presence_verified": False,
        "release_authenticated": False,
        "installation_authorized": False,
        "migration_authorized": False,
        "task_execution_authorized": False,
        "changes_performed": False,
    }
