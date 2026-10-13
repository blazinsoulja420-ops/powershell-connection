"""Watcher v3 execution readiness gate — never runs or authorizes tasks.

All caller-provided objects and proof receipts are UNTRUSTED. This module
only reports the missing trust boundaries before an actual executor can be
integrated. It cannot be tricked into returning execution_allowed=True.
"""
from __future__ import annotations

from typing import Any

from .v3_policy import PolicyBlocked, ReviewJob

_REPORT_SCHEMA = "upab.watcher-v3.execution-readiness.v1"
_EXPECTED_RECEIPT_KEYS = frozenset({
    "status", "task_id", "authenticated_owner",
    "execution_authorized", "proof_consumed",
})
_ALLOWED_INVENTORY_KEYS = frozenset({
    "schema", "status", "legacy_nonce_present", "legacy_records",
    "v2_database_present", "verified_v1_quiescent",
    "authorized_to_migrate", "changes_performed",
})


def evaluate_readiness(
    *,
    task_id: str,
    digest: str,
    receipt: object | None = None,
    migration_inventory: object | None = None,
) -> dict[str, Any]:
    """Build a structured blocker report from inert candidate metadata.

    No live identity provider, repo attestation, or v2 runtime is connected.
    Never treat a caller-supplied assertion, a valid HMAC, or a marker file
    as authorization. This method has no path to an executable result.
    """
    job = ReviewJob(task_id=task_id, digest=digest)
    blockers = [
        "PROTECTED_OWNER_AUTHENTICATION_NOT_CONNECTED",
        "INDEPENDENT_APPROVAL_ISSUER_NOT_CONNECTED",
        "LIVE_REPOSITORY_ATTESTATION_NOT_CONNECTED",
        "LEGACY_V1_PROCESS_LOCKOUT_NOT_VERIFIED",
        "EXECUTOR_ISOLATION_AND_ROLLBACK_NOT_VERIFIED",
        "WINDOWS_HARDWARE_ACCEPTANCE_NOT_VERIFIED",
    ]
    receipt_state = "ABSENT"
    if receipt is not None:
        if not isinstance(receipt, dict) or set(receipt) != _EXPECTED_RECEIPT_KEYS:
            raise PolicyBlocked("unexpected proof receipt fields")
        if receipt["task_id"] != job.task_id:
            raise PolicyBlocked("proof receipt task mismatch")
        if (receipt["status"] != "PROOF_VERIFIED_FOR_REVIEW_ONLY"
                or receipt["authenticated_owner"] is not False
                or receipt["execution_authorized"] is not False
                or receipt["proof_consumed"] is not True):
            raise PolicyBlocked("proof receipt claims unsupported authority")
        receipt_state = "REVIEW_ONLY"
        blockers.append("REVIEW_PROOF_IS_NOT_EXECUTION_APPROVAL")
    migration_state = "ABSENT"
    if migration_inventory is not None:
        if (not isinstance(migration_inventory, dict)
                or set(migration_inventory) != _ALLOWED_INVENTORY_KEYS):
            raise PolicyBlocked("unexpected migration inventory fields")
        if migration_inventory["schema"] != "upab.watcher-v3.migration-inventory.v1":
            raise PolicyBlocked("unknown inventory schema")
        if (migration_inventory["verified_v1_quiescent"] is not False
                or migration_inventory["authorized_to_migrate"] is not False
                or migration_inventory["changes_performed"] is not False):
            raise PolicyBlocked("inventory claims unsupported migration authority")
        if migration_inventory["status"] not in {
            "V1_INVENTORIED_NOT_READY", "V2_STATE_PRESENT_REVIEW",
            "MIGRATION_MARKER_PRESENT_STOP"
        }:
            raise PolicyBlocked("unexpected inventory status")
        for field in ("legacy_nonce_present", "v2_database_present"):
            if type(migration_inventory[field]) is not bool:
                raise PolicyBlocked("invalid inventory boolean field")
        count = migration_inventory["legacy_records"]
        if count is not None and (type(count) is not int or count < 0 or count > 1000000):
            raise PolicyBlocked("invalid legacy record count")
        migration_state = migration_inventory["status"]
        blockers.append("MIGRATION_INVENTORY_IS_NOT_PROCESS_QUIESCENCE_PROOF")
    return {
        "schema": _REPORT_SCHEMA,
        "task_id": job.task_id,
        "task_sha256": job.digest.upper(),
        "status": "NOT_READY",
        "proof_receipt_state": receipt_state,
        "migration_inventory_state": migration_state,
        "blockers": blockers,
        "execution_allowed": False,
        "can_activate": False,
        "side_effects": False,
    }
