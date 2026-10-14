"""Stage 23 supervised Windows acceptance PROTOCOL (never a live runner).

A static, inspectable list of real owner-device acceptance requirements and
explicit consent checkpoints. The only accepted observations are categorical
and UNTRUSTED. Even if all are reported PASS, this module NEVER authenticates
the reporter, enrolls Windows Hello, migrates a watcher or authorizes work.

No laptop interaction, subprocess, filesystem reads/writes, credentials, repo
connections or network activity. Human review remains a separate boundary.
"""
from __future__ import annotations

import hashlib
import json

from .v3_policy import PolicyBlocked

SCHEMA = "upab.watcher-v3.supervised-windows-acceptance.v1"
CHECKPOINTS = (
    ("BASELINE", "Record exact Windows user/session and independent v1 binary/version baseline."),
    ("V1_QUIESCENCE", "Verify old watcher and all in-flight work have stopped under independent OS evidence."),
    ("LAUNCH_EXCLUSION", "Inspect and block ALL authorized v1 startup paths before cutover."),
    ("PROTECTED_BACKUP", "Inspect complete backup contents, ACL/owner and provenance under trusted custody."),
    ("BACKUP_RESTORE", "Rehearse restore into isolated user-approved location, verify replay history and hash."),
    ("TRUSTED_RP", "Verify owner-controlled RP/HTTPS origin, protected challenge issuer and identity lifecycle."),
    ("WINDOWS_HELLO", "Obtain fresh, interactive owner approval and genuine Windows Hello credential registration."),
    ("BROKER_SECURITY", "Verify protected peer/session checks, nonce/counter ledger and exact task-scoped proof."),
    ("EXECUTOR_ISOLATION", "Reject arbitrary commands, repo boundary escapes and writes without exact approval."),
    ("SINGLE_FLIGHT", "Verify no v1/v2 split-brain and concurrent/replayed execution attempts are denied."),
    ("FAULT_RECOVERY", "Force crashes at bounded synthetic checkpoints; uncertain writes must not auto-replay."),
    ("ROLLBACK_GATES", "Verify guarded rollback, required nonce rotation and old launch exclusion."),
    ("DEVICE_PERFORMANCE", "Benchmark idle memory/CPU and event responsiveness on owner's real Windows device."),
    ("INDEPENDENT_REVIEW", "Complete security review and get separate explicit owner deployment authorization."),
)
_ALLOWED = frozenset({"NOT_TESTED", "REPORTED_PASS_UNVERIFIED", "FAILED"})


def review_acceptance_plan(*, observations: object | None = None) -> dict[str, object]:
    """Categorical stage plan; NEVER an approval source."""
    reports = {} if observations is None else observations
    if type(reports) is not dict:
        raise PolicyBlocked("acceptance observations must be a fixed mapping")
    names = {x[0] for x in CHECKPOINTS}
    if not set(reports).issubset(names):
        raise PolicyBlocked("unknown acceptance checkpoint")
    states = {}
    for key, description in CHECKPOINTS:
        value = reports.get(key, "NOT_TESTED")
        if type(value) is not str or value not in _ALLOWED:
            raise PolicyBlocked("acceptance outcome is untrusted or invalid")
        states[key] = value
    failed = [k for k,v in states.items() if v == "FAILED"]
    incomplete = [k for k,v in states.items() if v == "NOT_TESTED"]
    claimed = [k for k,v in states.items() if v == "REPORTED_PASS_UNVERIFIED"]
    evidence_id = hashlib.sha256(json.dumps(states,sort_keys=True,separators=(",",":")).encode()).hexdigest()
    return {
        "schema": SCHEMA,
        "status": "BLOCKED_OWNER_DEVICE_ACCEPTANCE_REQUIRED",
        "checkpoint_count": len(CHECKPOINTS),
        "checkpoint_states": states,
        "checkpoint_descriptions": {name: explanation for name,explanation in CHECKPOINTS},
        "not_tested_count": len(incomplete),
        "failed_count": len(failed),
        "unverified_report_count": len(claimed),
        "report_fingerprint_sha256": evidence_id,
        "report_is_authentic_owner_evidence": False,
        "actual_owner_consent_verified": False,
        "real_device_acceptance_passed": False,
        "legacy_shutdown_and_rollback_proven": False,
        "watcher_enabled": False,
        "live_task_execution_authorized": False,
        "safe_to_install": False,
        "safe_to_migrate": False,
        "changes_performed": False,
    }
