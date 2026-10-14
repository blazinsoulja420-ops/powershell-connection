"""Stage 43: pure, caller-controlled protected-witness architecture review.

This module makes NO TPM calls, Windows API calls, service connections,
network requests, writes, approvals, or trust-enrollment decisions.
Architectural conformance is not device verification or production authority.
"""
from __future__ import annotations

from .v3_policy import PolicyBlocked

SCHEMA = "upab.watcher-v3.protected-witness-architecture.v1"
RECEIPT_SCHEMA = "upab.watcher-v3.protected-witness-architecture-review.v1"
_FIELDS = frozenset({
    "schema", "provider_kind", "project_boundary", "trust_root",
    "writer_model", "collector_authentication", "owner_approval",
    "state_binding", "transition_protocol", "revocation_policy",
    "offline_policy", "recovery_policy", "reported_writes_per_day",
    "reported_write_capacity_per_day", "hardware_evidence_kind",
})
_ALLOWED = {
    "provider_kind": frozenset({"TPM_NV_CANDIDATE", "EXTERNAL_WITNESS_CANDIDATE",
                                 "UNDECIDED"}),
    "project_boundary": frozenset({"INDEPENDENT_WATCHER", "SHARED_POINDEXTER_AUTHORITY",
                                    "UNKNOWN"}),
    "trust_root": frozenset({"SEPARATELY_ENROLLED", "CALLER_SUPPLIED", "UNKNOWN"}),
    "writer_model": frozenset({"BROKER_SINGLE_WRITER", "CALLER_MUTABLE", "UNKNOWN"}),
    "collector_authentication": frozenset({"BOUND_ENROLLED_SCOPE", "SELF_SIGNED_ONLY",
                                            "UNKNOWN"}),
    "owner_approval": frozenset({"SEPARATE_SCOPED_CEREMONY",
                                  "REUSE_POINDEXTER_APPROVAL", "UNKNOWN"}),
    "state_binding": frozenset({"EPOCH_AND_AUTHENTICATED_STATE_COMMITMENT",
                                 "EPOCH_ONLY", "LOCAL_HASH_ONLY", "UNKNOWN"}),
    "transition_protocol": frozenset({"PREPARE_ANCHOR_FINALIZE_FAIL_CLOSED",
                                       "SQLITE_ONLY", "UNKNOWN"}),
    "revocation_policy": frozenset({"EPOCH_ADVANCE_AND_REVOKE",
                                     "SAME_EPOCH_RESEAL", "UNKNOWN"}),
    "offline_policy": frozenset({"QUARANTINE_ON_UNAVAILABLE",
                                 "ACCEPT_UNANCHORED", "UNKNOWN"}),
    "recovery_policy": frozenset({"AUTHENTICATED_MANUAL_REVIEW_ON_AMBIGUITY",
                                  "AUTO_RESTORE_OLD_STATE", "UNKNOWN"}),
    "hardware_evidence_kind": frozenset({"NOT_COLLECTED", "CALLER_REPORTED",
                                           "INDEPENDENT_PLATFORM_VALIDATION"}),
}
_REQUIRED = {
    "project_boundary": "INDEPENDENT_WATCHER",
    "trust_root": "SEPARATELY_ENROLLED",
    "writer_model": "BROKER_SINGLE_WRITER",
    "collector_authentication": "BOUND_ENROLLED_SCOPE",
    "owner_approval": "SEPARATE_SCOPED_CEREMONY",
    "state_binding": "EPOCH_AND_AUTHENTICATED_STATE_COMMITMENT",
    "transition_protocol": "PREPARE_ANCHOR_FINALIZE_FAIL_CLOSED",
    "revocation_policy": "EPOCH_ADVANCE_AND_REVOKE",
    "offline_policy": "QUARANTINE_ON_UNAVAILABLE",
    "recovery_policy": "AUTHENTICATED_MANUAL_REVIEW_ON_AMBIGUITY",
}
_REJECT = frozenset({
    "SHARED_POINDEXTER_AUTHORITY", "CALLER_SUPPLIED", "CALLER_MUTABLE",
    "SELF_SIGNED_ONLY", "REUSE_POINDEXTER_APPROVAL", "EPOCH_ONLY",
    "LOCAL_HASH_ONLY", "SQLITE_ONLY", "SAME_EPOCH_RESEAL",
    "ACCEPT_UNANCHORED", "AUTO_RESTORE_OLD_STATE",
})


def review_witness_architecture(proposal: object) -> dict[str, object]:
    """Assess a hypothetical plan, not a genuine secure device/provider.

    Caller-provided assertions, even claims labelled INDEPENDENT, are never
    promoted to facts. Return only bounded enumerated gap codes and deny flags.
    """
    if type(proposal) is not dict or set(proposal) != _FIELDS:
        raise PolicyBlocked("invalid witness architecture fields")
    if proposal.get("schema") != SCHEMA:
        raise PolicyBlocked("unsupported witness architecture schema")
    for field, choices in _ALLOWED.items():
        value = proposal[field]
        if type(value) is not str or value not in choices:
            raise PolicyBlocked("invalid witness architecture option")
    expected = proposal["reported_writes_per_day"]
    capacity = proposal["reported_write_capacity_per_day"]
    if type(expected) is not int or not 1 <= expected <= 100000:
        raise PolicyBlocked("invalid proposed daily witness write count")
    if capacity is not None and (
        type(capacity) is not int or not 1 <= capacity <= 100000000
    ):
        raise PolicyBlocked("invalid claimed witness write capacity")

    gaps = [field.upper() + "_NOT_DESIGNED" for field, required in _REQUIRED.items()
            if proposal[field] != required]
    if proposal["provider_kind"] == "UNDECIDED":
        gaps.append("WITNESS_BACKEND_UNDECIDED")
    if capacity is None:
        gaps.append("WRITE_CAPACITY_NOT_EVIDENCED")
    elif expected > capacity:
        gaps.append("EXPECTED_WRITES_EXCEED_CLAIMED_CAPACITY")
    if proposal["provider_kind"] == "TPM_NV_CANDIDATE":
        # Even true TPM presence/ready would not prove NV counter support,
        # persistent authenticated digest, Windows permissions or wear budget.
        gaps.append("REAL_WINDOWS_TPM_NV_PROVISIONING_UNVERIFIED")
    elif proposal["provider_kind"] == "EXTERNAL_WITNESS_CANDIDATE":
        # Service identity, durable CAS, availability, rate limits and cost
        # remain unknown in a caller-provided design document.
        gaps.append("EXTERNAL_AUTHENTICATED_CAS_SERVICE_UNVERIFIED")
    if proposal["hardware_evidence_kind"] != "INDEPENDENT_PLATFORM_VALIDATION":
        gaps.append("HARDWARE_OR_SERVICE_EVIDENCE_NOT_INDEPENDENTLY_VALIDATED")
    # A caller naming independent validation does NOT mean it occurred.
    gaps.append("EXTERNAL_SECURITY_REVIEW_NOT_COMPLETED")

    rejected = any(proposal[field] in _REJECT for field in _REQUIRED)
    status = ("REJECTED_UNSAFE_ARCHITECTURE" if rejected
              else "UNVERIFIED_ARCHITECTURE_REQUIRES_EVIDENCE")
    return {
        "schema": RECEIPT_SCHEMA,
        "status": status,
        "evidence_trust": "UNTRUSTED_CALLER_ARCHITECTURE",
        "gap_codes": sorted(set(gaps)),
        "gap_count": len(set(gaps)),
        "candidate_architecture_policy_passed": (
            not rejected and all(proposal[key] == value
                                 for key, value in _REQUIRED.items())
        ),
        "real_windows_device_inspected": False,
        "tpm_nv_index_provisioned": False,
        "external_witness_connected": False,
        "independent_witness_authenticated": False,
        "collector_identity_authenticated": False,
        "owner_presence_verified": False,
        "protected_monotonicity_verified": False,
        "rollback_resistance_verified": False,
        "recovery_execution_authorized": False,
        "monitoring_enabled": False,
        "task_execution_authorized": False,
        "project_roster_modified": False,
    }
