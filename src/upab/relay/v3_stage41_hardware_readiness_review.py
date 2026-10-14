"""Stage 41: untrusted, caller-reported hardware readiness review. NO device probe.

This is a PURE validator. It never calls Get-Tpm, WMI, Windows Hello,
WebAuthn, TPM NV commands, subprocesses, networks, enrollment or monitoring.
A report of all-positive capabilities is not independent verification,
device identity, owner approval, a protected monotonic anchor or authority.
"""
from __future__ import annotations

from .v3_policy import PolicyBlocked

SCHEMA = "upab.watcher-v3.hardware-readiness-report.v1"
RECEIPT_SCHEMA = "upab.watcher-v3.hardware-readiness-review.v1"
MAX_EPOCH_S = 253402300799  # 9999-12-31T23:59:59Z
FIELDS = frozenset({
    "schema", "source_kind", "captured_at_epoch_s", "platform",
    "tpm_present", "tpm_ready", "tpm_enabled", "tpm_activated",
    "webauthn_api_present",
})
CAPABILITY_FIELDS = (
    "tpm_present", "tpm_ready", "tpm_enabled", "tpm_activated",
    "webauthn_api_present",
)
SOURCES = frozenset({"CALLER_REPORTED", "SYNTHETIC_FIXTURE"})


def _epoch(value: object) -> bool:
    return type(value) is int and 0 <= value <= MAX_EPOCH_S


def assess_untrusted_hardware_report(
    evidence: object, *, now_epoch_s: int, max_age_s: int = 900,
) -> dict[str, object]:
    """Classify a tiny untrusted observation without contacting any hardware.

    Invalid schema, surplus fields (including approval or owner identity),
    non-boolean capability values, unbounded ages and false timestamps block.
    Unknown fields MUST NOT be silently interpreted as permission.
    """
    if (type(evidence) is not dict or set(evidence) != FIELDS
            or evidence.get("schema") != SCHEMA):
        raise PolicyBlocked("invalid untrusted hardware report structure")
    if evidence["source_kind"] not in SOURCES or type(evidence["source_kind"]) is not str:
        raise PolicyBlocked("unsupported untrusted report source")
    if type(evidence["platform"]) is not str or evidence["platform"] not in (
        "WINDOWS", "OTHER", "UNKNOWN"
    ):
        raise PolicyBlocked("invalid reported operating system")
    if (not _epoch(now_epoch_s) or not _epoch(evidence["captured_at_epoch_s"])
            or type(max_age_s) is not int or not 1 <= max_age_s <= 86400):
        raise PolicyBlocked("invalid untrusted evidence time boundary")
    if any(type(evidence[field]) not in (bool, type(None)) for field in CAPABILITY_FIELDS):
        raise PolicyBlocked("invalid hardware capability field")

    missing = sum(evidence[field] is None for field in CAPABILITY_FIELDS)
    elapsed = now_epoch_s - evidence["captured_at_epoch_s"]
    if elapsed < 0 or elapsed > max_age_s:
        state = "STALE_OR_FUTURE_UNTRUSTED_REPORT"
    elif evidence["platform"] != "WINDOWS" or missing:
        state = "INCOMPLETE_OR_UNSUPPORTED_UNTRUSTED_REPORT"
    elif all(evidence[field] is True for field in CAPABILITY_FIELDS):
        state = "UNTRUSTED_CAPABILITY_CLAIM_ONLY"
    else:
        state = "REPORTED_CAPABILITY_GAP"

    return {
        "schema": RECEIPT_SCHEMA,
        "status": state,
        "evidence_trust": "UNTRUSTED_SELF_REPORT",
        "missing_capability_field_count": missing,
        "owner_authorized_device_preflight": False,
        "real_device_inspected": False,
        "tpm_nv_capability_verified": False,
        "protected_ledger_available": False,
        "hardware_monotonic_store_verified": False,
        "owner_presence_verified": False,
        "collector_enrollment_authorized": False,
        "credential_created": False,
        "tpm_provisioning_authorized": False,
        "monitoring_enabled": False,
        "task_execution_authorized": False,
        "project_roster_modified": False,
        "owner_approval_required_for_next_probe": True,
    }
