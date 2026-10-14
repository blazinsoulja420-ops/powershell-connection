"""Stage 42: pure, test-only dual-resource monotonic transition review.

Does not create or read real ledger, TPM, Windows key, file, GitHub API or
monitor. Both ledger and witness are *caller-controlled hypothetical*
records. A consistent result is NOT evidence of authenticated state; status
never unlocks execution, enrollment, remote observation or live recovery.
"""
from __future__ import annotations

from copy import deepcopy
import re

from .v3_policy import PolicyBlocked
from .v3_portfolio_health_rollup import MAX_EPOCH
from .v3_portfolio_review import PROJECTS, POINDEXTER_MODULES

LEDGER_SCHEMA = "upab.watcher-v3.synthetic-transition-ledger.v1"
WITNESS_SCHEMA = "upab.watcher-v3.synthetic-transition-witness.v1"
PENDING_SCHEMA = "upab.watcher-v3.synthetic-transition-pending.v1"
RECEIPT_SCHEMA = "upab.watcher-v3.synthetic-transition-review.v1"
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
HEX32 = re.compile(r"[0-9a-f]{32}\Z")
ACTIONS = frozenset({"HEALTH_ADVANCE", "COLLECTOR_REVOKE", "COLLECTOR_ROTATE"})
BOUNDARIES = frozenset({"BEFORE_PREPARE", "AFTER_PREPARE", "AFTER_WITNESS_ADVANCE", "AFTER_FINALIZE"})
LEDGER_FIELDS = frozenset({"schema", "ledger_id", "epoch", "committed_digest", "phase", "pending"})
WITNESS_FIELDS = frozenset({"schema", "ledger_id", "epoch", "committed_digest", "availability"})
PENDING_FIELDS = frozenset({"schema", "action", "repository", "module_id", "expected_epoch",
                           "next_epoch", "previous_digest", "next_digest", "previous_sequence",
                           "next_sequence", "previous_key_id", "next_key_id"})


def _hex(value: object, pattern: re.Pattern) -> bool:
    return type(value) is str and pattern.fullmatch(value) is not None


def _epoch(value: object) -> bool:
    return type(value) is int and 0 <= value <= MAX_EPOCH


def _scope(repo: object, module: object) -> bool:
    if type(repo) is not str or repo not in PROJECTS:
        return False
    if module is None:
        return True
    return (repo == "UP-UHAIB-001-Poindexter" and type(module) is str
            and module in {item[0] for item in POINDEXTER_MODULES})


def _validate_pending(pending: object) -> None:
    if type(pending) is not dict or set(pending) != PENDING_FIELDS:
        raise PolicyBlocked("invalid synthetic pending transition fields")
    if (pending["schema"] != PENDING_SCHEMA
            or type(pending["action"]) is not str or pending["action"] not in ACTIONS
            or not _scope(pending["repository"], pending["module_id"])
            or not _epoch(pending["expected_epoch"])
            or not _epoch(pending["next_epoch"])
            or pending["next_epoch"] != pending["expected_epoch"] + 1
            or not _hex(pending["previous_digest"], HEX64)
            or not _hex(pending["next_digest"], HEX64)
            or pending["next_digest"] == pending["previous_digest"]
            or not _hex(pending["previous_key_id"], HEX64)):
        raise PolicyBlocked("synthetic transition shape or monotonic epoch invalid")
    action = pending["action"]
    prev, next_value = pending["previous_sequence"], pending["next_sequence"]
    new_key = pending["next_key_id"]
    if action == "HEALTH_ADVANCE":
        if (not _epoch(prev) or prev < 1 or not _epoch(next_value)
                or next_value != prev + 1 or new_key != pending["previous_key_id"]):
            raise PolicyBlocked("synthetic health sequence and key continuity invalid")
    elif action == "COLLECTOR_REVOKE":
        if prev is not None or next_value is not None or new_key is not None:
            raise PolicyBlocked("synthetic revocation must retire key and advance epoch")
    elif action == "COLLECTOR_ROTATE":
        if (prev is not None or next_value is not None
                or not _hex(new_key, HEX64)
                or new_key == pending["previous_key_id"]):
            raise PolicyBlocked("synthetic rotation requires distinct replacement key")


def _validate(ledger: object, witness: object) -> None:
    if type(ledger) is not dict or set(ledger) != LEDGER_FIELDS:
        raise PolicyBlocked("invalid synthetic ledger fields")
    if type(witness) is not dict or set(witness) != WITNESS_FIELDS:
        raise PolicyBlocked("invalid synthetic witness fields")
    if (ledger["schema"] != LEDGER_SCHEMA or witness["schema"] != WITNESS_SCHEMA
            or not _hex(ledger["ledger_id"], HEX32)
            or not _hex(witness["ledger_id"], HEX32)
            or not _epoch(ledger["epoch"]) or not _epoch(witness["epoch"])
            or not _hex(ledger["committed_digest"], HEX64)
            or not _hex(witness["committed_digest"], HEX64)
            or type(ledger["phase"]) is not str or ledger["phase"] not in ("READY", "PREPARED", "QUARANTINED")
            or type(witness["availability"]) is not str or witness["availability"] not in ("PRESENT", "MISSING")):
        raise PolicyBlocked("invalid synthetic ledger/witness field values")
    if ledger["phase"] == "PREPARED":
        _validate_pending(ledger["pending"])
        if (ledger["pending"]["expected_epoch"] != ledger["epoch"]
                or ledger["pending"]["previous_digest"] != ledger["committed_digest"]):
            raise PolicyBlocked("pending transition does not bind prior ledger state")
    elif ledger["phase"] == "READY" and ledger["pending"] is not None:
        raise PolicyBlocked("READY cannot contain a pending transition")
    elif ledger["pending"] is not None:
        _validate_pending(ledger["pending"])


def _receipt(status: str) -> dict[str, object]:
    return {
        "schema": RECEIPT_SCHEMA, "status": status,
        "evidence_trust": "UNTRUSTED_SYNTHETIC_PAIR",
        "source_authenticated": False, "collector_enrolled": False,
        "owner_authenticated": False, "real_witness_contacted": False,
        "tpm_nv_capability_verified": False,
        "protected_monotonicity_verified": False,
        "real_crash_recovery_verified": False,
        "rollback_resistance_verified": False,
        "recovery_execution_allowed": False,
        "new_enrollment_authorized": False,
        "real_monitoring_enabled": False,
        "task_execution_authorized": False,
        "project_roster_modified": False,
    }


def review_synthetic_transition(*, ledger: object, witness: object) -> dict[str, object]:
    """Fail closed; a recovery candidate still needs genuine trust/owner action."""
    _validate(ledger, witness)
    if witness["availability"] != "PRESENT":
        return _receipt("BLOCKED_WITNESS_UNAVAILABLE")
    if ledger["phase"] == "QUARANTINED":
        return _receipt("QUARANTINED_PREEXISTING")
    if ledger["ledger_id"] != witness["ledger_id"]:
        return _receipt("QUARANTINED_IDENTITY_MISMATCH")
    current_epoch, anchored_epoch = ledger["epoch"], witness["epoch"]
    if ledger["phase"] == "READY":
        if current_epoch > anchored_epoch:
            return _receipt("QUARANTINED_LEDGER_AHEAD")
        if current_epoch < anchored_epoch:
            return _receipt("QUARANTINED_WITNESS_AHEAD")
        if ledger["committed_digest"] != witness["committed_digest"]:
            return _receipt("QUARANTINED_DIGEST_MISMATCH")
        return _receipt("SYNTHETIC_READY_CONSISTENT_NO_TRUST")

    pending = ledger["pending"]
    if (current_epoch == anchored_epoch
            and ledger["committed_digest"] == witness["committed_digest"]):
        # The pending transaction is not anchored: uncertain prepare can only
        # be discarded/quarantined via a future authenticated operator policy.
        return _receipt("QUARANTINED_PREPARED_NOT_ANCHORED")
    if (anchored_epoch == pending["next_epoch"]
            and witness["committed_digest"] == pending["next_digest"]):
        # Intentional manual review, not automatic SQLite finalization.
        return _receipt("SYNTHETIC_RECOVERY_REVIEW_REQUIRED")
    return _receipt("QUARANTINED_AMBIGUOUS_TRANSITION")


def model_synthetic_crash_boundary(*, ledger: object, witness: object,
                                   proposal: object, boundary: str) -> tuple[dict, dict]:
    """Pure test-vector constructor. Does NOT persist or advance any anchor."""
    if type(boundary) is not str or boundary not in BOUNDARIES:
        raise PolicyBlocked("invalid synthetic crash boundary")
    _validate(ledger, witness)
    _validate_pending(proposal)
    if review_synthetic_transition(ledger=ledger, witness=witness)["status"] != "SYNTHETIC_READY_CONSISTENT_NO_TRUST":
        raise PolicyBlocked("synthetic crash model requires consistent READY baseline")
    if (proposal["expected_epoch"] != ledger["epoch"]
            or proposal["previous_digest"] != ledger["committed_digest"]):
        raise PolicyBlocked("synthetic proposal not bound to baseline")
    db_copy, anchor_copy = deepcopy(ledger), deepcopy(witness)
    if boundary == "BEFORE_PREPARE":
        return db_copy, anchor_copy
    db_copy["phase"] = "PREPARED"
    db_copy["pending"] = deepcopy(proposal)
    if boundary == "AFTER_PREPARE":
        return db_copy, anchor_copy
    anchor_copy["epoch"] = proposal["next_epoch"]
    anchor_copy["committed_digest"] = proposal["next_digest"]
    if boundary == "AFTER_WITNESS_ADVANCE":
        return db_copy, anchor_copy
    db_copy["phase"] = "READY"
    db_copy["pending"] = None
    db_copy["epoch"] = proposal["next_epoch"]
    db_copy["committed_digest"] = proposal["next_digest"]
    return db_copy, anchor_copy
