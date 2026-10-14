"""Stage 44: pure hypothetical protected-witness request/response contract.

DOES NOT perform authenticated compare-and-swap, hardware access, disk writes,
network calls, enrollment, credential operations, or monitoring. A caller can
forge both the request and state (including replay history). Simulation success
is NEVER evidence of protected monotonicity or approval.
"""
from __future__ import annotations

from copy import deepcopy
import re

from .v3_policy import PolicyBlocked
from .v3_portfolio_health_rollup import MAX_EPOCH

REQUEST_SCHEMA = "upab.watcher-v3.synthetic-witness-request.v1"
STATE_SCHEMA = "upab.watcher-v3.synthetic-witness-state.v1"
RESPONSE_SCHEMA = "upab.watcher-v3.synthetic-witness-response.v1"

HEX32 = re.compile(r"[0-9a-f]{32}\Z")
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
REQUEST_FIELDS = frozenset({
    "schema", "operation", "witness_id", "request_id",
    "expected_epoch", "expected_commitment", "next_epoch",
    "next_commitment", "transition_kind",
})
STATE_FIELDS = frozenset({
    "schema", "witness_id", "epoch", "commitment",
    "available", "remaining_write_budget", "seen_request_ids",
})
TRANSITIONS = frozenset({"HEALTH", "ENROLL", "ROTATE", "REVOKE", "RECOVER"})
MAX_SEEN = 256


def _is_hex(value: object, matcher: re.Pattern) -> bool:
    return type(value) is str and matcher.fullmatch(value) is not None


def _epoch(value: object) -> bool:
    return type(value) is int and 0 <= value <= MAX_EPOCH


def _check_request(request: object) -> None:
    if type(request) is not dict or set(request) != REQUEST_FIELDS:
        raise PolicyBlocked("invalid synthetic witness request shape")
    if (request["schema"] != REQUEST_SCHEMA
            or type(request["operation"]) is not str
            or request["operation"] not in ("READ_SNAPSHOT", "COMPARE_ADVANCE")
            or not _is_hex(request["witness_id"], HEX32)
            or not _is_hex(request["request_id"], HEX32)
            or not _epoch(request["expected_epoch"])
            or not _is_hex(request["expected_commitment"], HEX64)):
        raise PolicyBlocked("invalid synthetic witness request values")
    if request["operation"] == "READ_SNAPSHOT":
        if (request["next_epoch"] is not None or
                request["next_commitment"] is not None or
                request["transition_kind"] is not None):
            raise PolicyBlocked("synthetic read cannot request mutation")
    elif (not _epoch(request["next_epoch"])
          or request["expected_epoch"] >= MAX_EPOCH
          or request["next_epoch"] != request["expected_epoch"] + 1
          or not _is_hex(request["next_commitment"], HEX64)
          or request["next_commitment"] == request["expected_commitment"]
          or type(request["transition_kind"]) is not str
          or request["transition_kind"] not in TRANSITIONS):
        raise PolicyBlocked("synthetic advance requires new epoch and digest")


def _check_state(state: object) -> None:
    if type(state) is not dict or set(state) != STATE_FIELDS:
        raise PolicyBlocked("invalid synthetic witness state shape")
    seen = state["seen_request_ids"]
    if (state["schema"] != STATE_SCHEMA
            or not _is_hex(state["witness_id"], HEX32)
            or not _epoch(state["epoch"])
            or not _is_hex(state["commitment"], HEX64)
            or type(state["available"]) is not bool
            or type(state["remaining_write_budget"]) is not int
            or not 0 <= state["remaining_write_budget"] <= 100000
            or type(seen) is not list or len(seen) > MAX_SEEN
            or any(not _is_hex(token, HEX32) for token in seen)
            or len(set(seen)) != len(seen)):
        raise PolicyBlocked("invalid synthetic witness state values")


def _receipt(status: str, mutated: bool = False) -> dict[str, object]:
    return {
        "schema": RESPONSE_SCHEMA,
        "status": status,
        "evidence_trust": "CALLER_CONTROLLED_SYNTHETIC_STATE",
        "synthetic_copy_changed": mutated,
        "real_state_modified": False,
        "real_provider_contacted": False,
        "request_authenticated": False,
        "owner_approval_verified": False,
        "collector_identity_verified": False,
        "hardware_monotonicity_verified": False,
        "atomic_cross_resource_commit_verified": False,
        "replay_resistance_verified": False,
        "owner_enrollment_authorized": False,
        "monitoring_enabled": False,
        "task_execution_authorized": False,
        "project_roster_modified": False,
    }


def simulate_untrusted_witness_contract(
    *, request: object, state: object,
) -> tuple[dict[str, object], dict[str, object]]:
    """Review one candidate method and return a changed *copy* at most.

    All inputs and outputs are caller-mutable and have ZERO trust authority.
    A real CAS requires a protected independent signer/serializing writer and
    durable nonce history; this model deliberately provides none of those.
    """
    _check_request(request)
    _check_state(state)
    copy = deepcopy(state)
    if not state["available"]:
        return _receipt("DENIED_SYNTHETIC_WITNESS_UNAVAILABLE"), copy
    if request["witness_id"] != state["witness_id"]:
        return _receipt("DENIED_SYNTHETIC_WITNESS_IDENTITY_MISMATCH"), copy
    if (request["expected_epoch"] != state["epoch"]
            or request["expected_commitment"] != state["commitment"]):
        return _receipt("DENIED_SYNTHETIC_EXPECTED_STATE_MISMATCH"), copy
    if request["operation"] == "READ_SNAPSHOT":
        return _receipt("SYNTHETIC_READ_CONSISTENT_NOT_AUTHENTICATED"), copy
    if request["request_id"] in state["seen_request_ids"]:
        return _receipt("DENIED_SYNTHETIC_REPLAYED_REQUEST"), copy
    if len(state["seen_request_ids"]) == MAX_SEEN:
        return _receipt("DENIED_SYNTHETIC_NONCE_HISTORY_FULL"), copy
    if state["remaining_write_budget"] == 0:
        return _receipt("DENIED_SYNTHETIC_WRITE_BUDGET_EXHAUSTED"), copy

    # Deliberately unprotected paper experiment; no locking or authority.
    copy["epoch"] = request["next_epoch"]
    copy["commitment"] = request["next_commitment"]
    copy["remaining_write_budget"] -= 1
    copy["seen_request_ids"].append(request["request_id"])
    return _receipt("SYNTHETIC_ADVANCE_APPLIED_NO_TRUST", mutated=True), copy
