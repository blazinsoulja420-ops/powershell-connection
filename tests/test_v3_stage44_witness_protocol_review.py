"""Stage 44: inert witness-interface and nonce/budget policy regression tests."""
from __future__ import annotations

from copy import deepcopy
import json
import unittest

from upab.relay.v3_policy import PolicyBlocked
from upab.relay.v3_portfolio_health_rollup import MAX_EPOCH
from upab.relay.v3_stage44_witness_protocol_review import (
    REQUEST_SCHEMA, STATE_SCHEMA, MAX_SEEN, simulate_untrusted_witness_contract,
)

WITNESS = "a" * 32
OLD = "b" * 64
NEW = "c" * 64
NONCE = "d" * 32


def specimen(operation="COMPARE_ADVANCE", transition="HEALTH"):
    return {
        "schema": REQUEST_SCHEMA,
        "operation": operation,
        "witness_id": WITNESS,
        "request_id": NONCE,
        "expected_epoch": 11,
        "expected_commitment": OLD,
        "next_epoch": 12 if operation == "COMPARE_ADVANCE" else None,
        "next_commitment": NEW if operation == "COMPARE_ADVANCE" else None,
        "transition_kind": transition if operation == "COMPARE_ADVANCE" else None,
    }


def hypothetical_state():
    return {
        "schema": STATE_SCHEMA,
        "witness_id": WITNESS,
        "epoch": 11,
        "commitment": OLD,
        "available": True,
        "remaining_write_budget": 120,
        "seen_request_ids": [],
    }


class Stage44SyntheticWitnessTests(unittest.TestCase):
    def run_model(self, request=None, state=None):
        return simulate_untrusted_witness_contract(
            request=specimen() if request is None else request,
            state=hypothetical_state() if state is None else state,
        )

    def denied_authority(self, receipt):
        for field in (
            "real_state_modified", "real_provider_contacted",
            "request_authenticated", "owner_approval_verified",
            "collector_identity_verified", "hardware_monotonicity_verified",
            "atomic_cross_resource_commit_verified",
            "replay_resistance_verified", "owner_enrollment_authorized",
            "monitoring_enabled", "task_execution_authorized",
            "project_roster_modified",
        ):
            self.assertIs(receipt[field], False, field)
        self.assertEqual(receipt["evidence_trust"], "CALLER_CONTROLLED_SYNTHETIC_STATE")

    def test_read_only_returns_copy_and_no_change(self):
        input_state = hypothetical_state()
        receipt, candidate = self.run_model(specimen("READ_SNAPSHOT"), input_state)
        self.assertEqual(receipt["status"], "SYNTHETIC_READ_CONSISTENT_NOT_AUTHENTICATED")
        self.assertFalse(receipt["synthetic_copy_changed"])
        self.assertEqual(candidate, input_state)
        self.assertIsNot(candidate, input_state)
        self.denied_authority(receipt)

    def test_simulated_cas_mutates_copy_only(self):
        state = hypothetical_state()
        untouched = deepcopy(state)
        receipt, updated = self.run_model(state=state)
        self.assertEqual(receipt["status"], "SYNTHETIC_ADVANCE_APPLIED_NO_TRUST")
        self.assertTrue(receipt["synthetic_copy_changed"])
        self.assertEqual(updated["epoch"], 12)
        self.assertEqual(updated["commitment"], NEW)
        self.assertEqual(updated["remaining_write_budget"], 119)
        self.assertEqual(updated["seen_request_ids"], [NONCE])
        self.assertEqual(state, untouched)
        self.denied_authority(receipt)

    def test_all_transition_kinds_remain_hypothetical(self):
        for action in ("HEALTH", "ENROLL", "ROTATE", "REVOKE", "RECOVER"):
            with self.subTest(action=action):
                receipt, result = self.run_model(specimen(transition=action))
                self.assertEqual(receipt["status"], "SYNTHETIC_ADVANCE_APPLIED_NO_TRUST")
                self.denied_authority(receipt)
                self.assertEqual(result["epoch"], 12)

    def test_replayed_nonce_refused_even_after_matching_new_expected_epoch(self):
        _, state = self.run_model()
        req = specimen()
        req.update(expected_epoch=12, expected_commitment=NEW,
                   next_epoch=13, next_commitment="e" * 64)
        receipt, copy = self.run_model(req, state)
        self.assertEqual(receipt["status"], "DENIED_SYNTHETIC_REPLAYED_REQUEST")
        self.assertEqual(copy, state)
        self.denied_authority(receipt)

    def test_compare_state_mismatch_denied(self):
        for changes in (
            {"expected_epoch": 10},
            {"expected_epoch": 12, "next_epoch": 13},
            {"expected_commitment": "f" * 64},
        ):
            req = specimen()
            req.update(changes)
            with self.subTest(changes=changes):
                report, unchanged = self.run_model(req)
                self.assertEqual(report["status"], "DENIED_SYNTHETIC_EXPECTED_STATE_MISMATCH")
                self.assertEqual(unchanged, hypothetical_state())
                self.denied_authority(report)

    def test_witness_identity_mismatch_denied(self):
        req = specimen()
        req["witness_id"] = "f" * 32
        report, result = self.run_model(req)
        self.assertEqual(report["status"], "DENIED_SYNTHETIC_WITNESS_IDENTITY_MISMATCH")
        self.assertEqual(result, hypothetical_state())
        self.denied_authority(report)

    def test_unavailable_witness_denied_for_read_and_write(self):
        for operation in ("READ_SNAPSHOT", "COMPARE_ADVANCE"):
            state = hypothetical_state()
            state["available"] = False
            with self.subTest(operation=operation):
                report, result = self.run_model(specimen(operation), state)
                self.assertEqual(report["status"], "DENIED_SYNTHETIC_WITNESS_UNAVAILABLE")
                self.assertEqual(result, state)
                self.denied_authority(report)

    def test_zero_write_budget_denies_all_transitions(self):
        state = hypothetical_state()
        state["remaining_write_budget"] = 0
        report, after = self.run_model(state=state)
        self.assertEqual(report["status"], "DENIED_SYNTHETIC_WRITE_BUDGET_EXHAUSTED")
        self.assertEqual(after, state)
        self.denied_authority(report)

    def test_history_full_denied_without_eviction(self):
        state = hypothetical_state()
        state["seen_request_ids"] = [f"{n:032x}" for n in range(MAX_SEEN)]
        report, after = self.run_model(state=state)
        self.assertEqual(report["status"], "DENIED_SYNTHETIC_NONCE_HISTORY_FULL")
        self.assertEqual(after, state)
        self.assertEqual(len(after["seen_request_ids"]), MAX_SEEN)
        self.denied_authority(report)

    def test_two_independent_copies_can_both_accept_shows_missing_real_cas(self):
        # An explicit counterexample: two callers have a matching old snapshot.
        state = hypothetical_state()
        first, first_out = self.run_model(state=deepcopy(state))
        second, second_out = self.run_model(state=deepcopy(state))
        self.assertEqual(first["status"], "SYNTHETIC_ADVANCE_APPLIED_NO_TRUST")
        self.assertEqual(second["status"], "SYNTHETIC_ADVANCE_APPLIED_NO_TRUST")
        self.assertEqual(first_out, second_out)
        self.denied_authority(first)
        self.denied_authority(second)

    def test_revoke_cannot_reseal_same_epoch(self):
        request = specimen(transition="REVOKE")
        request["next_epoch"] = 11
        with self.assertRaises(PolicyBlocked):
            self.run_model(request)

    def test_rotation_cannot_reuse_same_commitment(self):
        request = specimen(transition="ROTATE")
        request["next_commitment"] = OLD
        with self.assertRaises(PolicyBlocked):
            self.run_model(request)

    def test_read_cannot_embed_write_mutation(self):
        for field, value in (
            ("next_epoch", 12), ("next_commitment", NEW),
            ("transition_kind", "REVOKE"),
        ):
            obj = specimen("READ_SNAPSHOT")
            obj[field] = value
            with self.subTest(field=field), self.assertRaises(PolicyBlocked):
                self.run_model(obj)

    def test_invalid_transition_kind_rejected(self):
        for kind in ("EXECUTE", "ENROLL_OWNER", None, True, [], {}):
            req = specimen()
            req["transition_kind"] = kind
            with self.subTest(kind=str(kind)), self.assertRaises(PolicyBlocked):
                self.run_model(req)

    def test_invalid_integer_types_or_epoch_overflow_rejected(self):
        for val in (True, -1, "11", 11.0, None, [], MAX_EPOCH + 1):
            request = specimen()
            request["expected_epoch"] = val
            with self.subTest(value=str(val)), self.assertRaises(PolicyBlocked):
                self.run_model(request)
        request = specimen()
        request["expected_epoch"] = MAX_EPOCH
        request["next_epoch"] = MAX_EPOCH + 1
        with self.assertRaises(PolicyBlocked):
            self.run_model(request)

    def test_invalid_and_unhashable_request_field_rejected(self):
        for field, value in (
            ("operation", []), ("operation", "CREATE_OWNER"),
            ("schema", "wrong"), ("witness_id", []),
            ("request_id", 44), ("expected_commitment", {}),
            ("next_commitment", True), ("next_epoch", "12"),
        ):
            request = specimen()
            request[field] = value
            with self.subTest(field=field), self.assertRaises(PolicyBlocked):
                self.run_model(request)

    def test_invalid_state_values_rejected(self):
        for field, value in (
            ("available", "True"), ("available", 1),
            ("remaining_write_budget", -1),
            ("remaining_write_budget", True),
            ("remaining_write_budget", "10"),
            ("remaining_write_budget", 100001),
            ("seen_request_ids", {}),
            ("seen_request_ids", [[], []]),
            ("seen_request_ids", [NONCE, NONCE]),
            ("seen_request_ids", ["x"]),
            ("seen_request_ids", [f"{n:032x}" for n in range(MAX_SEEN + 1)]),
            ("epoch", True), ("commitment", None),
        ):
            state = hypothetical_state()
            state[field] = value
            with self.subTest(field=field, value_type=type(value).__name__):
                with self.assertRaises(PolicyBlocked):
                    self.run_model(state=state)

    def test_unknown_and_missing_fields_do_not_get_approval(self):
        request, state = specimen(), hypothetical_state()
        for field in request:
            obj = deepcopy(request)
            obj.pop(field)
            with self.subTest(field=field), self.assertRaises(PolicyBlocked):
                self.run_model(obj)
        for field in state:
            obj = deepcopy(state)
            obj.pop(field)
            with self.subTest(field=field), self.assertRaises(PolicyBlocked):
                self.run_model(state=obj)
        for added in ("owner_approved", "trusted", "tpm_nv_ready",
                      "auth_proof", "execute", "disable_quarantine"):
            obj = specimen()
            obj[added] = True
            with self.subTest(extra=added), self.assertRaises(PolicyBlocked):
                self.run_model(obj)

    def test_deterministic_and_sanitized_response(self):
        request, state = specimen(), hypothetical_state()
        a = self.run_model(request, state)
        b = self.run_model(request, state)
        self.assertEqual(a, b)
        self.assertEqual(state, hypothetical_state())
        payload = json.dumps(a[0])
        for secretlike in (WITNESS, OLD, NEW, NONCE):
            self.assertNotIn(secretlike, payload)
        self.assertLess(len(payload), 1000)
        self.denied_authority(a[0])

    def test_no_external_or_privileged_execution_path(self):
        import upab.relay.v3_stage44_witness_protocol_review as m
        for name in ("get_tpm", "write_tpm_nv", "connect_witness",
                     "enroll_owner", "start_monitor", "run_task",
                     "execute", "approve", "persist_ledger",
                     "revoke_credential", "make_credential"):
            self.assertFalse(hasattr(m, name))
        self.denied_authority(self.run_model()[0])


if __name__ == "__main__":
    unittest.main()
