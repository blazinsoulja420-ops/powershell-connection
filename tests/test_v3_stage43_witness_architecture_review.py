"""Stage 43: inspect hypothetical protected-witness designs without trust grants."""
from __future__ import annotations

from copy import deepcopy
import json
import unittest

from upab.relay.v3_policy import PolicyBlocked
from upab.relay.v3_stage43_witness_architecture_review import (
    SCHEMA, review_witness_architecture,
)


def proposal():
    return {
        "schema": SCHEMA,
        "provider_kind": "TPM_NV_CANDIDATE",
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
        "reported_writes_per_day": 24,
        "reported_write_capacity_per_day": None,
        "hardware_evidence_kind": "NOT_COLLECTED",
    }


class Stage43WitnessArchitectureTests(unittest.TestCase):
    def assess(self, overrides=None):
        obj = proposal()
        obj.update(overrides or {})
        return review_witness_architecture(obj)

    def assert_denied(self, report):
        for key in (
            "real_windows_device_inspected", "tpm_nv_index_provisioned",
            "external_witness_connected", "independent_witness_authenticated",
            "collector_identity_authenticated", "owner_presence_verified",
            "protected_monotonicity_verified", "rollback_resistance_verified",
            "recovery_execution_authorized", "monitoring_enabled",
            "task_execution_authorized", "project_roster_modified",
        ):
            self.assertIs(report[key], False, key)
        self.assertEqual(report["evidence_trust"], "UNTRUSTED_CALLER_ARCHITECTURE")
        self.assertEqual(report["gap_count"], len(report["gap_codes"]))
        self.assertEqual(report["gap_codes"], sorted(set(report["gap_codes"])))

    def test_tpm_plan_never_claims_hardware_support(self):
        report = self.assess()
        self.assertTrue(report["candidate_architecture_policy_passed"])
        self.assertIn("REAL_WINDOWS_TPM_NV_PROVISIONING_UNVERIFIED", report["gap_codes"])
        self.assertIn("WRITE_CAPACITY_NOT_EVIDENCED", report["gap_codes"])
        self.assertEqual(report["status"], "UNVERIFIED_ARCHITECTURE_REQUIRES_EVIDENCE")
        self.assert_denied(report)

    def test_optimistic_claims_still_untrusted(self):
        report = self.assess({
            "hardware_evidence_kind": "INDEPENDENT_PLATFORM_VALIDATION",
            "reported_write_capacity_per_day": 10000,
        })
        self.assertTrue(report["candidate_architecture_policy_passed"])
        self.assertIn("EXTERNAL_SECURITY_REVIEW_NOT_COMPLETED", report["gap_codes"])
        self.assertIn("REAL_WINDOWS_TPM_NV_PROVISIONING_UNVERIFIED", report["gap_codes"])
        self.assert_denied(report)

    def test_external_provider_never_connects_network(self):
        report = self.assess({
            "provider_kind": "EXTERNAL_WITNESS_CANDIDATE",
            "reported_write_capacity_per_day": 1000,
        })
        self.assertIn("EXTERNAL_AUTHENTICATED_CAS_SERVICE_UNVERIFIED", report["gap_codes"])
        self.assert_denied(report)

    def test_backend_undecided_stays_unverified(self):
        report = self.assess({"provider_kind": "UNDECIDED"})
        self.assertIn("WITNESS_BACKEND_UNDECIDED", report["gap_codes"])
        self.assert_denied(report)

    def test_caller_supplied_root_is_rejected(self):
        report = self.assess({"trust_root": "CALLER_SUPPLIED"})
        self.assertEqual(report["status"], "REJECTED_UNSAFE_ARCHITECTURE")
        self.assertFalse(report["candidate_architecture_policy_passed"])
        self.assertIn("TRUST_ROOT_NOT_DESIGNED", report["gap_codes"])
        self.assert_denied(report)

    def test_poindexter_approval_cannot_be_reused(self):
        report = self.assess({
            "project_boundary": "SHARED_POINDEXTER_AUTHORITY",
            "owner_approval": "REUSE_POINDEXTER_APPROVAL",
        })
        self.assertEqual(report["status"], "REJECTED_UNSAFE_ARCHITECTURE")
        self.assertIn("PROJECT_BOUNDARY_NOT_DESIGNED", report["gap_codes"])
        self.assert_denied(report)

    def test_same_epoch_reseal_is_rejected(self):
        report = self.assess({"revocation_policy": "SAME_EPOCH_RESEAL"})
        self.assertEqual(report["status"], "REJECTED_UNSAFE_ARCHITECTURE")
        self.assert_denied(report)

    def test_counter_without_digest_binding_is_rejected(self):
        for value in ("EPOCH_ONLY", "LOCAL_HASH_ONLY"):
            with self.subTest(value=value):
                report = self.assess({"state_binding": value})
                self.assertEqual(report["status"], "REJECTED_UNSAFE_ARCHITECTURE")
                self.assert_denied(report)

    def test_auto_restore_and_accept_offline_are_rejected(self):
        for change in (
            {"recovery_policy": "AUTO_RESTORE_OLD_STATE"},
            {"offline_policy": "ACCEPT_UNANCHORED"},
            {"transition_protocol": "SQLITE_ONLY"},
            {"writer_model": "CALLER_MUTABLE"},
            {"collector_authentication": "SELF_SIGNED_ONLY"},
        ):
            with self.subTest(change=change):
                report = self.assess(change)
                self.assertEqual(report["status"], "REJECTED_UNSAFE_ARCHITECTURE")
                self.assert_denied(report)

    def test_unknown_fields_are_gaps_not_evidence(self):
        for name in (
            "project_boundary", "trust_root", "writer_model",
            "collector_authentication", "owner_approval", "state_binding",
            "transition_protocol", "revocation_policy",
            "offline_policy", "recovery_policy",
        ):
            with self.subTest(field=name):
                report = self.assess({name: "UNKNOWN"})
                self.assertFalse(report["candidate_architecture_policy_passed"])
                self.assertIn(name.upper() + "_NOT_DESIGNED", report["gap_codes"])
                self.assert_denied(report)

    def test_declared_write_budget_shortfall(self):
        report = self.assess({
            "reported_writes_per_day": 101,
            "reported_write_capacity_per_day": 100,
        })
        self.assertIn("EXPECTED_WRITES_EXCEED_CLAIMED_CAPACITY", report["gap_codes"])
        self.assert_denied(report)

    def test_bounded_write_budget_validation(self):
        for field, values in (
            ("reported_writes_per_day", (0, -1, 100001, True, "24", 24.0, None)),
            ("reported_write_capacity_per_day",
             (0, -1, 100000001, True, "1200", [], 1200.0)),
        ):
            for value in values:
                with self.subTest(field=field, value=value), self.assertRaises(PolicyBlocked):
                    self.assess({field: value})

    def test_missing_and_surplus_fields_fail_closed(self):
        baseline = proposal()
        for name in tuple(baseline):
            obj = proposal()
            obj.pop(name)
            with self.subTest(missing=name), self.assertRaises(PolicyBlocked):
                review_witness_architecture(obj)
        for name in ("owner_authorized", "tpm_nv_provisioned",
                     "task_execution_authorized", "recovery_approved"):
            with self.subTest(extra=name), self.assertRaises(PolicyBlocked):
                self.assess({name: True})

    def test_schema_and_option_types_fail_closed(self):
        for key, value in (
            ("schema", "upab.watcher-v3.protected-witness-architecture.v2"),
            ("provider_kind", []),
            ("provider_kind", "REAL_HARDWARE_VERIFIED"),
            ("project_boundary", True),
            ("trust_root", 22),
            ("revocation_policy", None),
            ("hardware_evidence_kind", {}),
            ("transition_protocol", "RUN_ANYTHING"),
        ):
            with self.subTest(key=key, value=value), self.assertRaises(PolicyBlocked):
                self.assess({key: value})

    def test_caller_approval_claims_never_confer_authority(self):
        report = self.assess({
            "hardware_evidence_kind": "INDEPENDENT_PLATFORM_VALIDATION",
            "reported_write_capacity_per_day": 999999,
        })
        self.assertFalse(report["task_execution_authorized"])
        self.assertFalse(report["tpm_nv_index_provisioned"])
        self.assert_denied(report)

    def test_deterministic_and_does_not_change_input(self):
        data = proposal()
        saved = deepcopy(data)
        a = review_witness_architecture(data)
        b = review_witness_architecture(data)
        self.assertEqual(a, b)
        self.assertEqual(saved, data)
        self.assert_denied(a)

    def test_output_is_bounded_and_no_source_values_echoed(self):
        report = self.assess()
        payload = json.dumps(report)
        self.assertLess(len(payload), 2600)
        for private in ("TPM_NV_CANDIDATE", "INDEPENDENT_WATCHER",
                        "SEPARATELY_ENROLLED", "reported_writes_per_day"):
            self.assertNotIn(private, payload)

    def test_no_operational_entrypoints(self):
        import upab.relay.v3_stage43_witness_architecture_review as module
        for name in (
            "get_tpm", "provision_tpm_nv", "open_connection", "make_credential",
            "execute_task", "authorize", "enable_watcher", "connect_repo",
            "read_local_device", "write_counter", "start_monitor", "enroll_owner",
        ):
            self.assertFalse(hasattr(module, name))
        self.assert_denied(self.assess())


if __name__ == "__main__":
    unittest.main()
