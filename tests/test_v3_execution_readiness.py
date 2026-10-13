from __future__ import annotations

import unittest

from upab.relay.v3_execution_readiness import evaluate_readiness
from upab.relay.v3_policy import PolicyBlocked


def receipt():
    return {
        "status": "PROOF_VERIFIED_FOR_REVIEW_ONLY",
        "task_id": "task-1",
        "authenticated_owner": False,
        "execution_authorized": False,
        "proof_consumed": True,
    }


def inventory():
    return {
        "schema": "upab.watcher-v3.migration-inventory.v1",
        "status": "V1_INVENTORIED_NOT_READY",
        "legacy_nonce_present": True,
        "legacy_records": 0,
        "v2_database_present": False,
        "verified_v1_quiescent": False,
        "authorized_to_migrate": False,
        "changes_performed": False,
    }


class ExecutionReadinessTests(unittest.TestCase):
    def test_no_proof_or_migration_denies_execution(self):
        report = evaluate_readiness(task_id="task-1", digest="A"*64)
        self.assertEqual(report["status"], "NOT_READY")
        self.assertFalse(report["execution_allowed"])
        self.assertFalse(report["can_activate"])
        self.assertGreaterEqual(len(report["blockers"]), 6)

    def test_review_proof_and_migration_inventory_cannot_grant_execution(self):
        report = evaluate_readiness(
            task_id="task-1", digest="A"*64,
            receipt=receipt(), migration_inventory=inventory(),
        )
        self.assertEqual(report["proof_receipt_state"], "REVIEW_ONLY")
        self.assertFalse(report["execution_allowed"])
        self.assertIn(
            "MIGRATION_INVENTORY_IS_NOT_PROCESS_QUIESCENCE_PROOF",
            report["blockers"],
        )

    def test_forged_owner_authorization_rejected(self):
        for key in ("authenticated_owner", "execution_authorized"):
            fake = receipt()
            fake[key] = True
            with self.subTest(key=key):
                with self.assertRaises(PolicyBlocked):
                    evaluate_readiness(task_id="task-1", digest="A"*64, receipt=fake)

    def test_mismatched_or_extra_proof_claims_rejected(self):
        for edit in ({"task_id":"different"}, {"proof_consumed":False},
                     {"status":"APPROVED"}, {"unknown":"access"}):
            fake = dict(receipt(), **edit)
            with self.subTest(edit=edit):
                with self.assertRaises(PolicyBlocked):
                    evaluate_readiness(task_id="task-1", digest="A"*64, receipt=fake)

    def test_untrusted_migration_authority_rejected(self):
        for key in ("verified_v1_quiescent", "authorized_to_migrate", "changes_performed"):
            fake = inventory()
            fake[key] = True
            with self.subTest(key=key):
                with self.assertRaises(PolicyBlocked):
                    evaluate_readiness(
                        task_id="task-1", digest="A"*64, migration_inventory=fake
                    )

    def test_unbounded_inventory_fields_are_rejected(self):
        for changes in (
            {"status": "ACCEPTED" + "X"*2000},
            {"legacy_nonce_present": "yes"},
            {"legacy_records": -1},
            {"legacy_records": 1000001},
        ):
            fake = dict(inventory(), **changes)
            with self.subTest(changes=changes):
                with self.assertRaises(PolicyBlocked):
                    evaluate_readiness(
                        task_id="task-1", digest="A"*64, migration_inventory=fake
                    )

    def test_no_command_or_executor_hooks(self):
        report = evaluate_readiness(task_id="task-1", digest="A"*64)
        self.assertFalse(report["side_effects"])
        self.assertNotIn("run_command", report)
        self.assertNotIn("authorization_token", report)


if __name__ == "__main__":
    unittest.main()
