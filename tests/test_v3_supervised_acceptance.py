from __future__ import annotations

import unittest

from upab.relay.v3_policy import PolicyBlocked
from upab.relay.v3_supervised_acceptance import (
    SCHEMA,CHECKPOINTS,review_acceptance_plan,
)


class Stage23SupervisedAcceptanceTests(unittest.TestCase):
    def test_default_requires_every_supervised_checkpoint(self):
        result=review_acceptance_plan()
        self.assertEqual(result["schema"],SCHEMA)
        self.assertEqual(result["checkpoint_count"],14)
        self.assertEqual(result["not_tested_count"],14)
        self.assertEqual(result["status"],"BLOCKED_OWNER_DEVICE_ACCEPTANCE_REQUIRED")
        self.assertEqual(set(result["checkpoint_states"]),{x[0] for x in CHECKPOINTS})
        for key in (
            "report_is_authentic_owner_evidence",
            "actual_owner_consent_verified",
            "real_device_acceptance_passed",
            "legacy_shutdown_and_rollback_proven",
            "watcher_enabled","live_task_execution_authorized",
            "safe_to_install","safe_to_migrate","changes_performed",
        ):
            self.assertIs(result[key],False,key)

    def test_all_reported_pass_still_cannot_authorize(self):
        report=review_acceptance_plan(
            observations={key:"REPORTED_PASS_UNVERIFIED" for key,_ in CHECKPOINTS}
        )
        self.assertEqual(report["not_tested_count"],0)
        self.assertEqual(report["unverified_report_count"],len(CHECKPOINTS))
        self.assertFalse(report["real_device_acceptance_passed"])
        self.assertFalse(report["live_task_execution_authorized"])
        self.assertFalse(report["safe_to_install"])
        self.assertFalse(report["safe_to_migrate"])
        self.assertFalse(report["report_is_authentic_owner_evidence"])

    def test_failed_checkpoint_stays_blocked(self):
        report=review_acceptance_plan(
            observations={"V1_QUIESCENCE":"FAILED",
                          "BACKUP_RESTORE":"REPORTED_PASS_UNVERIFIED"}
        )
        self.assertEqual(report["failed_count"],1)
        self.assertEqual(report["unverified_report_count"],1)
        self.assertEqual(report["not_tested_count"],12)
        self.assertFalse(report["legacy_shutdown_and_rollback_proven"])

    def test_forged_approval_unknown_check_or_bad_field_rejected(self):
        for invalid in (
            {"OWNER_APPROVED":"REPORTED_PASS_UNVERIFIED"},
            {"TRUSTED_RP":"AUTHENTICATED"},
            {"INDEPENDENT_REVIEW":True},
            {"WINDOWS_HELLO":1},
            {"ROLLBACK_GATES":{"approved":True}},
            ["V1_QUIESCENCE"],
        ):
            with self.subTest(invalid=invalid):
                with self.assertRaises(PolicyBlocked):
                    review_acceptance_plan(observations=invalid)

    def test_unsigned_report_digest_is_repeatable_not_credentials(self):
        one=review_acceptance_plan()
        two=review_acceptance_plan()
        self.assertEqual(one["report_fingerprint_sha256"],
                         two["report_fingerprint_sha256"])
        self.assertEqual(len(one["report_fingerprint_sha256"]),64)
        self.assertFalse(one["report_is_authentic_owner_evidence"])

    def test_no_interactive_device_execution_or_enrollment_methods(self):
        import upab.relay.v3_supervised_acceptance as m
        for name in (
            "start_windows_hello","enroll_owner","run_task","stop_watcher",
            "disable_launcher","restore_backup","install","authorize","connect_repo",
        ):
            self.assertFalse(hasattr(m,name))


if __name__=="__main__":
    unittest.main()
