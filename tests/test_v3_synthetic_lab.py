from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from upab.relay.v3_policy import PolicyBlocked
from upab.relay.v3_synthetic_lab import SyntheticReviewLab
from upab.relay.review_queue_v2 import QueueBlocked
from upab.relay.v3_checkpoint import CheckpointStore


class SyntheticIntegrationLabTests(unittest.TestCase):
    def test_synthetic_single_review_finishes_once(self):
        with tempfile.TemporaryDirectory(prefix="upab-v3-lab-") as td:
            lab = SyntheticReviewLab(td)
            started = lab.begin()
            self.assertEqual(started["status"], "SYNTHETIC_REVIEW_STARTED")
            self.assertFalse(started["task_executed"])
            with self.assertRaises(QueueBlocked):
                lab.begin()
            finished = lab.finish()
            self.assertFalse(finished["execution_authorized"])
            self.assertEqual(
                CheckpointStore(td).summary()["counts"]["REVIEW_COMPLETED"],1
            )
            with self.assertRaises(PolicyBlocked):
                lab.finish()
            result = lab.reconcile()
            self.assertFalse(result["needs_manual_review"])

    def test_simulated_crash_quarantines_and_prevents_replay(self):
        with tempfile.TemporaryDirectory(prefix="upab-v3-lab-") as td:
            original = SyntheticReviewLab(td)
            original.begin()
            restarted = SyntheticReviewLab(td)
            result = restarted.reconcile()
            self.assertTrue(result["needs_manual_review"])
            self.assertEqual(result["interrupted_queue_claims"],1)
            self.assertEqual(result["interrupted_checkpoints"],1)
            self.assertEqual(
                CheckpointStore(td).status("synthetic-review-lab-v1")["phase"],
                "INTERRUPTED",
            )
            with self.assertRaises(QueueBlocked):
                restarted.begin()
            with self.assertRaises(PolicyBlocked):
                restarted.finish()
            self.assertFalse(restarted.reconcile()["needs_manual_review"])

    def test_lab_refuses_arbitrary_or_missing_root(self):
        with tempfile.TemporaryDirectory() as td:
            with self.assertRaises(PolicyBlocked):
                SyntheticReviewLab(td)
        with self.assertRaises(PolicyBlocked):
            SyntheticReviewLab("upab-v3-lab-does-not-exist")

    def test_synthetic_harness_contains_no_execution_capability(self):
        with tempfile.TemporaryDirectory(prefix="upab-v3-lab-") as td:
            lab = SyntheticReviewLab(td)
            for method in ("execute_task", "run_shell", "write_project",
                           "approve", "grant_access"):
                self.assertFalse(hasattr(lab, method))
            started = lab.begin()
            self.assertFalse(started["task_executed"])


if __name__ == "__main__":
    unittest.main()
