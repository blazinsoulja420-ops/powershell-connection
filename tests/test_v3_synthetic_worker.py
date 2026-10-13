from __future__ import annotations

import tempfile
import threading
import unittest

from upab.relay.v3_policy import PolicyBlocked
from upab.relay.v3_synthetic_worker import (
    FIXTURE_RESULT, SyntheticSingleWorker,
)


class SyntheticSingleWorkerTests(unittest.TestCase):
    def test_fixed_public_fixture_runs_once(self):
        with tempfile.TemporaryDirectory(prefix="upab-v3-lab-") as td:
            worker = SyntheticSingleWorker(td)
            self.assertEqual(worker.status()["state"], "PENDING")
            receipt = worker.run()
            self.assertEqual(receipt["state"], "DONE")
            self.assertEqual(receipt["attempts"], 1)
            self.assertEqual(receipt["result_digest"], FIXTURE_RESULT)
            self.assertFalse(receipt["real_task_execution_enabled"])
            with self.assertRaisesRegex(PolicyBlocked, "no replay"):
                worker.run()
            after_restart = SyntheticSingleWorker(td)
            self.assertEqual(after_restart.status()["state"], "DONE")
            self.assertEqual(after_restart.status()["attempts"], 1)

    def test_simulated_interrupt_quarantines_instead_of_retry(self):
        with tempfile.TemporaryDirectory(prefix="upab-v3-lab-") as td:
            worker = SyntheticSingleWorker(td)
            fault = worker.run(inject_interruption=True)
            self.assertEqual(fault["state"], "RUNNING")
            self.assertTrue(fault["simulated_interruption"])
            restarted = SyntheticSingleWorker(td)
            with self.assertRaises(PolicyBlocked):
                restarted.run()
            record = restarted.reconcile()
            self.assertEqual(record["state"], "INTERRUPTED")
            self.assertEqual(record["attempts"], 1)
            self.assertIsNone(record["result_digest"])
            with self.assertRaises(PolicyBlocked):
                restarted.run()
            self.assertEqual(restarted.reconcile()["state"], "INTERRUPTED")

    def test_concurrent_only_one_fixed_fixture_claim(self):
        with tempfile.TemporaryDirectory(prefix="upab-v3-lab-") as td:
            worker = SyntheticSingleWorker(td)
            barrier = threading.Barrier(6)
            reports = []
            mutex = threading.Lock()

            def attempt():
                barrier.wait(timeout=10)
                try:
                    worker.run()
                    answer = "done"
                except (PolicyBlocked, RuntimeError):
                    answer = "blocked"
                with mutex:
                    reports.append(answer)

            threads = [threading.Thread(target=attempt) for _ in range(6)]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join(timeout=20)
                self.assertFalse(thread.is_alive(), "fixture thread hung")
            self.assertEqual(reports.count("done"), 1, reports)
            self.assertEqual(reports.count("blocked"), 5, reports)
            self.assertEqual(worker.status()["attempts"], 1)

    def test_non_fixture_root_and_invalid_args_denied(self):
        with tempfile.TemporaryDirectory() as td:
            with self.assertRaises(PolicyBlocked):
                SyntheticSingleWorker(td)
        with tempfile.TemporaryDirectory(prefix="upab-v3-lab-") as td:
            worker = SyntheticSingleWorker(td)
            with self.assertRaises(PolicyBlocked):
                worker.run(inject_interruption="true")
            self.assertFalse(hasattr(worker, "execute_task"))
            self.assertFalse(hasattr(worker, "run_shell"))
            self.assertFalse(hasattr(worker, "approve"))
            self.assertFalse(hasattr(worker, "write_project"))


if __name__ == "__main__":
    unittest.main()
