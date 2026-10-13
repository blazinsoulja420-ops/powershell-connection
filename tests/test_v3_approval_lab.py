from __future__ import annotations

from datetime import datetime, timedelta, timezone
import tempfile
import threading
import unittest

from upab.relay.v3_approval_lab import IsolatedApprovalLab, FIXTURE_SHA
from upab.relay.v3_policy import PolicyBlocked
from upab.relay.v3_synthetic_worker import SyntheticSingleWorker

NOW = datetime(2026, 10, 13, 22, 0, tzinfo=timezone.utc)


class ApprovalLabTests(unittest.TestCase):
    def test_no_simulation_means_no_fixture_execution(self):
        with tempfile.TemporaryDirectory(prefix="upab-v3-lab-") as td:
            broker = IsolatedApprovalLab(td)
            challenge = broker.request(now=NOW)
            self.assertFalse(challenge["owner_authenticated"])
            self.assertFalse(challenge["execution_authorized"])
            self.assertEqual(challenge["digest"], FIXTURE_SHA)
            with self.assertRaises(PolicyBlocked):
                broker.simulate_approval(challenge["challenge"], now=NOW)
            with self.assertRaises(PolicyBlocked):
                broker.run_fixed_fixture(challenge["challenge"], now=NOW)
            self.assertEqual(SyntheticSingleWorker(td).status()["state"], "PENDING")

    def test_simulated_challenge_single_use_and_no_real_authority(self):
        with tempfile.TemporaryDirectory(prefix="upab-v3-lab-") as td:
            broker = IsolatedApprovalLab(td)
            issued = broker.request(now=NOW)
            first = broker.simulate_approval(issued["challenge"],
                                             now=NOW,test_simulation=True)
            self.assertFalse(first["owner_authenticated"])
            self.assertFalse(first["execution_authorized"])
            result = broker.run_fixed_fixture(issued["challenge"], now=NOW)
            self.assertEqual(result["lab_fixture_state"], "DONE")
            self.assertFalse(result["real_task_execution_enabled"])
            self.assertFalse(result["owner_authenticated"])
            with self.assertRaises(PolicyBlocked):
                broker.run_fixed_fixture(issued["challenge"], now=NOW)
            with self.assertRaises(PolicyBlocked):
                broker.simulate_approval(issued["challenge"], now=NOW,test_simulation=True)
            self.assertEqual(SyntheticSingleWorker(td).status()["attempts"], 1)

    def test_90_second_expiry_and_bad_challenges_fail_closed(self):
        with tempfile.TemporaryDirectory(prefix="upab-v3-lab-") as td:
            broker = IsolatedApprovalLab(td)
            item = broker.request(now=NOW)
            for bad in ("", "not-a-token", "f"*64, "A"*64):
                with self.subTest(bad=bad):
                    with self.assertRaises(PolicyBlocked):
                        broker.simulate_approval(bad,now=NOW,test_simulation=True)
            with self.assertRaises(PolicyBlocked):
                broker.simulate_approval(item["challenge"],now=NOW+timedelta(seconds=90),
                                         test_simulation=True)
            self.assertEqual(SyntheticSingleWorker(td).status()["state"],"PENDING")

    def test_broker_restart_retains_spent_challenge(self):
        with tempfile.TemporaryDirectory(prefix="upab-v3-lab-") as td:
            issued = IsolatedApprovalLab(td).request(now=NOW)
            IsolatedApprovalLab(td).simulate_approval(
                issued["challenge"],now=NOW,test_simulation=True
            )
            IsolatedApprovalLab(td).run_fixed_fixture(issued["challenge"],now=NOW)
            with self.assertRaises(PolicyBlocked):
                IsolatedApprovalLab(td).run_fixed_fixture(issued["challenge"],now=NOW)

    def test_crash_avoids_replay_even_after_new_challenge(self):
        with tempfile.TemporaryDirectory(prefix="upab-v3-lab-") as td:
            broker = IsolatedApprovalLab(td)
            first=broker.request(now=NOW)
            broker.simulate_approval(first["challenge"],now=NOW,test_simulation=True)
            report=broker.run_fixed_fixture(
                first["challenge"],now=NOW,inject_interruption=True
            )
            self.assertEqual(report["lab_fixture_state"],"RUNNING")
            second=broker.request(now=NOW)
            broker.simulate_approval(second["challenge"],now=NOW,test_simulation=True)
            with self.assertRaises(PolicyBlocked):
                broker.run_fixed_fixture(second["challenge"],now=NOW)
            state = SyntheticSingleWorker(td).reconcile()
            self.assertEqual(state["state"],"INTERRUPTED")
            self.assertEqual(state["attempts"],1)

    def test_duplicate_parallel_claim_only_one(self):
        with tempfile.TemporaryDirectory(prefix="upab-v3-lab-") as td:
            broker=IsolatedApprovalLab(td)
            item=broker.request(now=NOW)
            broker.simulate_approval(item["challenge"],now=NOW,test_simulation=True)
            gate=threading.Barrier(6)
            outcomes=[]
            mutex=threading.Lock()
            def try_claim():
                gate.wait(timeout=10)
                try:
                    broker.run_fixed_fixture(item["challenge"],now=NOW)
                    status="done"
                except (PolicyBlocked,RuntimeError):
                    status="blocked"
                with mutex:
                    outcomes.append(status)
            workers=[threading.Thread(target=try_claim) for _ in range(6)]
            for w in workers: w.start()
            for w in workers:
                w.join(timeout=20)
                self.assertFalse(w.is_alive())
            self.assertEqual(outcomes.count("done"),1,outcomes)
            self.assertEqual(outcomes.count("blocked"),5,outcomes)

    def test_arbitrary_root_refused(self):
        with tempfile.TemporaryDirectory() as td:
            with self.assertRaises(PolicyBlocked):
                IsolatedApprovalLab(td)


if __name__ == "__main__":
    unittest.main()
