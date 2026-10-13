from __future__ import annotations

import tempfile
import threading
import unittest

from upab.relay.single_flight_v2 import SingleFlightLock
from upab.relay.v3_checkpoint import CheckpointStore
from upab.relay.v3_policy import PolicyBlocked


class V3CheckpointTests(unittest.TestCase):
    def test_metadata_only_durable_successful_review(self):
        with tempfile.TemporaryDirectory() as tmp:
            store=CheckpointStore(tmp)
            self.assertEqual(store.propose("id-one","A"*64),"PROPOSED")
            self.assertEqual(store.transition("id-one",expected_digest="A"*64,next_phase="REVIEW_STARTED"),"REVIEW_STARTED")
            self.assertEqual(store.transition("id-one",expected_digest="A"*64,next_phase="REVIEW_COMPLETED"),"REVIEW_COMPLETED")
            reloaded=CheckpointStore(tmp)
            record=reloaded.status("id-one")
            self.assertEqual(record["phase"],"REVIEW_COMPLETED")
            self.assertFalse(record["execution_authorized"])
            self.assertFalse(record["can_auto_resume"])
            self.assertFalse(reloaded.summary()["execution_enabled"])
            self.assertFalse(hasattr(reloaded,"execute_task"))

    def test_crash_recovery_quarantines_without_retry(self):
        with tempfile.TemporaryDirectory() as tmp:
            with SingleFlightLock(tmp):
                store=CheckpointStore(tmp)
                store.propose("id-two","B"*64)
                store.transition("id-two",expected_digest="B"*64,next_phase="REVIEW_STARTED")
            with SingleFlightLock(tmp):
                restarted=CheckpointStore(tmp)
                self.assertEqual(restarted.reconcile_interrupted(),1)
                self.assertEqual(restarted.reconcile_interrupted(),0)
                self.assertEqual(restarted.status("id-two")["phase"],"INTERRUPTED")
                with self.assertRaises(PolicyBlocked):
                    restarted.transition("id-two",expected_digest="B"*64,next_phase="REVIEW_STARTED")
                restarted.transition("id-two",expected_digest="B"*64,next_phase="DISMISSED")

    def test_immutable_digest_and_disallowed_transition(self):
        with tempfile.TemporaryDirectory() as tmp:
            store=CheckpointStore(tmp)
            store.propose("id-three","C"*64)
            with self.assertRaises(PolicyBlocked):
                store.propose("id-three","C"*64)
            with self.assertRaises(PolicyBlocked):
                store.transition("id-three",expected_digest="D"*64,next_phase="REVIEW_STARTED")
            with self.assertRaises(PolicyBlocked):
                store.transition("id-three",expected_digest="C"*64,next_phase="REVIEW_COMPLETED")
            with self.assertRaises(PolicyBlocked):
                store.transition("id-three",expected_digest="C"*64,next_phase="EXECUTE")
            self.assertEqual(store.status("id-three")["phase"],"PROPOSED")

    def test_store_bounded_and_no_lost_inserts(self):
        with tempfile.TemporaryDirectory() as tmp:
            CheckpointStore(tmp,max_records=1).propose("first","A"*64)
            with self.assertRaises(PolicyBlocked):
                CheckpointStore(tmp,max_records=1).propose("second","B"*64)
            self.assertEqual(CheckpointStore(tmp,max_records=1).summary()["counts"]["PROPOSED"],1)
            for invalid in (0,65537,True):
                with self.assertRaises(PolicyBlocked):
                    CheckpointStore(tmp,max_records=invalid)

    def test_concurrent_duplicate_admission(self):
        with tempfile.TemporaryDirectory() as tmp:
            store=CheckpointStore(tmp)
            barrier=threading.Barrier(8)
            results=[]
            mutex=threading.Lock()
            def attempt():
                barrier.wait(timeout=10)
                try:
                    store.propose("same","E"*64)
                    outcome="accepted"
                except PolicyBlocked:
                    outcome="rejected"
                with mutex:
                    results.append(outcome)
            workers=[threading.Thread(target=attempt) for _ in range(8)]
            for worker in workers:
                worker.start()
            for worker in workers:
                worker.join(timeout=20)
                self.assertFalse(worker.is_alive())
            self.assertEqual(results.count("accepted"),1)
            self.assertEqual(results.count("rejected"),7)


if __name__ == "__main__":
    unittest.main()
