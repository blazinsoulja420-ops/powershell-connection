import tempfile
import threading
import unittest

from upab.relay.review_queue_v2 import BoundedReviewQueue, QueueBlocked
from upab.relay.single_flight_v2 import SingleFlightLock


class ReviewQueueTests(unittest.TestCase):
    def test_capacity_restart_and_replay(self):
        with tempfile.TemporaryDirectory() as td:
            q = BoundedReviewQueue(td, 2)
            q.submit("first", "A" * 64)
            q.submit("second", "B" * 64)
            with self.assertRaisesRegex(QueueBlocked, "full"):
                q.submit("third", "C" * 64)
            fresh = BoundedReviewQueue(td, 2)
            self.assertEqual(fresh.summary()["active"], 2)
            with self.assertRaisesRegex(QueueBlocked, "duplicate"):
                fresh.submit("first", "A" * 64)
            self.assertEqual(fresh.claim_for_review()["task_id"], "first")
            self.assertIsNone(fresh.claim_for_review())
            self.assertFalse(fresh.summary()["execution_enabled"])

    def test_reconcile_requires_manual_resolution(self):
        with tempfile.TemporaryDirectory() as td:
            with SingleFlightLock(td):
                q = BoundedReviewQueue(td, 1)
                q.submit("one", "1" * 64)
                q.claim_for_review()
            with SingleFlightLock(td):
                restarted = BoundedReviewQueue(td, 1)
                self.assertEqual(restarted.reconcile_after_exclusive_restart(), 1)
                self.assertIsNone(restarted.claim_for_review())
                self.assertEqual(restarted.summary()["active"], 1)
                restarted.dismiss("one")
                restarted.submit("two", "2" * 64)
                self.assertEqual(restarted.claim_for_review()["task_id"], "two")

    def test_bad_values_and_no_authority(self):
        with tempfile.TemporaryDirectory() as td:
            for capacity in (0, 33, True):
                with self.assertRaises(ValueError):
                    BoundedReviewQueue(td, capacity)
            q = BoundedReviewQueue(td)
            for task_id in ("", "../other", "x" * 129):
                with self.assertRaises(QueueBlocked):
                    q.submit(task_id, "F" * 64)
            for digest in ("invalid", "F" * 63):
                with self.assertRaises(QueueBlocked):
                    q.submit("task", digest)
            self.assertFalse(hasattr(q, "execute_task"))
            self.assertFalse(hasattr(q, "approve"))
            self.assertFalse(q.summary()["stores_task_payload"])

    def test_thread_contention_single_claim(self):
        with tempfile.TemporaryDirectory() as td:
            q = BoundedReviewQueue(td)
            for i in range(8):
                q.submit(f"task-{i}", "A" * 64)
            barrier = threading.Barrier(8)
            results = []
            def take():
                barrier.wait(timeout=10)
                results.append(BoundedReviewQueue(td).claim_for_review())
            threads = [threading.Thread(target=take) for _ in range(8)]
            for t in threads:
                t.start()
            for t in threads:
                t.join(timeout=20)
                self.assertFalse(t.is_alive())
            self.assertEqual(sum(x is not None for x in results), 1)


if __name__ == "__main__":
    unittest.main()
