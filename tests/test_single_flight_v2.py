from __future__ import annotations

import multiprocessing
import tempfile
import unittest
from pathlib import Path

from upab.relay.single_flight_v2 import SingleFlightLock, WatcherAlreadyRunning


def try_acquire_from_other_process(root: str, results) -> None:
    try:
        with SingleFlightLock(root):
            results.put("acquired")
    except WatcherAlreadyRunning:
        results.put("blocked")


class SingleFlightV2Tests(unittest.TestCase):
    def test_single_process_collision_and_safe_release(self):
        with tempfile.TemporaryDirectory() as td:
            with SingleFlightLock(td):
                with self.assertRaises(WatcherAlreadyRunning):
                    with SingleFlightLock(td):
                        pass
            with SingleFlightLock(td):
                self.assertTrue((Path(td) / "relay" / "watcher_v2.lock").exists())

    def test_other_process_denied_while_lock_is_held(self):
        with tempfile.TemporaryDirectory() as td:
            ctx = multiprocessing.get_context("spawn")
            with SingleFlightLock(td):
                queue = ctx.Queue()
                worker = ctx.Process(target=try_acquire_from_other_process, args=(td, queue))
                worker.start()
                outcome = queue.get(timeout=30)
                worker.join(timeout=30)
                self.assertEqual(worker.exitcode, 0)
                self.assertEqual(outcome, "blocked")
            queue = ctx.Queue()
            worker = ctx.Process(target=try_acquire_from_other_process, args=(td, queue))
            worker.start()
            outcome = queue.get(timeout=30)
            worker.join(timeout=30)
            self.assertEqual(worker.exitcode, 0)
            self.assertEqual(outcome, "acquired")

    def test_exception_releases_lock(self):
        with tempfile.TemporaryDirectory() as td:
            with self.assertRaisesRegex(ValueError, "deliberate"):
                with SingleFlightLock(td):
                    raise ValueError("deliberate")
            with SingleFlightLock(td):
                pass

    def test_cannot_enter_same_instance_twice(self):
        with tempfile.TemporaryDirectory() as td:
            guard = SingleFlightLock(td)
            with guard:
                with self.assertRaises(WatcherAlreadyRunning):
                    with guard:
                        pass
            with guard:
                pass


if __name__ == "__main__":
    unittest.main()
