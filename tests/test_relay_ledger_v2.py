from __future__ import annotations

import json
import multiprocessing
import tempfile
import threading
import unittest
from pathlib import Path

from upab.relay.ledger_v2 import RelayLedgerV2


def _consume_in_process(root: str, nonce: str, suffix: int, start, results) -> None:
    try:
        start.wait(30)
        ledger = RelayLedgerV2(root)
        next_nonce = ledger.consume(f"process-{suffix}", "A" * 64, nonce)
        results.put(("accepted", next_nonce))
    except Exception as exc:
        results.put(("blocked", type(exc).__name__))


class RelayLedgerV2Tests(unittest.TestCase):
    def test_durable_nonce_rotation_and_task_id_replay(self):
        with tempfile.TemporaryDirectory() as td:
            ledger = RelayLedgerV2(td)
            first = ledger.current_nonce()
            second = ledger.consume("task-1", "A" * 64, first)
            self.assertNotEqual(first, second)
            restarted = RelayLedgerV2(td)
            self.assertEqual(restarted.current_nonce(), second)
            self.assertIn("task-1", restarted.seen_task_ids())
            with self.assertRaises(ValueError):
                restarted.consume("task-1", "A" * 64, second)
            self.assertEqual(restarted.current_nonce(), second)
            with self.assertRaises(ValueError):
                restarted.consume("task-2", "B" * 64, first)

    def test_existing_legacy_ledger_is_imported_once(self):
        with tempfile.TemporaryDirectory() as td:
            relay = Path(td) / "relay"
            relay.mkdir()
            (relay / "nonce.txt").write_text("existing-secret-nonce\n", encoding="utf-8")
            (relay / "seen_tasks.jsonl").write_text(
                json.dumps({"task_id": "prior", "sha256": "D" * 64}) + "\n",
                encoding="utf-8",
            )
            ledger = RelayLedgerV2(td)
            self.assertEqual(ledger.current_nonce(), "existing-secret-nonce")
            self.assertIn("prior", ledger.seen_task_ids())
            with self.assertRaises(ValueError):
                ledger.consume("prior", "D" * 64, "existing-secret-nonce")
            self.assertEqual(ledger.current_nonce(), "existing-secret-nonce")
            self.assertTrue((relay / "nonce.txt").exists())

    def test_concurrent_threads_only_one_consumer(self):
        with tempfile.TemporaryDirectory() as td:
            nonce = RelayLedgerV2(td).current_nonce()
            barrier = threading.Barrier(12)
            outcomes = []
            mutex = threading.Lock()

            def attempt(i: int) -> None:
                barrier.wait(timeout=15)
                try:
                    RelayLedgerV2(td).consume(f"thread-{i}", "C" * 64, nonce)
                    outcome = "accepted"
                except ValueError:
                    outcome = "blocked"
                with mutex:
                    outcomes.append(outcome)

            threads = [threading.Thread(target=attempt, args=(i,)) for i in range(12)]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join(timeout=25)
                self.assertFalse(thread.is_alive(), "consumer thread hung")
            self.assertEqual(outcomes.count("accepted"), 1, outcomes)
            self.assertEqual(outcomes.count("blocked"), 11, outcomes)

    def test_concurrent_processes_only_one_consumer(self):
        with tempfile.TemporaryDirectory() as td:
            nonce = RelayLedgerV2(td).current_nonce()
            ctx = multiprocessing.get_context("spawn")
            start = ctx.Event()
            results = ctx.Queue()
            processes = [
                ctx.Process(target=_consume_in_process, args=(td, nonce, i, start, results))
                for i in range(4)
            ]
            for process in processes:
                process.start()
            start.set()
            outcomes = [results.get(timeout=40)[0] for _ in processes]
            for process in processes:
                process.join(timeout=20)
                self.assertEqual(process.exitcode, 0)
            self.assertEqual(outcomes.count("accepted"), 1, outcomes)
            self.assertEqual(outcomes.count("blocked"), 3, outcomes)

    def test_uncommitted_transaction_cannot_consume_nonce(self):
        with tempfile.TemporaryDirectory() as td:
            ledger = RelayLedgerV2(td)
            current = ledger.current_nonce()
            with ledger._connect() as conn:
                conn.execute("BEGIN IMMEDIATE")
                conn.execute(
                    "UPDATE state SET value=? WHERE key='current_nonce'",
                    ("an-uncommitted-change",),
                )
                conn.execute("ROLLBACK")
            self.assertEqual(RelayLedgerV2(td).current_nonce(), current)
            self.assertNotEqual(
                RelayLedgerV2(td).consume("after-rollback", "F" * 64, current),
                current,
            )


if __name__ == "__main__":
    unittest.main()
