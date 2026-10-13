from __future__ import annotations

from datetime import datetime, timedelta, timezone
import sqlite3
import sys
import tempfile
import threading
import unittest
from pathlib import Path

from upab.relay.v3_policy import PolicyBlocked
from upab.relay.v3_synthetic_assertion_journal import (
    PUBLIC_FIXTURE_CHALLENGE, SyntheticAssertionJournal
)
from test_v3_assertion_crypto import CLIENT, AUTH, SIG

NOW = datetime(2026,10,13,23,0,tzinfo=timezone.utc)


def issue(journal, *, fixed=True, now=NOW):
    return journal.issue(
        project_id="universal-ai", task_id="synthetic-task",
        task_sha256="B"*64, now=now, fixed_public_fixture=fixed,
    )


def inspect(journal, frame, *, now=NOW, sig=SIG, task_id="synthetic-task"):
    return journal.inspect_fixture(
        challenge_hex=frame["challenge_hex"], project_id="universal-ai",
        task_id=task_id, task_sha256="B"*64, client_data_json=CLIENT,
        authenticator_data=AUTH, signature_der=sig, now=now,
    )


class DurableSyntheticAssertionJournalTests(unittest.TestCase):
    @unittest.skipUnless(sys.platform == "win32", "Windows CNG verification only")
    def test_public_fixture_signature_spent_and_counter_durable(self):
        with tempfile.TemporaryDirectory(prefix="upab-v3-lab-") as root:
            journal = SyntheticAssertionJournal(root)
            item = issue(journal)
            answer = inspect(journal,item)
            self.assertTrue(answer["public_fixture_signature_valid"])
            self.assertEqual(answer["status"],"CRYPTO_VERIFIED_ONLY")
            self.assertTrue(answer["challenge_spent"])
            for key in ("trusted_credential_enrolled", "owner_authenticated",
                        "approval_issued", "execution_authorized",
                        "real_task_executed"):
                self.assertFalse(answer[key])
            reloaded = SyntheticAssertionJournal(root)
            self.assertEqual(reloaded.summary()["synthetic_counter"],1)
            self.assertEqual(reloaded.summary()["counts"]["CRYPTO_VERIFIED_ONLY"],1)
            with self.assertRaises(PolicyBlocked):
                inspect(reloaded,item)
            with self.assertRaises(PolicyBlocked):
                issue(reloaded)

    @unittest.skipUnless(sys.platform == "win32", "Windows CNG verification only")
    def test_bad_crypto_consumes_nonce_but_never_advances_counter(self):
        with tempfile.TemporaryDirectory(prefix="upab-v3-lab-") as root:
            journal = SyntheticAssertionJournal(root)
            item = issue(journal)
            bad = SIG[:-1] + bytes([SIG[-1] ^ 1])
            answer = inspect(journal,item,sig=bad)
            self.assertFalse(answer["public_fixture_signature_valid"])
            self.assertEqual(answer["status"],"REJECTED")
            self.assertEqual(journal.summary()["synthetic_counter"],0)
            with self.assertRaises(PolicyBlocked):
                inspect(journal,item,sig=SIG)

    @unittest.skipUnless(sys.platform == "win32", "Windows CNG verification only")
    def test_simultaneous_single_use_never_double_verifies(self):
        with tempfile.TemporaryDirectory(prefix="upab-v3-lab-") as root:
            journal = SyntheticAssertionJournal(root)
            item = issue(journal)
            barrier = threading.Barrier(6)
            mutex=threading.Lock()
            answers=[]
            def attempt():
                barrier.wait(timeout=10)
                try:
                    result=inspect(journal,item)
                    outcome=result["status"]
                except PolicyBlocked:
                    outcome="BLOCKED"
                with mutex:
                    answers.append(outcome)
            threads=[threading.Thread(target=attempt) for _ in range(6)]
            for t in threads:
                t.start()
            for t in threads:
                t.join(timeout=20)
                self.assertFalse(t.is_alive())
            self.assertEqual(answers.count("CRYPTO_VERIFIED_ONLY"),1,answers)
            self.assertEqual(answers.count("BLOCKED"),5,answers)
            self.assertEqual(journal.summary()["synthetic_counter"],1)

    def test_only_exact_context_is_accepted_and_random_challenge_fails_closed(self):
        with tempfile.TemporaryDirectory(prefix="upab-v3-lab-") as root:
            journal = SyntheticAssertionJournal(root)
            item = issue(journal, fixed=False)
            self.assertEqual(len(item["challenge_hex"]),64)
            self.assertFalse(item["trusted_credential_enrolled"])
            with self.assertRaises(PolicyBlocked):
                inspect(journal,item,task_id="wrong-task")
            with self.assertRaisesRegex(PolicyBlocked,"lacks a fixture"):
                inspect(journal,item)
            self.assertEqual(journal.summary()["counts"]["PENDING"],1)
            self.assertFalse(journal.summary()["execution_authorized"])

    def test_expiry_capacity_reclaim_and_backdated_claim_refusal(self):
        with tempfile.TemporaryDirectory(prefix="upab-v3-lab-") as root:
            journal = SyntheticAssertionJournal(root)
            item = issue(journal)
            with self.assertRaisesRegex(PolicyBlocked,"predates"):
                inspect(journal,item,now=NOW-timedelta(seconds=1))
            for _ in range(7):
                issue(journal,fixed=False)
            with self.assertRaisesRegex(PolicyBlocked,"full"):
                issue(journal,fixed=False)
            with self.assertRaises(PolicyBlocked):
                inspect(journal,item,now=NOW+timedelta(seconds=90))
            replacement=issue(journal,fixed=False,now=NOW+timedelta(seconds=91))
            self.assertNotEqual(replacement["challenge_hex"],item["challenge_hex"])
            self.assertEqual(journal.summary()["counts"]["EXPIRED"],8)

    def test_crash_quarantines_claimed_never_requeues(self):
        with tempfile.TemporaryDirectory(prefix="upab-v3-lab-") as root:
            journal = SyntheticAssertionJournal(root)
            item = issue(journal)
            file=Path(root)/"relay"/"v3_synthetic_assertions.sqlite3"
            with sqlite3.connect(file) as db:
                db.execute("UPDATE challenges SET phase='CLAIMED'")
            restarted = SyntheticAssertionJournal(root)
            self.assertEqual(restarted.reconcile_after_restart(),1)
            self.assertEqual(restarted.summary()["counts"]["INTERRUPTED"],1)
            self.assertEqual(restarted.reconcile_after_restart(),0)
            with self.assertRaises(PolicyBlocked):
                inspect(restarted,item)
            self.assertEqual(restarted.summary()["synthetic_counter"],0)

    def test_ordinary_project_path_refused_without_creating_state(self):
        with tempfile.TemporaryDirectory() as parent:
            outside=Path(parent)/"upab-v3-lab-fake"
            outside.mkdir()
            with self.assertRaises(PolicyBlocked):
                SyntheticAssertionJournal(outside)
            self.assertEqual(list(outside.iterdir()),[])

    def test_invalid_task_context_rejected(self):
        with tempfile.TemporaryDirectory(prefix="upab-v3-lab-") as root:
            j = SyntheticAssertionJournal(root)
            for options in (
                {"project_id":"../escape"},
                {"task_id":"../../outside"},
                {"task_sha256":"1234"},
                {"fixed_public_fixture":"yes"},
            ):
                args=dict(project_id="universal-ai",task_id="safe",task_sha256="A"*64,
                          fixed_public_fixture=False,now=NOW)
                args.update(options)
                with self.subTest(options=options):
                    with self.assertRaises(PolicyBlocked):
                        j.issue(**args)
            self.assertEqual(j.summary()["counts"],{})


if __name__ == "__main__":
    unittest.main()
