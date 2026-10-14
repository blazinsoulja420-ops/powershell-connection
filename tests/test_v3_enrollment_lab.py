from __future__ import annotations

from contextlib import closing
from datetime import datetime, timedelta, timezone
from pathlib import Path
import sqlite3
import sys
import tempfile
import threading
import unittest

from upab.relay.v3_enrollment_lab import SyntheticEnrollmentLab
from upab.relay.v3_policy import PolicyBlocked

NOW = datetime(2026,10,14,12,0,tzinfo=timezone.utc)


@unittest.skipUnless(sys.platform == "win32", "Windows current-user DPAPI lab only")
class Stage14EnrollmentLabTests(unittest.TestCase):
    def test_random_challenge_and_fixture_seal_never_enrolls_owner(self):
        with tempfile.TemporaryDirectory(prefix="upab-v3-lab-") as root:
            lab = SyntheticEnrollmentLab(root)
            request = lab.begin(now=NOW)
            self.assertEqual(len(request["challenge_hex"]),64)
            self.assertFalse(request["authenticator_prompted"])
            self.assertFalse(request["credential_enrolled"])
            with self.assertRaises(PolicyBlocked):
                lab.seal_public_fixture(request["challenge_hex"],now=NOW)
            result = lab.seal_public_fixture(
                request["challenge_hex"],now=NOW,synthetic_test_only=True
            )
            self.assertEqual(result["status"],"SEALED_UNTRUSTED")
            self.assertFalse(result["attestation_verified"])
            self.assertFalse(result["owner_authenticated"])
            self.assertFalse(result["execution_authorized"])
            later = SyntheticEnrollmentLab(root)
            integrity = later.inspect_sealed_fixture()
            self.assertTrue(integrity["encrypted_record_recovered"])
            self.assertFalse(integrity["credential_enrolled"])
            self.assertEqual(later.summary()["trusted_credential_count"],0)
            with self.assertRaises(PolicyBlocked):
                later.seal_public_fixture(request["challenge_hex"],now=NOW,
                                          synthetic_test_only=True)
            with self.assertRaises(PolicyBlocked):
                later.begin(now=NOW)

    def test_concurrent_one_use_only_one_candidate(self):
        with tempfile.TemporaryDirectory(prefix="upab-v3-lab-") as root:
            lab = SyntheticEnrollmentLab(root)
            request = lab.begin(now=NOW)
            barrier = threading.Barrier(6)
            results=[]
            lock=threading.Lock()

            def attempt():
                barrier.wait(timeout=10)
                try:
                    response = lab.seal_public_fixture(
                        request["challenge_hex"], now=NOW,synthetic_test_only=True
                    )
                    status=response["status"]
                except PolicyBlocked:
                    status="BLOCKED"
                with lock:
                    results.append(status)

            threads=[threading.Thread(target=attempt) for _ in range(6)]
            for thread in threads: thread.start()
            for thread in threads:
                thread.join(timeout=20)
                self.assertFalse(thread.is_alive())
            self.assertEqual(results.count("SEALED_UNTRUSTED"),1,results)
            self.assertEqual(results.count("BLOCKED"),5,results)
            self.assertEqual(lab.summary()["sealed_fixture_count"],1)
            self.assertFalse(lab.summary()["real_execution_authorized"])

    def test_bad_challenge_expired_and_backdated_denied(self):
        with tempfile.TemporaryDirectory(prefix="upab-v3-lab-") as root:
            lab = SyntheticEnrollmentLab(root)
            challenge=lab.begin(now=NOW)["challenge_hex"]
            for invalid in ("", "0"*63, "G"*64, "0"*64, 42):
                with self.subTest(invalid=invalid):
                    with self.assertRaises(PolicyBlocked):
                        lab.seal_public_fixture(invalid,now=NOW,synthetic_test_only=True)
            with self.assertRaisesRegex(PolicyBlocked,"predates"):
                lab.seal_public_fixture(
                    challenge,now=NOW-timedelta(seconds=1),synthetic_test_only=True
                )
            with self.assertRaisesRegex(PolicyBlocked,"expired"):
                lab.seal_public_fixture(
                    challenge,now=NOW+timedelta(seconds=90),synthetic_test_only=True
                )
            self.assertEqual(lab.summary()["sealed_fixture_count"],0)

    def test_crash_between_claim_and_seal_quarantines(self):
        with tempfile.TemporaryDirectory(prefix="upab-v3-lab-") as root:
            lab=SyntheticEnrollmentLab(root)
            issued=lab.begin(now=NOW)
            state=lab.seal_public_fixture(
                issued["challenge_hex"],now=NOW,
                synthetic_test_only=True,inject_interruption=True,
            )
            self.assertEqual(state["status"],"CLAIMED_INTERRUPTED_FOR_TEST")
            self.assertFalse(state["test_candidate_sealed"])
            restart=SyntheticEnrollmentLab(root)
            self.assertEqual(restart.reconcile(),1)
            self.assertEqual(restart.reconcile(),0)
            self.assertEqual(restart.summary()["phases"]["INTERRUPTED"],1)
            with self.assertRaises(PolicyBlocked):
                restart.seal_public_fixture(
                    issued["challenge_hex"], now=NOW,
                    synthetic_test_only=True,
                )
            with self.assertRaises(PolicyBlocked):
                restart.inspect_sealed_fixture()

    def test_ciphertext_tampering_cannot_promote_candidate(self):
        with tempfile.TemporaryDirectory(prefix="upab-v3-lab-") as root:
            lab=SyntheticEnrollmentLab(root)
            issued=lab.begin(now=NOW)
            lab.seal_public_fixture(
                issued["challenge_hex"],now=NOW,synthetic_test_only=True
            )
            path=Path(root)/"relay"/"v3_synthetic_enrollment.sqlite3"
            with closing(sqlite3.connect(path)) as db:
                row=db.execute("SELECT ciphertext FROM candidate").fetchone()
                blob=bytearray(row[0])
                blob[-3] ^= 0x6A
                db.execute("UPDATE candidate SET ciphertext=?",(bytes(blob),))
                db.commit()
            with self.assertRaises(PolicyBlocked):
                SyntheticEnrollmentLab(root).inspect_sealed_fixture()
            self.assertEqual(lab.summary()["trusted_credential_count"],0)

    def test_capacity_and_expired_queue_reclaimed(self):
        with tempfile.TemporaryDirectory(prefix="upab-v3-lab-") as root:
            lab=SyntheticEnrollmentLab(root)
            challenges=[lab.begin(now=NOW) for _ in range(4)]
            self.assertEqual(len(set(x["challenge_hex"] for x in challenges)),4)
            with self.assertRaisesRegex(PolicyBlocked,"full"):
                lab.begin(now=NOW)
            again=lab.begin(now=NOW+timedelta(seconds=91))
            self.assertNotIn(again["challenge_hex"],
                             [x["challenge_hex"] for x in challenges])
            self.assertEqual(lab.summary()["phases"]["EXPIRED"],4)

    def test_non_lab_directory_rejected(self):
        with tempfile.TemporaryDirectory() as unrelated:
            not_lab=Path(unrelated)/"upab-v3-lab-not-in-temp"
            not_lab.mkdir()
            with self.assertRaises(PolicyBlocked):
                SyntheticEnrollmentLab(not_lab)
            self.assertEqual(list(not_lab.iterdir()),[])

    def test_disarmed_api_has_no_verifier_or_executor(self):
        from upab.relay import v3_enrollment_lab as module
        for method in (
            "enroll_owner", "verify_attestation", "issue_approval",
            "execute_task", "run_shell", "connect_repository",
        ):
            self.assertFalse(hasattr(module,method))


if __name__ == "__main__":
    unittest.main()
