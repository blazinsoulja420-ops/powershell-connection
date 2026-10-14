from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import secrets
import tempfile
import threading
import unittest

from upab.relay.v3_approval_preview import (
    ApprovalProofPreview, SCHEMA, canonical_proof_bytes, check_proof_format
)
from upab.relay.v3_policy import PolicyBlocked

KEY = b"A" * 48
NOW = datetime(2026, 10, 13, 20, 0, tzinfo=timezone.utc)


def proof(*, task_id: str = "sample-1", digest: str = "C"*64):
    data = {
        "schema": SCHEMA,
        "issuer": "trusted-approval-broker",
        "task_id": task_id,
        "task_sha256": digest,
        "channel_id": "upab-local",
        "repository": "example-ops/demo",
        "expected_head": "1"*40,
        "scope": "read_only",
        "issued_at_utc": (NOW-timedelta(seconds=20)).isoformat(),
        "expires_at_utc": (NOW+timedelta(seconds=60)).isoformat(),
        "nonce": secrets.token_hex(24),
        "mac": "0"*64,
    }
    data["mac"] = hmac.new(KEY, canonical_proof_bytes(data), hashlib.sha256).hexdigest()
    return data


def accept(store, item, **overrides):
    values = {
        "task_id": item["task_id"],
        "task_sha256": item["task_sha256"],
        "channel_id": item["channel_id"],
        "repository": item["repository"],
        "expected_head": item["expected_head"],
        "issuer": item["issuer"],
        "now": NOW,
    }
    values.update(overrides)
    return store.admit_for_review(item, **values)


class ProofAdmissionTests(unittest.TestCase):
    def test_matching_proof_is_single_use_review_only(self):
        with tempfile.TemporaryDirectory() as td:
            candidate = ApprovalProofPreview(td, trusted_verifier_key=KEY)
            item = proof()
            result = accept(candidate, item)
            self.assertEqual(result["status"], "PROOF_VERIFIED_FOR_REVIEW_ONLY")
            self.assertFalse(result["execution_authorized"])
            self.assertFalse(result["authenticated_owner"])
            self.assertTrue(result["proof_consumed"])
            with self.assertRaisesRegex(PolicyBlocked, "replayed"):
                accept(ApprovalProofPreview(td,trusted_verifier_key=KEY),item)

    def test_scope_and_binding_tampering_denied(self):
        with tempfile.TemporaryDirectory() as td:
            store=ApprovalProofPreview(td,trusted_verifier_key=KEY)
            for field,bad in (
                ("scope","mutation"),
                ("task_sha256","D"*64),
                ("repository","other/project"),
                ("expected_head","2"*40),
                ("task_id","another-task"),
                ("channel_id","another-channel"),
                ("issuer","fake-issuer"),
                ("nonce",secrets.token_hex(24)),
            ):
                with self.subTest(field=field):
                    tampered=proof()
                    tampered[field]=bad
                    with self.assertRaises(PolicyBlocked):
                        accept(store,tampered)
            self.assertEqual(accept(store,proof(task_id="untainted"))["status"],
                             "PROOF_VERIFIED_FOR_REVIEW_ONLY")

    def test_caller_expected_binding_must_match(self):
        with tempfile.TemporaryDirectory() as td:
            store=ApprovalProofPreview(td,trusted_verifier_key=KEY)
            item=proof()
            for key,other in (
                ("repository","evil/other"),
                ("expected_head","f"*40),
                ("task_sha256","B"*64),
                ("channel_id","upab-other"),
                ("issuer","different-broker"),
                ("task_id","another-task"),
            ):
                with self.subTest(key=key):
                    with self.assertRaisesRegex(PolicyBlocked,"binding mismatch"):
                        accept(store,item,**{key:other})

    def test_expiry_future_issued_and_max_lifetime(self):
        for issued,expire in (
            (NOW-timedelta(minutes=20),NOW-timedelta(seconds=1)),
            (NOW+timedelta(seconds=1),NOW+timedelta(seconds=30)),
            (NOW-timedelta(seconds=30),NOW+timedelta(minutes=9)),
            (NOW,NOW),
        ):
            with self.subTest(issued=issued,expire=expire):
                item=proof()
                item["issued_at_utc"]=issued.isoformat()
                item["expires_at_utc"]=expire.isoformat()
                item["mac"]=hmac.new(KEY,canonical_proof_bytes(item),hashlib.sha256).hexdigest()
                with self.assertRaises(PolicyBlocked):
                    check_proof_format(item,now=NOW)

    def test_unknown_claims_and_weak_key_are_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            with self.assertRaises(PolicyBlocked):
                ApprovalProofPreview(td,trusted_verifier_key=b"weak")
            item=proof()
            item["automatically_approve"]=True
            with self.assertRaises(PolicyBlocked):
                canonical_proof_bytes(item)
            with self.assertRaises(PolicyBlocked):
                check_proof_format(item,now=NOW)

    def test_concurrent_same_task_only_one_admission(self):
        with tempfile.TemporaryDirectory() as td:
            item=proof()
            gate=threading.Barrier(8)
            results=[]
            guard=threading.Lock()
            def worker():
                store=ApprovalProofPreview(td,trusted_verifier_key=KEY)
                gate.wait(timeout=10)
                try:
                    accept(store,item)
                    outcome="reviewed"
                except PolicyBlocked:
                    outcome="blocked"
                with guard:
                    results.append(outcome)
            threads=[threading.Thread(target=worker) for _ in range(8)]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join(timeout=20)
                self.assertFalse(thread.is_alive())
            self.assertEqual(results.count("reviewed"),1,results)
            self.assertEqual(results.count("blocked"),7,results)


if __name__ == "__main__":
    unittest.main()
