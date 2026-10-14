from __future__ import annotations

from copy import deepcopy
import hashlib
import json
from pathlib import Path
import sys
import unittest
from unittest import mock

from upab.relay.v3_policy import PolicyBlocked
from upab.relay.v3_health_sequence_continuity_review import (
    SCHEMA, SNAPSHOT_SCHEMA, MAX_PRIOR_ENTRIES, review_sequence_continuity,
)
from upab.relay.v3_signed_health_evidence_review import (
    CLAIM_SCHEMA, ENVELOPE_SCHEMA, DOMAIN, canonical_health_claim,
)

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
except ImportError:
    Ed25519PrivateKey = None

ROOT=Path(__file__).resolve().parents[1]
PORTFOLIO=ROOT/"config"/"watcher-v3-owner-selected-portfolio.example.json"
NOW=1_800_000_000


def portfolio():
    return json.loads(PORTFOLIO.read_text(encoding="utf-8"))


def private_key():
    key=Ed25519PrivateKey.generate()  # Disposable CI test fixture only.
    pub=key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return key, pub


def envelope(key, pub, *, repo="Universal-AI-", module=None, seq=3,
             when=NOW, condition="OK", source="GITHUB_CI"):
    claim={
        "schema":CLAIM_SCHEMA,"repository":repo,"module_id":module,
        "condition":condition,"observed_at_epoch_s":when,
        "sequence":seq,"source_kind":source,
    }
    return {
        "schema":ENVELOPE_SCHEMA,"claim":claim,
        "public_key_hex":pub.hex(),
        "public_key_sha256":hashlib.sha256(pub).hexdigest(),
        "signature_hex":key.sign(DOMAIN+canonical_health_claim(claim)).hex(),
    }


def snapshot(*entries):
    return {"schema":SNAPSHOT_SCHEMA,"entries":list(entries)}


def entry(e, *, seq=2, when=NOW-10):
    return {
        "signer_key_sha256":e["public_key_sha256"],
        "repository":e["claim"]["repository"],
        "module_id":e["claim"]["module_id"],
        "last_sequence":seq,
        "last_observed_at_epoch_s":when,
    }


def review(items, previous=None, **kwargs):
    return review_sequence_continuity(
        portfolio=portfolio(),envelopes=items,
        previous_snapshot=snapshot() if previous is None else previous,
        now_epoch_s=NOW,**kwargs
    )


class Stage37InertNoSourceTests(unittest.TestCase):
    def test_missing_evidence_and_empty_snapshot_preserve_unknown(self):
        r=review([])
        self.assertEqual(r["schema"],SCHEMA)
        self.assertEqual(r["unknown_total"],28)
        self.assertEqual(r["signed_observations_with_matching_prior"],0)
        self.assertEqual(r["signed_observations_with_missing_prior"],0)
        self.assertFalse(r["cross_restart_replay_prevented"])
        self.assertFalse(r["hardware_monotonic_store_verified"])
        self.assertFalse(r["live_monitoring_enabled"])
        self.assertFalse(r["task_execution_authorized"])

    def test_bogus_snapshot_has_no_implicit_trust(self):
        invalid=[
            None,[],{},{"schema":SNAPSHOT_SCHEMA,"entries":{}},
            {"schema":"future","entries":[]},
            {"schema":SNAPSHOT_SCHEMA,"entries":[],"authorized":True},
            snapshot(*([{}]*(MAX_PRIOR_ENTRIES+1))),
        ]
        for value in invalid:
            with self.subTest(value=str(value)[:75]):
                with self.assertRaises(PolicyBlocked):
                    review([],previous=value)

    def test_no_persistent_ledger_or_executor_surface(self):
        import upab.relay.v3_health_sequence_continuity_review as module
        for name in (
            "persist_sequence","write_snapshot","accept_health","enroll_signer",
            "get_owner_credential","install","deploy","monitor","start_watcher",
            "execute_task","approve","connect_repo","create_chat","create_folder",
            "disable_task",
        ):
            self.assertFalse(hasattr(module,name))


@unittest.skipIf(Ed25519PrivateKey is None, "Optional cryptography backend missing")
class Stage37SequenceContinuityTests(unittest.TestCase):
    def _denied_authority(self, report):
        self.assertEqual(report["status"],
                         "UNTRUSTED_SEQUENCE_CONTINUITY_PREVIEW_NOT_REPLAY_PROTECTION")
        for field in (
            "caller_supplied_prior_snapshot_authenticated",
            "signature_signers_independently_trusted",
            "cross_restart_replay_prevented",
            "last_sequences_durably_persisted",
            "hardware_monotonic_store_verified",
            "owner_windows_hello_authenticated",
            "operational_health_verified",
            "live_monitoring_enabled",
            "project_roster_modified",
            "repository_connections_enabled",
            "task_execution_authorized",
            "settings_changed",
        ):
            self.assertIs(report[field],False,field)
        self.assertEqual(report["verified_healthy_projects"],0)
        self.assertEqual(report["verified_healthy_modules"],0)

    def test_matching_prior_increments_but_does_not_prove_trust(self):
        key,pub=private_key()
        e=envelope(key,pub,seq=3)
        previous=snapshot(entry(e,seq=2))
        untouched=deepcopy(previous),deepcopy(e)
        result=review([e],previous=previous)
        self.assertEqual(result["signed_observations_with_matching_prior"],1)
        self.assertEqual(result["signed_observations_with_missing_prior"],0)
        self.assertEqual(result["sequence_gaps_for_review"],0)
        self.assertEqual(result["fresh_unverified_ok"],1)
        self._denied_authority(result)
        self.assertEqual(untouched,(previous,e))
        rendered=json.dumps(result)
        for literal in (e["public_key_hex"],e["public_key_sha256"],
                        e["signature_hex"],"Universal-AI-","online-store"):
            self.assertNotIn(literal,rendered)

    def test_old_or_equal_sequence_does_not_pass_supplied_snapshot(self):
        key,pub=private_key()
        for seq in (1,2):
            e=envelope(key,pub,seq=seq)
            with self.subTest(seq=seq):
                with self.assertRaises(PolicyBlocked):
                    review([e],previous=snapshot(entry(e,seq=2)))

    def test_jump_is_flagged_for_review_not_silently_healthy(self):
        key,pub=private_key()
        e=envelope(key,pub,seq=12)
        r=review([e],previous=snapshot(entry(e,seq=2)))
        self.assertEqual(r["sequence_gaps_for_review"],1)
        self.assertEqual(r["fresh_unverified_ok"],1)
        self._denied_authority(r)

    def test_lost_prior_is_explicitly_unknown_even_on_valid_signature(self):
        key,pub=private_key()
        e=envelope(key,pub,seq=800)
        r=review([e])
        self.assertEqual(r["signed_observations_with_missing_prior"],1)
        self.assertEqual(r["signed_observations_with_matching_prior"],0)
        self.assertFalse(r["cross_restart_replay_prevented"])
        self._denied_authority(r)

    def test_changed_signer_cannot_inherit_other_signer_prior(self):
        first,first_pub=private_key()
        second,second_pub=private_key()
        older=envelope(first,first_pub,seq=3)
        next_e=envelope(second,second_pub,seq=3)
        r=review([next_e],previous=snapshot(entry(older,seq=3)))
        self.assertEqual(r["signed_observations_with_missing_prior"],1)
        self.assertFalse(r["signature_signers_independently_trusted"])
        self._denied_authority(r)

    def test_backward_observation_time_rejected(self):
        key,pub=private_key()
        e=envelope(key,pub,seq=7,when=NOW-20)
        with self.assertRaises(PolicyBlocked):
            review([e],previous=snapshot(entry(e,seq=6,when=NOW-10)))

    def test_nested_poindexter_module_and_repo_are_separate_scopes(self):
        key,pub=private_key()
        top=envelope(key,pub,repo="UP-UHAIB-001-Poindexter",seq=10,
                     source="LOCAL_WATCHER")
        nested=envelope(key,pub,repo="UP-UHAIB-001-Poindexter",
                        module="019",seq=11,source="LOCAL_WATCHER")
        prior=sorted([entry(top,seq=9),entry(nested,seq=10)],
                     key=lambda x:(x["signer_key_sha256"],x["repository"],x["module_id"] or ""))
        r=review([top,nested],previous=snapshot(*prior))
        self.assertEqual(r["signed_observations_with_matching_prior"],2)
        self.assertEqual(r["selected_repository_count"],9)
        self.assertEqual(r["nested_poindexter_module_count"],19)
        self._denied_authority(r)

    def test_unselected_or_excluded_repo_in_snapshot_denied(self):
        key,pub=private_key()
        e=envelope(key,pub)
        for repo in ("online-store","School.tutor","RAID-AI","","Unknown"):
            bad=entry(e)
            bad["repository"]=repo
            with self.subTest(repo=repo):
                with self.assertRaises(PolicyBlocked):
                    review([e],previous=snapshot(bad))

    def test_snapshot_duplicate_out_of_order_and_wrong_module_denied(self):
        key,pub=private_key()
        e=envelope(key,pub)
        valid=entry(e)
        bad=deepcopy(valid);bad["module_id"]="001"
        cases=[
            snapshot(valid,valid),
            snapshot({**valid,"last_sequence":5},valid),
            snapshot(bad),
            snapshot({**valid,"new_field":"owner approved"}),
        ]
        for case in cases:
            with self.subTest(case=str(case)[:65]):
                with self.assertRaises(PolicyBlocked):
                    review([e],previous=case)

    def test_snapshot_timestamp_sequence_and_signer_input_denied(self):
        key,pub=private_key()
        e=envelope(key,pub)
        for field,value in (
            ("last_sequence",0),("last_sequence",True),
            ("last_sequence",2**53),("last_observed_at_epoch_s",NOW+1),
            ("last_observed_at_epoch_s",-1),("last_observed_at_epoch_s",True),
            ("signer_key_sha256","X"*64),("signer_key_sha256","f"*63),
        ):
            bad=entry(e)
            bad[field]=value
            with self.subTest(field=field,value=str(value)[:20]):
                with self.assertRaises(PolicyBlocked):
                    review([e],previous=snapshot(bad))

    def test_invalid_signature_denied_before_sequence_compare(self):
        key,pub=private_key()
        e=envelope(key,pub,seq=4)
        e["signature_hex"]="0"*128
        with self.assertRaises(PolicyBlocked):
            review([e],previous=snapshot(entry(e,seq=3)))

    def test_signed_stale_ok_is_unknown_not_verified(self):
        key,pub=private_key()
        e=envelope(key,pub,seq=4,when=NOW-301)
        r=review([e],previous=snapshot(entry(e,seq=3,when=NOW-302)))
        self.assertEqual(r["stale_unknown"],1)
        self.assertEqual(r["fresh_unverified_ok"],0)
        self._denied_authority(r)

    def test_missing_crypto_backend_fails_closed(self):
        key,pub=private_key()
        e=envelope(key,pub)
        with mock.patch.dict(sys.modules,{
            "cryptography.exceptions":None,
            "cryptography.hazmat.primitives.asymmetric.ed25519":None
        }):
            with self.assertRaises(PolicyBlocked):
                review([e])

    def test_batch_with_duplicate_identity_is_denied_even_if_sequence_grows(self):
        key,pub=private_key()
        e1=envelope(key,pub,seq=4)
        e2=envelope(key,pub,seq=5)
        with self.assertRaises(PolicyBlocked):
            review([e1,e2],previous=snapshot(entry(e1,seq=3)))


if __name__=="__main__":
    unittest.main()
