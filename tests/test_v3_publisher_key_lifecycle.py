from __future__ import annotations

from copy import deepcopy
import json
import unittest

from upab.relay.v3_policy import PolicyBlocked
from upab.relay.v3_publisher_key_lifecycle import (
    SCHEMA, MAX_REVOKED, MAX_EPOCH, MAX_RELEASE_SEQUENCE,
    review_publisher_transition, review_json,
)

ROOT_A="a"*64
ROOT_B="b"*64
ROOT_C="c"*64
PSCHEMA="upab.watcher-v3.publisher-transition-proposal.v1"


def proposal(action: str, epoch: int, key: str | None, floor: int = 0) -> dict:
    return {"schema":PSCHEMA,"action":action,"next_epoch":epoch,
            "new_key_sha256":key,"minimum_release_sequence":floor}


def state(*, epoch: int = 1, active: str | None = ROOT_A,
          revoked: list[str] | None = None, floor: int = 2) -> dict:
    return {"schema":SCHEMA,"epoch":epoch,"active_key_sha256":active,
            "revoked_key_sha256":[] if revoked is None else revoked,
            "minimum_release_sequence":floor}


class Stage31PublisherKeyLifecycleTests(unittest.TestCase):
    def _never_authorized(self, result: dict) -> None:
        self.assertEqual(result["status"],"PROPOSAL_FORMAT_VALID_BUT_UNAUTHORIZED")
        for field in ("prior_state_cryptographically_authenticated","owner_identity_verified",
                      "trusted_root_enrolled","publisher_signatures_verified",
                      "monotonic_counter_protected","trusted_revocation_registry_updated",
                      "roll_forward_state_committed","installation_authorized",
                      "migration_authorized","task_execution_authorized","writes_performed"):
            self.assertIs(result[field],False,field)
        self.assertNotIn(ROOT_A,json.dumps(result))
        self.assertNotIn(ROOT_B,json.dumps(result))
        self.assertNotIn(ROOT_C,json.dumps(result))

    def test_bootstrap_candidate_is_only_a_proposal(self):
        original=proposal("ENROLL",1,ROOT_A,1)
        before=deepcopy(original)
        result=review_publisher_transition(None,original)
        self.assertEqual(result["proposed_action"],"ENROLL")
        self.assertEqual(result["proposed_epoch"],1)
        self.assertTrue(result["proposed_key_active"])
        self.assertEqual(result["proposed_revoked_key_count"],0)
        self.assertEqual(result["required_external_ceremony"],
                         "OFFLINE_OWNER_BOOTSTRAP_AND_PUBLISHER_PROOF")
        self._never_authorized(result)
        self.assertEqual(original,before)

    def test_rotation_requires_old_and_new_signed_authorization(self):
        old=state(floor=4)
        next_stage=proposal("ROTATE",2,ROOT_B,5)
        before=deepcopy(old),deepcopy(next_stage)
        result=review_publisher_transition(old,next_stage)
        self.assertEqual(result["required_external_ceremony"],
                         "OWNER_PLUS_OLD_AND_NEW_PUBLISHER_SIGNED_ROTATION")
        self.assertEqual(result["proposed_revoked_key_count"],1)
        self.assertEqual(result["proposed_minimum_release_sequence"],5)
        self._never_authorized(result)
        self.assertEqual(before,(old,next_stage))

    def test_emergency_revocation_fails_closed_for_execution(self):
        report=review_publisher_transition(state(),proposal("REVOKE",2,None,2))
        self.assertFalse(report["proposed_key_active"])
        self.assertEqual(report["proposed_revoked_key_count"],1)
        self.assertEqual(report["required_external_ceremony"],
                         "OWNER_AUTHENTICATED_EMERGENCY_REVOCATION")
        self._never_authorized(report)

    def test_cannot_reenroll_silently_after_revocation(self):
        previous=state(epoch=2,active=None,revoked=[ROOT_A],floor=12)
        for action,key in (("ENROLL",ROOT_B),("ROTATE",ROOT_B),("REVOKE",None)):
            with self.subTest(action=action):
                with self.assertRaises(PolicyBlocked):
                    review_publisher_transition(previous,proposal(action,3,key,12))

    def test_rejects_same_key_reuse_or_revoked_key_resurrection(self):
        for candidate in (ROOT_A,ROOT_B):
            previous=state(epoch=2,active=ROOT_A,revoked=[ROOT_B],floor=9)
            with self.subTest(candidate=candidate):
                with self.assertRaises(PolicyBlocked):
                    review_publisher_transition(previous,proposal("ROTATE",3,candidate,9))

    def test_epoch_replay_gap_overflow_and_release_rollback_refused(self):
        previous=state(epoch=3,floor=999)
        for epoch,floor in ((3,999),(1,999),(5,999),(4,998),(True,1000),
                            (MAX_EPOCH+1,1000),(4,MAX_RELEASE_SEQUENCE+1)):
            with self.subTest(epoch=epoch,floor=floor):
                with self.assertRaises(PolicyBlocked):
                    review_publisher_transition(previous,proposal("ROTATE",epoch,ROOT_B,floor))
        with self.assertRaises(PolicyBlocked):
            review_publisher_transition(
                state(epoch=MAX_EPOCH),proposal("ROTATE",MAX_EPOCH+1,ROOT_B,999))

    def test_rejects_unsigned_claims_extra_fields_wrong_action(self):
        baseline=proposal("ENROLL",1,ROOT_A)
        for mutant in (
            {**baseline,"owner_approved":True},
            {**baseline,"schema":"v99"},
            {**baseline,"action":"INSTALL"},
            {**baseline,"new_key_sha256":"A"*64},
            {**baseline,"new_key_sha256":""},
            {**baseline,"minimum_release_sequence":True},
        ):
            with self.subTest(mutant=str(mutant)[:80]):
                with self.assertRaises(PolicyBlocked):
                    review_publisher_transition(None,mutant)
        for invalid in (None,[],True,"approve",{"action":"ENROLL"}):
            with self.subTest(invalid=invalid):
                with self.assertRaises(PolicyBlocked):
                    review_publisher_transition(None,invalid)

    def test_rejects_untrusted_previous_state_and_revocation_tampering(self):
        valid=state()
        altered=[
            {**valid,"owner_proof":"signed"},
            {**valid,"schema":"not-accepted"},
            {**valid,"epoch":0},
            {**valid,"active_key_sha256":"z"*64},
            {**valid,"revoked_key_sha256":[ROOT_A]},
            {**valid,"revoked_key_sha256":[ROOT_B,ROOT_B]},
            {**valid,"revoked_key_sha256":[ROOT_C,ROOT_B]},
            {**valid,"revoked_key_sha256":[ROOT_B]*(MAX_REVOKED+1)},
            {**valid,"minimum_release_sequence":-1},
            {**valid,"epoch":True},
            {**valid,"active_key_sha256":None},
        ]
        for candidate in altered:
            with self.subTest(index=altered.index(candidate)):
                with self.assertRaises(PolicyBlocked):
                    review_publisher_transition(candidate,proposal("ROTATE",2,ROOT_C,2))

    def test_revoked_list_capacity_fails_without_dropping_history(self):
        # Use deterministic sorted SHA-256-like synthetic pins.
        revoked=[f"{i:064x}" for i in range(MAX_REVOKED)]
        old=state(epoch=7,active=ROOT_A,revoked=revoked,floor=10)
        with self.assertRaises(PolicyBlocked):
            review_publisher_transition(old,proposal("ROTATE",8,ROOT_B,10))
        self.assertEqual(len(old["revoked_key_sha256"]),MAX_REVOKED)

    def test_review_json_is_bounded_and_read_only(self):
        proposal_json=json.dumps(proposal("ENROLL",1,ROOT_A,3))
        result=review_json(None,proposal_json)
        self._never_authorized(result)
        self.assertEqual(result["proposed_minimum_release_sequence"],3)
        for prior,p in ((None,"{"),(None,"x"*8193),("",proposal_json),
                        (None,True),(42,proposal_json)):
            with self.subTest(p=p):
                with self.assertRaises(PolicyBlocked):
                    review_json(prior,p)

    def test_no_install_persistence_owner_enrollment_or_execution_entrypoints(self):
        import upab.relay.v3_publisher_key_lifecycle as module
        for forbidden in ("persist", "enroll_owner", "register_key", "save_registry",
                          "generate_private_key","approve","execute","migrate","deploy",
                          "sign_release","install_watcher","connect_repo"):
            self.assertFalse(hasattr(module,forbidden))


if __name__=="__main__":
    unittest.main()
