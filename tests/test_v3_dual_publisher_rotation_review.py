from __future__ import annotations

from copy import deepcopy
import hashlib
import json
import sys
import unittest
from unittest import mock

from upab.relay.v3_policy import PolicyBlocked
from upab.relay.v3_dual_publisher_rotation_review import (
    DOMAIN, STATEMENT_SCHEMA, rotation_statement,
    verify_dual_rotation_review,
)

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
except ImportError:
    Ed25519PrivateKey = None


def _key():
    # Only disposable fixture key, never a production publisher key.
    signing = Ed25519PrivateKey.generate()
    public = signing.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return signing, public.hex(), hashlib.sha256(public).hexdigest()


def _inputs():
    old_priv, old_pub, old_pin = _key()
    new_priv, new_pub, new_pin = _key()
    prior = {
        "schema": "upab.watcher-v3.publisher-key-review.v1",
        "epoch": 7,
        "active_key_sha256": old_pin,
        "revoked_key_sha256": ["0"*64],
        "minimum_release_sequence": 12,
    }
    proposal = {
        "schema": "upab.watcher-v3.publisher-transition-proposal.v1",
        "action": "ROTATE",
        "next_epoch": 8,
        "new_key_sha256": new_pin,
        "minimum_release_sequence": 13,
    }
    wire = DOMAIN + rotation_statement(prior, proposal)
    args = {
        "prior": prior,
        "proposal": proposal,
        "old_public_key_hex": old_pub,
        "new_public_key_hex": new_pub,
        "old_signature_hex": old_priv.sign(wire).hex(),
        "new_signature_hex": new_priv.sign(wire).hex(),
    }
    return args, old_priv, new_priv


@unittest.skipIf(Ed25519PrivateKey is None, "Optional maintained cryptography backend unavailable")
class Stage32DualSignerRotationTests(unittest.TestCase):
    def _not_trusted(self, report):
        self.assertEqual(report["status"], "DUAL_SIGNATURES_VALID_FOR_UNTRUSTED_KEYS_ONLY")
        for field in (
            "previous_state_authenticated_by_protected_store",
            "publisher_key_pins_independently_enrolled",
            "trusted_publisher_identity_proven",
            "trusted_revocation_history_proven",
            "hardware_monotonic_counter_proven",
            "windows_hello_owner_verified",
            "owner_approved_rotation",
            "key_rotation_committed",
            "installation_authorized",
            "migration_authorized",
            "task_execution_authorized",
            "writes_performed",
        ):
            self.assertIs(report[field], False, field)

    def test_real_dual_signatures_validate_without_granting_trust(self):
        args, _, _ = _inputs()
        before = deepcopy(args)
        report = verify_dual_rotation_review(**args)
        self.assertTrue(report["old_signature_cryptographically_valid_for_supplied_key"])
        self.assertTrue(report["new_signature_cryptographically_valid_for_supplied_key"])
        self.assertTrue(report["prior_state_and_proposal_bound_in_statement"])
        self.assertEqual(report["proposed_next_epoch"], 8)
        self.assertEqual(report["proposed_release_floor"], 13)
        self._not_trusted(report)
        self.assertEqual(args, before)
        rendered = json.dumps(report)
        for secret in (args["old_public_key_hex"],args["new_public_key_hex"],
                       args["old_signature_hex"],args["new_signature_hex"]):
            self.assertNotIn(secret, rendered)

    def test_missing_either_signature_fails(self):
        for signer in ("old_signature_hex", "new_signature_hex"):
            with self.subTest(signer=signer):
                args, _, _ = _inputs()
                args[signer] = "0" * 128
                with self.assertRaises(PolicyBlocked):
                    verify_dual_rotation_review(**args)

    def test_signatures_cannot_be_swapped(self):
        args, _, _ = _inputs()
        args["old_signature_hex"], args["new_signature_hex"] = (
            args["new_signature_hex"], args["old_signature_hex"]
        )
        with self.assertRaises(PolicyBlocked):
            verify_dual_rotation_review(**args)

    def test_old_key_pin_must_match_supplied_old_pubkey(self):
        args, _, _ = _inputs()
        _, another_pub, _ = _key()
        args["old_public_key_hex"] = another_pub
        with self.assertRaises(PolicyBlocked):
            verify_dual_rotation_review(**args)

    def test_new_key_pin_must_match_supplied_new_pubkey(self):
        args, _, _ = _inputs()
        _, another_pub, _ = _key()
        args["new_public_key_hex"] = another_pub
        with self.assertRaises(PolicyBlocked):
            verify_dual_rotation_review(**args)

    def test_history_and_prior_floor_bound_to_signatures(self):
        for mutation in ("revoke-history", "old-floor", "old-epoch"):
            with self.subTest(mutation=mutation):
                args, _, _ = _inputs()
                if mutation == "revoke-history":
                    args["prior"]["revoked_key_sha256"] = ["1"*64]
                elif mutation == "old-floor":
                    args["prior"]["minimum_release_sequence"] = 11
                else:
                    args["prior"]["epoch"] = 6
                    args["proposal"]["next_epoch"] = 7
                with self.assertRaises(PolicyBlocked):
                    verify_dual_rotation_review(**args)

    def test_new_release_floor_bound_and_downgrade_denied(self):
        args, _, _ = _inputs()
        args["proposal"]["minimum_release_sequence"] = 14
        with self.assertRaises(PolicyBlocked):
            verify_dual_rotation_review(**args)
        args, _, _ = _inputs()
        args["proposal"]["minimum_release_sequence"] = 11
        with self.assertRaises(PolicyBlocked):
            verify_dual_rotation_review(**args)

    def test_epoch_replay_gap_or_wrong_operation_denied(self):
        for epoch, action in ((7,"ROTATE"), (10,"ROTATE"), (8,"ENROLL"), (8,"REVOKE")):
            with self.subTest(epoch=epoch, action=action):
                args, _, _ = _inputs()
                args["proposal"]["next_epoch"] = epoch
                args["proposal"]["action"] = action
                with self.assertRaises(PolicyBlocked):
                    verify_dual_rotation_review(**args)

    def test_domain_separation_required(self):
        args, old_priv, new_priv = _inputs()
        unsigned = rotation_statement(args["prior"], args["proposal"])
        args["old_signature_hex"] = old_priv.sign(unsigned).hex()
        args["new_signature_hex"] = new_priv.sign(unsigned).hex()
        with self.assertRaises(PolicyBlocked):
            verify_dual_rotation_review(**args)

    def test_cross_repository_replay_is_rejected(self):
        args, old_priv, new_priv = _inputs()
        statement = json.loads(rotation_statement(args["prior"],args["proposal"]))
        self.assertEqual(statement["schema"], STATEMENT_SCHEMA)
        statement["repository"]="an-unrelated/private-repo"
        forged = DOMAIN + json.dumps(
            statement, sort_keys=True, separators=(",",":"), ensure_ascii=True
        ).encode("ascii")
        args["old_signature_hex"] = old_priv.sign(forged).hex()
        args["new_signature_hex"] = new_priv.sign(forged).hex()
        with self.assertRaises(PolicyBlocked):
            verify_dual_rotation_review(**args)

    def test_reused_revoked_key_rejected_even_with_new_valid_signatures(self):
        args, old_priv, new_priv = _inputs()
        args["prior"]["revoked_key_sha256"] = [args["proposal"]["new_key_sha256"]]
        unsigned = DOMAIN + json.dumps({}, sort_keys=True).encode()
        args["old_signature_hex"] = old_priv.sign(unsigned).hex()
        args["new_signature_hex"] = new_priv.sign(unsigned).hex()
        with self.assertRaises(PolicyBlocked):
            verify_dual_rotation_review(**args)

    def test_invalid_hex_and_extra_claim_field_are_blocked(self):
        for field, value in (("old_public_key_hex", "X"*64),
                             ("new_public_key_hex", 3),
                             ("old_signature_hex", "F"*128),
                             ("new_signature_hex", "f"*127)):
            with self.subTest(field=field):
                args, _, _ = _inputs()
                args[field] = value
                with self.assertRaises(PolicyBlocked):
                    verify_dual_rotation_review(**args)
        args, _, _ = _inputs()
        args["proposal"]["owner_approved"] = True
        with self.assertRaises(PolicyBlocked):
            verify_dual_rotation_review(**args)

    def test_same_pubkey_does_not_count_as_rotation(self):
        args, _, _ = _inputs()
        args["new_public_key_hex"] = args["old_public_key_hex"]
        with self.assertRaises(PolicyBlocked):
            verify_dual_rotation_review(**args)


@unittest.skipIf(Ed25519PrivateKey is None, "Optional signing fixture backend unavailable")
class Stage32BackendDenyTests(unittest.TestCase):
    def test_missing_crypto_dependency_fails_closed(self):
        args, _, _ = _inputs()
        with mock.patch.dict(sys.modules, {
            "cryptography.exceptions": None,
            "cryptography.hazmat.primitives.asymmetric.ed25519": None,
        }):
            with self.assertRaises(PolicyBlocked):
                verify_dual_rotation_review(**args)

    def test_no_real_install_enroll_sign_or_restore_methods(self):
        import upab.relay.v3_dual_publisher_rotation_review as module
        for attr in ("save_trust", "enroll_key", "register_owner", "generate_private_key",
                     "sign_transition", "activate", "install_watcher",
                     "run_watcher", "execute_task", "migrate_state", "stop_service"):
            self.assertFalse(hasattr(module, attr))


if __name__ == "__main__":
    unittest.main()
