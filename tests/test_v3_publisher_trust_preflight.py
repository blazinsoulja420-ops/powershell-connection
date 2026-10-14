from __future__ import annotations

import unittest

from upab.relay.v3_policy import PolicyBlocked
from upab.relay.v3_publisher_trust_preflight import inspect_release_trust


class Stage30TrustBoundaryTests(unittest.TestCase):
    def test_unenrolled_trust_denies_every_authority(self):
        r=inspect_release_trust(expected_commit="a"*40)
        self.assertEqual(r["status"],"TRUST_ROOT_NOT_ENROLLED")
        for key in ("signature_cryptographically_verified","trusted_publisher_key_enrolled",
                    "owner_presence_verified","release_authenticated","installation_authorized",
                    "migration_authorized","task_execution_authorized","changes_performed"):
            self.assertFalse(r[key])

    def test_supplied_fingerprint_is_not_enrollment(self):
        r=inspect_release_trust(expected_commit="b"*40,publisher_key_sha256="c"*64)
        self.assertTrue(r["publisher_fingerprint_supplied"])
        self.assertFalse(r["trusted_publisher_key_enrolled"])

    def test_caller_claims_cannot_bypass_signature_verification(self):
        r=inspect_release_trust(expected_commit="d"*40,
                                signed_release_verified=True,owner_authenticated=True)
        self.assertFalse(r["signature_cryptographically_verified"])
        self.assertFalse(r["owner_presence_verified"])
        self.assertFalse(r["installation_authorized"])

    def test_invalid_commit_rejected(self):
        for value in ("", "A"*40, "g"*40, "a"*39, True):
            with self.subTest(value=value):
                with self.assertRaises(PolicyBlocked):
                    inspect_release_trust(expected_commit=value)

    def test_invalid_fingerprint_rejected(self):
        for value in ("A"*64, "f"*63, "z"*64, True):
            with self.subTest(value=value):
                with self.assertRaises(PolicyBlocked):
                    inspect_release_trust(expected_commit="a"*40,publisher_key_sha256=value)

    def test_boolean_trust_assertions_must_be_exact_bool(self):
        for key in ("signed_release_verified","owner_authenticated"):
            with self.subTest(key=key):
                with self.assertRaises(PolicyBlocked):
                    inspect_release_trust(expected_commit="a"*40,**{key:1})


if __name__=="__main__":
    unittest.main()
