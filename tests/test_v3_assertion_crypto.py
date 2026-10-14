"""PUBLIC-only deterministic WebAuthn ES256 test vector (no private key stored).

The fixture is constructed using a fixed development key and offline ES256
signature, NOT from an enrolled owner authenticator. It is cryptographically
meaningful but cannot authorize real work.
"""
from __future__ import annotations

import base64
import hashlib
import json
import sys
import unittest

from upab.relay.v3_assertion_crypto import inspect_es256_assertion
from upab.relay.v3_policy import PolicyBlocked

X = bytes.fromhex("1ee3e20b7836c44e865ec199a838e3944c724acfcb858fd6744459fb1c2f5722")
Y = bytes.fromhex("8c29c28c357150527a5f75b2a23194868f57a4c1191b2bd154b0306340986e80")
SIG = bytes.fromhex(
    "304502200c6ed5d51977e6089c2d927138ede40b29acbf9fea1f120ac2373dcddfbfbdf3"
    "022100d561a0eb4b0a922a9baff3f153879217164b9a065ee864f3bf53ea4e8e3b8ea6"
)
CHALLENGE = bytes.fromhex("cd"*32)
RP = "upab.example.test"
ORIGIN = "https://upab.example.test"
CLIENT = (b'{"challenge":"zc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc0",'
          b'"crossOrigin":false,"origin":"https://upab.example.test","type":"webauthn.get"}')
AUTH = bytes.fromhex("aac017a99245622c2f0e7f062b3c8bfc829ab2642d5e2f0548281d53dea537010500000001")


def inspect(**override):
    args = dict(
        expected_challenge=CHALLENGE, expected_origin=ORIGIN,
        expected_rp_id=RP, credential_public_x=X, credential_public_y=Y,
        client_data_json=CLIENT, authenticator_data=AUTH,
        signature_der=SIG, previous_sign_count=0,
    )
    args.update(override)
    return inspect_es256_assertion(**args)


class AssertionCryptoStage12Tests(unittest.TestCase):
    def test_native_public_fixture_signature_is_valid_but_never_authorizes(self):
        if sys.platform != "win32":
            with self.assertRaises(PolicyBlocked):
                inspect()
            return
        result = inspect()
        self.assertTrue(result["signed_assertion_valid"])
        self.assertTrue(result["signed_user_verified_flag"])
        self.assertEqual(result["new_sign_count"], 1)
        self.assertFalse(result["trusted_credential_enrollment_proven"])
        self.assertFalse(result["challenge_replay_protection_connected"])
        for field in ("owner_authenticated", "approval_issued",
                      "execution_authorized", "task_executed"):
            self.assertFalse(result[field])

    @unittest.skipUnless(sys.platform == "win32", "Win32 CNG only")
    def test_tampered_signature_does_not_validate(self):
        bad = bytearray(SIG)
        bad[-1] ^= 0x01
        report = inspect(signature_der=bytes(bad))
        self.assertFalse(report["signed_assertion_valid"])
        self.assertIsNone(report["new_sign_count"])
        self.assertFalse(report["execution_authorized"])

    @unittest.skipUnless(sys.platform == "win32", "Win32 CNG only")
    def test_wrong_p256_key_does_not_validate(self):
        # ECC point is invalid or a different key. Both must block.
        with self.assertRaises(PolicyBlocked):
            inspect(credential_public_x=b"\0"*32)

    def test_origin_rpid_challenge_and_client_flags_are_checked(self):
        cases = (
            {"expected_challenge": bytes.fromhex("ba"*32)},
            {"expected_origin": "https://evil.example.test"},
            {"expected_rp_id": "other.example.test"},
            {"client_data_json": CLIENT.replace(b"webauthn.get",b"webauthn.put")},
            {"client_data_json": CLIENT.replace(b'"crossOrigin":false',b'"crossOrigin":true')},
            {"client_data_json": CLIENT.replace(b'"origin":"https://upab.example.test"',
                                              b'"origin":"https://evil.example.test"')},
            {"client_data_json": CLIENT+b"garbage"},
        )
        for change in cases:
            with self.subTest(change=change):
                with self.assertRaises(PolicyBlocked):
                    inspect(**change)

    def test_invalid_origin_urls_fail_as_policy_blocks(self):
        for value in (
            "https://upab.example.test:wrong",
            "https://upab.example.test:443",
            "http://upab.example.test",
            "https://upab.example.test/another",
            "https://upab.example.test?token=unused",
            "https://person@upab.example.test",
        ):
            with self.subTest(value=value):
                with self.assertRaises(PolicyBlocked):
                    inspect(expected_origin=value)

    def test_user_presence_uv_backup_flags_and_counter_advanced(self):
        for flags in (0x00,0x01,0x04,0x45,0x85,0x07,0x15,0x25):
            forged = AUTH[:32] + bytes([flags]) + AUTH[33:]
            with self.subTest(flags=flags):
                with self.assertRaises(PolicyBlocked):
                    inspect(authenticator_data=forged)
        for prev in (1,2,2**32,-1,True):
            with self.subTest(prev=prev):
                with self.assertRaises(PolicyBlocked):
                    inspect(previous_sign_count=prev)
        with self.assertRaises(PolicyBlocked):
            inspect(authenticator_data=AUTH[:-1]+b"\0")

    def test_der_canonicality_and_bounds(self):
        sig_cases = (
            b"",
            SIG+b"\0",
            SIG[:1]+bytes([SIG[1]-1])+SIG[2:],
            SIG[:2]+b"\x03"+SIG[3:],
            b"0\x06\x02\x01\x00\x02\x01\x01",
            b"0\x06\x02\x01\x01\x02\x01\x00",
        )
        for sig in sig_cases:
            with self.subTest(sig=sig[:10]):
                with self.assertRaises(PolicyBlocked):
                    inspect(signature_der=sig)

    def test_duplicate_json_fields_rejected(self):
        client=CLIENT[:-1]+b',"origin":"https://upab.example.test"}'
        with self.assertRaises(PolicyBlocked):
            inspect(client_data_json=client)

    def test_no_enrollment_or_execution_api(self):
        import upab.relay.v3_assertion_crypto as verifier
        for forbidden in ("approve", "issue_token", "enroll", "store_owner",
                          "run_command", "execute_task", "issue_execution_proof"):
            self.assertFalse(hasattr(verifier, forbidden))


if __name__ == "__main__":
    unittest.main()
