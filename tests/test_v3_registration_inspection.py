from __future__ import annotations

import base64
import hashlib
import json
import unittest

from upab.relay.v3_policy import PolicyBlocked
from upab.relay.v3_registration_inspection import inspect_registration_candidate

RP = "upab.example.test"
ORIGIN = "https://" + RP
CHALLENGE = bytes.fromhex("3c"*32)
X = bytes.fromhex("1ee3e20b7836c44e865ec199a838e3944c724acfcb858fd6744459fb1c2f5722")
Y = bytes.fromhex("8c29c28c357150527a5f75b2a23194868f57a4c1191b2bd154b0306340986e80")


def head(major: int, n: int) -> bytes:
    if n < 24:
        return bytes([(major << 5) | n])
    if n < 256:
        return bytes([(major << 5) | 24, n])
    if n < 65536:
        return bytes([(major << 5) | 25]) + n.to_bytes(2, "big")
    return bytes([(major << 5) | 26]) + n.to_bytes(4, "big")


def encode(value) -> bytes:
    if type(value) is int:
        return head(0, value) if value >= 0 else head(1, -1-value)
    if type(value) is bytes:
        return head(2, len(value)) + value
    if type(value) is str:
        text = value.encode("utf-8")
        return head(3, len(text)) + text
    if type(value) is list:
        return head(4, len(value)) + b"".join(encode(x) for x in value)
    if type(value) is dict:
        return head(5, len(value)) + b"".join(
            encode(k) + encode(v) for k, v in value.items()
        )
    raise ValueError("fixture cannot encode type")


def client_data(**overrides):
    payload = {
        "type": "webauthn.create",
        "challenge": base64.urlsafe_b64encode(CHALLENGE).rstrip(b"=").decode(),
        "origin": ORIGIN,
        "crossOrigin": False,
    }
    payload.update(overrides)
    return json.dumps(payload, separators=(",", ":")).encode()


def auth_data(*, flags=0x45, rp=RP, cred_id=b"synthetic-credential-01",
              key=None, sign_count=0, suffix=b""):
    if key is None:
        key = {1: 2, 3: -7, -1: 1, -2: X, -3: Y}
    return (
        hashlib.sha256(rp.encode("ascii")).digest() +
        bytes([flags]) + sign_count.to_bytes(4, "big") +
        b"\0"*16 + len(cred_id).to_bytes(2, "big") +
        cred_id + encode(key) + suffix
    )


def att_obj(*, fmt="none", stmt=None, auth=None):
    return encode({
        "fmt": fmt, "authData": auth_data() if auth is None else auth,
        "attStmt": {} if stmt is None else stmt,
    })


def inspect(*, data=None, attestation=None, rp=RP, origin=ORIGIN,
            challenge=CHALLENGE):
    return inspect_registration_candidate(
        expected_challenge=challenge, expected_rp_id=rp,
        expected_origin=origin,
        client_data_json=client_data() if data is None else data,
        attestation_object=att_obj() if attestation is None else attestation,
    )


class Stage15RegistrationInspectionTests(unittest.TestCase):
    def test_valid_none_public_registration_stays_untrusted(self):
        result = inspect()
        self.assertEqual(result["format"], "none")
        self.assertEqual(result["key_algorithm"], "ES256")
        self.assertEqual(result["registration_sign_counter"],0)
        self.assertEqual(len(result["credential_id_sha256"]),64)
        self.assertEqual(len(result["public_key_sha256"]),64)
        self.assertTrue(result["user_verified_flag"])
        self.assertTrue(result["user_present_flag"])
        self.assertNotIn("credential_id", result)
        self.assertNotIn("public_key_x", result)
        for label in (
            "attestation_trust_verified", "trusted_relying_party_configured",
            "challenge_was_issued_by_trusted_broker", "credential_record_stored",
            "owner_authenticated", "approval_issued", "execution_authorized",
            "real_task_executed",
        ):
            self.assertFalse(result[label])

    def test_wrong_challenge_client_type_and_cross_origin_refused(self):
        variations = [
            {"type": "webauthn.get"},
            {"challenge": base64.urlsafe_b64encode(b"X"*32).rstrip(b"=").decode()},
            {"origin": "https://evil.example.test"},
            {"crossOrigin": True},
            {"unexpected": "adversarial"},
        ]
        for update in variations:
            with self.subTest(update=update):
                with self.assertRaises(PolicyBlocked):
                    inspect(data=client_data(**update))
        with self.assertRaises(PolicyBlocked):
            inspect(data=b'{"type":"webauthn.create","type":"webauthn.get"}')
        with self.assertRaises(PolicyBlocked):
            inspect(challenge=b"x"*32)

    def test_invalid_relying_party_origin_and_auth_hash_refused(self):
        for rp, origin in (
            ("evil.example.test", ORIGIN),
            (RP, "http://" + RP),
            (RP, "https://" + RP + ":443"),
            (RP, "https://" + RP + "/bad"),
            ("..invalid", "https://..invalid"),
        ):
            with self.subTest(rp=rp,origin=origin):
                with self.assertRaises(PolicyBlocked):
                    inspect(rp=rp,origin=origin)
        with self.assertRaises(PolicyBlocked):
            inspect(attestation=att_obj(auth=auth_data(rp="bad.example.test")))

    def test_required_attested_up_uv_and_backup_flag_checks(self):
        for flags in (0, 1, 4, 0x41, 0x44, 0x45|0x80,
                      0x45|0x02, 0x45|0x20, 0x45|0x10):
            with self.subTest(flags=flags):
                with self.assertRaises(PolicyBlocked):
                    inspect(attestation=att_obj(auth=auth_data(flags=flags)))
        self.assertEqual(
            inspect(attestation=att_obj(auth=auth_data(flags=0x4D)))["key_algorithm"],
            "ES256",
        )

    def test_none_attestation_only_and_unknown_top_level_denied(self):
        for item in (
            att_obj(fmt="packed"),
            att_obj(stmt={"sig": b"forged"}),
            encode({"fmt":"none", "authData":auth_data()}),
            encode({"fmt":"none", "attStmt":{}, "authData":auth_data(),
                    "trust_owner": 1}),
        ):
            with self.assertRaises(PolicyBlocked):
                inspect(attestation=item)

    def test_wrong_cose_key_types_alg_and_curve_denied(self):
        for mutated in (
            {1:2,3:-8,-1:1,-2:X,-3:Y},
            {1:3,3:-7,-1:1,-2:X,-3:Y},
            {1:2,3:-7,-1:2,-2:X,-3:Y},
            {1:2,3:-7,-1:1,-2:b"short",-3:Y},
            {1:2,3:-7,-1:1,-2:X,-3:Y, 99:1},
        ):
            with self.subTest(key=mutated):
                with self.assertRaises(PolicyBlocked):
                    inspect(attestation=att_obj(auth=auth_data(key=mutated)))

    def test_credential_length_and_trailing_data_refused(self):
        for credential in (b"", b"x"*1025):
            with self.assertRaises(PolicyBlocked):
                inspect(attestation=att_obj(auth=auth_data(cred_id=credential)))
        for trailing in (b"x", b"\x00", b"\xa0"):
            with self.assertRaises(PolicyBlocked):
                inspect(attestation=att_obj(auth=auth_data(suffix=trailing)))

    def test_reject_noncanonical_indefinite_duplicate_and_truncated_cbor(self):
        original=att_obj()
        for fixture in (
            b"\xbf" + original[1:],
            original+b"\x00",
            original[:-1],
            b"\xf5",
            b"\xa2" + encode("fmt")+encode("none") +
                encode("fmt")+encode("none"),
            encode({"fmt":"none", "attStmt":{}, "authData": b"\0"*12}),
            b"\xa1"+encode("fmt")+b"\x78\x04none",
        ):
            with self.subTest(fixture=fixture[:15]):
                with self.assertRaises(PolicyBlocked):
                    inspect(attestation=fixture)

    def test_bounded_inputs_refused(self):
        with self.assertRaises(PolicyBlocked):
            inspect(attestation=b"x"*8193)
        with self.assertRaises(PolicyBlocked):
            inspect(data=b"{" + b" "*2048 + b"}")
        with self.assertRaises(PolicyBlocked):
            inspect(data="json text")
        with self.assertRaises(PolicyBlocked):
            inspect(attestation=None, challenge="0"*64)

    def test_no_enrollment_or_execution_hook(self):
        import upab.relay.v3_registration_inspection as module
        for item in (
            "register_owner", "make_credential", "trust_credential",
            "enroll", "execute_task", "issue_execution_proof",
            "start_server", "approve_task",
        ):
            self.assertFalse(hasattr(module, item))


if __name__ == "__main__":
    unittest.main()
