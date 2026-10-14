"""Stage 45: ephemeral-key, caller-chosen-pin provider-ack adversarial tests."""
from __future__ import annotations

import hashlib
import json
import unittest
from copy import deepcopy

from upab.relay.v3_policy import PolicyBlocked
from upab.relay.v3_stage44_witness_protocol_review import REQUEST_SCHEMA
from upab.relay.v3_stage45_provider_ack_review import (
    CLAIM_SCHEMA, ENVELOPE_SCHEMA, DOMAIN, MAX_HISTORY,
    canonical_provider_claim, review_untrusted_provider_ack,
)

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
except ImportError:
    Ed25519PrivateKey = None

NOW = 1_800_000_000
_OMITTED = object()
ID = "a" * 32
REQ = "b" * 32
BEFORE = "c" * 64
AFTER = "d" * 64


def request(operation="COMPARE_ADVANCE", transition="HEALTH"):
    return {
        "schema": REQUEST_SCHEMA, "operation": operation,
        "witness_id": ID, "request_id": REQ, "expected_epoch": 8,
        "expected_commitment": BEFORE,
        "next_epoch": 9 if operation == "COMPARE_ADVANCE" else None,
        "next_commitment": AFTER if operation == "COMPARE_ADVANCE" else None,
        "transition_kind": transition if operation == "COMPARE_ADVANCE" else None,
    }


def request_hash(req):
    return hashlib.sha256(json.dumps(req, sort_keys=True, separators=(",", ":"),
                                    ensure_ascii=True).encode("ascii")).hexdigest()


@unittest.skipIf(Ed25519PrivateKey is None, "maintained Ed25519 backend unavailable")
class Stage45ProviderAcknowledgementTests(unittest.TestCase):
    def setUp(self):
        self.private = Ed25519PrivateKey.generate()
        self.public = self.private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        self.pin = hashlib.sha256(self.public).hexdigest()

    def envelope(self, req=None, claim_override=None, key=None):
        req = request() if req is None else req
        claim = {
            "schema": CLAIM_SCHEMA, "provider_kind": "TPM_NV_CANDIDATE",
            "witness_id": req["witness_id"], "request_id": req["request_id"],
            "request_sha256": request_hash(req),
            "operation": req["operation"], "transition_kind": req["transition_kind"],
            "claimed_status": "APPLIED" if req["operation"] == "COMPARE_ADVANCE" else "SNAPSHOT",
            "claimed_epoch": req["next_epoch"] if req["operation"] == "COMPARE_ADVANCE" else req["expected_epoch"],
            "claimed_commitment": req["next_commitment"] if req["operation"] == "COMPARE_ADVANCE" else req["expected_commitment"],
            "issued_at_epoch_s": NOW - 3,
            "expires_at_epoch_s": NOW + 60,
        }
        claim.update(claim_override or {})
        key = self.private if key is None else key
        pub = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        return {
            "schema": ENVELOPE_SCHEMA, "claim": claim,
            "public_key_hex": pub.hex(),
            "signature_hex": key.sign(DOMAIN + canonical_provider_claim(claim)).hex(),
        }

    def review(self, *, req=None, envelope=None, pin=None, seen=_OMITTED, now=NOW):
        req = request() if req is None else req
        return review_untrusted_provider_ack(
            request=req,
            envelope=self.envelope(req) if envelope is None else envelope,
            caller_selected_public_key_sha256=self.pin if pin is None else pin,
            seen_ack_claim_sha256=[] if seen is _OMITTED else seen,
            now_epoch_s=now,
        )

    def assert_no_authority(self, out):
        for field in (
            "provider_independently_authenticated", "pin_independently_enrolled",
            "genuine_tpm_or_external_service_verified",
            "durable_replay_history_verified", "protected_monotonicity_verified",
            "remote_cas_verified", "actual_recovery_verified",
            "owner_approval_verified", "collector_identity_verified",
            "real_monitoring_enabled", "task_execution_authorized",
            "project_roster_modified",
        ):
            self.assertIs(out[field], False, field)
        self.assertTrue(out["signature_consistency_demonstrated"])
        self.assertEqual(out["evidence_trust"],
                         "CALLER_SELECTED_PROVIDER_PIN_AND_REPLAY_HISTORY")
        encoded = json.dumps(out)
        self.assertNotIn(self.pin, encoded)
        self.assertNotIn(self.public.hex(), encoded)
        self.assertNotIn(ID, encoded)

    def test_valid_signed_advance_stays_review_only(self):
        result = self.review()
        self.assertEqual(result["status"], "SYNTHETIC_SIGNED_ACK_CONSISTENT_NO_PROVIDER_TRUST")
        self.assert_no_authority(result)

    def test_valid_signed_snapshot_stays_review_only(self):
        req = request(operation="READ_SNAPSHOT")
        result = self.review(req=req)
        self.assertEqual(result["status"], "SYNTHETIC_SIGNED_ACK_CONSISTENT_NO_PROVIDER_TRUST")
        self.assert_no_authority(result)

    def test_valid_self_generated_key_and_self_pin_can_spoof_provider(self):
        counterfeit = Ed25519PrivateKey.generate()
        pub = counterfeit.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        env = self.envelope(key=counterfeit)
        report = self.review(envelope=env, pin=hashlib.sha256(pub).hexdigest())
        self.assertEqual(report["status"], "SYNTHETIC_SIGNED_ACK_CONSISTENT_NO_PROVIDER_TRUST")
        self.assert_no_authority(report)

    def test_unpinned_new_key_rejected(self):
        unknown = Ed25519PrivateKey.generate()
        with self.assertRaises(PolicyBlocked):
            self.review(envelope=self.envelope(key=unknown))

    def test_mutated_signature_rejected(self):
        env = self.envelope()
        env["signature_hex"] = "0" * 128
        with self.assertRaises(PolicyBlocked):
            self.review(envelope=env)

    def test_mutated_claim_without_resigning_rejected(self):
        env = self.envelope()
        env["claim"]["claimed_epoch"] = 15
        with self.assertRaises(PolicyBlocked):
            self.review(envelope=env)

    def test_domain_separated_signature_required(self):
        env = self.envelope()
        env["signature_hex"] = self.private.sign(canonical_provider_claim(env["claim"])).hex()
        with self.assertRaises(PolicyBlocked):
            self.review(envelope=env)

    def test_expired_or_future_ack_is_blocked(self):
        for change in (
            {"issued_at_epoch_s": NOW - 150, "expires_at_epoch_s": NOW - 1},
            {"issued_at_epoch_s": NOW + 1, "expires_at_epoch_s": NOW + 90},
        ):
            env = self.envelope(claim_override=change)
            with self.subTest(change=change):
                report = self.review(envelope=env)
                self.assertEqual(report["status"], "BLOCKED_SYNTHETIC_ACK_EXPIRED_OR_FUTURE")
                self.assert_no_authority(report)

    def test_excessive_ack_lifetime_rejected(self):
        with self.assertRaises(PolicyBlocked):
            self.envelope(claim_override={"issued_at_epoch_s": NOW-100,
                                           "expires_at_epoch_s": NOW+600})

    def test_replayed_ack_claim_hash_is_quarantined(self):
        env = self.envelope()
        replay = hashlib.sha256(canonical_provider_claim(env["claim"])).hexdigest()
        report = self.review(envelope=env, seen=[replay])
        self.assertEqual(report["status"], "QUARANTINED_SYNTHETIC_ACK_REPLAY")
        self.assert_no_authority(report)

    def test_empty_caller_history_allows_duplicate_ack_known_weakness(self):
        env = self.envelope()
        first = self.review(envelope=env, seen=[])
        second = self.review(envelope=env, seen=[])
        self.assertEqual(first, second)
        self.assert_no_authority(second)

    def test_replay_history_tamper_and_overflow_refused(self):
        for seen in (
            ["x"], ["f" * 64, "f" * 64], {},
            [f"{n:064x}" for n in range(MAX_HISTORY + 1)],
            [False], [""], None,
        ):
            with self.subTest(history=type(seen).__name__), self.assertRaises(PolicyBlocked):
                self.review(seen=seen)

    def test_request_identity_and_digest_substitution_quarantined(self):
        for change in (
            {"request_id": "e" * 32},
            {"witness_id": "e" * 32},
            {"request_sha256": "e" * 64},
            {"operation": "READ_SNAPSHOT", "transition_kind": None},
        ):
            env = self.envelope(claim_override=change)
            with self.subTest(change=change):
                result = self.review(envelope=env)
                self.assertEqual(result["status"], "QUARANTINED_SYNTHETIC_ACK_REQUEST_MISMATCH")
                self.assert_no_authority(result)

    def test_wrong_applied_epoch_or_digest_quarantined(self):
        for change in (
            {"claimed_epoch": 8}, {"claimed_epoch": 10},
            {"claimed_commitment": "e"*64}, {"claimed_status": "SNAPSHOT"},
        ):
            env = self.envelope(claim_override=change)
            with self.subTest(change=change):
                result = self.review(envelope=env)
                self.assertEqual(result["status"], "QUARANTINED_SYNTHETIC_ADVANCE_STATE_MISMATCH")
                self.assert_no_authority(result)

    def test_read_with_claimed_mutation_quarantined(self):
        req = request(operation="READ_SNAPSHOT")
        env = self.envelope(req=req, claim_override={"claimed_epoch": 9})
        result = self.review(req=req, envelope=env)
        self.assertEqual(result["status"], "QUARANTINED_SYNTHETIC_READ_STATE_MISMATCH")
        self.assert_no_authority(result)

    def test_signed_provider_denial_cannot_authorize_retry(self):
        env = self.envelope(claim_override={"claimed_status": "DENIED"})
        out = self.review(envelope=env)
        self.assertEqual(out["status"], "BLOCKED_PROVIDER_REPORTED_DENIAL_NO_RETRY_AUTHORITY")
        self.assert_no_authority(out)

    def test_recovery_always_requires_owner_review(self):
        req = request(transition="RECOVER")
        env = self.envelope(req=req, claim_override={"claimed_status": "RECOVERY_REVIEW_REQUIRED"})
        out = self.review(req=req, envelope=env)
        self.assertEqual(out["status"], "SYNTHETIC_RECOVERY_HUMAN_REVIEW_REQUIRED")
        self.assert_no_authority(out)

    def test_recovery_report_on_normal_operation_quarantined(self):
        env = self.envelope(claim_override={"claimed_status": "RECOVERY_REVIEW_REQUIRED"})
        out = self.review(envelope=env)
        self.assertEqual(out["status"], "QUARANTINED_SYNTHETIC_RECOVERY_SCOPE_MISMATCH")
        self.assert_no_authority(out)

    def test_recover_marked_applied_never_auto_finalized(self):
        req = request(transition="RECOVER")
        out = self.review(req=req)
        self.assertEqual(out["status"], "QUARANTINED_SYNTHETIC_ADVANCE_STATE_MISMATCH")
        self.assert_no_authority(out)

    def test_missing_or_extra_claim_envelope_fields_denied(self):
        base = self.envelope()
        for key in tuple(base):
            obj = deepcopy(base)
            obj.pop(key)
            with self.subTest(missing_envelope=key), self.assertRaises(PolicyBlocked):
                self.review(envelope=obj)
        for key in tuple(base["claim"]):
            obj = deepcopy(base)
            obj["claim"].pop(key)
            with self.subTest(missing_claim=key), self.assertRaises(PolicyBlocked):
                self.review(envelope=obj)
        for extra in ("owner_approved", "trusted", "execute_task", "provider_confirmed"):
            obj = deepcopy(base)
            obj["claim"][extra] = True
            with self.subTest(extra=extra), self.assertRaises(PolicyBlocked):
                self.review(envelope=obj)

    def test_invalid_unhashable_types_fail_policy(self):
        for key, value in (
            ("provider_kind", []), ("operation", {}), ("transition_kind", []),
            ("claimed_status", None), ("claimed_epoch", True),
            ("request_id", ["a"]), ("witness_id", 4),
            ("issued_at_epoch_s", "1800000000"),
            ("expires_at_epoch_s", -1),
        ):
            obj = self.envelope()
            obj["claim"][key] = value
            with self.subTest(field=key), self.assertRaises(PolicyBlocked):
                self.review(envelope=obj)
        for bad_pin in (True, "", [], "f"*63):
            with self.subTest(pin=type(bad_pin).__name__), self.assertRaises(PolicyBlocked):
                self.review(pin=bad_pin)

    def test_status_is_deterministic_no_input_mutation(self):
        env, req = self.envelope(), request()
        before = deepcopy((env, req))
        first = self.review(req=req, envelope=env)
        second = self.review(req=req, envelope=env)
        self.assertEqual(first, second)
        self.assertEqual((env, req), before)
        self.assert_no_authority(first)

    def test_no_real_provider_control_entrypoints(self):
        import upab.relay.v3_stage45_provider_ack_review as mod
        for method in ("execute", "connect_provider", "write_tpm_nv",
                       "issue_approval", "enroll_owner", "set_trust_root",
                       "finalize_recovery", "start_monitor", "run_task"):
            self.assertFalse(hasattr(mod, method))
