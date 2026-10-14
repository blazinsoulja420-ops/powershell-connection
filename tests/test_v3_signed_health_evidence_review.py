from __future__ import annotations

from copy import deepcopy
import hashlib
import json
from pathlib import Path
import sys
import unittest
from unittest import mock

from upab.relay.v3_policy import PolicyBlocked
from upab.relay.v3_signed_health_evidence_review import (
    CLAIM_SCHEMA, DOMAIN, ENVELOPE_SCHEMA, SCHEMA, canonical_health_claim,
    review_signed_health_batch,
)

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
except ImportError:
    Ed25519PrivateKey = None

ROOT = Path(__file__).resolve().parents[1]
CONFIG = ROOT / "config" / "watcher-v3-owner-selected-portfolio.example.json"
NOW = 1_800_000_000


def portfolio():
    return json.loads(CONFIG.read_text(encoding="utf-8"))


def claim(repo="Universal-AI-", *, module=None, condition="OK",
          when=NOW, sequence=1, source="GITHUB_CI"):
    return {
        "schema": CLAIM_SCHEMA,
        "repository": repo,
        "module_id": module,
        "condition": condition,
        "observed_at_epoch_s": when,
        "sequence": sequence,
        "source_kind": source,
    }


def signing_key():
    private = Ed25519PrivateKey.generate()  # Ephemeral CI fixture ONLY
    public = private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return private, public


def envelope(item, private=None, public=None, domain=DOMAIN):
    if private is None:
        private, public = signing_key()
    if public is None:
        public = private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return {
        "schema": ENVELOPE_SCHEMA,
        "claim": item,
        "public_key_hex": public.hex(),
        "public_key_sha256": hashlib.sha256(public).hexdigest(),
        "signature_hex": private.sign(domain + canonical_health_claim(item)).hex(),
    }


def review(items, *, now=NOW, max_age=300, config=None):
    return review_signed_health_batch(
        portfolio=portfolio() if config is None else config,
        envelopes=items, now_epoch_s=now, max_age_s=max_age,
    )


class Stage36NoEvidenceTests(unittest.TestCase):
    def test_empty_evidence_remains_unknown_and_non_authorizing(self):
        result = review([])
        self.assertEqual(result["schema"], SCHEMA)
        self.assertEqual(result["signature_consistent_untrusted_observations"], 0)
        self.assertEqual(result["missing_project_observations_unknown"], 9)
        self.assertEqual(result["missing_module_observations_unknown"], 19)
        self.assertEqual(result["unknown_total"], 28)
        for key in (
            "signer_keys_independently_enrolled",
            "signed_claim_origins_authenticated",
            "replay_protected_across_batches",
            "last_accepted_sequences_protected",
            "github_ci_authenticity_verified",
            "windows_observer_identity_verified",
            "publisher_owner_authenticated",
            "live_monitoring_enabled",
            "task_execution_authorized",
            "settings_changed",
        ):
            self.assertFalse(result[key])

    def test_bad_empty_batch_clock_and_portfolio_rejected(self):
        with self.assertRaises(PolicyBlocked):
            review([], now=True)
        with self.assertRaises(PolicyBlocked):
            review([], max_age=0)
        wrong = portfolio()
        wrong["projects"].append({"repository":"online-store"})
        with self.assertRaises(PolicyBlocked):
            review([], config=wrong)

    def test_no_exec_or_network_api(self):
        import upab.relay.v3_signed_health_evidence_review as module
        for name in ("execute_task", "activate", "install", "start_watcher",
                     "fetch_github", "watch_path", "create_chat", "register_key",
                     "store_sequence", "monitor_repo", "connect_repo"):
            self.assertFalse(hasattr(module, name))


@unittest.skipIf(Ed25519PrivateKey is None, "Optional cryptography backend absent")
class Stage36RealCryptographicReviewTests(unittest.TestCase):
    def test_valid_real_signature_remains_untrusted_not_healthy(self):
        item = envelope(claim())
        original = deepcopy(item)
        result = review([item])
        self.assertEqual(result["status"], "SIGNATURE_CONSISTENCY_ONLY_UNTRUSTED_SIGNER")
        self.assertEqual(result["signature_consistent_untrusted_observations"], 1)
        self.assertEqual(result["fresh_unverified_ok"], 1)
        self.assertEqual(result["verified_healthy_projects"], 0)
        self.assertEqual(result["verified_healthy_modules"], 0)
        self.assertEqual(result["unknown_total"], 27)
        self.assertFalse(result["github_ci_authenticity_verified"])
        self.assertFalse(result["task_execution_authorized"])
        self.assertEqual(item, original)
        dumped = json.dumps(result)
        for secret in (item["signature_hex"],item["public_key_hex"],
                       item["public_key_sha256"],"Universal-AI-", "online-store"):
            self.assertNotIn(secret, dumped)

    def test_poindexter_modules_are_nested_not_extra_repositories(self):
        item = envelope(claim("UP-UHAIB-001-Poindexter",module="019",
                              source="LOCAL_WATCHER"))
        result = review([item])
        self.assertEqual(result["selected_repository_count"], 9)
        self.assertEqual(result["nested_poindexter_module_count"], 19)
        self.assertEqual(result["missing_project_observations_unknown"], 9)
        self.assertEqual(result["missing_module_observations_unknown"], 18)
        self.assertEqual(result["fresh_unverified_ok"], 1)
        self.assertFalse(result["windows_observer_identity_verified"])

    def test_tampered_claim_and_wrong_signer_denied(self):
        for field, replacement in (
            ("condition","ALERT"), ("sequence",2),
            ("observed_at_epoch_s",NOW-1),
            ("source_kind","LOCAL_WATCHER"),
            ("repository","NSFW"),
        ):
            item=envelope(claim())
            item["claim"][field]=replacement
            with self.subTest(field=field):
                with self.assertRaises(PolicyBlocked):
                    review([item])
        item=envelope(claim())
        _, second_pub=signing_key()
        item["public_key_hex"]=second_pub.hex()
        item["public_key_sha256"]=hashlib.sha256(second_pub).hexdigest()
        with self.assertRaises(PolicyBlocked):
            review([item])

    def test_wrong_domain_and_signature_pinning_denied(self):
        item=envelope(claim(),domain=b"WRONG_DOMAIN\0")
        with self.assertRaises(PolicyBlocked):
            review([item])
        item=envelope(claim())
        item["public_key_sha256"]="0"*64
        with self.assertRaises(PolicyBlocked):
            review([item])
        item=envelope(claim())
        item["signature_hex"]="0"*128
        with self.assertRaises(PolicyBlocked):
            review([item])

    def test_duplicate_replay_within_batch_denied_not_double_counted(self):
        item=envelope(claim())
        duplicate=envelope(claim(sequence=2))
        with self.assertRaises(PolicyBlocked):
            review([item,duplicate])
        with self.assertRaises(PolicyBlocked):
            review([item,item])

    def test_expired_signed_ok_does_not_become_healthy(self):
        old=envelope(claim(when=NOW-301))
        result=review([old])
        self.assertEqual(result["stale_unknown"],1)
        self.assertEqual(result["fresh_unverified_ok"],0)
        self.assertEqual(result["verified_healthy_projects"],0)
        self.assertEqual(result["unknown_total"],28)

    def test_signatures_cannot_claim_actual_ci_or_owner_auth(self):
        for attr,value in (
            ("owner_authenticated",True),("windows_hello",True),
            ("command","cmd /c start"),("path","C:\\private"),
            ("source_url","https://example.com"),("verified",True),
        ):
            item=claim()
            item[attr]=value
            with self.subTest(attr=attr):
                with self.assertRaises(PolicyBlocked):
                    envelope(item)

    def test_online_store_and_unknown_repositories_rejected(self):
        for repo in ("online-store","School.tutor","RAID-AI","UnknownRepo"):
            with self.subTest(repo=repo):
                with self.assertRaises(PolicyBlocked):
                    envelope(claim(repo))

    def test_unsupported_nested_module_and_source_type_denied(self):
        for item in (
            claim("Universal-AI-",module="001",source="LOCAL_WATCHER"),
            claim("UP-UHAIB-001-Poindexter",module="020",source="LOCAL_WATCHER"),
            claim("UP-UHAIB-001-Poindexter",module="001",source="GITHUB_CI"),
            claim("UP-UHAIB-001-Poindexter",module=True,source="LOCAL_WATCHER"),
            claim(source="REMOTE_PRIVILEGED"),
        ):
            with self.subTest(item=str(item)[:80]):
                with self.assertRaises(PolicyBlocked):
                    envelope(item)

    def test_invalid_types_and_future_timestamp_are_denied(self):
        for field,value in (
            ("observed_at_epoch_s",True),("observed_at_epoch_s",-1),
            ("observed_at_epoch_s",NOW+1),("sequence",0),
            ("sequence",True),("sequence",2**53),
            ("condition","HEALTHY_VERIFIED"),("module_id",1),
        ):
            item=claim()
            item[field]=value
            with self.subTest(field=field,value=value):
                if field=="observed_at_epoch_s" and value==NOW+1:
                    with self.assertRaises(PolicyBlocked):
                        review([envelope(item)])
                else:
                    with self.assertRaises(PolicyBlocked):
                        envelope(item)

    def test_malformed_envelopes_fail_closed(self):
        item=envelope(claim())
        examples=[
            {**item,"approved":True},
            {**item,"schema":"forged"},
            {**item,"public_key_hex":"A"*64},
            {**item,"signature_hex":True},
            {**item,"signature_hex":"0"*127},
            {**item,"claim":{"schema":CLAIM_SCHEMA}},
            "all",
            None,
        ]
        for bad in examples:
            with self.subTest(bad=str(bad)[:80]):
                with self.assertRaises(PolicyBlocked):
                    review([bad])

    def test_batch_max_and_portfolio_tampering_denied(self):
        items=[envelope(claim("Universal-AI-")) for _ in range(29)]
        with self.assertRaises(PolicyBlocked):
            review(items)
        source=portfolio()
        source["projects"][0]["monitor_enabled"]=True
        with self.assertRaises(PolicyBlocked):
            review([envelope(claim())],config=source)

    def test_missing_crypto_backend_denies_signed_receipts(self):
        item=envelope(claim())
        with mock.patch.dict(sys.modules,{
            "cryptography.exceptions":None,
            "cryptography.hazmat.primitives.asymmetric.ed25519":None,
        }):
            with self.assertRaises(PolicyBlocked):
                review([item])


if __name__=="__main__":
    unittest.main()
