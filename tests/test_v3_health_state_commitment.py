"""Stage 39: synthetically anchored state-digest tampering and quarantine tests.

These tests DO NOT establish trusted storage or anti-rollback protection.
"""
from __future__ import annotations

from contextlib import closing
import hashlib
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest

from upab.relay.v3_policy import PolicyBlocked
from upab.relay.v3_synthetic_health_ledger import (
    FakeMonotonicWitness, SimulatedInterruption, SyntheticHealthLedger,
)
from upab.relay.v3_signed_health_evidence_review import (
    CLAIM_SCHEMA, DOMAIN, ENVELOPE_SCHEMA, canonical_health_claim,
)

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
except ImportError:
    Ed25519PrivateKey = None

NOW = 1_800_000_000
PORTFOLIO = (Path(__file__).resolve().parents[1] /
             "config" / "watcher-v3-owner-selected-portfolio.example.json")
SCOPE = "Universal-AI-:-"


@unittest.skipIf(Ed25519PrivateKey is None, "optional maintained crypto backend unavailable")
class Stage39StateCommitmentTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="upab-v3-lab-")
        self.addCleanup(self.temp.cleanup)
        self.witness = FakeMonotonicWitness()
        self.ledger = SyntheticHealthLedger(self.temp.name, witness=self.witness)
        self.key = Ed25519PrivateKey.generate()
        pub = self.key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        self.pin = hashlib.sha256(pub).hexdigest()
        self.public_hex = pub.hex()
        self.portfolio = json.loads(PORTFOLIO.read_text(encoding="utf-8"))
        self.ledger.seed_fixture(
            enrollment_id="fixture-stage39", fingerprint=self.pin,
            repository="Universal-AI-", module_id=None,
            source_kind="GITHUB_CI", initial_sequence=1,
            initial_when=NOW-30, valid_from=NOW-500, valid_until=NOW+500,
        )

    def signed(self, sequence=2):
        claim = {
            "schema": CLAIM_SCHEMA, "repository": "Universal-AI-",
            "module_id": None, "condition": "OK",
            "observed_at_epoch_s": NOW, "sequence": sequence,
            "source_kind": "GITHUB_CI",
        }
        return {
            "schema": ENVELOPE_SCHEMA, "claim": claim,
            "public_key_hex": self.public_hex, "public_key_sha256": self.pin,
            "signature_hex": self.key.sign(DOMAIN + canonical_health_claim(claim)).hex(),
        }

    def accept(self, sequence=2, **kwargs):
        return self.ledger.accept_fixture(
            portfolio=self.portfolio, envelope=self.signed(sequence),
            now_epoch_s=NOW, **kwargs,
        )

    def edit(self, sql, params=()):
        with closing(sqlite3.connect(self.ledger.path)) as db:
            db.execute(sql, params)
            db.commit()

    def blocked_and_quarantined(self):
        with self.assertRaises(PolicyBlocked):
            self.accept()
        result = self.ledger.recover_fixture()
        self.assertEqual(result["quarantined_count"], 1)
        self.assertIs(result["rollback_resistance_verified"], False)
        self.assertIs(result["task_execution_authorized"], False)

    def test_ready_commitment_changes_when_observation_accepted(self):
        before = self.witness.commitment_snapshot()
        report = self.accept()
        after = self.witness.commitment_snapshot()
        self.assertNotEqual(before[2], after[2])
        self.assertEqual((before[1], after[1]), (0, 1))
        self.assertFalse(report["trusted_collector_authenticated"])
        self.assertFalse(report["hardware_monotonic_store_verified"])
        self.assertEqual(self.ledger.recover_fixture()["status"],
                         "SYNTHETIC_LEDGER_READY_NOT_AUTHENTICATED")

    def test_modify_prior_sequence_recompute_row_hash_same_epoch_denied(self):
        digest = self.ledger._digest(SCOPE, 50, NOW-20, 0)
        self.edit("UPDATE sequences SET last_sequence=50,last_when=?,digest=? "
                  "WHERE scope=?", (NOW-20, digest, SCOPE))
        self.blocked_and_quarantined()

    def test_modify_collector_pin_same_epoch_denied(self):
        self.edit("UPDATE collectors SET fingerprint=? WHERE scope=?",
                  ("0"*64, SCOPE))
        self.blocked_and_quarantined()

    def test_modify_collector_expiry_same_epoch_denied(self):
        self.edit("UPDATE collectors SET valid_until=? WHERE scope=?",
                  (NOW+5000, SCOPE))
        self.blocked_and_quarantined()

    def test_modify_collector_source_same_epoch_denied(self):
        self.edit("UPDATE collectors SET source_kind='LOCAL_WATCHER' WHERE scope=?",
                  (SCOPE,))
        self.blocked_and_quarantined()

    def test_modify_enrollment_identifier_same_epoch_denied(self):
        self.edit("UPDATE collectors SET enrollment_id='counterfeit' WHERE scope=?",
                  (SCOPE,))
        self.blocked_and_quarantined()

    def test_delete_prior_history_same_epoch_denied(self):
        self.edit("DELETE FROM sequences WHERE scope=?", (SCOPE,))
        self.blocked_and_quarantined()

    def test_insert_forged_scoped_registration_same_epoch_denied(self):
        self.edit("INSERT INTO collectors VALUES (?,?,?,?,?,?,?)",
                  ("Kali-Linux-:-", "rogue-fixture", "a"*64, "GITHUB_CI",
                   "ENROLLED", NOW-500, NOW+500))
        self.blocked_and_quarantined()

    def test_trigger_added_to_database_schema_denied(self):
        self.edit("CREATE TRIGGER rogue AFTER UPDATE ON collectors "
                  "BEGIN SELECT 1; END")
        self.blocked_and_quarantined()

    def test_revocation_reseal_is_explicitly_insecure_test_only(self):
        start = self.witness.commitment_snapshot()
        result = self.ledger.revoke_fixture(
            repository="Universal-AI-", module_id=None)
        self.assertEqual(self.witness.snapshot()[1], 0)
        self.assertNotEqual(self.witness.commitment_snapshot()[2], start[2])
        self.assertFalse(result["trusted_collector_authenticated"])
        with self.assertRaises(PolicyBlocked):
            self.accept()

    def test_restored_pre_revocation_snapshot_denied_same_epoch(self):
        backup = Path(self.temp.name) / "stage39-backup.sqlite3"
        with closing(sqlite3.connect(self.ledger.path)) as orig, closing(
                sqlite3.connect(backup)) as target:
            orig.backup(target)
        self.ledger.revoke_fixture(repository="Universal-AI-", module_id=None)
        with closing(sqlite3.connect(backup)) as source, closing(
                sqlite3.connect(self.ledger.path)) as target:
            source.backup(target)
        self.blocked_and_quarantined()

    def test_manually_unrevoke_with_same_epoch_is_denied(self):
        self.ledger.revoke_fixture(repository="Universal-AI-", module_id=None)
        self.edit("UPDATE collectors SET state='ENROLLED' WHERE scope=?", (SCOPE,))
        self.blocked_and_quarantined()

    def test_manually_clear_gap_quarantine_status_is_denied(self):
        self.assertEqual(self.accept(8)["quarantined_count"], 1)
        self.assertTrue(self.witness.is_quarantined())
        self.edit("UPDATE meta SET phase='READY' WHERE id=1")
        with self.assertRaises(PolicyBlocked):
            self.accept()
        self.assertEqual(self.ledger.recover_fixture()["quarantined_count"], 1)

    def test_manually_clear_uncertain_recovery_quarantine_is_denied(self):
        with self.assertRaises(SimulatedInterruption):
            self.accept(interrupt_at="after_prepare")
        self.assertEqual(self.ledger.recover_fixture()["quarantined_count"], 1)
        self.edit("DELETE FROM pending")
        self.edit("UPDATE meta SET phase='READY' WHERE id=1")
        with self.assertRaises(PolicyBlocked):
            self.accept()
        self.assertEqual(self.ledger.recover_fixture()["quarantined_count"], 1)

    def test_tamper_during_post_anchor_recovery_is_denied(self):
        with self.assertRaises(SimulatedInterruption):
            self.accept(interrupt_at="after_anchor")
        self.edit("UPDATE collectors SET state='REVOKED' WHERE scope=?", (SCOPE,))
        with self.assertRaises(PolicyBlocked):
            self.ledger.recover_fixture()
        with self.assertRaises(PolicyBlocked):
            self.accept()

    def test_in_memory_witness_is_not_protected_persistent_hardware(self):
        self.assertFalse(self.witness.is_quarantined())
        # This fixture cannot verify Windows/TPM continuity across reboot:
        second = FakeMonotonicWitness()
        self.assertEqual(second.snapshot(), (None, 0))
        self.assertIsNone(second.commitment_snapshot()[2])
        with self.assertRaises(PolicyBlocked):
            SyntheticHealthLedger(self.temp.name, witness=second)

    def test_untrusted_witness_digest_change_does_not_grant_authority(self):
        self.witness._commitment = "0"*64  # explicitly hostile test-double rewrite
        with self.assertRaises(PolicyBlocked):
            self.accept()
        self.assertEqual(self.ledger.recover_fixture()["quarantined_count"], 1)
