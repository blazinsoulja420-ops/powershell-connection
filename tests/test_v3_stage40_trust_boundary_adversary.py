"""Stage 40: independent adversarial trust-boundary tests for the Stage 39 LAB.

These deliberately show what still breaks when BOTH the local SQLite state
and the *fake* in-memory witness are adversary-controlled. A successful
synthetic acceptance is not proof of real monitoring, authenticated GitHub
origin, TPM rollback protection, safe production key custody, or owner consent.
Never run these synthetic tests on an owner's actual watcher state.
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
    FakeMonotonicWitness, SyntheticHealthLedger,
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
ROOT = Path(__file__).resolve().parents[1]
PORTFOLIO = ROOT / "config" / "watcher-v3-owner-selected-portfolio.example.json"


@unittest.skipIf(Ed25519PrivateKey is None, "optional synthetic signing backend absent")
class Stage40TrustBoundaryAdversaryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="upab-v3-lab-")
        self.addCleanup(self.temp.cleanup)
        self.witness = FakeMonotonicWitness()
        self.ledger = SyntheticHealthLedger(self.temp.name, witness=self.witness)
        self.key = Ed25519PrivateKey.generate()  # throwaway LAB key, not an owner key
        pub = self.key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        self.pub = pub.hex()
        self.pin = hashlib.sha256(pub).hexdigest()
        self.portfolio = json.loads(PORTFOLIO.read_text(encoding="utf-8"))
        self.ledger.seed_fixture(
            enrollment_id="untrusted-lab-collector", fingerprint=self.pin,
            repository="Universal-AI-", module_id=None, source_kind="GITHUB_CI",
            initial_sequence=1, initial_when=NOW-30,
            valid_from=NOW-200, valid_until=NOW+200,
        )

    def envelope(self, sequence=2):
        claim = {
            "schema": CLAIM_SCHEMA,
            "repository": "Universal-AI-",
            "module_id": None,
            "condition": "OK",
            "observed_at_epoch_s": NOW,
            "sequence": sequence,
            "source_kind": "GITHUB_CI",
        }
        return {
            "schema": ENVELOPE_SCHEMA,
            "claim": claim,
            "public_key_hex": self.pub,
            "public_key_sha256": self.pin,
            "signature_hex": self.key.sign(
                DOMAIN + canonical_health_claim(claim)
            ).hex(),
        }

    def accept(self, envelope=None):
        return self.ledger.accept_fixture(
            portfolio=self.portfolio,
            envelope=self.envelope() if envelope is None else envelope,
            now_epoch_s=NOW,
        )

    def snapshot_database(self, name):
        path = Path(self.temp.name) / name
        with closing(sqlite3.connect(self.ledger.path)) as source:
            with closing(sqlite3.connect(path)) as target:
                source.backup(target)
        return path

    def restore_database(self, path):
        with closing(sqlite3.connect(path)) as source:
            with closing(sqlite3.connect(self.ledger.path)) as target:
                source.backup(target)

    def assert_no_operational_authority(self, receipt):
        for field in (
            "trusted_collector_authenticated", "rollback_resistance_verified",
            "hardware_monotonic_store_verified", "operational_health_verified",
            "owner_authenticated", "real_monitoring_enabled",
            "task_execution_authorized", "project_roster_modified"
        ):
            self.assertIs(receipt[field], False, field)
        output = json.dumps(receipt)
        self.assertNotIn(self.pin, output)
        self.assertNotIn(self.pub, output)
        self.assertNotIn(self.temp.name, output)
        self.assertNotIn("online-store", output)

    def test_single_resource_rollback_is_detected_with_witness_intact(self):
        backup = self.snapshot_database("prior-db.sqlite3")
        self.assertEqual(self.accept()["accepted_count"], 1)
        self.restore_database(backup)
        self.assertEqual(self.ledger.recover_fixture()["quarantined_count"], 1)
        with self.assertRaises(PolicyBlocked):
            self.accept()

    def test_paired_sqlite_and_fake_witness_rollback_can_reaccept_signed_claim(self):
        """DEMONSTRATES INSECURITY: process-local witness is not a trust anchor."""
        stale = self.snapshot_database("old-state.sqlite3")
        earlier_id, earlier_epoch, earlier_commitment = (
            self.witness.commitment_snapshot())
        signed = self.envelope()
        first = self.accept(envelope=signed)
        self.assert_no_operational_authority(first)
        self.assertEqual(self.witness.snapshot()[1], 1)

        # A lab attacker controls both the DB bytes and *fake* witness memory.
        # No real Windows state, hardware, keys or services are touched.
        self.restore_database(stale)
        with self.witness._lock:
            self.witness._identity = earlier_id
            self.witness._epoch = earlier_epoch
            self.witness._commitment = earlier_commitment
            self.witness._quarantined = False

        self.assertEqual(
            self.ledger.recover_fixture()["status"],
            "SYNTHETIC_LEDGER_READY_NOT_AUTHENTICATED"
        )
        second = self.accept(envelope=signed)
        self.assertEqual(second["accepted_count"], 1,
                         "known fake-witness paired rollback limitation changed")
        self.assert_no_operational_authority(second)
        self.assertEqual(self.witness.snapshot()[1], 1)

    def test_paired_revocation_and_fake_witness_rollback_can_restore_lab_key(self):
        """DEMONSTRATES INSECURITY: same-epoch lab revocation is reversible."""
        before = self.snapshot_database("before-revoke.sqlite3")
        older = self.witness.commitment_snapshot()
        revoke = self.ledger.revoke_fixture(
            repository="Universal-AI-", module_id=None
        )
        self.assert_no_operational_authority(revoke)
        with self.assertRaises(PolicyBlocked):
            self.accept()

        self.restore_database(before)
        with self.witness._lock:
            self.witness._identity, self.witness._epoch, self.witness._commitment = older
            self.witness._quarantined = False
        recovered = self.ledger.recover_fixture()
        self.assert_no_operational_authority(recovered)
        self.assertEqual(recovered["status"],
                         "SYNTHETIC_LEDGER_READY_NOT_AUTHENTICATED")
        accepted = self.accept()
        self.assertEqual(accepted["accepted_count"], 1)
        self.assert_no_operational_authority(accepted)

    def test_fake_source_kind_and_valid_signature_are_not_origin_attestation(self):
        """Signature from a test caller can pretend to be GITHUB_CI."""
        receipt = self.accept()
        self.assertEqual(receipt["accepted_count"], 1)
        self.assert_no_operational_authority(receipt)
        # The assertion above must never imply an external Actions job was read,
        # an actual release was checked, or a collector key was truly enrolled.
        self.assertEqual(self.portfolio["connections"], [])
        self.assertNotIn(
            "online-store",
            [p["repository"] for p in self.portfolio["projects"]],
        )

    def test_witness_process_loss_refuses_to_infer_safe_restart(self):
        self.accept()
        replacement = FakeMonotonicWitness()
        with self.assertRaises(PolicyBlocked):
            SyntheticHealthLedger(self.temp.name, witness=replacement)
        # The lost state is not silently recovered from the local DB alone.
        self.assertEqual(replacement.snapshot(), (None, 0))

    def test_no_production_activation_or_privileged_methods(self):
        import upab.relay.v3_synthetic_health_ledger as ledger_module
        for name in (
            "start_monitor", "run_task", "install_service", "enroll_owner",
            "register_publisher_key", "enable_watcher", "tpm_nv_increment",
            "enable_paid_api", "connect_project",
        ):
            self.assertFalse(hasattr(ledger_module, name))


if __name__ == "__main__":
    unittest.main()
