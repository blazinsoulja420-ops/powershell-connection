"""Stage 38: disposable fake-witness failure, replay and scope tests."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
import hashlib
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest

from upab.relay.v3_policy import PolicyBlocked
from upab.relay.v3_synthetic_health_ledger import (
    FakeMonotonicWitness, SyntheticHealthLedger, SimulatedInterruption,
)
from upab.relay.v3_signed_health_evidence_review import (
    DOMAIN, ENVELOPE_SCHEMA, CLAIM_SCHEMA, canonical_health_claim,
)

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
except ImportError:
    Ed25519PrivateKey = None

ROOT = Path(__file__).resolve().parents[1]
NOW = 1_800_000_000
PORTFOLIO = ROOT / "config" / "watcher-v3-owner-selected-portfolio.example.json"


@unittest.skipIf(Ed25519PrivateKey is None, "maintained test signing backend unavailable")
class Stage38SyntheticLedgerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="upab-v3-lab-")
        self.addCleanup(self.temp.cleanup)
        self.anchor = FakeMonotonicWitness()
        self.ledger = SyntheticHealthLedger(self.temp.name, witness=self.anchor)
        self.key = Ed25519PrivateKey.generate()
        self.public = self.key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        self.fingerprint = hashlib.sha256(self.public).hexdigest()
        self.portfolio = json.loads(PORTFOLIO.read_text(encoding="utf-8"))
        self.ledger.seed_fixture(
            enrollment_id="fixture-001", fingerprint=self.fingerprint,
            repository="Universal-AI-", module_id=None, source_kind="GITHUB_CI",
            initial_sequence=1, initial_when=NOW-30,
            valid_from=NOW-1000, valid_until=NOW+1000,
        )

    def envelope(self, *, seq=2, when=NOW, repository="Universal-AI-", module=None,
                 source="GITHUB_CI", key=None):
        key = key or self.key
        public = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        claim = {
            "schema": CLAIM_SCHEMA, "repository": repository, "module_id": module,
            "condition": "OK", "observed_at_epoch_s": when,
            "sequence": seq, "source_kind": source,
        }
        return {
            "schema": ENVELOPE_SCHEMA, "claim": claim,
            "public_key_hex": public.hex(),
            "public_key_sha256": hashlib.sha256(public).hexdigest(),
            "signature_hex": key.sign(DOMAIN + canonical_health_claim(claim)).hex(),
        }

    def accept(self, *, seq=2, envelope=None, **kwargs):
        return self.ledger.accept_fixture(
            portfolio=self.portfolio, envelope=envelope or self.envelope(seq=seq),
            now_epoch_s=NOW, **kwargs,
        )

    def assert_untrusted(self, result):
        for key in ("trusted_collector_authenticated", "rollback_resistance_verified",
                    "hardware_monotonic_store_verified", "operational_health_verified",
                    "owner_authenticated", "real_monitoring_enabled",
                    "task_execution_authorized", "project_roster_modified"):
            self.assertIs(result[key], False)
        rendered = json.dumps(result)
        for token in (self.fingerprint, self.public.hex(), self.temp.name,
                      "Universal-AI-", "online-store"):
            self.assertNotIn(token, rendered)

    def test_normal_accept_exact_one_then_replay_rejected(self):
        result = self.accept()
        self.assertEqual(result["accepted_count"], 1)
        self.assert_untrusted(result)
        self.assertEqual(self.anchor.snapshot()[1], 1)
        with self.assertRaises(PolicyBlocked):
            self.accept()
        self.assertEqual(self.anchor.snapshot()[1], 1)
        self.assertEqual(self.ledger.recover_fixture()["status"],
                         "SYNTHETIC_LEDGER_READY_NOT_AUTHENTICATED")

    def test_before_prepare_simulated_crash_does_not_advance(self):
        with self.assertRaises(SimulatedInterruption):
            self.accept(interrupt_at="before_prepare")
        self.assertEqual(self.anchor.snapshot()[1], 0)
        self.assertEqual(self.ledger.recover_fixture()["status"],
                         "SYNTHETIC_LEDGER_READY_NOT_AUTHENTICATED")
        self.assertEqual(self.accept()["accepted_count"], 1)

    def test_crash_after_prepare_with_no_anchor_quarantines(self):
        with self.assertRaises(SimulatedInterruption):
            self.accept(interrupt_at="after_prepare")
        self.assertEqual(self.anchor.snapshot()[1], 0)
        self.assertEqual(self.ledger.recover_fixture()["quarantined_count"], 1)
        with self.assertRaises(PolicyBlocked):
            self.accept()

    def test_crash_after_anchor_recovers_only_matching_pending(self):
        with self.assertRaises(SimulatedInterruption):
            self.accept(interrupt_at="after_anchor")
        recovered = SyntheticHealthLedger(self.temp.name, witness=self.anchor)
        self.assertEqual(recovered.recover_fixture()["status"],
                         "SYNTHETIC_INTERRUPTED_COMMIT_RECOVERED")
        self.assertEqual(self.anchor.snapshot()[1], 1)
        with self.assertRaises(PolicyBlocked):
            self.accept()

    def test_crash_after_finalization_remains_single_use(self):
        with self.assertRaises(SimulatedInterruption):
            self.accept(interrupt_at="after_finalize")
        self.assertEqual(self.ledger.recover_fixture()["status"],
                         "SYNTHETIC_LEDGER_READY_NOT_AUTHENTICATED")
        with self.assertRaises(PolicyBlocked):
            self.accept()

    def test_witness_advance_failure_keeps_pending_and_fails_closed(self):
        self.anchor.fail_next_advance = True
        with self.assertRaises(PolicyBlocked):
            self.accept()
        self.assertEqual(self.ledger.recover_fixture()["quarantined_count"], 1)
        with self.assertRaises(PolicyBlocked):
            self.accept()

    def test_database_rollback_with_independent_fake_witness_detected(self):
        backup_path = Path(self.temp.name) / "snapshot.sqlite3"
        with closing(sqlite3.connect(self.ledger.path)) as source, closing(sqlite3.connect(backup_path)) as dest:
            source.backup(dest)
        self.accept()
        self.assertEqual(self.anchor.snapshot()[1], 1)
        with closing(sqlite3.connect(backup_path)) as source, closing(sqlite3.connect(self.ledger.path)) as dest:
            source.backup(dest)
        reopened = SyntheticHealthLedger(self.temp.name, witness=self.anchor)
        self.assertEqual(reopened.recover_fixture()["quarantined_count"], 1)
        with self.assertRaises(PolicyBlocked):
            reopened.accept_fixture(portfolio=self.portfolio, envelope=self.envelope(),
                                    now_epoch_s=NOW)

    def test_missing_ledger_with_bound_witness_denied(self):
        self.accept()
        self.ledger.path.unlink()
        with self.assertRaises(PolicyBlocked):
            SyntheticHealthLedger(self.temp.name, witness=self.anchor)

    def test_valid_fresh_new_signer_is_not_fixture_enrolled(self):
        unknown = Ed25519PrivateKey.generate()
        with self.assertRaises(PolicyBlocked):
            self.accept(envelope=self.envelope(key=unknown))

    def test_revoke_different_source_and_expiry_rejected(self):
        with self.assertRaises(PolicyBlocked):
            self.accept(envelope=self.envelope(source="LOCAL_WATCHER"))
        self.ledger.revoke_fixture(repository="Universal-AI-", module_id=None)
        with self.assertRaises(PolicyBlocked):
            self.accept()

    def test_replay_timestamp_and_scope_denied(self):
        for env in (
            self.envelope(seq=1), self.envelope(seq=2, when=NOW-40),
            self.envelope(seq=2, repository="UP-UHAIB-001-Poindexter"),
        ):
            with self.subTest(env=env["claim"]):
                with self.assertRaises(PolicyBlocked):
                    self.accept(envelope=env)
        with self.assertRaises(PolicyBlocked):
            self.envelope(seq=2, repository="online-store")
        with self.assertRaises(PolicyBlocked):
            self.envelope(seq=2, repository="Universal-AI-", module="019")
        self.assertEqual(self.anchor.snapshot()[1], 0)

    def test_sequence_gap_quarantines_but_no_witness_advance(self):
        result = self.accept(seq=6)
        self.assertEqual(result["quarantined_count"], 1)
        self.assert_untrusted(result)
        self.assertEqual(self.anchor.snapshot()[1], 0)
        with self.assertRaises(PolicyBlocked):
            self.accept()

    def test_wrong_pending_digest_recovery_fails_closed(self):
        with self.assertRaises(SimulatedInterruption):
            self.accept(interrupt_at="after_anchor")
        with closing(sqlite3.connect(self.ledger.path)) as db:
            db.execute("UPDATE pending SET new_digest=? WHERE id=1", ("0"*64,))
            db.commit()
        with self.assertRaises(PolicyBlocked):
            self.ledger.recover_fixture()
        with self.assertRaises(PolicyBlocked):
            self.accept()

    def test_concurrent_duplicate_only_one_accepts(self):
        def attempt(_):
            try:
                return self.accept()["accepted_count"]
            except PolicyBlocked:
                return 0
        with ThreadPoolExecutor(max_workers=3) as executor:
            results = list(executor.map(attempt, range(3)))
        self.assertEqual(sum(results), 1)
        self.assertEqual(self.anchor.snapshot()[1], 1)

    def test_bad_lab_root_and_missing_witness_denied(self):
        with self.assertRaises(PolicyBlocked):
            SyntheticHealthLedger(Path(self.temp.name).parent, witness=self.anchor)
        with self.assertRaises(PolicyBlocked):
            SyntheticHealthLedger(self.temp.name, witness=None)

    def test_missing_history_does_not_bootstrap_from_signed_claim(self):
        with self.assertRaises(PolicyBlocked):
            self.accept(envelope=self.envelope(repository="Kali-Linux-"))

    def test_no_executor_or_network_listener(self):
        import upab.relay.v3_synthetic_health_ledger as module
        for name in ("execute", "run_task", "install", "deploy", "connect_repo",
                     "start_monitor", "start_watcher", "approve", "bind_pipe",
                     "serve", "enroll_owner", "set_owner_credential"):
            self.assertFalse(hasattr(module, name))


if __name__ == "__main__":
    unittest.main()
