from __future__ import annotations

import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

from upab.relay.ledger import RelayLedger
from upab.relay.ledger_v2 import RelayLedgerV2
from upab.relay.v3_migration_risk_audit import audit_migration_risks, main
from upab.relay.v3_policy import PolicyBlocked


class Stage17LegacyMigrationRiskAuditTests(unittest.TestCase):
    @staticmethod
    def _snapshot(root):
        return sorted(
            (path.relative_to(root).as_posix(), path.read_bytes())
            for path in Path(root).rglob("*") if path.is_file()
        )

    def test_existing_v1_records_preserved_and_audit_is_read_only(self):
        with tempfile.TemporaryDirectory() as td:
            v1 = RelayLedger(td)
            v1.consume("historic-01", "A"*64, v1.current_nonce())
            before = self._snapshot(td)
            report = audit_migration_risks(td)
            self.assertEqual(report["legacy_record_count"], 1)
            self.assertEqual(report["status"], "BLOCKED_NOT_AUTHORIZED")
            self.assertFalse(report["v1_quiescence_proven"])
            self.assertFalse(report["owner_approval_proven"])
            self.assertFalse(report["migration_allowed"])
            self.assertFalse(report["task_execution_allowed"])
            self.assertFalse(report["writes_performed"])
            self.assertIn("UNVERIFIED_V1_PROCESS_QUIESCENCE", report["blocked_reasons"])
            self.assertEqual(main(["--state", td]), 0)
            self.assertEqual(before, self._snapshot(td))

    def test_v2_import_is_checked_without_enabling_or_marking(self):
        with tempfile.TemporaryDirectory() as td:
            v1 = RelayLedger(td)
            v1.consume("historic-01", "A"*64, v1.current_nonce())
            v2 = RelayLedgerV2(td)  # Fixture only; creates candidate DB in disposable temp.
            self.assertTrue(v2.has_seen("historic-01"))
            before = self._snapshot(td)
            report = audit_migration_risks(td)
            self.assertTrue(report["v2_database_present"])
            self.assertEqual(report["v2_consumed_count"], 1)
            self.assertEqual(report["missing_legacy_records_in_v2"], 0)
            self.assertIn("V2_LEDGER_PRESENT_WITHOUT_V1_LOCKOUT_MARKER",
                          report["blocked_reasons"])
            self.assertFalse(report["migration_allowed"])
            self.assertEqual(before, self._snapshot(td))

    def test_marker_is_not_quiescence_evidence(self):
        with tempfile.TemporaryDirectory() as td:
            RelayLedger(td)
            (Path(td)/"relay"/"v2_active.marker").write_text("fixture", encoding="utf-8")
            report = audit_migration_risks(td)
            self.assertTrue(report["activation_marker_present"])
            self.assertFalse(report["v1_quiescence_proven"])
            self.assertIn("ACTIVATION_MARKER_WITHOUT_V2_LEDGER",report["blocked_reasons"])
            self.assertFalse(report["migration_allowed"])

    def test_missing_imported_replay_history_blocks(self):
        with tempfile.TemporaryDirectory() as td:
            v1 = RelayLedger(td)
            v1.consume("historic-01", "B"*64, v1.current_nonce())
            RelayLedgerV2(td)
            db = Path(td)/"relay"/"relay_v2.sqlite3"
            with sqlite3.connect(db) as conn:
                conn.execute("DELETE FROM consumed WHERE task_id='historic-01'")
            report = audit_migration_risks(td)
            self.assertEqual(report["missing_legacy_records_in_v2"], 1)
            self.assertIn("LEGACY_HISTORY_NOT_FULLY_IN_V2", report["blocked_reasons"])
            self.assertFalse(report["migration_allowed"])

    def test_duplicate_or_incomplete_v1_lines_fail_closed(self):
        for invalid in (
            "duplicate", "bad_digest", "missing_field", "garbage", "oversized",
        ):
            with self.subTest(invalid=invalid):
                with tempfile.TemporaryDirectory() as td:
                    v1=RelayLedger(td)
                    v1.consume("historic-01","B"*64,v1.current_nonce())
                    history=Path(td)/"relay"/"seen_tasks.jsonl"
                    line=history.read_text(encoding="utf-8")
                    if invalid == "duplicate":
                        history.write_text(line+line, encoding="utf-8")
                    elif invalid == "bad_digest":
                        record=json.loads(line)
                        record["sha256"]="not-a-sha256"
                        history.write_text(json.dumps(record)+"\n", encoding="utf-8")
                    elif invalid == "missing_field":
                        record=json.loads(line)
                        del record["consumed_at_utc"]
                        history.write_text(json.dumps(record)+"\n", encoding="utf-8")
                    elif invalid == "garbage":
                        history.write_text(line+"not-json\n", encoding="utf-8")
                    elif invalid == "oversized":
                        history.write_text("x"*4200, encoding="utf-8")
                    with self.assertRaises(PolicyBlocked):
                        audit_migration_risks(td)
                    self.assertEqual(main(["--state", td]),7)

    def test_invalid_nonce_and_non_database_fail_closed(self):
        with tempfile.TemporaryDirectory() as td:
            RelayLedger(td)
            relay=Path(td)/"relay"
            (relay/"nonce.txt").write_text("A" * 500, encoding="ascii")
            with self.assertRaises(PolicyBlocked):
                audit_migration_risks(td)
            (relay/"nonce.txt").write_text("A" * 36+"\n", encoding="ascii")
            (relay/"relay_v2.sqlite3").write_bytes(b"not a real database")
            with self.assertRaises(PolicyBlocked):
                audit_migration_risks(td)

    def test_redirected_relay_file_or_state_root_denied(self):
        with tempfile.TemporaryDirectory() as td:
            RelayLedger(td)
            relay=Path(td)/"relay"
            original=relay/"nonce.txt"
            original.unlink()
            outside=Path(td)/"outside-nonce.txt"
            outside.write_text("sensitive existing fixture", encoding="utf-8")
            try:
                original.symlink_to(outside)
            except (OSError, NotImplementedError):
                self.skipTest("symlink creation not permitted on runner")
            with self.assertRaises(PolicyBlocked):
                audit_migration_risks(td)
            self.assertEqual(outside.read_text(encoding="utf-8"),
                             "sensitive existing fixture")

    def test_uninitialized_state_and_missing_nonce_stay_blocked(self):
        with tempfile.TemporaryDirectory() as td:
            with self.assertRaises(PolicyBlocked):
                audit_migration_risks(td)
            relay = Path(td)/"relay"
            relay.mkdir()
            result = audit_migration_risks(td)
            self.assertIn("LEGACY_NONCE_MISSING",result["blocked_reasons"])
            self.assertFalse(result["migration_allowed"])


if __name__ == "__main__":
    unittest.main()
