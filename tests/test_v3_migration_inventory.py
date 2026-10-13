from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from upab.relay.ledger import RelayLedger
from upab.relay.v3_migration_inventory import inspect_migration_state, main
from upab.relay.v3_policy import PolicyBlocked


class MigrationInventoryTests(unittest.TestCase):
    def test_existing_v1_state_read_only_and_not_authorized(self):
        with tempfile.TemporaryDirectory() as td:
            ledger = RelayLedger(td)
            ledger.consume("task-old", "B"*64, ledger.current_nonce())
            before = sorted((p.relative_to(td).as_posix(),p.read_bytes())
                            for p in Path(td).rglob("*") if p.is_file())
            report = inspect_migration_state(td)
            self.assertEqual(report["status"], "V1_INVENTORIED_NOT_READY")
            self.assertEqual(report["legacy_records"], 1)
            self.assertFalse(report["verified_v1_quiescent"])
            self.assertFalse(report["authorized_to_migrate"])
            self.assertFalse(report["changes_performed"])
            self.assertEqual(main(["--state", td]), 0)
            after = sorted((p.relative_to(td).as_posix(),p.read_bytes())
                           for p in Path(td).rglob("*") if p.is_file())
            self.assertEqual(before, after)

    def test_corrupt_legacy_record_denies_migration(self):
        with tempfile.TemporaryDirectory() as td:
            RelayLedger(td)
            file = Path(td)/"relay"/"seen_tasks.jsonl"
            file.write_text('{"task_id":"good"}\n{"task_id":', encoding="utf-8")
            with self.assertRaises(PolicyBlocked):
                inspect_migration_state(td)
            self.assertEqual(main(["--state",td]),7)

    def test_marker_and_v2_data_still_do_not_authorize(self):
        with tempfile.TemporaryDirectory() as td:
            RelayLedger(td)
            relay = Path(td)/"relay"
            (relay/"relay_v2.sqlite3").write_bytes(b"just a preflight fixture")
            result=inspect_migration_state(td)
            self.assertEqual(result["status"],"V2_STATE_PRESENT_REVIEW")
            (relay/"v2_active.marker").write_text("fixture",encoding="utf-8")
            result=inspect_migration_state(td)
            self.assertEqual(result["status"],"MIGRATION_MARKER_PRESENT_STOP")
            self.assertFalse(result["authorized_to_migrate"])

    def test_nonce_size_or_absent_state_blocks(self):
        with tempfile.TemporaryDirectory() as td:
            with self.assertRaises(PolicyBlocked):
                inspect_migration_state(td)
            RelayLedger(td)
            (Path(td)/"relay"/"nonce.txt").write_text("",encoding="utf-8")
            with self.assertRaises(PolicyBlocked):
                inspect_migration_state(td)
            self.assertFalse((Path(td)/"relay"/"v2_active.marker").exists())


if __name__ == "__main__":
    unittest.main()
