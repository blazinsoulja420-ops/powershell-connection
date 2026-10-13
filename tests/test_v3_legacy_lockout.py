from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from upab.relay.ledger import RelayLedger


class LegacyRelayMigrationLockoutTests(unittest.TestCase):
    def test_existing_v1_instance_stops_after_v2_marker_appears(self):
        with tempfile.TemporaryDirectory() as td:
            old = RelayLedger(td)
            original = old.current_nonce()
            self.assertIsInstance(original, str)
            marker = Path(td) / "relay" / "v2_active.marker"
            marker.write_text("migration-preview-only", encoding="utf-8")
            for operation in (
                lambda: old.current_nonce(),
                lambda: old.seen_task_ids(),
                lambda: old.consume("task-after-marker","A"*64,original),
                lambda: RelayLedger(td),
            ):
                with self.assertRaisesRegex(RuntimeError, "legacy relay v1 disabled"):
                    operation()
            self.assertEqual((Path(td)/"relay"/"nonce.txt").read_text().strip(),original)
            self.assertFalse((Path(td)/"relay"/"seen_tasks.jsonl").exists())

    def test_no_marker_preserves_existing_v1_workflow(self):
        with tempfile.TemporaryDirectory() as td:
            old=RelayLedger(td)
            original=old.current_nonce()
            changed=old.consume("normal-v1-task","A"*64,original)
            self.assertNotEqual(original,changed)
            self.assertIn("normal-v1-task",old.seen_task_ids())

    def test_directory_named_marker_also_fails_closed(self):
        with tempfile.TemporaryDirectory() as td:
            relay=Path(td)/"relay"
            relay.mkdir()
            (relay/"v2_active.marker").mkdir()
            with self.assertRaisesRegex(RuntimeError,"legacy relay v1 disabled"):
                RelayLedger(td)


if __name__ == "__main__":
    unittest.main()
