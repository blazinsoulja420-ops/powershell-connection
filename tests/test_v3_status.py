from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from upab.relay.v3_checkpoint import CheckpointStore
from upab.relay.v3_status import main, status_snapshot
from upab.relay.v3_policy import PolicyBlocked


class V3StatusTests(unittest.TestCase):
    def test_uninitialized_status_does_not_create_files(self):
        with tempfile.TemporaryDirectory() as td:
            before = list(Path(td).rglob("*"))
            report = status_snapshot(td)
            self.assertEqual(report["checkpoint_state"], "NOT_INITIALIZED")
            self.assertIsNone(report["is_live"])
            self.assertFalse(report["task_execution_enabled"])
            self.assertFalse(report["changes_performed"])
            self.assertEqual(before, list(Path(td).rglob("*")))
            self.assertEqual(main(["--state", td]), 0)

    def test_previews_existing_checkpoint_records(self):
        with tempfile.TemporaryDirectory() as td:
            db = CheckpointStore(td)
            db.propose("one", "A"*64)
            report = status_snapshot(td)
            self.assertEqual(report["checkpoint_state"], "AVAILABLE")
            self.assertEqual(report["review_counts"]["PROPOSED"], 1)
            self.assertFalse(report["approval_gateway_connected"])
            self.assertEqual(main(["--state", td]), 0)

    def test_missing_or_corrupt_state_fails_closed(self):
        with tempfile.TemporaryDirectory() as td:
            self.assertEqual(main(["--state", str(Path(td)/"does-not-exist")]), 7)
            root = Path(td)/"relay"
            root.mkdir()
            (root/"v3_checkpoints.sqlite3").write_text("not a SQLite DB",encoding="utf-8")
            with self.assertRaises(PolicyBlocked):
                status_snapshot(td)
            self.assertEqual(main(["--state", td]), 7)


if __name__ == "__main__":
    unittest.main()
