from __future__ import annotations

import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from upab.relay.schema import RelayValidationError, format_task_block, parse_task_block, validate_task


def config(root: Path):
    return {
        "repository": {"root": str(root), "expected_head": None},
        "exact_relay": {
            "channel_id": "chan",
            "max_task_lifetime_seconds": 900,
            "max_operations": 10,
            "auto_copy_result": True,
            "rollback_on_failure": True,
            "require_task_expected_head_for_mutation": True,
        },
    }


def task(root: Path, nonce="nonce"):
    now = datetime.now(timezone.utc)
    return {
        "schema": "upab.exact-relay.task.v1",
        "task_id": "task-1",
        "channel_id": "chan",
        "relay_nonce": nonce,
        "issued_at_utc": now.isoformat(),
        "expires_at_utc": (now + timedelta(minutes=5)).isoformat(),
        "repository": {"root": str(root), "expected_head": None},
        "mode": "read_only",
        "operations": [{"op": "git_status", "args": {}}],
    }


class RelaySchemaTests(unittest.TestCase):
    def test_round_trip_task_block(self):
        with tempfile.TemporaryDirectory() as td:
            value = task(Path(td))
            parsed = parse_task_block(format_task_block(value))
            self.assertEqual(parsed, value)

    def test_nonce_mismatch_denied(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            with self.assertRaises(RelayValidationError):
                validate_task(task(root, "wrong"), config(root), "nonce")

    def test_readonly_write_denied(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            value = task(root)
            value["operations"] = [{"op": "write_file", "args": {"path": "x", "content": "x"}}]
            with self.assertRaises(RelayValidationError):
                validate_task(value, config(root), "nonce")

    def test_mutation_requires_expected_head(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            value = task(root)
            value["mode"] = "mutation"
            with self.assertRaises(RelayValidationError):
                validate_task(value, config(root), "nonce")

    def test_expired_task_denied(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            value = task(root)
            past = datetime.now(timezone.utc) - timedelta(minutes=10)
            value["issued_at_utc"] = past.isoformat()
            value["expires_at_utc"] = (past + timedelta(minutes=5)).isoformat()
            with self.assertRaises(RelayValidationError):
                validate_task(value, config(root), "nonce")


if __name__ == "__main__":
    unittest.main()
