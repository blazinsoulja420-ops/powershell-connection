from __future__ import annotations

import hashlib
import json
import subprocess
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from upab.relay.pipeline import ExactRelayPipeline


def git(root: Path, *args):
    cp = subprocess.run(["git", "-C", str(root), *args], text=True, capture_output=True, check=False)
    if cp.returncode != 0:
        raise RuntimeError(cp.stderr)
    return cp.stdout.strip()


def make_cfg(root: Path, state: Path, allowed: list[str], read_only=False):
    return {
        "provider": {"kind": "lmstudio", "base_url": "http://127.0.0.1:1234/v1", "model": "unused", "timeout_seconds": 1},
        "repository": {"root": str(root), "expected_head": None},
        "governance": {
            "upgs_version": "3.1.1",
            "canonical_package_sha256": "00" * 32,
            "canonical_package_path": None,
            "require_canonical_for_mutation": False,
            "read_only": read_only,
            "authorized_write_paths": allowed,
            "require_expected_hash_for_overwrite": True,
            "allow_test_execution": False,
            "test_command": ["python", "-c", "print('x')"],
            "powershell_executable": "powershell.exe",
            "powershell_allow_prefixes": ["Get-Content"],
            "max_command_seconds": 10,
            "max_output_chars": 10000,
            "max_file_read_bytes": 10000,
            "max_list_entries": 100,
            "max_agent_steps": 5,
        },
        "state": {"directory": str(state)},
        "exact_relay": {
            "enabled": True,
            "channel_id": "chan",
            "poll_interval_ms": 100,
            "max_task_lifetime_seconds": 900,
            "max_operations": 20,
            "auto_copy_result": True,
            "rollback_on_failure": True,
            "require_task_expected_head_for_mutation": True,
        },
    }


def envelope(root: Path, nonce: str, head: str, operations, mode="mutation", task_id="task-1"):
    now = datetime.now(timezone.utc)
    return {
        "schema": "upab.exact-relay.task.v1",
        "task_id": task_id,
        "channel_id": "chan",
        "relay_nonce": nonce,
        "issued_at_utc": now.isoformat(),
        "expires_at_utc": (now + timedelta(minutes=5)).isoformat(),
        "repository": {"root": str(root), "expected_head": head if mode == "mutation" else head},
        "mode": mode,
        "stop_on_failure": True,
        "rollback_on_failure": True,
        "operations": operations,
        "result": {"copy_to_clipboard": True},
    }


class RelayPipelineTests(unittest.TestCase):
    def setUpRepo(self):
        td = tempfile.TemporaryDirectory()
        root = Path(td.name) / "repo"
        state = Path(td.name) / "state"
        root.mkdir()
        git(root, "init")
        git(root, "config", "user.email", "test@example.com")
        git(root, "config", "user.name", "Test")
        (root / "a.txt").write_text("old", encoding="utf-8")
        git(root, "add", "a.txt")
        git(root, "commit", "-m", "base")
        return td, root, state

    def test_exact_write_and_result(self):
        td, root, state = self.setUpRepo()
        self.addCleanup(td.cleanup)
        cfg = make_cfg(root, state, ["a.txt"])
        pipe = ExactRelayPipeline(cfg)
        old_hash = hashlib.sha256(b"old").hexdigest().upper()
        head = git(root, "rev-parse", "HEAD")
        task = envelope(root, pipe.current_nonce(), head, [
            {"operation_id": "write", "op": "write_file", "args": {"path": "a.txt", "content": "new", "expected_sha256": old_hash}},
            {"operation_id": "diff", "op": "git_diff", "args": {"path": "a.txt"}},
        ])
        result = pipe.execute_task(task)
        self.assertEqual(result["status"], "PASS", result)
        self.assertEqual((root / "a.txt").read_text(), "new")
        self.assertNotEqual(result["next_relay_nonce"], task["relay_nonce"])

    def test_failure_rolls_back_prior_write(self):
        td, root, state = self.setUpRepo()
        self.addCleanup(td.cleanup)
        cfg = make_cfg(root, state, ["a.txt"])
        pipe = ExactRelayPipeline(cfg)
        old_hash = hashlib.sha256(b"old").hexdigest().upper()
        head = git(root, "rev-parse", "HEAD")
        task = envelope(root, pipe.current_nonce(), head, [
            {"operation_id": "write", "op": "write_file", "args": {"path": "a.txt", "content": "new", "expected_sha256": old_hash}},
            {"operation_id": "blocked", "op": "write_file", "args": {"path": "not-authorized.txt", "content": "x"}},
        ])
        result = pipe.execute_task(task)
        self.assertEqual(result["status"], "FAIL_CLOSED", result)
        self.assertEqual((root / "a.txt").read_text(), "old")
        self.assertTrue(result["rollback"]["ok"])

    def test_head_mismatch_blocks_before_nonce_consumption(self):
        td, root, state = self.setUpRepo()
        self.addCleanup(td.cleanup)
        cfg = make_cfg(root, state, ["a.txt"])
        pipe = ExactRelayPipeline(cfg)
        nonce = pipe.current_nonce()
        task = envelope(root, nonce, "0" * 40, [{"op": "git_status", "args": {}}])
        result = pipe.execute_task(task)
        self.assertEqual(result["status"], "BLOCKED")
        self.assertEqual(pipe.current_nonce(), nonce)


if __name__ == "__main__":
    unittest.main()
