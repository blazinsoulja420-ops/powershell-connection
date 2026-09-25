from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from upab.executor import ToolExecutor


def make_cfg(root: Path, state: Path, allowed: list[str]):
    return {
        "provider": {
            "kind": "lmstudio",
            "base_url": "http://127.0.0.1:1234/v1",
            "model": "test",
            "timeout_seconds": 1,
        },
        "repository": {"root": str(root), "expected_head": None},
        "governance": {
            "upgs_version": "3.1.1",
            "canonical_package_sha256": "00" * 32,
            "canonical_package_path": None,
            "require_canonical_for_mutation": False,
            "read_only": False,
            "authorized_write_paths": allowed,
            "require_expected_hash_for_overwrite": True,
            "allow_test_execution": False,
            "test_command": ["python", "-c", "print('x')"],
            "powershell_executable": "powershell.exe",
            "powershell_allowed_command_ids": ["get_item", "resolve_path", "select_string"],
            "max_command_seconds": 10,
            "max_output_chars": 10000,
            "max_file_read_bytes": 10000,
            "max_list_entries": 100,
            "max_agent_steps": 5,
        },
        "state": {"directory": str(state)},
    }


class ExecutorTests(unittest.TestCase):
    def test_new_file_exact_manifest_and_rollback(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            root = base / "repo"
            state = base / "state"
            root.mkdir()
            ex = ToolExecutor(make_cfg(root, state, ["new.txt"]))
            result = ex.execute("write_file", {"path": "new.txt", "content": "hello"})
            self.assertTrue(result.ok, result.output)
            self.assertEqual((root / "new.txt").read_text(), "hello")
            rb = ex.execute("rollback_last_write", {})
            self.assertTrue(rb.ok, rb.output)
            self.assertFalse((root / "new.txt").exists())

    def test_existing_file_requires_matching_hash(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            root = base / "repo"
            state = base / "state"
            root.mkdir()
            p = root / "a.txt"
            p.write_text("old", encoding="utf-8")
            ex = ToolExecutor(make_cfg(root, state, ["a.txt"]))

            bad = ex.execute(
                "write_file",
                {"path": "a.txt", "content": "new", "expected_sha256": "BAD"},
            )
            self.assertFalse(bad.ok)
            self.assertEqual(p.read_text(), "old")

            expected = hashlib.sha256(b"old").hexdigest().upper()
            good = ex.execute(
                "write_file",
                {"path": "a.txt", "content": "new", "expected_sha256": expected},
            )
            self.assertTrue(good.ok, good.output)
            self.assertEqual(p.read_text(), "new")

    def test_run_powershell_blocks_raw_command(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            root = base / "repo"
            state = base / "state"
            root.mkdir()
            ex = ToolExecutor(make_cfg(root, state, []))
            result = ex.execute(
                "run_powershell",
                {"command": "Remove-Item anything"},
            )
            self.assertFalse(result.ok)
            self.assertTrue(
                "PS_RAW_COMMAND_UNSUPPORTED" in result.output
            )

    def test_run_powershell_blocks_target_escape_before_execution(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            root = base / "repo"
            state = base / "state"
            root.mkdir()
            ex = ToolExecutor(make_cfg(root, state, []))
            result = ex.execute(
                "run_powershell",
                {"command_id": "get_item", "path": "../outside.txt"},
            )
            self.assertFalse(result.ok)
            self.assertIn("PS_PATH_ESCAPE", result.output)

    def test_run_powershell_blocks_unknown_argument(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            root = base / "repo"
            state = base / "state"
            root.mkdir()
            ex = ToolExecutor(make_cfg(root, state, []))
            result = ex.execute(
                "run_powershell",
                {"command_id": "get_item", "path": "x.txt", "argv": ["bad"]},
            )
            self.assertFalse(result.ok)
            self.assertTrue(
                "PS_ARGUMENT_UNKNOWN" in result.output
            )

    def test_read_file(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            root = base / "repo"
            state = base / "state"
            root.mkdir()
            (root / "x.txt").write_text("abc", encoding="utf-8")
            ex = ToolExecutor(make_cfg(root, state, []))
            result = ex.execute("read_file", {"path": "x.txt"})
            self.assertTrue(result.ok)
            self.assertEqual(result.output, "abc")


if __name__ == "__main__":
    unittest.main()
