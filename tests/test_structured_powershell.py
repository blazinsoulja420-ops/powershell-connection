from __future__ import annotations

import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

from upab.agent import TOOLS
from upab.executor import ToolExecutor
from upab.powershell_commands import CommandRequestError, resolve_bound_path, validate_request


def make_cfg(root: Path, state: Path) -> dict:
    return {
        "provider": {"kind": "lmstudio", "base_url": "http://127.0.0.1:1234/v1", "model": "test", "timeout_seconds": 1},
        "repository": {"root": str(root), "expected_head": None},
        "governance": {
            "upgs_version": "3.1.1", "canonical_package_sha256": "00" * 32,
            "canonical_package_path": None, "require_canonical_for_mutation": False,
            "read_only": True, "authorized_write_paths": [], "require_expected_hash_for_overwrite": True,
            "allow_test_execution": False, "test_command": ["python", "-c", "print('x')"],
            "powershell_executable": "powershell.exe",
            "powershell_allowed_command_ids": ["get_item", "resolve_path", "select_string"],
            "max_command_seconds": 30, "max_output_chars": 2_000_000,
            "max_file_read_bytes": 10_000, "max_list_entries": 100, "max_agent_steps": 5,
        },
        "state": {"directory": str(state)},
    }


class StructuredPowerShellTests(unittest.TestCase):
    def test_public_schema_is_closed_and_has_no_raw_command(self):
        tool = next(item for item in TOOLS if item["function"]["name"] == "run_powershell")
        schema = tool["function"]["parameters"]
        self.assertFalse(schema["additionalProperties"])
        self.assertNotIn("command", schema["properties"])
        self.assertNotIn("executable", schema["properties"])
        self.assertNotIn("argv", schema["properties"])

    def test_deterministic_request_denials(self):
        cases = [
            ({"command": "Get-Item x"}, "PS_RAW_COMMAND_UNSUPPORTED"),
            ({}, "PS_COMMAND_ID_REQUIRED"),
            ({"command_id": "unknown", "path": "x"}, "PS_COMMAND_UNKNOWN"),
            ({"command_id": "get_item", "path": "x", "executable": "cmd.exe"}, "PS_ARGUMENT_UNKNOWN"),
            ({"command_id": "get_item", "path": "x", "argv": ["/c"]}, "PS_ARGUMENT_UNKNOWN"),
            ({"command_id": "get_item", "path": 1}, "PS_ARGUMENT_TYPE"),
            ({"command_id": "get_item"}, "PS_PATH_REQUIRED"),
            ({"command_id": "select_string", "path": "x"}, "PS_ARGUMENT_REQUIRED"),
        ]
        for request, code in cases:
            with self.subTest(code=code), self.assertRaises(CommandRequestError) as caught:
                validate_request(request)
            self.assertEqual(caught.exception.code, code)

    def test_path_traversal_absolute_drive_and_symlink_escape(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            root = base / "repo"
            outside = base / "outside"
            root.mkdir()
            outside.mkdir()
            for path in ("../outside", str(outside.resolve())):
                with self.subTest(path=path), self.assertRaises(CommandRequestError) as caught:
                    resolve_bound_path(root, path)
                self.assertEqual(caught.exception.code, "PS_PATH_ESCAPE")
            if os.name == "nt":
                with self.assertRaises(CommandRequestError) as caught:
                    resolve_bound_path(root, "Z:\\outside.txt")
                self.assertEqual(caught.exception.code, "PS_PATH_ESCAPE")
            link = root / "escape-link"
            try:
                link.symlink_to(outside, target_is_directory=True)
            except OSError:
                if os.name != "nt":
                    self.skipTest("symlink creation unavailable on this host")
                created = subprocess.run(
                    ["cmd.exe", "/d", "/c", "mklink", "/J", str(link), str(outside)],
                    capture_output=True, text=True, check=False,
                )
                if created.returncode != 0:
                    self.skipTest("symlink and junction creation unavailable on this Windows host")
            with self.assertRaises(CommandRequestError) as caught:
                resolve_bound_path(root, "escape-link/file.txt")
            self.assertEqual(caught.exception.code, "PS_PATH_ESCAPE")

    def test_all_operations_execute_with_fixed_wrapper_and_evidence(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            root, state = base / "repo", base / "state"
            root.mkdir()
            marker = "literal $() & | > ; `n -EncodedCommand powershell.exe -Command"
            target = root / "sample [literal].txt"
            target.write_text(marker, encoding="utf-8")
            before = target.read_bytes()
            ex = ToolExecutor(make_cfg(root, state))
            requests = [
                {"command_id": "get_item", "path": target.name},
                {"command_id": "resolve_path", "path": target.name},
                {"command_id": "select_string", "path": target.name, "pattern": marker},
            ]
            for request in requests:
                with self.subTest(command_id=request["command_id"]):
                    result = ex.execute("run_powershell", request)
                    self.assertTrue(result.ok, result.output)
                    self.assertEqual(result.metadata["command_id"], request["command_id"])
                    self.assertEqual(result.metadata["timeout_seconds"], 10)
            self.assertEqual(json.loads(result.output)["Line"], marker)
            self.assertEqual(target.read_bytes(), before)
            events = [json.loads(line) for line in ex.evidence.log_path.read_text(encoding="utf-8").splitlines()]
            self.assertGreaterEqual(sum(e.get("event") == "tool_result" for e in events), 3)

    def test_language_payloads_are_not_accepted_as_program_source(self):
        payloads = ["$()", "& whoami", "x | whoami", "x > out", "x; whoami", "x\nwhoami", "-EncodedCommand AAA=", "powershell.exe -Command whoami"]
        with tempfile.TemporaryDirectory() as td:
            root, state = Path(td) / "repo", Path(td) / "state"
            root.mkdir()
            ex = ToolExecutor(make_cfg(root, state))
            for payload in payloads:
                result = ex.execute("run_powershell", {"command": payload})
                self.assertFalse(result.ok)
                self.assertIn("PS_RAW_COMMAND_UNSUPPORTED", result.output)

    def test_timeout_is_deterministic(self):
        with tempfile.TemporaryDirectory() as td:
            root, state = Path(td) / "repo", Path(td) / "state"
            root.mkdir()
            (root / "x.txt").write_text("x", encoding="utf-8")
            ex = ToolExecutor(make_cfg(root, state))
            ex._process = lambda *a, **k: (_ for _ in ()).throw(subprocess.TimeoutExpired("powershell.exe", 10))
            result = ex.execute("run_powershell", {"command_id": "get_item", "path": "x.txt"})
            self.assertFalse(result.ok)
            self.assertIn("PS_TIMEOUT", result.output)

    def test_wrapper_change_is_denied_before_execution(self):
        with tempfile.TemporaryDirectory() as td:
            root, state = Path(td) / "repo", Path(td) / "state"
            root.mkdir()
            (root / "x.txt").write_text("x", encoding="utf-8")
            ex = ToolExecutor(make_cfg(root, state))
            ex.powershell_wrapper_sha256 = "0" * 64
            result = ex.execute("run_powershell", {"command_id": "get_item", "path": "x.txt"})
            self.assertFalse(result.ok)
            self.assertIn("PS_WRAPPER_MISSING", result.output)


if __name__ == "__main__":
    unittest.main()
