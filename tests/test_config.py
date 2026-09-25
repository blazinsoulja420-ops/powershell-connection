from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from upab.config import ConfigError, load_config


class ConfigTests(unittest.TestCase):
    def test_loads_and_normalizes_paths(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "repo"
            root.mkdir()
            cfg = {
                "provider": {
                    "kind": "lmstudio",
                    "base_url": "http://127.0.0.1:1234/v1",
                    "model": "x",
                    "timeout_seconds": 1
                },
                "repository": {"root": str(root), "expected_head": None},
                "governance": {
                    "upgs_version": "3.1.1",
                    "canonical_package_sha256": "00",
                    "canonical_package_path": None,
                    "require_canonical_for_mutation": True,
                    "read_only": True,
                    "authorized_write_paths": ["src\\x.py"],
                    "powershell_allowed_command_ids": [],
                    "max_command_seconds": 1,
                    "max_output_chars": 100,
                    "max_file_read_bytes": 100,
                    "max_list_entries": 100,
                    "max_agent_steps": 2
                },
                "state": {"directory": str(Path(td) / "state")}
            }
            path = Path(td) / "c.json"
            path.write_text(json.dumps(cfg), encoding="utf-8")
            loaded = load_config(path)
            self.assertEqual(loaded["governance"]["authorized_write_paths"], ["src/x.py"])

    def test_rejects_non_local_provider_in_v1(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "c.json"
            path.write_text(json.dumps({
                "provider": {"kind": "openai", "base_url": "x", "model": "x", "timeout_seconds": 1},
                "repository": {"root": td},
                "governance": {},
                "state": {}
            }), encoding="utf-8")
            with self.assertRaises(ConfigError):
                load_config(path)


if __name__ == "__main__":
    unittest.main()
