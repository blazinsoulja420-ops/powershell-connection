from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from upab.governance import GovernanceGate


def cfg(root: Path):
    return {
        "governance": {
            "upgs_version": "3.1.1",
            "canonical_package_sha256": "00" * 32,
            "canonical_package_path": None,
            "require_canonical_for_mutation": True,
            "read_only": True,
            "authorized_write_paths": ["src/allowed.py"],
            "powershell_allow_prefixes": ["Get-Content", "git status"],
        }
    }


class GovernanceTests(unittest.TestCase):
    def test_path_escape_denied(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            gate = GovernanceGate(cfg(root), root)
            d = gate.authorize("read_file", {"path": "../escape.txt"})
            self.assertFalse(d.allowed)
            self.assertTrue(d.fatal)

    def test_write_requires_mutation_authority(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            gate = GovernanceGate(cfg(root), root)
            d = gate.authorize("write_file", {"path": "src/allowed.py", "content": "x"})
            self.assertFalse(d.allowed)
            self.assertEqual(d.code, "MUTATION_PRECONDITION")

    def test_write_requires_exact_manifest(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            c = cfg(root)
            c["governance"]["read_only"] = False
            c["governance"]["require_canonical_for_mutation"] = False
            gate = GovernanceGate(c, root)
            d = gate.authorize("write_file", {"path": "src/not-allowed.py", "content": "x"})
            self.assertFalse(d.allowed)
            self.assertEqual(d.code, "WRITE_NOT_IN_MANIFEST")

    def test_dangerous_powershell_denied(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            gate = GovernanceGate(cfg(root), root)
            d = gate.authorize("run_powershell", {"command": "Remove-Item x"})
            self.assertFalse(d.allowed)
            self.assertTrue(d.fatal)

    def test_chained_powershell_denied(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            gate = GovernanceGate(cfg(root), root)
            d = gate.authorize("run_powershell", {"command": "Get-Content x; Remove-Item x"})
            self.assertFalse(d.allowed)

    def test_readonly_powershell_allowed(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            gate = GovernanceGate(cfg(root), root)
            d = gate.authorize("run_powershell", {"command": "Get-Content README.md"})
            self.assertTrue(d.allowed)


if __name__ == "__main__":
    unittest.main()
