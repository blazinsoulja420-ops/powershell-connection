from __future__ import annotations

import os
from pathlib import Path
import sys
import tempfile
import unittest

from upab.relay.v3_dpapi_fixture_store import (
    create_synthetic_seed, verify_synthetic_seed,
)
from upab.relay.v3_policy import PolicyBlocked


@unittest.skipUnless(sys.platform == "win32", "Windows DPAPI custody only")
class SyntheticVaultTests(unittest.TestCase):
    def test_current_user_disposable_seed_survives_new_object_and_never_exports(self):
        with tempfile.TemporaryDirectory(prefix="upab-v3-lab-") as td:
            vault=Path(td)/"synthetic_dpapi_seed.bin"
            report=create_synthetic_seed(td)
            self.assertTrue(report["synthetic_seed_created"])
            self.assertFalse(report["seed_exported"])
            self.assertFalse(report["execution_authorized"])
            self.assertGreater(vault.stat().st_size,32)
            self.assertNotIn(b"UPAB",vault.read_bytes())
            recovered=verify_synthetic_seed(td)
            self.assertTrue(recovered["seed_verified_under_current_user"])
            self.assertFalse(recovered["owner_authenticated"])
            self.assertFalse(recovered["seed_exported"])
            with self.assertRaises(PolicyBlocked):
                create_synthetic_seed(td)

    def test_corrupt_ciphertext_and_missing_file_fail_closed(self):
        with tempfile.TemporaryDirectory(prefix="upab-v3-lab-") as td:
            with self.assertRaises(PolicyBlocked):
                verify_synthetic_seed(td)
            create_synthetic_seed(td)
            target=Path(td)/"synthetic_dpapi_seed.bin"
            wire=bytearray(target.read_bytes())
            wire[-1] ^= 0x5A
            target.write_bytes(wire)
            with self.assertRaises(PolicyBlocked):
                verify_synthetic_seed(td)
            with self.assertRaises(PolicyBlocked):
                create_synthetic_seed(td)

    def test_rejects_arbitrary_root_including_project_like_folder(self):
        with tempfile.TemporaryDirectory() as outside:
            fake=Path(outside)/"upab-v3-lab-project"
            fake.mkdir()
            with self.assertRaises(PolicyBlocked):
                create_synthetic_seed(fake)
            self.assertEqual(list(fake.iterdir()),[])

    def test_oversized_vault_refused_before_decryption(self):
        with tempfile.TemporaryDirectory(prefix="upab-v3-lab-") as td:
            (Path(td)/"synthetic_dpapi_seed.bin").write_bytes(b"\0"*4097)
            with self.assertRaises(PolicyBlocked):
                verify_synthetic_seed(td)


if __name__ == "__main__":
    unittest.main()
