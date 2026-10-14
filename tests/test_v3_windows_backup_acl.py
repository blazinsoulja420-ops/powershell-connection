from __future__ import annotations

from pathlib import Path
import sys
import tempfile
import unittest

from upab.relay.v3_policy import PolicyBlocked
from upab.relay.v3_windows_backup_acl import (
    ACL_SIZE_INFORMATION, _WRITE_MASK, inspect_backup_file_acl,
)


class Stage20BackupAclObservationTests(unittest.TestCase):
    def test_native_acl_observation_never_proves_protected_backup(self):
        with tempfile.TemporaryDirectory() as td:
            existing=Path(td)/"synthetic_backup.bin"
            existing.write_bytes(b"public fixed fixture only")
            if sys.platform != "win32":
                with self.assertRaises(PolicyBlocked):
                    inspect_backup_file_acl(existing)
                return
            before=existing.read_bytes()
            report=inspect_backup_file_acl(existing)
            self.assertTrue(report["security_descriptor_observed"])
            self.assertIsInstance(report["ace_count"],int)
            self.assertGreaterEqual(report["ace_count"],0)
            for key in ("dacl_present", "null_or_missing_dacl",
                        "dacl_inheritance_protected",
                        "broad_write_allow_ace_observed"):
                self.assertIsInstance(report[key],bool)
            for key in ("path_and_acl_race_free",
                        "all_file_acl_components_audited",
                        "backup_access_isolation_proven",
                        "backup_authenticity_proven",
                        "backup_immutability_proven",
                        "owner_authenticated", "migration_authorized",
                        "changes_performed"):
                self.assertFalse(report[key],key)
            for sensitive in ("file", "path", "security_descriptor",
                              "owner_sid", "sids", "ace_list", "acl_text"):
                self.assertNotIn(sensitive,report)
            self.assertEqual(before,existing.read_bytes())

    def test_invalid_file_and_dir_paths_fail_closed(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            for bad in (root,root/"missing.bin"):
                with self.subTest(bad=bad):
                    with self.assertRaises(PolicyBlocked):
                        inspect_backup_file_acl(bad)
            huge=root/"too_big.bin"
            with huge.open("wb") as f:
                f.truncate(8*1024*1024+1)
            with self.assertRaises(PolicyBlocked):
                inspect_backup_file_acl(huge)

    def test_link_redirection_denied_when_supported(self):
        with tempfile.TemporaryDirectory() as td:
            p=Path(td)
            original=p/"public.bin"
            original.write_bytes(b"public synthetic")
            link=p/"redirect.bin"
            try:
                link.symlink_to(original)
            except (OSError,NotImplementedError):
                self.skipTest("symlink creation unavailable")
            with self.assertRaises(PolicyBlocked):
                inspect_backup_file_acl(link)
            self.assertEqual(original.read_bytes(),b"public synthetic")

    def test_acl_parsing_has_explicit_write_permission_masks(self):
        self.assertNotEqual(_WRITE_MASK & 0x40000000,0)
        self.assertNotEqual(_WRITE_MASK & 0x00040000,0)
        import ctypes
        self.assertEqual(ctypes.sizeof(ACL_SIZE_INFORMATION),12)

    def test_no_backup_modification_or_migration_api(self):
        import upab.relay.v3_windows_backup_acl as module
        for name in ("SetNamedSecurityInfoW", "set_acl", "allow_execution",
                     "restore_backup", "revoke_access", "approve",
                     "copy_backup", "migrate"):
            self.assertFalse(hasattr(module,name))


if __name__ == "__main__":
    unittest.main()
