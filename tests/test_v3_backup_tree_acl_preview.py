from __future__ import annotations

from pathlib import Path
import sys
import tempfile
import unittest

from upab.relay.v3_policy import PolicyBlocked
from upab.relay.v3_backup_tree_acl_preview import inspect_backup_tree
from upab.relay.v3_windows_backup_acl import inspect_backup_directory_acl


def setup_backup(directory: str):
    root=Path(directory)
    state=root/"existing_backup"
    relay=state/"relay"
    relay.mkdir(parents=True)
    (relay/"nonce.txt").write_text("public-synthetic-nonce-0000000000000000000000\n",
                                   encoding="ascii")
    (relay/"seen_tasks.jsonl").write_text(
        '{"task_id":"synthetic","sha256":"not-a-real-secret"}\n', encoding="ascii"
    )
    return state


def snapshot(root: Path):
    return sorted(
        (x.relative_to(root).as_posix(), x.read_bytes())
        for x in root.rglob("*") if x.is_file()
    )


class Stage21BackupDirectoryAclTests(unittest.TestCase):
    def test_whitelist_acl_tree_always_reports_untrusted_backup(self):
        with tempfile.TemporaryDirectory() as td:
            root=setup_backup(td)
            before=snapshot(root)
            if sys.platform!="win32":
                with self.assertRaises(PolicyBlocked):
                    inspect_backup_tree(root)
                return
            report=inspect_backup_tree(root)
            self.assertEqual(report["expected_state_files_observed"],2)
            self.assertEqual(report["state_directories_sampled"],2)
            self.assertEqual(report["total_dacl_objects_sampled"],4)
            self.assertTrue(report["layout_contains_only_allowlisted_relay_files"])
            for k in ("null_or_missing_dacl_objects","broad_write_allow_objects",
                      "uninterpreted_ace_total",
                      "dacl_inheritance_not_protected_objects"):
                self.assertIsInstance(report[k],int)
                self.assertGreaterEqual(report[k],0)
            for key in (
                "backup_bytes_read_or_exported","backup_contents_proven_restorable",
                "acl_sampling_race_free","effective_windows_rights_verified",
                "full_backup_integrity_proven","tamper_protected_backup_proven",
                "owner_authenticated","migration_authorized",
                "task_execution_authorized","filesystem_changes_performed",
            ):
                self.assertFalse(report[key], key)
            self.assertEqual(snapshot(root),before)

    def test_directory_acl_observation_not_owner_approval(self):
        with tempfile.TemporaryDirectory() as td:
            if sys.platform!="win32":
                with self.assertRaises(PolicyBlocked):
                    inspect_backup_directory_acl(td)
                return
            report=inspect_backup_directory_acl(td)
            self.assertTrue(report["observed_directory"])
            self.assertFalse(report["directory_child_entries_checked"])
            self.assertFalse(report["backup_access_isolation_proven"])
            self.assertFalse(report["migration_authorized"])
            self.assertFalse(report["changes_performed"])

    def test_unexpected_or_missing_backup_files_denied(self):
        with tempfile.TemporaryDirectory() as td:
            root=setup_backup(td)
            (root/"relay"/"private.pem").write_text("must not inspect",encoding="utf-8")
            with self.assertRaises(PolicyBlocked):
                inspect_backup_tree(root)
        with tempfile.TemporaryDirectory() as td:
            root=setup_backup(td)
            (root/"relay"/"seen_tasks.jsonl").unlink()
            with self.assertRaises(PolicyBlocked):
                inspect_backup_tree(root)
        with tempfile.TemporaryDirectory() as td:
            root=setup_backup(td)
            (root/"unexpected").mkdir()
            with self.assertRaises(PolicyBlocked):
                inspect_backup_tree(root)

    def test_missing_redirected_and_oversized_relay_state_denied(self):
        with tempfile.TemporaryDirectory() as td:
            root=setup_backup(td)
            (root/"relay"/"nonce.txt").write_bytes(b"Z"*513)
            with self.assertRaises(PolicyBlocked):
                inspect_backup_tree(root)
        with tempfile.TemporaryDirectory() as td:
            root=setup_backup(td)
            source=root/"relay"/"nonce.txt"
            source.unlink()
            target=Path(td)/"outside"
            target.write_text("public","utf-8")
            try:
                source.symlink_to(target)
            except (OSError, NotImplementedError):
                self.skipTest("symlink unavailable")
            with self.assertRaises(PolicyBlocked):
                inspect_backup_tree(root)
            self.assertEqual(target.read_text("utf-8"),"public")

    def test_no_backup_modification_exposed(self):
        import upab.relay.v3_backup_tree_acl_preview as module
        for forbidden in ("approve_backup","restore","copytree","delete",
                          "migrate","execute","set_permissions","authorize"):
            self.assertFalse(hasattr(module,forbidden))


if __name__ == "__main__":
    unittest.main()
