from __future__ import annotations

import hashlib
from pathlib import Path
import tempfile
import unittest

from upab.relay.v3_migration_rehearsal import rehearse_disposable_migration
from upab.relay.v3_migration_risk_audit import audit_migration_risks
from upab.relay.v3_policy import PolicyBlocked


def hashes(folder):
    return {
        name: hashlib.sha256((Path(folder)/name).read_bytes()).hexdigest()
        for name in ("nonce.txt", "seen_tasks.jsonl")
    }


class Stage18DisposableMigrationTests(unittest.TestCase):
    def test_backup_import_marker_and_separate_rollback(self):
        with tempfile.TemporaryDirectory(prefix="upab-v3-lab-") as td:
            result = rehearse_disposable_migration(td)
            self.assertEqual(result["status"],"DISPOSABLE_REHEARSAL_COMPLETE_NO_ACTIVATION")
            for key in ("backup_checksums_match",
                        "candidate_v2_import_replay_checked",
                        "separate_restored_copy_verified", "fixture_only"):
                self.assertIs(result[key],True,key)
            for key in ("actual_v1_stopped_and_verified",
                        "migration_authorized", "real_activation_marker_written",
                        "real_files_changed", "actual_repositories_accessed",
                        "real_task_execution_allowed", "real_rollback_performed"):
                self.assertIs(result[key],False,key)
            lab=Path(td)
            source=hashes(lab/"source"/"relay")
            self.assertEqual(source,hashes(lab/"backup"/"relay"))
            self.assertEqual(source,hashes(lab/"restored"/"relay"))
            self.assertEqual(source,hashes(lab/"candidate"/"relay"))
            self.assertFalse((lab/"source"/"relay"/"v2_active.marker").exists())
            self.assertFalse((lab/"restored"/"relay"/"v2_active.marker").exists())
            self.assertTrue((lab/"candidate"/"relay"/"v2_active.marker").exists())
            self.assertTrue((lab/"candidate"/"relay"/"relay_v2.sqlite3").exists())
            self.assertEqual(audit_migration_risks(lab/"source")["legacy_record_count"],2)
            self.assertFalse(audit_migration_risks(lab/"candidate")["migration_allowed"])

    def test_fault_injections_do_not_automatically_resume_or_restore(self):
        for injection, key in (
            ("after_backup","SIMULATED_INTERRUPTED_AFTER_BACKUP"),
            ("after_v2_import","SIMULATED_INTERRUPTED_AFTER_V2_IMPORT"),
            ("after_marker","SIMULATED_INTERRUPTED_AFTER_MARKER"),
        ):
            with self.subTest(stage=injection):
                with tempfile.TemporaryDirectory(prefix="upab-v3-lab-") as td:
                    result=rehearse_disposable_migration(td,inject_at=injection)
                    self.assertEqual(result["status"],key)
                    self.assertTrue(result["injected_interruption"])
                    self.assertFalse(result["separate_restored_copy_verified"])
                    self.assertFalse(result["migration_authorized"])
                    self.assertFalse(result["real_task_execution_allowed"])
                    lab=Path(td)
                    self.assertEqual(hashes(lab/"source"/"relay"),
                                     hashes(lab/"backup"/"relay"))
                    self.assertFalse((lab/"restored").exists())
                    self.assertFalse((lab/"source"/"relay"/"v2_active.marker").exists())
                    if injection == "after_backup":
                        self.assertFalse((lab/"candidate").exists())
                    elif injection == "after_v2_import":
                        self.assertFalse((lab/"candidate"/"relay"/"v2_active.marker").exists())
                    else:
                        self.assertTrue((lab/"candidate"/"relay"/"v2_active.marker").exists())
                    with self.assertRaises(PolicyBlocked):
                        rehearse_disposable_migration(td)

    def test_nonempty_lab_and_unrelated_project_directory_refused_without_mutation(self):
        with tempfile.TemporaryDirectory(prefix="upab-v3-lab-") as td:
            existing=Path(td)/"keep.txt"
            existing.write_text("do not touch",encoding="ascii")
            with self.assertRaises(PolicyBlocked):
                rehearse_disposable_migration(td)
            self.assertEqual(existing.read_text(encoding="ascii"),"do not touch")
            self.assertEqual([p.name for p in Path(td).iterdir()],["keep.txt"])
        with tempfile.TemporaryDirectory() as base:
            fake=Path(base)/"upab-v3-lab-imitation"
            fake.mkdir()
            with self.assertRaises(PolicyBlocked):
                rehearse_disposable_migration(fake)
            self.assertEqual(list(fake.iterdir()),[])

    def test_reject_arbitrary_interruptions_and_symlinked_roots(self):
        with tempfile.TemporaryDirectory(prefix="upab-v3-lab-") as td:
            for marker in ("after_real_cutover","activate","rollback_real", "",None,True):
                with self.subTest(value=marker):
                    with self.assertRaises(PolicyBlocked):
                        rehearse_disposable_migration(td, inject_at=marker)
            self.assertEqual(list(Path(td).iterdir()), [])
            link = Path(td).parent / (Path(td).name + "-redirect")
            try:
                link.symlink_to(Path(td),target_is_directory=True)
            except (OSError,NotImplementedError):
                self.skipTest("Windows symlink creation not enabled")
            try:
                with self.assertRaises(PolicyBlocked):
                    rehearse_disposable_migration(link)
            finally:
                link.unlink()
            self.assertEqual(list(Path(td).iterdir()), [])

    def test_no_worker_executor_service_or_repo_api(self):
        import upab.relay.v3_migration_rehearsal as candidate
        for forbidden in (
            "migrate_real_state", "enable_watcher", "stop_process",
            "connect_repo", "execute_task", "approve", "deploy",
            "activate", "restore_real_state",
        ):
            self.assertFalse(hasattr(candidate,forbidden))


if __name__ == "__main__":
    unittest.main()
