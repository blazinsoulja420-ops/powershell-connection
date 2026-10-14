from __future__ import annotations

from pathlib import Path
import shutil
import sys
import tempfile
import unittest

from upab.relay.ledger import RelayLedger
from upab.relay.v3_policy import PolicyBlocked
from upab.relay.v3_windows_cutover_preflight import (
    PROGRAM_NAMES, KNOWN_REPO_LAUNCHERS, PROCESSENTRY32W,
    compare_existing_backup, snapshot_possible_host_processes,
)


def fixtures(tmp):
    source = Path(tmp) / "original"
    source.mkdir()
    ledger = RelayLedger(source)
    ledger.consume("stage19-public-record", "A"*64, ledger.current_nonce())
    backup = Path(tmp) / "saved"
    shutil.copytree(source, backup)
    return source, backup


def content_snapshot(folder):
    return sorted(
        (p.relative_to(folder).as_posix(), p.read_bytes())
        for p in Path(folder).rglob("*") if p.is_file()
    )


class Stage19Win32CutoverEvidenceTests(unittest.TestCase):
    def test_native_process_snapshot_never_claims_shutdown(self):
        if sys.platform != "win32":
            with self.assertRaises(PolicyBlocked):
                snapshot_possible_host_processes()
            return
        evidence = snapshot_possible_host_processes()
        self.assertTrue(evidence["process_snapshot_completed"])
        self.assertGreater(evidence["total_process_entries_observed"], 1)
        self.assertEqual(set(evidence["possible_host_counts"]), PROGRAM_NAMES)
        self.assertEqual(tuple(evidence["known_repo_launcher_names"]),
                         KNOWN_REPO_LAUNCHERS)
        for count in evidence["possible_host_counts"].values():
            self.assertIsInstance(count, int)
            self.assertGreaterEqual(count, 0)
        for guard in (
            "all_relevant_processes_identified",
            "candidate_process_absence_proven", "old_watcher_not_running_proven",
            "in_flight_v1_task_absence_proven", "scheduled_tasks_inventory_complete",
            "windows_services_inventory_complete",
            "registry_autostart_inventory_complete",
            "startup_shortcuts_inventory_complete",
            "old_launcher_paths_disabled_verified",
            "migration_authorized", "execution_authorized",
            "processes_stopped", "startup_modified",
        ):
            self.assertIs(evidence[guard], False, guard)
        self.assertNotIn("command_lines", evidence)
        self.assertNotIn("pids", evidence)

    @unittest.skipUnless(sys.platform == "win32", "Win32 ctypes structure only")
    def test_windows_processentry_structure_layout(self):
        from ctypes import sizeof, wintypes
        self.assertGreaterEqual(sizeof(PROCESSENTRY32W),
                                260 * sizeof(wintypes.WCHAR) + 32)

    def test_matching_backup_is_not_certified_protected_or_restorable(self):
        with tempfile.TemporaryDirectory() as td:
            source, backup = fixtures(td)
            before_source, before_backup = content_snapshot(source),content_snapshot(backup)
            result = compare_existing_backup(source_state=source,backup_state=backup)
            self.assertTrue(result["files_identical_at_sample_time"])
            self.assertEqual(result["matched_file_count"],2)
            self.assertEqual(result["mismatched_file_count"],0)
            self.assertGreater(result["bytes_hashed"],0)
            for item in ("source_quiescence_proven",
                         "backup_protected_by_verified_acl",
                         "backup_authenticity_proven", "backup_immutable",
                         "backup_restoration_test_passed",
                         "migration_authorized", "file_changes_performed"):
                self.assertIs(result[item],False,item)
            self.assertEqual(before_source,content_snapshot(source))
            self.assertEqual(before_backup,content_snapshot(backup))

    def test_backup_tampering_is_reported_without_mutation(self):
        with tempfile.TemporaryDirectory() as td:
            source, backup=fixtures(td)
            ledger=backup/"relay"/"seen_tasks.jsonl"
            ledger.write_bytes(ledger.read_bytes()+b"x")
            before=content_snapshot(backup)
            result=compare_existing_backup(source_state=source,backup_state=backup)
            self.assertFalse(result["files_identical_at_sample_time"])
            self.assertEqual(result["mismatched_file_count"],1)
            self.assertFalse(result["migration_authorized"])
            self.assertEqual(before,content_snapshot(backup))

    def test_wrong_or_nested_paths_fail_closed_without_side_effects(self):
        with tempfile.TemporaryDirectory() as td:
            source, backup=fixtures(td)
            nested=source/"nested"
            nested.mkdir()
            for args in (
                (source,source), (source,nested), (source,source/"absent"),
                (Path(td)/"missing",backup),
            ):
                with self.subTest(args=args):
                    with self.assertRaises(PolicyBlocked):
                        compare_existing_backup(
                            source_state=args[0], backup_state=args[1]
                        )
            self.assertFalse((backup/"relay"/"v2_active.marker").exists())

    def test_missing_oversized_and_redirected_files_denied(self):
        with tempfile.TemporaryDirectory() as td:
            source,backup=fixtures(td)
            b=backup/"relay"/"nonce.txt"
            b.unlink()
            with self.assertRaises(PolicyBlocked):
                compare_existing_backup(source_state=source,backup_state=backup)
            b.write_bytes(b"Z"*513)
            with self.assertRaises(PolicyBlocked):
                compare_existing_backup(source_state=source,backup_state=backup)
            b.unlink()
            outside=Path(td)/"unrelated"
            outside.write_text("unrelated protected fixture",encoding="ascii")
            try:
                b.symlink_to(outside)
            except (OSError,NotImplementedError):
                self.skipTest("symlinks unavailable on this Windows runner")
            with self.assertRaises(PolicyBlocked):
                compare_existing_backup(source_state=source,backup_state=backup)
            self.assertEqual(outside.read_text(encoding="ascii"),
                             "unrelated protected fixture")

    def test_symlinked_relay_and_parent_denied(self):
        with tempfile.TemporaryDirectory() as td:
            source,backup=fixtures(td)
            relay=backup/"relay"
            destination=Path(td)/"real-relay"
            relay.rename(destination)
            try:
                relay.symlink_to(destination,target_is_directory=True)
            except (OSError,NotImplementedError):
                self.skipTest("symlinks unavailable on Windows runner")
            with self.assertRaises(PolicyBlocked):
                compare_existing_backup(source_state=source,backup_state=backup)

    def test_no_process_stop_or_approval_api(self):
        import upab.relay.v3_windows_cutover_preflight as module
        for name in ("stop_watcher","kill_process","disable_service",
                     "disable_task","approve_migration","run_command",
                     "execute_task","deploy","restore_backup"):
            self.assertFalse(hasattr(module,name))


if __name__ == "__main__":
    unittest.main()
