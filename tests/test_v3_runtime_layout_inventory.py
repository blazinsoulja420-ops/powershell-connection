from __future__ import annotations

import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest

from upab.relay.v3_policy import PolicyBlocked
from upab.relay.v3_runtime_layout_inventory import (
    inspect_explicit_layout, main, MARKERS, SCHEMA, MAX_ROOT_CHILDREN,
)


class Stage27ExplicitRuntimeLayoutInventoryTests(unittest.TestCase):
    def test_empty_folder_is_not_installed_runtime(self):
        with tempfile.TemporaryDirectory() as td:
            candidate=Path(td)/"UPAB"
            candidate.mkdir()
            result=inspect_explicit_layout(candidate)
            self.assertEqual(result["status"],"EMPTY_DIRECTORY_NOT_INSTALLATION")
            self.assertEqual(result["top_level_entries_observed"],0)
            self.assertEqual(result["expected_markers_present"],0)
            self.assertEqual(result["expected_markers_missing"],len(MARKERS))
            self.assertFalse(result["v1_source_anchors_present"])
            self.assertFalse(result["v2_source_anchor_present"])
            self.assertFalse(result["v3_example_feature_config_present"])
            self.assertEqual(list(candidate.iterdir()),[])
            for key in (
                "source_file_content_read","private_config_or_replay_state_read",
                "source_origin_authenticated","all_installations_found",
                "installed_runtime_identified","old_watcher_running_proven",
                "old_watcher_stopped_proven","startup_launchers_disabled_proven",
                "owner_authenticated","installation_authorized",
                "migration_authorized","task_execution_authorized",
                "system_changes_performed",
            ):
                self.assertIs(result[key],False,key)

    def test_incomplete_source_checkout_is_not_authenticated(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)/"repo";root.mkdir()
            launcher=root/"scripts"/"Start-UPAB-ExactRelay.ps1"
            launcher.parent.mkdir()
            launcher.write_text("public synthetic",encoding="utf-8")
            result=inspect_explicit_layout(root)
            self.assertEqual(result["status"],"PARTIAL_SOURCE_LAYOUT_NOT_AUTHENTICATED")
            self.assertEqual(result["expected_markers_present"],1)
            self.assertFalse(result["v1_source_anchors_present"])
            self.assertFalse(result["installed_runtime_identified"])

    def test_v1_source_pattern_does_not_identify_running_process(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)/"repo";root.mkdir()
            for marker in ("scripts/Start-UPAB-ExactRelay.ps1",
                           "src/upab/relay/ledger.py"):
                path=root/marker
                path.parent.mkdir(parents=True,exist_ok=True)
                path.write_text("synthetic public",encoding="utf-8")
            result=inspect_explicit_layout(root)
            self.assertEqual(result["status"],"POSSIBLE_SOURCE_LAYOUT_NOT_AUTHENTICATED")
            self.assertTrue(result["v1_source_anchors_present"])
            self.assertFalse(result["v2_source_anchor_present"])
            self.assertFalse(result["v3_example_feature_config_present"])
            self.assertFalse(result["old_watcher_running_proven"])
            self.assertFalse(result["old_watcher_stopped_proven"])

    def test_all_markers_still_cannot_authorize(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)/"selected";root.mkdir()
            for marker in MARKERS:
                path=root/marker
                path.parent.mkdir(parents=True,exist_ok=True)
                path.write_text("synthetic public",encoding="utf-8")
            before={p.as_posix():p.read_bytes() for p in root.rglob("*") if p.is_file()}
            result=inspect_explicit_layout(root)
            self.assertEqual(result["expected_markers_present"],len(MARKERS))
            self.assertTrue(result["v2_source_anchor_present"])
            self.assertTrue(result["v3_example_feature_config_present"])
            self.assertFalse(result["source_origin_authenticated"])
            self.assertFalse(result["installed_runtime_identified"])
            self.assertFalse(result["installation_authorized"])
            self.assertFalse(result["task_execution_authorized"])
            self.assertEqual(before,{p.as_posix():p.read_bytes()
                                     for p in root.rglob("*") if p.is_file()})

    def test_unknown_file_does_not_get_opened(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)/"root";root.mkdir()
            sensitive=root/"local.json"
            sensitive.write_text("private fixture do not read",encoding="utf-8")
            report=inspect_explicit_layout(root)
            self.assertEqual(report["status"],"NO_EXPECTED_WATCHER_SOURCE_MARKERS")
            self.assertFalse(report["private_config_or_replay_state_read"])
            self.assertNotIn("private fixture",json.dumps(report))
            self.assertNotIn(str(root),json.dumps(report))

    def test_symlink_root_or_marker_is_denied(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)/"real";root.mkdir()
            link=Path(td)/"UPAB"
            try:
                link.symlink_to(root,target_is_directory=True)
            except (OSError,NotImplementedError):
                self.skipTest("Windows test runner cannot create symlink")
            with self.assertRaises(PolicyBlocked):
                inspect_explicit_layout(link)
            link.unlink()
            marker=root/"scripts"/"upab.ps1";marker.parent.mkdir()
            marker.symlink_to(root/"private.ini")
            with self.assertRaises(PolicyBlocked):
                inspect_explicit_layout(root)

    def test_bounded_entries_and_invalid_paths_fail_closed(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)/"root";root.mkdir()
            for i in range(MAX_ROOT_CHILDREN+1):
                (root/f"public-{i}").write_text("x",encoding="utf-8")
            with self.assertRaises(PolicyBlocked):
                inspect_explicit_layout(root)
            for candidate in (None, 1, "relative", Path("relative")):
                with self.subTest(candidate=candidate):
                    with self.assertRaises(PolicyBlocked):
                        inspect_explicit_layout(candidate)

    def test_cli_has_no_paths_or_private_file_contents(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)/"UPAB";root.mkdir()
            output=io.StringIO()
            with contextlib.redirect_stdout(output):
                self.assertEqual(main(["--candidate",str(root)]),0)
            data=json.loads(output.getvalue())
            self.assertEqual(data["schema"],SCHEMA)
            self.assertFalse(data["task_execution_authorized"])
            self.assertNotIn(str(root),output.getvalue())
            self.assertNotIn("nonce.txt",output.getvalue())

    def test_no_process_or_install_methods(self):
        import upab.relay.v3_runtime_layout_inventory as module
        for name in ("install","activate","run_watcher","delete_task",
                     "stop_service","kill_process","migrate","approve",
                     "connect_repository","execute_task","restore_backup"):
            self.assertFalse(hasattr(module,name))


if __name__=="__main__":
    unittest.main()
