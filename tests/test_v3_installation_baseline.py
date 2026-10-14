from __future__ import annotations

import contextlib
import io
import json
from pathlib import Path
import shutil
import tempfile
import unittest

from upab.relay.v3_installation_baseline import (
    _FILES, _FILE_LIMIT, inspect_checkout_baseline, main
)
from upab.relay.v3_policy import PolicyBlocked

PROJECT = Path(__file__).resolve().parents[1]


def fixture(root: Path):
    checkout = root / "selected"
    for index, relative in enumerate(_FILES):
        target = checkout.joinpath(*relative.split("/"))
        target.parent.mkdir(parents=True, exist_ok=True)
        if relative.endswith("watcher-v3-features.example.json"):
            shutil.copyfile(PROJECT / relative, target)
        else:
            target.write_text("synthetic public launcher file " + str(index),
                              encoding="utf-8")
    return checkout


class Stage26ExplicitInstallationBaselineTests(unittest.TestCase):
    def test_explicit_checkout_is_fingerprint_only_never_installer(self):
        with tempfile.TemporaryDirectory() as td:
            root = fixture(Path(td))
            before = {name:(root / name).read_bytes() for name in _FILES}
            report = inspect_checkout_baseline(root)
            again = inspect_checkout_baseline(root)
            self.assertEqual(report, again)
            self.assertEqual(report["allowlisted_files_observed"], 6)
            self.assertEqual(report["feature_flags_enabled"], 0)
            self.assertEqual(report["registered_project_limit"], 64)
            self.assertEqual(report["active_monitored_folder_limit"], 32)
            self.assertIsNone(report["supplied_fingerprint_matches"])
            self.assertEqual(len(report["source_fingerprint_sha256"]),64)
            for guard in (
                "all_possible_launchers_observed",
                "source_origin_authenticated",
                "external_fingerprint_owner_authenticated",
                "actual_installation_identified",
                "live_watcher_running_proven",
                "old_watcher_stopped_proven",
                "owner_approval_issued",
                "safe_to_install",
                "safe_to_migrate",
                "task_execution_authorized",
                "files_changed",
            ):
                self.assertIs(report[guard], False, guard)
            self.assertNotIn(str(root), json.dumps(report))
            self.assertEqual(before,
                             {name:(root / name).read_bytes() for name in _FILES})

    def test_matching_or_mismatching_caller_supplied_pin_stays_untrusted(self):
        with tempfile.TemporaryDirectory() as td:
            root = fixture(Path(td))
            digest = inspect_checkout_baseline(root)["source_fingerprint_sha256"]
            match = inspect_checkout_baseline(root, supplied_fingerprint=digest)
            self.assertTrue(match["supplied_fingerprint_matches"])
            self.assertFalse(match["safe_to_install"])
            self.assertFalse(match["source_origin_authenticated"])
            wrong = "0"*64 if digest != "0"*64 else "1"*64
            mismatch = inspect_checkout_baseline(root, supplied_fingerprint=wrong)
            self.assertFalse(mismatch["supplied_fingerprint_matches"])
            self.assertFalse(mismatch["task_execution_authorized"])

    def test_source_byte_change_is_detected_by_fingerprint(self):
        with tempfile.TemporaryDirectory() as td:
            root = fixture(Path(td))
            previous=inspect_checkout_baseline(root)["source_fingerprint_sha256"]
            path=root / _FILES[0]
            path.write_bytes(path.read_bytes()+b"\nmodified synthetic code")
            fresh=inspect_checkout_baseline(root, supplied_fingerprint=previous)
            self.assertFalse(fresh["supplied_fingerprint_matches"])
            self.assertNotEqual(previous, fresh["source_fingerprint_sha256"])

    def test_feature_enabled_project_limit_and_unknown_stage_rejected(self):
        for mutant in ("feature", "project", "monitor", "stage", "name"):
            with self.subTest(mutant=mutant):
                with tempfile.TemporaryDirectory() as td:
                    root = fixture(Path(td))
                    path=root / _FILES[-1]
                    data=json.loads(path.read_text(encoding="utf-8"))
                    if mutant=="feature":
                        data["features"][0]["enabled"]=True
                    elif mutant=="project":
                        data["project_limit"]=65
                    elif mutant=="monitor":
                        data["monitor_limit"]=33
                    elif mutant=="stage":
                        data["features"][0]["stage"]="activated"
                    elif mutant=="name":
                        data["features"][0]["id"]="unreviewed_new_provider"
                    path.write_text(json.dumps(data),encoding="utf-8")
                    with self.assertRaises(PolicyBlocked):
                        inspect_checkout_baseline(root)

    def test_missing_files_symlink_and_large_files_fail_closed(self):
        with tempfile.TemporaryDirectory() as td:
            root=fixture(Path(td))
            missing=root / _FILES[0]
            missing.unlink()
            with self.assertRaises(PolicyBlocked):
                inspect_checkout_baseline(root)
        with tempfile.TemporaryDirectory() as td:
            root=fixture(Path(td))
            huge=root / _FILES[1]
            with huge.open("wb") as f:
                f.truncate(_FILE_LIMIT+1)
            with self.assertRaises(PolicyBlocked):
                inspect_checkout_baseline(root)
        with tempfile.TemporaryDirectory() as td:
            root=fixture(Path(td))
            path=root / _FILES[0]
            data=path.read_bytes()
            path.unlink()
            outside=Path(td)/"outside"
            outside.write_bytes(data)
            try:
                path.symlink_to(outside)
            except (OSError,NotImplementedError):
                self.skipTest("symlink creation unavailable")
            with self.assertRaises(PolicyBlocked):
                inspect_checkout_baseline(root)
            self.assertEqual(data,outside.read_bytes())

    def test_reject_unknown_paths_and_invalid_fingerprints(self):
        with tempfile.TemporaryDirectory() as td:
            root=fixture(Path(td))
            for supplied in ("", "F"*64, True, 1, "0"*63):
                with self.subTest(supplied=supplied):
                    with self.assertRaises(PolicyBlocked):
                        inspect_checkout_baseline(root,supplied_fingerprint=supplied)
            for selected in (None, 0, "not-absolute", Path("relative")):
                with self.subTest(root=selected):
                    with self.assertRaises(PolicyBlocked):
                        inspect_checkout_baseline(selected)

    def test_read_only_cli_outputs_no_secret_state_or_authority(self):
        with tempfile.TemporaryDirectory() as td:
            root=fixture(Path(td))
            output=io.StringIO()
            with contextlib.redirect_stdout(output):
                self.assertEqual(main(["--checkout",str(root)]),0)
            data=json.loads(output.getvalue())
            self.assertFalse(data["task_execution_authorized"])
            self.assertFalse(data["files_changed"])
            self.assertNotIn(str(root),output.getvalue())
            self.assertNotIn("nonce.txt",output.getvalue())

    def test_does_not_expose_installer_or_process_stop(self):
        import upab.relay.v3_installation_baseline as module
        for forbidden in (
            "run_watcher","install","migrate","stop_service","kill_process",
            "approve","activate","connect_repo","deploy","copy_backup",
        ):
            self.assertFalse(hasattr(module,forbidden))


if __name__ == "__main__":
    unittest.main()
