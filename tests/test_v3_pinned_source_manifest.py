from __future__ import annotations

from copy import deepcopy
import contextlib
import hashlib
import io
import json
from pathlib import Path
import shutil
import tempfile
import unittest

from upab.relay.v3_installation_baseline import _FILES
from upab.relay.v3_pinned_source_manifest import (
    SCHEMA, REPOSITORY, canonical_manifest_bytes,
    compare_selected_checkout, main,
)
from upab.relay.v3_policy import PolicyBlocked

ROOT=Path(__file__).resolve().parents[1]
FIXED_COMMIT="a" * 40


def fixture(root: Path) -> tuple[Path, dict, str]:
    checkout=root/"candidate"
    for i, name in enumerate(_FILES):
        path=checkout/name
        path.parent.mkdir(parents=True, exist_ok=True)
        if name.endswith(".json"):
            shutil.copyfile(ROOT/name, path)
        else:
            path.write_bytes(("synthetic public source "+str(i)+"\n").encode())
    files={}
    for name in _FILES:
        data=(checkout/name).read_bytes()
        files[name]={"bytes":len(data),"sha256":hashlib.sha256(data).hexdigest()}
    manifest={"schema":SCHEMA,"repository":REPOSITORY,
              "commit":FIXED_COMMIT,"files":files}
    return checkout,manifest,hashlib.sha256(canonical_manifest_bytes(manifest)).hexdigest()


def verify(checkout: Path, manifest: dict, digest: str, commit: str = FIXED_COMMIT):
    return compare_selected_checkout(
        checkout=checkout, manifest=manifest,
        manifest_sha256=digest, expected_commit=commit
    )


class Stage29PinnedSourceManifestTests(unittest.TestCase):
    def test_six_file_match_remains_unauthenticated_and_non_authorizing(self):
        with tempfile.TemporaryDirectory() as td:
            checkout,manifest,digest=fixture(Path(td))
            before={key:(checkout/key).read_bytes() for key in _FILES}
            result=verify(checkout,manifest,digest)
            self.assertEqual(result["status"],
                "FILE_MATCH_TO_UNAUTHENTICATED_REVIEWER_MANIFEST")
            self.assertEqual(result["files_observed"],len(_FILES))
            self.assertEqual(result["twelve_upgrade_flags_enabled"],0)
            self.assertEqual(result["project_registration_limit"],64)
            self.assertEqual(result["active_monitor_limit"],32)
            self.assertTrue(result["file_bytes_match_manifest"])
            for key in (
                "git_commit_object_validated",
                "github_commit_signature_verified",
                "reviewer_pin_cryptographically_authenticated",
                "owner_authenticated",
                "selected_checkout_is_active_installation_proven",
                "legacy_process_shutdown_proven",
                "safe_to_promote",
                "safe_to_install",
                "safe_to_migrate",
                "task_execution_authorized",
                "files_changed",
            ):
                self.assertIs(result[key],False,key)
            self.assertEqual(before,{key:(checkout/key).read_bytes() for key in _FILES})
            self.assertNotIn(str(checkout),json.dumps(result))
            self.assertNotIn(digest,json.dumps(result))

    def test_mismatch_in_single_source_byte_fails_closed(self):
        with tempfile.TemporaryDirectory() as td:
            checkout,manifest,digest=fixture(Path(td))
            selected=checkout/_FILES[0]
            selected.write_bytes(selected.read_bytes()+b"changed")
            with self.assertRaises(PolicyBlocked):
                verify(checkout,manifest,digest)

    def test_forged_expected_commit_or_manifest_pin_is_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            checkout,manifest,digest=fixture(Path(td))
            for wrong_commit in ("b"*40,FIXED_COMMIT.upper(),"x"*40):
                with self.subTest(commit=wrong_commit):
                    with self.assertRaises(PolicyBlocked):
                        verify(checkout,manifest,digest,wrong_commit)
            for wrong_pin in ("0"*64,"F"*64,"",True):
                with self.subTest(pin=wrong_pin):
                    with self.assertRaises(PolicyBlocked):
                        verify(checkout,manifest,wrong_pin)

    def test_forged_metadata_extra_paths_and_authority_fields_denied(self):
        with tempfile.TemporaryDirectory() as td:
            checkout,manifest,digest=fixture(Path(td))
            alternatives=[]
            a=deepcopy(manifest);a["owner_approved"]=True;alternatives.append(a)
            a=deepcopy(manifest);a["repository"]="different/repo";alternatives.append(a)
            a=deepcopy(manifest);a["files"]["config/local.json"]={
                "bytes":5,"sha256":"0"*64
            };alternatives.append(a)
            a=deepcopy(manifest);a["files"].pop(_FILES[0]);alternatives.append(a)
            a=deepcopy(manifest);a["files"][_FILES[0]]["approved"]=True;alternatives.append(a)
            a=deepcopy(manifest);a["files"][_FILES[0]]["bytes"]=True;alternatives.append(a)
            a=deepcopy(manifest);a["files"][_FILES[0]]["sha256"]="A"*64;alternatives.append(a)
            a=deepcopy(manifest);a["schema"]="unrecognized";alternatives.append(a)
            for candidate in alternatives:
                with self.subTest(candidate=str(candidate)[:90]):
                    with self.assertRaises(PolicyBlocked):
                        verify(checkout,candidate,digest)

    def test_replacement_manifest_cannot_pass_old_pin(self):
        with tempfile.TemporaryDirectory() as td:
            checkout,manifest,digest=fixture(Path(td))
            tampered=deepcopy(manifest)
            tampered["files"][_FILES[0]]["sha256"]="b"*64
            with self.assertRaises(PolicyBlocked):
                verify(checkout,tampered,digest)

    def test_disabled_upgrade_invariants_survive_match_precheck(self):
        with tempfile.TemporaryDirectory() as td:
            checkout,manifest,digest=fixture(Path(td))
            features=checkout/_FILES[-1]
            original=json.loads(features.read_text(encoding="utf-8"))
            original["project_limit"]=65
            features.write_text(json.dumps(original),encoding="utf-8")
            with self.assertRaises(PolicyBlocked):
                verify(checkout,manifest,digest)

    def test_missing_file_and_unexpected_symlink_denied(self):
        with tempfile.TemporaryDirectory() as td:
            checkout,manifest,digest=fixture(Path(td))
            path=checkout/_FILES[1]
            path.unlink()
            with self.assertRaises(PolicyBlocked):
                verify(checkout,manifest,digest)
        with tempfile.TemporaryDirectory() as td:
            checkout,manifest,digest=fixture(Path(td))
            path=checkout/_FILES[0]
            path.unlink()
            outside=Path(td)/"public-different-file"
            outside.write_text("synthetic",encoding="utf-8")
            try:
                path.symlink_to(outside)
            except (OSError,NotImplementedError):
                self.skipTest("symlink privileges unavailable")
            with self.assertRaises(PolicyBlocked):
                verify(checkout,manifest,digest)
            self.assertEqual(outside.read_text(encoding="utf-8"),"synthetic")

    def test_cli_does_not_export_selected_paths_or_manifest_contents(self):
        with tempfile.TemporaryDirectory() as td:
            checkout,manifest,digest=fixture(Path(td))
            manifest_path=Path(td)/"manifest.json"
            manifest_path.write_text(json.dumps(manifest),encoding="utf-8")
            stdout=io.StringIO()
            with contextlib.redirect_stdout(stdout):
                result=main([
                    "--checkout",str(checkout),
                    "--manifest",str(manifest_path),
                    "--manifest-sha256",digest,
                    "--expected-commit",FIXED_COMMIT,
                ])
            self.assertEqual(result,0)
            output=stdout.getvalue()
            data=json.loads(output)
            self.assertFalse(data["task_execution_authorized"])
            self.assertNotIn(str(checkout),output)
            self.assertNotIn(str(manifest_path),output)
            self.assertNotIn(digest,output)

    def test_manifest_file_missing_or_redirected_denied(self):
        with tempfile.TemporaryDirectory() as td:
            checkout,manifest,digest=fixture(Path(td))
            with contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(
                    main(["--checkout",str(checkout),
                          "--manifest",str(Path(td)/"not-found.json"),
                          "--manifest-sha256",digest,
                          "--expected-commit",FIXED_COMMIT]),7)

    def test_no_install_restore_or_execution_api(self):
        import upab.relay.v3_pinned_source_manifest as m
        for function in (
            "install","activate","stop_process","stop_service","restore",
            "migrate","approve","sign_source","connect_repo","execute_task",
            "merge_pull_request","enroll_owner",
        ):
            self.assertFalse(hasattr(m,function))


if __name__=="__main__":
    unittest.main()
