from __future__ import annotations

from copy import deepcopy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from upab.relay.v3_backup_manifest_evidence import (
    SCHEMA, verify_existing_backup_manifest
)
from upab.relay.v3_policy import PolicyBlocked


def fixture(root: Path):
    parent = root / "backup"
    relay = parent / "relay"
    relay.mkdir(parents=True)
    (relay / "nonce.txt").write_bytes(b"public-fixed-test-nonce\n")
    (relay / "seen_tasks.jsonl").write_bytes(
        b'{"task_id":"public-fictional-record"}\n')
    return parent


def make_manifest(root: Path):
    files = {}
    for p in sorted((root / "relay").iterdir()):
        wire = p.read_bytes()
        files[p.name] = {"bytes": len(wire), "sha256": hashlib.sha256(wire).hexdigest()}
    manifest = {"schema":SCHEMA, "files":files}
    pin = hashlib.sha256(
        json.dumps(manifest,sort_keys=True,separators=(",",":"),ensure_ascii=True).encode("ascii")
    ).hexdigest()
    return manifest,pin


class Stage23BackupProvenanceTests(unittest.TestCase):
    def test_external_pin_and_matching_files_are_never_owner_proof(self):
        with tempfile.TemporaryDirectory() as td:
            root=fixture(Path(td))
            manifest,pin=make_manifest(root)
            before=sorted((p.name,p.read_bytes()) for p in (root/"relay").iterdir())
            report=verify_existing_backup_manifest(
                backup_state=root,manifest=manifest,pinned_manifest_sha256=pin)
            self.assertEqual(report["status"],"MATCHED_UNTRUSTED_MANIFEST_ONLY")
            self.assertEqual(report["checked_file_count"],2)
            self.assertTrue(report["external_pin_consistency_observed"])
            self.assertTrue(report["backup_snapshot_consistency_observed"])
            for item in (
                "external_pin_owner_authenticated","manifest_signed_by_trusted_authority",
                "backup_origin_authenticated","backup_acls_and_immutability_verified",
                "atomic_snapshot_proven","rollback_restore_demonstrated",
                "real_v1_quiescence_proven","live_migration_authorized",
                "live_restore_authorized","real_task_execution_authorized",
                "writes_performed",
            ):
                self.assertFalse(report[item],item)
            self.assertNotIn("pin",report)
            self.assertNotIn("path",report)
            self.assertNotIn("nonce",report)
            self.assertEqual(before,
                sorted((p.name,p.read_bytes()) for p in (root/"relay").iterdir()))

    def test_tampered_backup_rejected_even_if_external_manifest_pin_matches(self):
        with tempfile.TemporaryDirectory() as td:
            root=fixture(Path(td))
            manifest,pin=make_manifest(root)
            path=root/"relay"/"seen_tasks.jsonl"
            path.write_bytes(path.read_bytes()+b"tamper\n")
            with self.assertRaises(PolicyBlocked):
                verify_existing_backup_manifest(
                    backup_state=root, manifest=manifest,pinned_manifest_sha256=pin)

    def test_external_manifest_sha_mismatch_refused(self):
        with tempfile.TemporaryDirectory() as td:
            root=fixture(Path(td))
            manifest,pin=make_manifest(root)
            with self.assertRaises(PolicyBlocked):
                verify_existing_backup_manifest(
                    backup_state=root,manifest=manifest,pinned_manifest_sha256="f"*64)
            with self.assertRaises(PolicyBlocked):
                verify_existing_backup_manifest(
                    backup_state=root,manifest=manifest,pinned_manifest_sha256=pin.upper())

    def test_manifest_cannot_claim_approval_or_include_unknown_files(self):
        with tempfile.TemporaryDirectory() as td:
            root=fixture(Path(td))
            manifest,pin=make_manifest(root)
            variants=[]
            m=deepcopy(manifest);m["owner_approved"]=True;variants.append(m)
            m=deepcopy(manifest);m["files"]["approval.json"]={"bytes":0,"sha256":"0"*64};variants.append(m)
            m=deepcopy(manifest);m["files"]["nonce.txt"]["authorized"]=True;variants.append(m)
            m=deepcopy(manifest);m["schema"]="unknown";variants.append(m)
            m=deepcopy(manifest);m["files"].pop("nonce.txt");variants.append(m)
            m=deepcopy(manifest);m["files"]["nonce.txt"]["sha256"]="X"*64;variants.append(m)
            m=deepcopy(manifest);m["files"]["nonce.txt"]["bytes"]=True;variants.append(m)
            m=deepcopy(manifest);m["files"]["nonce.txt"]["bytes"]=99999999;variants.append(m)
            for candidate in variants:
                with self.subTest(candidate=candidate):
                    with self.assertRaises(PolicyBlocked):
                        verify_existing_backup_manifest(
                            backup_state=root,manifest=candidate,pinned_manifest_sha256=pin)

    def test_unlisted_added_backup_file_denied(self):
        with tempfile.TemporaryDirectory() as td:
            root=fixture(Path(td))
            manifest,pin=make_manifest(root)
            (root/"relay"/"unexpected_private.key").write_bytes(b"never scanned")
            with self.assertRaises(PolicyBlocked):
                verify_existing_backup_manifest(
                    backup_state=root,manifest=manifest,pinned_manifest_sha256=pin)

    def test_missing_declared_backup_file_denied(self):
        with tempfile.TemporaryDirectory() as td:
            root=fixture(Path(td))
            manifest,pin=make_manifest(root)
            (root/"relay"/"nonce.txt").unlink()
            with self.assertRaises(PolicyBlocked):
                verify_existing_backup_manifest(
                    backup_state=root,manifest=manifest,pinned_manifest_sha256=pin)

    def test_backup_root_symlink_and_nested_reparse_denied(self):
        with tempfile.TemporaryDirectory() as td:
            root=fixture(Path(td))
            manifest,pin=make_manifest(root)
            # A test symlink may be forbidden under Windows runner policy.
            link=Path(td)/"redirected"
            try:
                link.symlink_to(root,target_is_directory=True)
            except (OSError,NotImplementedError):
                self.skipTest("symlink creation unavailable")
            with self.assertRaises(PolicyBlocked):
                verify_existing_backup_manifest(
                    backup_state=link,manifest=manifest,pinned_manifest_sha256=pin)
            link.unlink()
            path=root/"relay"/"nonce.txt"
            original=path.read_bytes()
            path.unlink()
            path.symlink_to(Path(td)/"backup"/"relay"/"seen_tasks.jsonl")
            with self.assertRaises(PolicyBlocked):
                verify_existing_backup_manifest(
                    backup_state=root,manifest=manifest,pinned_manifest_sha256=pin)
            self.assertNotEqual(original,path.read_bytes())

    def test_relative_and_mixed_type_root_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            root=fixture(Path(td))
            manifest,pin=make_manifest(root)
            for candidate in (Path("relative-backup"),0,None,"../outside"):
                with self.subTest(candidate=candidate):
                    with self.assertRaises(PolicyBlocked):
                        verify_existing_backup_manifest(
                            backup_state=candidate,manifest=manifest,pinned_manifest_sha256=pin)

    def test_restore_or_execution_api_does_not_exist(self):
        import upab.relay.v3_backup_manifest_evidence as module
        for forbidden in ("restore_backup","create_backup","sign_manifest",
                          "enroll_owner","authorize","migrate","execute_task"):
            self.assertFalse(hasattr(module,forbidden))


if __name__ == "__main__":
    unittest.main()
