from __future__ import annotations

from copy import deepcopy
import contextlib
import hashlib
import io
import json
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from unittest import mock

from upab.relay.v3_installation_baseline import _FILES
from upab.relay.v3_pinned_source_manifest import (
    SCHEMA as SOURCE_SCHEMA, REPOSITORY, canonical_manifest_bytes
)
from upab.relay.v3_policy import PolicyBlocked
from upab.relay.v3_signed_release_review import (
    SCHEMA, _DOMAIN, verify_signed_review, main
)

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
except ImportError:
    Ed25519PrivateKey = None

ROOT=Path(__file__).resolve().parents[1]
COMMIT="b"*40


def fixture(root: Path):
    checkout=root/"candidate"
    files={}
    for i,name in enumerate(_FILES):
        path=checkout/name
        path.parent.mkdir(parents=True,exist_ok=True)
        if name.endswith("watcher-v3-features.example.json"):
            shutil.copyfile(ROOT/name,path)
        else:
            path.write_bytes(("public fictional source "+str(i)).encode("utf-8"))
        wire=path.read_bytes()
        files[name]={"bytes":len(wire),"sha256":hashlib.sha256(wire).hexdigest()}
    manifest={"schema":SOURCE_SCHEMA, "repository":REPOSITORY,
              "commit":COMMIT, "files":files}
    pin=hashlib.sha256(canonical_manifest_bytes(manifest)).hexdigest()
    return checkout,manifest,pin


def signed(manifest):
    private=Ed25519PrivateKey.generate()   # Disposable synthetic test key ONLY.
    pub=private.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw)
    signature=private.sign(_DOMAIN+canonical_manifest_bytes(manifest))
    return pub.hex(),signature.hex(),hashlib.sha256(pub).hexdigest()


def run_review(checkout,manifest,manifest_pin,key,sig,key_pin,commit=COMMIT):
    return verify_signed_review(
        checkout=checkout,manifest=manifest,manifest_sha256=manifest_pin,
        expected_commit=commit,public_key_hex=key,signature_hex=sig,
        expected_public_key_sha256=key_pin
    )


@unittest.skipIf(Ed25519PrivateKey is None, "Optional maintained cryptography backend absent")
class Stage30CryptographicReleaseSignatureTests(unittest.TestCase):
    def test_valid_crypto_signature_never_becomes_owner_or_install_approval(self):
        with tempfile.TemporaryDirectory() as td:
            checkout,manifest,pin=fixture(Path(td))
            key,sig,key_pin=signed(manifest)
            before={name:(checkout/name).read_bytes() for name in _FILES}
            report=run_review(checkout,manifest,pin,key,sig,key_pin)
            self.assertEqual(report["schema"],SCHEMA)
            self.assertEqual(report["status"],
                "SIGNATURE_VALID_SIGNER_TRUST_NOT_ESTABLISHED")
            self.assertTrue(report["signature_cryptographically_valid_for_supplied_key"])
            self.assertTrue(report["source_bytes_match_signed_manifest"])
            self.assertEqual(report["source_files_observed"],6)
            self.assertEqual(report["activated_upgrade_flags"],0)
            self.assertEqual(report["registered_project_limit"],64)
            self.assertEqual(report["active_monitor_limit"],32)
            for field in (
                "trusted_owner_root_enrolled",
                "public_key_fingerprint_independently_trusted",
                "key_custody_and_revocation_verified",
                "github_commit_object_verified",
                "github_commit_signature_verified",
                "reproducible_build_verified",
                "installed_runtime_identity_verified",
                "legacy_watcher_absence_proven",
                "owner_authenticated",
                "real_device_acceptance_passed",
                "safe_to_install",
                "safe_to_migrate",
                "task_execution_authorized",
                "files_or_settings_changed",
            ):
                self.assertIs(report[field],False,field)
            self.assertEqual(before,{name:(checkout/name).read_bytes() for name in _FILES})
            for untrusted in (str(checkout), key, sig, key_pin):
                self.assertNotIn(untrusted,json.dumps(report))

    def test_wrong_public_key_is_not_accepted(self):
        with tempfile.TemporaryDirectory() as td:
            checkout,manifest,pin=fixture(Path(td))
            key,sig,key_pin=signed(manifest)
            another_key,_,another_pin=signed(manifest)
            with self.assertRaises(PolicyBlocked):
                run_review(checkout,manifest,pin,another_key,sig,another_pin)
            with self.assertRaises(PolicyBlocked):
                run_review(checkout,manifest,pin,key,sig,another_pin)

    def test_signature_binds_domain_and_exact_manifest_bytes(self):
        with tempfile.TemporaryDirectory() as td:
            checkout,manifest,pin=fixture(Path(td))
            private=Ed25519PrivateKey.generate()
            pub=private.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw)
            pin_key=hashlib.sha256(pub).hexdigest()
            wrong_domain_sig=private.sign(canonical_manifest_bytes(manifest)).hex()
            with self.assertRaises(PolicyBlocked):
                run_review(checkout,manifest,pin,pub.hex(),
                           wrong_domain_sig,pin_key)
            key,sig,key_pin=signed(manifest)
            tampered=deepcopy(manifest)
            tampered["commit"]="c"*40
            changed_pin=hashlib.sha256(canonical_manifest_bytes(tampered)).hexdigest()
            with self.assertRaises(PolicyBlocked):
                run_review(checkout,tampered,changed_pin,key,sig,key_pin,
                           commit="c"*40)

    def test_source_tamper_rejected_even_with_unmodified_signed_manifest(self):
        with tempfile.TemporaryDirectory() as td:
            checkout,manifest,pin=fixture(Path(td))
            key,sig,key_pin=signed(manifest)
            path=checkout/_FILES[0]
            path.write_bytes(path.read_bytes()+b"attacker-changed")
            with self.assertRaises(PolicyBlocked):
                run_review(checkout,manifest,pin,key,sig,key_pin)

    def test_changes_to_disabled_feature_catalog_blocked(self):
        with tempfile.TemporaryDirectory() as td:
            checkout,manifest,pin=fixture(Path(td))
            key,sig,key_pin=signed(manifest)
            path=checkout/_FILES[-1]
            flags=json.loads(path.read_text(encoding="utf-8"))
            flags["monitor_limit"]=33
            path.write_text(json.dumps(flags),encoding="utf-8")
            with self.assertRaises(PolicyBlocked):
                run_review(checkout,manifest,pin,key,sig,key_pin)

    def test_malformed_signature_key_or_commit_blocked(self):
        with tempfile.TemporaryDirectory() as td:
            checkout,manifest,pin=fixture(Path(td))
            key,sig,key_pin=signed(manifest)
            for badkey,badsig,badpin in (
                ("A"*64,sig,key_pin),
                (key,"x"*128,key_pin),
                (key,sig,"A"*64),
                (key,sig[:-2],key_pin),
                (key,"",key_pin),
                (True,sig,key_pin),
            ):
                with self.subTest(badkey=str(badkey)[:6],badsig=str(badsig)[:6]):
                    with self.assertRaises(PolicyBlocked):
                        run_review(checkout,manifest,pin,badkey,badsig,badpin)
            with self.assertRaises(PolicyBlocked):
                run_review(checkout,manifest,pin,key,sig,key_pin,commit="a"*40)

    def test_synthetic_valid_signature_does_not_allow_extra_approval_field(self):
        with tempfile.TemporaryDirectory() as td:
            checkout,manifest,pin=fixture(Path(td))
            key,sig,key_pin=signed(manifest)
            forged=deepcopy(manifest)
            forged["owner_signed"]=True
            with self.assertRaises(PolicyBlocked):
                run_review(checkout,forged,pin,key,sig,key_pin)

    def test_cli_valid_signature_returns_sanitized_receipt(self):
        with tempfile.TemporaryDirectory() as td:
            checkout,manifest,pin=fixture(Path(td))
            key,sig,key_pin=signed(manifest)
            manifest_path=Path(td)/"fixture-manifest.json"
            manifest_path.write_text(json.dumps(manifest),encoding="utf-8")
            out=io.StringIO()
            with contextlib.redirect_stdout(out):
                rc=main([
                    "--checkout",str(checkout),
                    "--manifest",str(manifest_path),
                    "--manifest-sha256",pin,
                    "--expected-commit",COMMIT,
                    "--public-key-hex",key,
                    "--signature-hex",sig,
                    "--public-key-sha256",key_pin,
                ])
            self.assertEqual(rc,0)
            self.assertFalse(json.loads(out.getvalue())["safe_to_install"])
            self.assertNotIn(str(manifest_path),out.getvalue())
            self.assertNotIn(str(checkout),out.getvalue())
            self.assertNotIn(sig,out.getvalue())


class Stage30FailClosedBackendTests(unittest.TestCase):
    def test_missing_crypto_backend_rejects_signature_not_validates_by_hash(self):
        with tempfile.TemporaryDirectory() as td:
            # This test runs when the optional backend exists. Forced missing
            # module simulates an offline owner laptop without cryptography.
            if Ed25519PrivateKey is None:
                self.skipTest("signature fixture requires backend")
            checkout,manifest,pin=fixture(Path(td))
            key,sig,key_pin=signed(manifest)
            with mock.patch.dict(sys.modules,{
                "cryptography.exceptions":None,
                "cryptography.hazmat.primitives.asymmetric.ed25519":None,
            }):
                with self.assertRaises(PolicyBlocked):
                    run_review(checkout,manifest,pin,key,sig,key_pin)

    def test_no_signing_key_registration_repo_write_or_runtime_actions(self):
        import upab.relay.v3_signed_release_review as module
        for method in (
            "create_private_key", "generate_trust_anchor", "enroll_owner",
            "install_watcher", "start_watcher", "approve", "execute_task",
            "migrate", "disable_launcher", "connect_repository", "merge",
            "sign_release", "restore_backup",
        ):
            self.assertFalse(hasattr(module,method))


if __name__=="__main__":
    unittest.main()
