from __future__ import annotations

import hashlib
import tempfile
import unittest
from pathlib import Path

from upab.relay.v3_policy import PolicyBlocked
from upab.relay.v3_release_guard import rollback_preview, verify_release_preview


class ReleaseGuardV3Tests(unittest.TestCase):
    def test_match_does_not_authorize_install(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            item=root/"src"/"sample.txt"
            item.parent.mkdir()
            item.write_text("verified candidate bytes",encoding="utf-8")
            digest=hashlib.sha256(item.read_bytes()).hexdigest()
            manifest={"schema":"upab.watcher.release-preview.v1","files":{"src/sample.txt":digest}}
            receipt=verify_release_preview(root,manifest)
            self.assertTrue(receipt["contents_match_manifest"])
            self.assertFalse(receipt["manifest_authenticated"])
            self.assertFalse(receipt["authorized_to_install"])
            self.assertFalse(receipt["performed_changes"])
            item.write_text("unexpected modification",encoding="utf-8")
            changed=verify_release_preview(root,manifest)
            self.assertFalse(changed["contents_match_manifest"])
            self.assertEqual(changed["mismatches"],["src/sample.txt"])

    def test_missing_paths_and_path_traversal(self):
        with tempfile.TemporaryDirectory() as tmp:
            expected="A"*64
            base={"schema":"upab.watcher.release-preview.v1","files":{}}
            for path in ("../outside", "/etc/passwd", r"..\evil", "src//file", "src/./file"):
                with self.subTest(path=path):
                    base["files"]={path:expected}
                    with self.assertRaises(PolicyBlocked):
                        verify_release_preview(tmp,base)
            base["files"]={"missing.txt":expected}
            self.assertFalse(verify_release_preview(tmp,base)["contents_match_manifest"])

    def test_bad_schema_digest_or_missing_manifest(self):
        with tempfile.TemporaryDirectory() as tmp:
            for item in (
                {},
                {"schema":"evil","files":{"a.txt":"A"*64}},
                {"schema":"upab.watcher.release-preview.v1","files":{}},
                {"schema":"upab.watcher.release-preview.v1","files":{"a.txt":"no"}},
            ):
                with self.subTest(item=item):
                    with self.assertRaises(PolicyBlocked):
                        verify_release_preview(tmp,item)

    def test_rollback_is_always_review_only(self):
        plan=rollback_preview()
        self.assertEqual(plan["status"],"REVIEW_ONLY")
        self.assertFalse(plan["performed_changes"])
        self.assertFalse(plan["rollback_authorized"])
        self.assertGreaterEqual(len(plan["requirements"]),5)


if __name__ == "__main__":
    unittest.main()
