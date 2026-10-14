from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from upab.relay.v3_features import (
    FEATURES, load_feature_catalog, validate_feature_catalog, main
)
from upab.relay.v3_policy import PolicyBlocked


class V3FeatureRegistryTests(unittest.TestCase):
    def test_all_twelve_declared_and_disabled(self):
        path=Path(__file__).resolve().parents[1]/"config"/"watcher-v3-features.example.json"
        report=load_feature_catalog(path)
        self.assertEqual(report["registered_upgrades"],12)
        self.assertEqual(report["project_limit"],64)
        self.assertEqual(report["monitor_limit"],32)
        self.assertEqual(report["activated_upgrades"],0)
        self.assertEqual(set(report["stages"]),set(FEATURES))
        self.assertFalse(report["execution_enabled"])
        self.assertEqual(main(["--config",str(path)]),0)

    def test_cannot_enable_a_feature_or_expand_limits(self):
        source=json.loads(
            (Path(__file__).resolve().parents[1]/"config"/"watcher-v3-features.example.json").read_text()
        )
        source["features"][0]["enabled"]=True
        with self.assertRaises(PolicyBlocked):
            validate_feature_catalog(source)
        source["features"][0]["enabled"]=False
        source["project_limit"]=1000
        with self.assertRaises(PolicyBlocked):
            validate_feature_catalog(source)
        source["project_limit"]=64
        source["auto_activation"]=True
        with self.assertRaises(PolicyBlocked):
            validate_feature_catalog(source)

    def test_missing_or_duplicate_feature_is_denied(self):
        source=json.loads(
            (Path(__file__).resolve().parents[1]/"config"/"watcher-v3-features.example.json").read_text()
        )
        source["features"][0]["id"]=source["features"][1]["id"]
        with self.assertRaises(PolicyBlocked):
            validate_feature_catalog(source)

    def test_duplicate_json_keys_and_corruption_are_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            path=Path(td)/"bad.json"
            path.write_text('{"schema":"A","schema":"B"}',encoding="utf-8")
            with self.assertRaises(PolicyBlocked):
                load_feature_catalog(path)
            path.write_text("{invalid",encoding="utf-8")
            self.assertEqual(main(["--config",str(path)]),7)


if __name__ == "__main__":
    unittest.main()
