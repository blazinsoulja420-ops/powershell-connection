from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from upab.relay.v3_diagnostics import BoundedDiagnosticLog
from upab.relay.v3_policy import PolicyBlocked


class V3DiagnosticsTests(unittest.TestCase):
    def test_bounded_rotation_and_no_free_text(self):
        with tempfile.TemporaryDirectory() as td:
            log=BoundedDiagnosticLog(td,max_bytes=1024,archives=2)
            for i in range(80):
                log.record("health_sample",elapsed_ms=i)
            inventory=log.inventory()
            self.assertGreater(inventory["files"],1)
            self.assertLessEqual(inventory["total_bytes"],3072)
            self.assertFalse(inventory["content_logging_enabled"])
            for f in (Path(td)/"relay").glob("v3_diagnostics.jsonl*"):
                for line in f.read_text(encoding="utf-8").splitlines():
                    obj=json.loads(line)
                    self.assertEqual(set(obj),{"event","elapsed_ms","timestamp_utc"})
                    self.assertEqual(obj["event"],"health_sample")

    def test_reject_sensitive_or_arbitrary_event_fields(self):
        with tempfile.TemporaryDirectory() as td:
            log=BoundedDiagnosticLog(td)
            for bad in ("api_key=TOPSECRET","task payload: sensitive","run_command"):
                with self.assertRaises(PolicyBlocked):
                    log.record(bad)
            for ms in (-1,3600001,"3",True):
                with self.assertRaises(PolicyBlocked):
                    log.record("health_sample",elapsed_ms=ms)
            self.assertEqual(log.inventory()["files"],0)

    def test_configuration_bounds_and_idle_inventory(self):
        with tempfile.TemporaryDirectory() as td:
            for size in (512,1048577,True):
                with self.assertRaises(PolicyBlocked):
                    BoundedDiagnosticLog(td,max_bytes=size)
            for count in (0,6,True):
                with self.assertRaises(PolicyBlocked):
                    BoundedDiagnosticLog(td,archives=count)
            self.assertEqual(BoundedDiagnosticLog(td).inventory()["total_bytes"],0)


if __name__ == "__main__":
    unittest.main()
