from __future__ import annotations

import sys
import unittest

from upab.relay.v3_policy import PolicyBlocked
from upab.relay.v3_windows_resources import (
    FILETIME, MEMORYSTATUSEX, admission_snapshot, compute_cpu_load,
    sample_windows_resources,
)


class ResourceSamplerV3Tests(unittest.TestCase):
    def test_counter_math(self):
        self.assertAlmostEqual(
            compute_cpu_load((100,200,100), (130,260,140)),70.0
        )
        self.assertEqual(
            compute_cpu_load((100,200,100), (200,300,100)),0.0
        )
        self.assertEqual(
            compute_cpu_load((100,200,100), (100,250,150)),100.0
        )

    def test_invalid_counter_intervals_denied(self):
        for before, after in (
            ((0,0,0),(0,0,0)),
            ((1,2,3),(0,5,6)),
            ((0,0,0),(20,10,0)),
            ((True,0,0),(20,30,50)),
        ):
            with self.subTest(before=before,after=after):
                with self.assertRaises(PolicyBlocked):
                    compute_cpu_load(before,after)

    def test_real_system_sample_or_explicit_platform_denial(self):
        if sys.platform != "win32":
            with self.assertRaises(PolicyBlocked):
                sample_windows_resources()
            return
        result = sample_windows_resources(interval_seconds=0.1)
        self.assertGreaterEqual(result.cpu_percent,0)
        self.assertLessEqual(result.cpu_percent,100)
        self.assertGreater(result.available_memory_mb,0)
        snapshot = admission_snapshot()
        self.assertFalse(snapshot["task_execution_enabled"])
        self.assertFalse(snapshot["owner_authorized"])
        self.assertIsInstance(snapshot["review_admission_suggested"],bool)

    def test_interval_requires_bounded_value(self):
        if sys.platform != "win32":
            self.skipTest("Windows-only duration validation")
        for value in (-1,0,3,True,"0.1"):
            with self.assertRaises(PolicyBlocked):
                sample_windows_resources(interval_seconds=value, sleep=lambda _: None)

    def test_windows_struct_contract(self):
        self.assertEqual(MEMORYSTATUSEX._fields_[0][0],"dwLength")
        self.assertEqual(len(FILETIME._fields_),2)


if __name__ == "__main__":
    unittest.main()
