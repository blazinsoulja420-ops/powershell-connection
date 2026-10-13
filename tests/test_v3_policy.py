from __future__ import annotations

import unittest

from upab.relay.v3_policy import (
    HeartbeatWatchdog, PolicyBlocked, ResourceSample, ReviewJob,
    ReviewScheduler, SanitizedMetrics, retry_delay_seconds,
    review_admission_allowed, validate_inbox_preview,
)


def job(name, *, priority=1, deps=()):
    return ReviewJob(task_id=name, digest="A"*64, priority=priority, dependencies=deps)


class WatcherV3PolicyTests(unittest.TestCase):
    def test_priority_dependency_and_single_review(self):
        queue = ReviewScheduler(capacity=4)
        queue.add(job("root", priority=0))
        queue.add(job("dependent", priority=3, deps=("root",)))
        queue.add(job("other", priority=1))
        self.assertEqual(queue.choose_for_review(), "other")
        self.assertIsNone(queue.choose_for_review())
        queue.finish_review("other")
        self.assertEqual(queue.choose_for_review(), "root")
        queue.finish_review("root")
        self.assertEqual(queue.choose_for_review(), "dependent")
        self.assertFalse(queue.snapshot()["execution_authorized"])

    def test_unknown_dependency_and_duplicates_are_denied(self):
        queue = ReviewScheduler()
        with self.assertRaises(PolicyBlocked):
            queue.add(job("a", deps=("nonexistent",)))
        queue.add(job("a"))
        with self.assertRaises(PolicyBlocked):
            queue.add(job("a"))
        with self.assertRaises(PolicyBlocked):
            queue.finish_review("a")
        self.assertEqual(queue.choose_for_review(), "a")
        self.assertEqual(queue.interrupted(), "a")
        self.assertIsNone(queue.choose_for_review())

    def test_capacity_32_and_bounded_settings(self):
        queue = ReviewScheduler(capacity=32)
        for i in range(32):
            queue.add(job("id-"+str(i)))
        with self.assertRaises(PolicyBlocked):
            queue.add(job("overflow"))
        self.assertEqual(queue.snapshot()["queued"], 32)
        for bad in (0,33,True,1.5):
            with self.assertRaises(PolicyBlocked):
                ReviewScheduler(capacity=bad)

    def test_invalid_review_items_are_denied(self):
        for kwargs in (
            {"task_id": "../bad", "digest":"A"*64},
            {"task_id":"good", "digest":"no"},
            {"task_id":"good", "digest":"A"*64, "priority":9},
            {"task_id":"good", "digest":"A"*64, "dependencies":("good",)},
            {"task_id":"good", "digest":"A"*64, "dependencies":("x","x")},
        ):
            with self.subTest(kwargs=kwargs):
                with self.assertRaises(PolicyBlocked):
                    ReviewJob(**kwargs)

    def test_resources_fail_closed_and_cannot_grant_authority(self):
        self.assertFalse(review_admission_allowed(None))
        self.assertFalse(review_admission_allowed(ResourceSample(90, 900)))
        self.assertFalse(review_admission_allowed(ResourceSample(10, 500)))
        self.assertTrue(review_admission_allowed(ResourceSample(20, 1000)))
        for cpu,mb in ((-1,1000),(101,1000),(float("nan"),1000),(10,-1)):
            with self.assertRaises(PolicyBlocked):
                ResourceSample(cpu,mb)

    def test_retry_only_safe_read_failures_and_bounded(self):
        self.assertEqual(retry_delay_seconds("clipboard_read_busy",1),0.1)
        self.assertEqual(retry_delay_seconds("clipboard_read_busy",2),0.2)
        self.assertIsNone(retry_delay_seconds("clipboard_read_busy",3))
        for kind in ("write_file","git_push","run_powershell","random", ""):
            self.assertIsNone(retry_delay_seconds(kind,1))
        with self.assertRaises(PolicyBlocked):
            retry_delay_seconds("clipboard_read_busy",0)

    def test_watchdog_is_observational(self):
        watch = HeartbeatWatchdog(max_silence_seconds=5)
        self.assertEqual(watch.status(now=10), "NOT_STARTED")
        watch.beat(now=10)
        self.assertEqual(watch.status(now=15), "HEALTHY")
        self.assertEqual(watch.status(now=15.001), "STALE_NEEDS_REVIEW")
        self.assertEqual(watch.status(now=9), "CLOCK_INVALID")
        self.assertFalse(hasattr(watch,"restart"))
        self.assertFalse(hasattr(watch,"kill"))

    def test_telemetry_allowlist_and_no_content(self):
        metrics=SanitizedMetrics()
        metrics.record("notification")
        self.assertEqual(metrics.snapshot()["counters"]["notification"],1)
        with self.assertRaises(PolicyBlocked):
            metrics.record("secret=private-value")
        self.assertFalse(metrics.snapshot()["contains_task_content"])

    def test_inbox_preview_never_authenticates(self):
        payload={"schema":"upab.inbox.preview.v1","task_id":"task-a","digest":"A"*64}
        preview=validate_inbox_preview(payload)
        self.assertFalse(preview["authenticated"])
        self.assertFalse(preview["authorized"])
        self.assertFalse(preview["execution_allowed"])
        for forged in (
            dict(payload,approved=True),
            dict(payload,principal="owner"),
            {"schema":"upab.inbox.preview.v1","task_id":"../bad","digest":"A"*64},
        ):
            with self.assertRaises(PolicyBlocked):
                validate_inbox_preview(forged)


if __name__ == "__main__":
    unittest.main()
