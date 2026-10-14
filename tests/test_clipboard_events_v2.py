from __future__ import annotations

import unittest

from upab.relay.clipboard_events_v2 import (
    ClipboardEventError,
    ClipboardTooLarge,
    PassiveClipboardObserver,
    WindowsClipboardEvents,
)
from upab.relay.schema import TASK_BEGIN, TASK_END
from upab.relay.clipboard import MemoryClipboard


class FakeBoundedClipboard:
    def __init__(self, text: str = ""):
        self.text = text
        self.failures = 0
        self.reads = 0
        self.bounds = []

    def get_text_limited(self, max_chars: int) -> str:
        self.bounds.append(max_chars)
        self.reads += 1
        if self.failures:
            self.failures -= 1
            raise OSError("clipboard busy")
        if len(self.text) > max_chars:
            raise ClipboardTooLarge("oversize")
        return self.text


class ClipboardObserverV2Tests(unittest.TestCase):
    def test_startup_snapshot_is_never_executed(self):
        old_task = TASK_BEGIN + "\n{}\n" + TASK_END
        clipboard = FakeBoundedClipboard(old_task)
        observer = PassiveClipboardObserver(clipboard, sleep=lambda _: None)
        self.assertEqual(observer.suppress_startup().kind, "STARTUP_SUPPRESSED")
        self.assertEqual(observer.counts["candidates"], 0)
        self.assertEqual(observer.on_change().kind, "DUPLICATE_IGNORED")
        self.assertEqual(observer.counts["events"], 1)
        self.assertEqual(observer.counts["candidates"], 0)

    def test_recognizes_task_candidate_without_parsing_or_execution(self):
        clipboard = FakeBoundedClipboard("original")
        observer = PassiveClipboardObserver(clipboard, sleep=lambda _: None)
        observer.suppress_startup()
        clipboard.text = TASK_BEGIN + "\nNOT JSON OR AUTHORIZED\n" + TASK_END
        self.assertEqual(observer.on_change().kind, "TASK_CANDIDATE_OBSERVED")
        self.assertEqual(observer.counts["candidates"], 1)
        self.assertEqual(observer.on_change().kind, "DUPLICATE_IGNORED")
        self.assertEqual(observer.counts["duplicates"], 1)

    def test_ordinary_clipboard_content_never_becomes_a_task(self):
        clipboard = FakeBoundedClipboard("a")
        observer = PassiveClipboardObserver(clipboard, sleep=lambda _: None)
        observer.suppress_startup()
        clipboard.text = "ignore this"
        self.assertEqual(observer.on_change().kind, "NON_TASK_IGNORED")
        self.assertEqual(observer.counts["ignored"], 1)
        self.assertNotIn("ignore this", repr(observer.counts))

    def test_bounded_transient_retries(self):
        clipboard = FakeBoundedClipboard("startup")
        observer = PassiveClipboardObserver(
            clipboard, attempts=3, retry_delay_seconds=0.025,
            sleep=lambda x: delays.append(x),
        )
        delays = []
        observer.suppress_startup()
        clipboard.text = "next"
        clipboard.failures = 2
        self.assertEqual(observer.on_change().kind, "NON_TASK_IGNORED")
        self.assertEqual(delays, [0.025, 0.05])
        self.assertEqual(observer.counts["read_errors"], 0)
        self.assertEqual(clipboard.reads, 4)

    def test_failure_does_not_advance_digest_and_can_recover(self):
        clipboard = FakeBoundedClipboard("init")
        observer = PassiveClipboardObserver(clipboard, attempts=2, sleep=lambda _: None)
        observer.suppress_startup()
        clipboard.text = TASK_BEGIN + "\n{}\n" + TASK_END
        clipboard.failures = 2
        event = observer.on_change()
        self.assertEqual(event.kind, "READ_UNAVAILABLE")
        self.assertTrue(event.retryable)
        self.assertEqual(observer.counts["read_errors"], 1)
        self.assertEqual(observer.on_change().kind, "TASK_CANDIDATE_OBSERVED")

    def test_oversized_payload_ignored_without_hashing(self):
        clipboard = FakeBoundedClipboard("start")
        observer = PassiveClipboardObserver(
            clipboard, max_text_chars=256, sleep=lambda _: None
        )
        observer.suppress_startup()
        clipboard.text = TASK_BEGIN + ("x" * 1024) + TASK_END
        self.assertEqual(observer.on_change().kind, "OVERSIZE_IGNORED")
        self.assertEqual(observer.counts["too_large"], 1)
        self.assertEqual(clipboard.bounds, [256, 256])

    def test_no_processing_without_startup_snapshot(self):
        clipboard = FakeBoundedClipboard("anything")
        observer = PassiveClipboardObserver(clipboard)
        with self.assertRaisesRegex(ClipboardEventError, "startup snapshot"):
            observer.on_change()

    def test_observer_allows_only_bounded_settings(self):
        for bad in (1, 255, 1048577, "unbounded"):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    PassiveClipboardObserver(FakeBoundedClipboard(), max_text_chars=bad)
        for bad in (0, 6, "3"):
            with self.subTest(attempts=bad):
                with self.assertRaises(ValueError):
                    PassiveClipboardObserver(FakeBoundedClipboard(), attempts=bad)

    def test_no_mutation_hook_or_pipeline(self):
        observer = PassiveClipboardObserver(MemoryClipboard("safe"))
        self.assertFalse(hasattr(observer, "execute_task"))
        self.assertFalse(hasattr(observer, "pipeline"))
        self.assertFalse(hasattr(observer, "set_text"))

    def test_clipboard_event_source_requires_windows(self):
        import sys
        if sys.platform != "win32":
            with self.assertRaises(ClipboardEventError):
                WindowsClipboardEvents()


if __name__ == "__main__":
    unittest.main()
