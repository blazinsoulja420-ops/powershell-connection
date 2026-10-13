from __future__ import annotations

import sys
import unittest
import uuid

from upab.relay.clipboard import ClipboardError, WindowsClipboard
from upab.relay.clipboard_events_v2 import (
    ClipboardEventError,
    PassiveClipboardObserver,
    WindowsClipboardEvents,
)
from upab.relay.clipboard_limited_v2 import BoundedWindowsClipboard


@unittest.skipUnless(sys.platform == "win32", "Win32 clipboard only")
class NativeWindowsClipboardV2Tests(unittest.TestCase):
    def test_native_event_and_limited_snapshot(self):
        # Disposable Windows CI desktop. Skip only when OS does not expose
        # an interactive clipboard; this test never executes relay tasks.
        try:
            clipboard = WindowsClipboard()
            bounded = BoundedWindowsClipboard()
            before = clipboard.get_text()
            with WindowsClipboardEvents() as source:
                observer = PassiveClipboardObserver(bounded)
                observer.suppress_startup()
                marker = "UPAB-V2-TEST-" + uuid.uuid4().hex
                clipboard.set_text(marker)
                saw_event = False
                for _ in range(20):
                    if source.wait_for_change(250):
                        saw_event = True
                        break
                self.assertTrue(saw_event, "Win32 listener missed clipboard change")
                self.assertEqual(bounded.get_text_limited(256), marker)
                self.assertEqual(observer.on_change().kind, "NON_TASK_IGNORED")
                self.assertEqual(observer.on_change().kind, "DUPLICATE_IGNORED")
        except (ClipboardEventError, ClipboardError) as exc:
            self.skipTest("CI session has no interactive clipboard: " + type(exc).__name__)
        finally:
            try:
                clipboard.set_text(before)
            except (UnboundLocalError, ClipboardError, OSError):
                pass

    def test_native_single_instance_denied_and_released(self):
        try:
            with WindowsClipboardEvents():
                with self.assertRaisesRegex(ClipboardEventError, "already exists"):
                    with WindowsClipboardEvents():
                        pass
            with WindowsClipboardEvents() as source:
                self.assertFalse(source.wait_for_change(0))
        except ClipboardEventError as exc:
            # If the runner has no interactive desktop, report an explicit
            # skip, not a false statement of successful live test coverage.
            if "could not create clipboard event window" in str(exc):
                self.skipTest("CI has no Win32 interactive message window")
            raise


if __name__ == "__main__":
    unittest.main()
