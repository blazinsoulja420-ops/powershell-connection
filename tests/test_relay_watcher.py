from __future__ import annotations

import unittest

from upab.relay.clipboard import MemoryClipboard
from upab.relay.watcher import ClipboardRelayWatcher


class RelayWatcherUnitTests(unittest.TestCase):
    def test_ordinary_clipboard_text_is_ignored_without_execution(self):
        watcher = object.__new__(ClipboardRelayWatcher)
        watcher.clipboard = MemoryClipboard("ordinary chat text")
        watcher.cfg = {}
        watcher.pipeline = None
        recognized, output = ClipboardRelayWatcher.process_text(watcher, "ordinary chat text")
        self.assertFalse(recognized)
        self.assertIsNone(output)


if __name__ == "__main__":
    unittest.main()
