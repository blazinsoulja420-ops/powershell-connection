from pathlib import Path

from upab.chat_watch import ChatMessageWatcher, WatchedMessage
from upab.file_search import search_files


class FakeSource:
    def __init__(self, message):
        self.message = message

    def read_latest(self):
        return self.message


def test_chat_watcher_emits_new_message_once():
    seen = []
    source = FakeSource(WatchedMessage("fixture", "c1", "m1", "user", "continue"))
    watcher = ChatMessageWatcher(source, seen.append, poll_seconds=0.2)
    assert watcher.poll_once() is True
    assert watcher.poll_once() is False
    assert seen[0].message_id == "m1"


def test_file_search_finds_named_file(tmp_path):
    target = tmp_path / "ProjectState.yaml"
    target.write_text("x", encoding="utf-8")
    results = search_files([tmp_path], query="projectstate")
    assert len(results) == 1
    assert results[0].path.endswith("ProjectState.yaml")
