from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass
from typing import Callable, Protocol


@dataclass(frozen=True)
class WatchedMessage:
    source: str
    conversation_id: str
    message_id: str
    role: str
    content: str


class MessageSource(Protocol):
    def read_latest(self) -> WatchedMessage | None: ...


class ChatMessageWatcher:
    def __init__(
        self,
        source: MessageSource,
        on_message: Callable[[WatchedMessage], None],
        *,
        poll_seconds: float = 1.0,
    ) -> None:
        self.source = source
        self.on_message = on_message
        self.poll_seconds = max(0.2, float(poll_seconds))
        self._last_digest: str | None = None

    @staticmethod
    def _digest(message: WatchedMessage) -> str:
        payload = "\n".join([
            message.source,
            message.conversation_id,
            message.message_id,
            message.role,
            message.content,
        ])
        return hashlib.sha256(payload.encode("utf-8", errors="replace")).hexdigest()

    def poll_once(self) -> bool:
        message = self.source.read_latest()
        if message is None:
            return False
        digest = self._digest(message)
        if digest == self._last_digest:
            return False
        self._last_digest = digest
        self.on_message(message)
        return True

    def watch(self) -> None:
        while True:
            self.poll_once()
            time.sleep(self.poll_seconds)
