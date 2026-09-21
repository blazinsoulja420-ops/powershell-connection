from __future__ import annotations

import hashlib
import time
from typing import Any

from .pipeline import ExactRelayPipeline
from .schema import RelayValidationError, format_result_block, parse_task_block


class ClipboardRelayWatcher:
    def __init__(self, cfg: dict[str, Any], clipboard):
        self.cfg = cfg
        self.clipboard = clipboard
        self.pipeline = ExactRelayPipeline(cfg)
        self.poll_seconds = max(0.1, int(cfg["exact_relay"]["poll_interval_ms"]) / 1000.0)
        self.last_clipboard_digest: str | None = None

    @staticmethod
    def _digest(text: str) -> str:
        return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()

    def process_text(self, text: str) -> tuple[bool, str | None]:
        try:
            task = parse_task_block(text)
        except RelayValidationError as exc:
            return True, f"INVALID_TASK_BLOCK: {exc}"
        if task is None:
            return False, None
        result = self.pipeline.execute_task(task)
        result_block = format_result_block(result)
        if bool(task.get("result", {}).get("copy_to_clipboard", self.cfg["exact_relay"].get("auto_copy_result", True))):
            self.clipboard.set_text(result_block)
        return True, result_block

    def watch(self, once: bool = False) -> int:
        if not self.cfg["exact_relay"].get("enabled", False):
            print("EXACT_RELAY_BLOCKED: exact_relay.enabled=false")
            return 7
        print("UPAB_EXACT_RELAY_ARMED")
        print(f"CHANNEL={self.cfg['exact_relay']['channel_id']}")
        print(f"NONCE={self.pipeline.current_nonce()}")
        print(f"REPOSITORY={self.cfg['repository']['root']}")
        print("Copy a complete UPAB Exact Relay Task block to the Windows clipboard.")
        while True:
            try:
                text = self.clipboard.get_text()
            except Exception as exc:
                print(f"CLIPBOARD_READ_ERROR: {type(exc).__name__}: {exc}")
                time.sleep(self.poll_seconds)
                continue
            digest = self._digest(text)
            if digest != self.last_clipboard_digest:
                self.last_clipboard_digest = digest
                recognized, output = self.process_text(text)
                if recognized:
                    if output:
                        print(output)
                    if once:
                        return 0
            time.sleep(self.poll_seconds)
