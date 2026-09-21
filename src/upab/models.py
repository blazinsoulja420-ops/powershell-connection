from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class Decision:
    allowed: bool
    code: str
    reason: str
    risk: str = "LOW"
    fatal: bool = False


@dataclass
class ToolResult:
    ok: bool
    output: str
    metadata: dict[str, Any] = field(default_factory=dict)
    fatal: bool = False

    def as_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "output": self.output,
            "metadata": self.metadata,
            "fatal": self.fatal,
        }
