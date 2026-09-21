from __future__ import annotations

import os
import re
from typing import Mapping


_SECRET_KEY_RE = re.compile(
    r"(TOKEN|SECRET|PASSWORD|PASSWD|API[_-]?KEY|CREDENTIAL|AUTH|PRIVATE[_-]?KEY)",
    re.IGNORECASE,
)

_TEXT_PATTERNS = [
    re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{8,}"),
    re.compile(r"\bsk-[A-Za-z0-9_-]{12,}\b"),
    re.compile(r"(?i)(password|passwd|api[_-]?key|token|secret)\s*[:=]\s*([^\s,;]+)"),
]


def sanitized_env(source: Mapping[str, str] | None = None) -> dict[str, str]:
    source = source or os.environ
    clean: dict[str, str] = {}
    for key, value in source.items():
        if _SECRET_KEY_RE.search(key):
            continue
        clean[key] = value
    return clean


def redact(text: str, max_chars: int = 40000) -> str:
    value = text[:max_chars]
    for pattern in _TEXT_PATTERNS:
        if pattern.pattern.startswith("(?i)(password"):
            value = pattern.sub(lambda m: f"{m.group(1)}=[REDACTED]", value)
        else:
            value = pattern.sub("[REDACTED]", value)
    return value
