"""Stage 25: classify launcher text in memory; report counts only.

Untrusted command lines may contain secrets. Never export them and never
derive execution permission from a signature match or from its absence.
"""

from __future__ import annotations

import re
from .v3_policy import PolicyBlocked

MAX_ITEMS = 12000
MAX_CHARS = 16384

KNOWN = (
    re.compile("Start-UPAB-ExactRelay[.]ps1", re.I),
    re.compile("upab[.]ps1", re.I),
    re.compile("-m[ ]+upab[ ]+relay-watch", re.I),
)
HINT = re.compile("upab|exact.?relay|powershell.connection", re.I)


def classify_description(text: object) -> str:
    if text is None or text == "":
        return "UNREADABLE"
    if type(text) is not str or len(text) > MAX_CHARS:
        raise PolicyBlocked("invalid bounded launcher description")
    if any(pattern.search(text) for pattern in KNOWN):
        return "KNOWN_SIGNATURE_CANDIDATE"
    if HINT.search(text):
        return "AMBIGUOUS_HINT"
    return "NO_KNOWN_SIGNATURE"


def count_launch_descriptions(items: object, *, source: str) -> dict[str, object]:
    if source not in ("process", "task", "service"):
        raise PolicyBlocked("unknown source")
    if type(items) is not list or len(items) > MAX_ITEMS:
        raise PolicyBlocked("invalid bounded evidence collection")
    observed = {k:0 for k in (
        "KNOWN_SIGNATURE_CANDIDATE", "AMBIGUOUS_HINT",
        "NO_KNOWN_SIGNATURE", "UNREADABLE"
    )}
    for item in items:
        observed[classify_description(item)] += 1
    return {
        "schema": "upab.watcher-v3.launch-attribution-preview.v1",
        "source": source,
        "items_examined": len(items),
        "candidate_signatures": observed["KNOWN_SIGNATURE_CANDIDATE"],
        "ambiguous_hints": observed["AMBIGUOUS_HINT"],
        "unreadable": observed["UNREADABLE"],
        "other": observed["NO_KNOWN_SIGNATURE"],
        "raw_command_lines_exposed": False,
        "watcher_identity_proven": False,
        "old_watcher_stopped_proven": False,
        "owner_authenticated": False,
        "migration_authorized": False,
        "execution_authorized": False,
        "changes_performed": False,
    }
