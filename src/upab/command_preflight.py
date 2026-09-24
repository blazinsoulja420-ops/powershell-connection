from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import re
import shutil


@dataclass(frozen=True)
class PowerShellPreflight:
    ok: bool
    command: str
    reasons: tuple[str, ...]
    target_paths: tuple[str, ...]


def _first_command_token(command: str) -> str:
    stripped = command.strip()
    if not stripped:
        return ""
    token = re.split(r"[\s;|&]+", stripped, maxsplit=1)[0]
    return token.strip().lower()


def command_matches_allow_prefix(
    command: str,
    allowed_prefixes: tuple[str, ...],
) -> bool:
    token = _first_command_token(command)
    if not token:
        return False

    normalized = tuple(
        prefix.strip().lower()
        for prefix in allowed_prefixes
        if prefix.strip()
    )

    return token in normalized


def contains_command_chaining(command: str) -> bool:
    """Reject shell chaining so an allowlisted first token cannot hide later commands."""
    return bool(re.search(r"[;|&]|\r|\n", command))


def preflight_powershell(
    command: str,
    *,
    repository_root: Path,
    target_paths: tuple[str, ...] = (),
    executable: str = "powershell.exe",
    allowed_prefixes: tuple[str, ...] = (),
) -> PowerShellPreflight:
    reasons: list[str] = []
    if not command.strip():
        reasons.append("empty command")
    if shutil.which(executable) is None:
        reasons.append(f"PowerShell executable not found: {executable}")
    if not allowed_prefixes:
        reasons.append("no PowerShell command allowlist configured")
    elif not command_matches_allow_prefix(command, allowed_prefixes):
        reasons.append("PowerShell command is not allowlisted")
    if contains_command_chaining(command):
        reasons.append("PowerShell command chaining is not allowed")

    resolved_targets: list[str] = []
    repo = repository_root.resolve()
    for raw in target_paths:
        candidate = (repo / raw).resolve()
        try:
            candidate.relative_to(repo)
        except ValueError:
            reasons.append(f"target escapes repository root: {raw}")
            continue
        resolved_targets.append(str(candidate))

    return PowerShellPreflight(
        ok=not reasons,
        command=command,
        reasons=tuple(reasons),
        target_paths=tuple(resolved_targets),
    )
