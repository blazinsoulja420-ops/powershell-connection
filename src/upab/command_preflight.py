from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import shutil


@dataclass(frozen=True)
class PowerShellPreflight:
    ok: bool
    command: str
    reasons: tuple[str, ...]
    target_paths: tuple[str, ...]


def preflight_powershell(
    command: str,
    *,
    repository_root: Path,
    target_paths: tuple[str, ...] = (),
    executable: str = "powershell.exe",
) -> PowerShellPreflight:
    reasons: list[str] = []
    if not command.strip():
        reasons.append("empty command")
    if shutil.which(executable) is None:
        reasons.append(f"PowerShell executable not found: {executable}")

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
