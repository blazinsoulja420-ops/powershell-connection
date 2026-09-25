from __future__ import annotations

import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .powershell_commands import CommandRequestError, CommandSpec, resolve_bound_path, validate_request


@dataclass(frozen=True)
class PowerShellPreflight:
    spec: CommandSpec
    arguments: dict[str, str]
    bound_paths: dict[str, Path]
    executable: str
    wrapper: Path


def preflight_powershell(args: dict[str, Any], *, repository_root: Path, executable: str, wrapper: Path) -> PowerShellPreflight:
    spec, arguments = validate_request(args)
    resolved_executable = shutil.which(executable)
    if resolved_executable is None:
        raise CommandRequestError("PS_EXECUTABLE_MISSING", f"PowerShell executable not found: {executable}")
    trusted_wrapper = wrapper.resolve(strict=False)
    if not trusted_wrapper.is_file():
        raise CommandRequestError("PS_WRAPPER_MISSING", f"PowerShell wrapper not found: {trusted_wrapper}")
    bound = {field: resolve_bound_path(repository_root, arguments[field]) for field in spec.path_fields}
    return PowerShellPreflight(spec, arguments, bound, resolved_executable, trusted_wrapper)
