from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class CommandSpec:
    command_id: str
    allowed_fields: frozenset[str]
    required_fields: frozenset[str]
    path_fields: frozenset[str]
    timeout_seconds: int
    operation: str


COMMANDS: dict[str, CommandSpec] = {
    "get_item": CommandSpec("get_item", frozenset({"command_id", "path"}), frozenset({"path"}), frozenset({"path"}), 10, "GetItem"),
    "resolve_path": CommandSpec("resolve_path", frozenset({"command_id", "path"}), frozenset({"path"}), frozenset({"path"}), 10, "ResolvePath"),
    "select_string": CommandSpec("select_string", frozenset({"command_id", "path", "pattern"}), frozenset({"path", "pattern"}), frozenset({"path"}), 10, "SelectString"),
}


class CommandRequestError(ValueError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


def validate_request(args: dict[str, Any]) -> tuple[CommandSpec, dict[str, str]]:
    if "command" in args:
        raise CommandRequestError("PS_RAW_COMMAND_UNSUPPORTED", "Raw PowerShell command input is unsupported")
    command_id = args.get("command_id")
    if not isinstance(command_id, str) or not command_id.strip():
        raise CommandRequestError("PS_COMMAND_ID_REQUIRED", "command_id is required")
    spec = COMMANDS.get(command_id)
    if spec is None:
        raise CommandRequestError("PS_COMMAND_UNKNOWN", f"Unknown command_id: {command_id}")
    unknown = set(args) - spec.allowed_fields
    if unknown:
        raise CommandRequestError("PS_ARGUMENT_UNKNOWN", f"Unknown argument: {sorted(unknown)[0]}")
    missing = spec.required_fields - set(args)
    if missing:
        code = "PS_PATH_REQUIRED" if "path" in missing else "PS_ARGUMENT_REQUIRED"
        raise CommandRequestError(code, f"Required argument missing: {sorted(missing)[0]}")
    validated: dict[str, str] = {"command_id": command_id}
    for name, value in args.items():
        if name == "command_id":
            continue
        if not isinstance(value, str):
            raise CommandRequestError("PS_ARGUMENT_TYPE", f"Argument must be a string: {name}")
        if name in spec.required_fields and not value:
            code = "PS_PATH_REQUIRED" if name == "path" else "PS_ARGUMENT_REQUIRED"
            raise CommandRequestError(code, f"Required argument is empty: {name}")
        validated[name] = value
    return spec, validated


def resolve_bound_path(repo_root: Path, raw: str) -> Path:
    if not isinstance(raw, str) or not raw.strip():
        raise CommandRequestError("PS_PATH_REQUIRED", "path is required")
    supplied = Path(raw)
    candidate = supplied.resolve(strict=False) if supplied.is_absolute() else (repo_root / supplied).resolve(strict=False)
    root = repo_root.resolve(strict=True)
    try:
        candidate.relative_to(root)
    except ValueError as exc:
        raise CommandRequestError("PS_PATH_ESCAPE", "path escapes repository root") from exc
    return candidate
