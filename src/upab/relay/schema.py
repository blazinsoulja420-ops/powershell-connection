from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

TASK_SCHEMA = "upab.exact-relay.task.v1"
RESULT_SCHEMA = "upab.exact-relay.result.v1"
TASK_BEGIN = "-----BEGIN UPAB EXACT RELAY TASK-----"
TASK_END = "-----END UPAB EXACT RELAY TASK-----"
RESULT_BEGIN = "-----BEGIN UPAB EXACT RELAY RESULT-----"
RESULT_END = "-----END UPAB EXACT RELAY RESULT-----"

_TASK_ID_RE = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
_SHA_RE = re.compile(r"^[0-9A-Fa-f]{40,64}$")
_ALLOWED_OPS = {
    "read_file",
    "list_files",
    "hash_file",
    "git_status",
    "git_diff",
    "run_powershell",
    "run_tests",
    "write_file",
}
_TOP_KEYS = {
    "schema",
    "task_id",
    "channel_id",
    "relay_nonce",
    "issued_at_utc",
    "expires_at_utc",
    "repository",
    "mode",
    "stop_on_failure",
    "rollback_on_failure",
    "operations",
    "result",
}


class RelayValidationError(ValueError):
    pass


def _parse_time(value: str, field: str) -> datetime:
    if not isinstance(value, str) or not value.strip():
        raise RelayValidationError(f"{field} must be a non-empty ISO-8601 timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise RelayValidationError(f"{field} is not valid ISO-8601") from exc
    if parsed.tzinfo is None:
        raise RelayValidationError(f"{field} must include timezone information")
    return parsed.astimezone(timezone.utc)


def canonical_task_bytes(task: dict[str, Any]) -> bytes:
    return json.dumps(task, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def task_sha256(task: dict[str, Any]) -> str:
    return hashlib.sha256(canonical_task_bytes(task)).hexdigest().upper()


def parse_task_block(text: str) -> dict[str, Any] | None:
    if not isinstance(text, str):
        return None
    stripped = text.strip()
    if not stripped.startswith(TASK_BEGIN) or not stripped.endswith(TASK_END):
        return None
    body = stripped[len(TASK_BEGIN):-len(TASK_END)].strip()
    if not body:
        raise RelayValidationError("Task block JSON body is empty")
    try:
        value = json.loads(body)
    except json.JSONDecodeError as exc:
        raise RelayValidationError(f"Task JSON is invalid: {exc}") from exc
    if not isinstance(value, dict):
        raise RelayValidationError("Task JSON root must be an object")
    return value


def format_task_block(task: dict[str, Any]) -> str:
    return TASK_BEGIN + "\n" + json.dumps(task, indent=2, ensure_ascii=False) + "\n" + TASK_END


def format_result_block(result: dict[str, Any]) -> str:
    return RESULT_BEGIN + "\n" + json.dumps(result, indent=2, ensure_ascii=False) + "\n" + RESULT_END


def validate_task(task: dict[str, Any], cfg: dict[str, Any], current_nonce: str) -> dict[str, Any]:
    unknown = set(task) - _TOP_KEYS
    if unknown:
        raise RelayValidationError("Unknown task field(s): " + ", ".join(sorted(unknown)))
    if task.get("schema") != TASK_SCHEMA:
        raise RelayValidationError(f"schema must equal {TASK_SCHEMA}")

    task_id = task.get("task_id")
    if not isinstance(task_id, str) or not _TASK_ID_RE.fullmatch(task_id):
        raise RelayValidationError("task_id must match [A-Za-z0-9._:-]{1,128}")

    relay_cfg = cfg["exact_relay"]
    if task.get("channel_id") != relay_cfg["channel_id"]:
        raise RelayValidationError("channel_id does not match this UPAB relay")
    if task.get("relay_nonce") != current_nonce:
        raise RelayValidationError("relay_nonce is stale or does not match the armed relay")

    issued = _parse_time(task.get("issued_at_utc"), "issued_at_utc")
    expires = _parse_time(task.get("expires_at_utc"), "expires_at_utc")
    now = datetime.now(timezone.utc)
    if expires <= issued:
        raise RelayValidationError("expires_at_utc must be later than issued_at_utc")
    if now > expires:
        raise RelayValidationError("task has expired")
    if issued > now.replace(microsecond=0) and (issued - now).total_seconds() > 120:
        raise RelayValidationError("issued_at_utc is too far in the future")
    lifetime = (expires - issued).total_seconds()
    if lifetime > int(relay_cfg["max_task_lifetime_seconds"]):
        raise RelayValidationError("task lifetime exceeds configured maximum")

    repo = task.get("repository")
    if not isinstance(repo, dict):
        raise RelayValidationError("repository must be an object")
    if set(repo) - {"root", "expected_head"}:
        raise RelayValidationError("repository contains unknown fields")
    root = repo.get("root")
    if not isinstance(root, str) or not root.strip():
        raise RelayValidationError("repository.root is required")
    configured_root = Path(cfg["repository"]["root"]).resolve()
    supplied_root = Path(root).expanduser().resolve()
    if str(configured_root).casefold() != str(supplied_root).casefold():
        raise RelayValidationError("repository.root does not match configured repository")

    mode = task.get("mode")
    if mode not in {"read_only", "mutation"}:
        raise RelayValidationError("mode must be read_only or mutation")
    expected_head = repo.get("expected_head")
    if expected_head is not None and (not isinstance(expected_head, str) or not _SHA_RE.fullmatch(expected_head)):
        raise RelayValidationError("repository.expected_head must be a 40-64 hex Git object id or null")
    if mode == "mutation" and relay_cfg.get("require_task_expected_head_for_mutation", True) and not expected_head:
        raise RelayValidationError("mutation task requires repository.expected_head")

    operations = task.get("operations")
    if not isinstance(operations, list) or not operations:
        raise RelayValidationError("operations must be a non-empty array")
    if len(operations) > int(relay_cfg["max_operations"]):
        raise RelayValidationError("operation count exceeds configured maximum")

    normalized_ops: list[dict[str, Any]] = []
    seen_ids: set[str] = set()
    for index, raw in enumerate(operations, start=1):
        if not isinstance(raw, dict):
            raise RelayValidationError(f"operation {index} must be an object")
        allowed_keys = {"operation_id", "op", "args"}
        if set(raw) - allowed_keys:
            raise RelayValidationError(f"operation {index} contains unknown fields")
        op = raw.get("op")
        if op not in _ALLOWED_OPS:
            raise RelayValidationError(f"operation {index} has unsupported op: {op}")
        operation_id = raw.get("operation_id") or f"op-{index:03d}"
        if not isinstance(operation_id, str) or not _TASK_ID_RE.fullmatch(operation_id):
            raise RelayValidationError(f"operation {index} has invalid operation_id")
        if operation_id in seen_ids:
            raise RelayValidationError(f"duplicate operation_id: {operation_id}")
        seen_ids.add(operation_id)
        args = raw.get("args") or {}
        if not isinstance(args, dict):
            raise RelayValidationError(f"operation {operation_id} args must be an object")
        if mode == "read_only" and op == "write_file":
            raise RelayValidationError("read_only task cannot contain write_file")
        normalized_ops.append({"operation_id": operation_id, "op": op, "args": args})

    result = task.get("result") or {}
    if not isinstance(result, dict) or set(result) - {"copy_to_clipboard"}:
        raise RelayValidationError("result must contain only copy_to_clipboard")

    normalized = dict(task)
    normalized["operations"] = normalized_ops
    normalized["stop_on_failure"] = bool(task.get("stop_on_failure", True))
    normalized["rollback_on_failure"] = bool(
        task.get("rollback_on_failure", relay_cfg.get("rollback_on_failure", True))
    )
    normalized["result"] = {
        "copy_to_clipboard": bool(result.get("copy_to_clipboard", relay_cfg.get("auto_copy_result", True)))
    }
    return normalized
