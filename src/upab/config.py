from __future__ import annotations

import json
from pathlib import Path
from typing import Any


class ConfigError(ValueError):
    pass


def _require(obj: dict[str, Any], key: str, where: str) -> Any:
    if key not in obj:
        raise ConfigError(f"Missing required key {where}.{key}")
    return obj[key]


def load_config(path: str | Path) -> dict[str, Any]:
    p = Path(path).expanduser().resolve()
    with p.open("r", encoding="utf-8-sig") as fh:
        cfg = json.load(fh)

    for top in ("provider", "repository", "governance", "state"):
        _require(cfg, top, "config")

    provider = cfg["provider"]
    repo = cfg["repository"]
    gov = cfg["governance"]
    state = cfg["state"]

    for key in ("kind", "base_url", "model", "timeout_seconds"):
        _require(provider, key, "provider")
    if provider["kind"] != "lmstudio":
        raise ConfigError("v1 Local Edition only supports provider.kind='lmstudio'")

    _require(repo, "root", "repository")
    repo["root"] = str(Path(repo["root"]).expanduser().resolve())

    required_gov = (
        "upgs_version",
        "canonical_package_sha256",
        "require_canonical_for_mutation",
        "read_only",
        "authorized_write_paths",
        "powershell_allowed_command_ids",
        "max_command_seconds",
        "max_output_chars",
        "max_file_read_bytes",
        "max_list_entries",
        "max_agent_steps",
    )
    for key in required_gov:
        _require(gov, key, "governance")

    if gov["canonical_package_path"]:
        gov["canonical_package_path"] = str(
            Path(gov["canonical_package_path"]).expanduser().resolve()
        )

    gov["authorized_write_paths"] = [
        x.replace("\\", "/").lstrip("/") for x in gov["authorized_write_paths"]
    ]
    if not isinstance(gov["powershell_allowed_command_ids"], list) or not all(
        isinstance(x, str) and x for x in gov["powershell_allowed_command_ids"]
    ):
        raise ConfigError("governance.powershell_allowed_command_ids must be an array of non-empty strings")

    _require(state, "directory", "state")
    state["directory"] = str(Path(state["directory"]).expanduser().resolve())

    file_search = cfg.setdefault("file_search", {})
    file_search.setdefault("roots", [repo["root"]])
    if not isinstance(file_search["roots"], list) or not all(isinstance(x, str) and x.strip() for x in file_search["roots"]):
        raise ConfigError("file_search.roots must be an array of non-empty strings")
    file_search["roots"] = [str(Path(x).expanduser().resolve()) for x in file_search["roots"]]

    relay = cfg.setdefault("exact_relay", {})
    relay.setdefault("enabled", False)
    relay.setdefault("channel_id", "upab-local")
    relay.setdefault("poll_interval_ms", 500)
    relay.setdefault("max_task_lifetime_seconds", 900)
    relay.setdefault("max_operations", 50)
    relay.setdefault("auto_copy_result", True)
    relay.setdefault("rollback_on_failure", True)
    relay.setdefault("require_task_expected_head_for_mutation", True)

    if not isinstance(relay["enabled"], bool):
        raise ConfigError("exact_relay.enabled must be boolean")
    if not isinstance(relay["channel_id"], str) or not relay["channel_id"].strip():
        raise ConfigError("exact_relay.channel_id must be a non-empty string")
    for key in ("poll_interval_ms", "max_task_lifetime_seconds", "max_operations"):
        if not isinstance(relay[key], int) or relay[key] <= 0:
            raise ConfigError(f"exact_relay.{key} must be a positive integer")

    return cfg
