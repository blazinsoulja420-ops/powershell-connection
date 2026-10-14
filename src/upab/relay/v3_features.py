"""Strict disabled-by-default feature registry for all 12 Watcher v3 upgrades.

Loading the registry is a read-only readiness check. It cannot enable any
feature, create a listener, schedule tasks or grant execution permissions.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

from .v3_policy import PolicyBlocked

FEATURES = (
    "secure_execution_controller",
    "intelligent_task_scheduler",
    "crash_recovery_engine",
    "local_task_inbox",
    "automatic_health_monitor",
    "resource_aware_scheduling",
    "task_dependency_engine",
    "smart_retry_system",
    "task_checkpointing",
    "performance_analytics",
    "automatic_log_management",
    "update_rollback_manager",
)
STAGES = frozenset({
    "planned", "candidate_policy", "candidate_review_only",
    "candidate_schema_only", "candidate_module", "candidate_verify_only",
})


def _unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise PolicyBlocked("duplicate JSON feature registry key")
        result[key] = value
    return result


def validate_feature_catalog(raw: object) -> dict[str, object]:
    if not isinstance(raw, dict) or set(raw) != {
        "schema", "project_limit", "monitor_limit", "auto_activation", "features"
    }:
        raise PolicyBlocked("feature catalog schema fields invalid")
    if raw["schema"] != "upab.watcher-v3.features.v1":
        raise PolicyBlocked("unknown feature catalog schema")
    if type(raw["project_limit"]) is not int or raw["project_limit"] != 64:
        raise PolicyBlocked("project registration maximum must remain 64")
    if type(raw["monitor_limit"]) is not int or raw["monitor_limit"] != 32:
        raise PolicyBlocked("monitoring maximum must remain 32")
    if raw["auto_activation"] is not False:
        raise PolicyBlocked("automatic feature activation is forbidden")
    items = raw["features"]
    if not isinstance(items, list) or len(items) != 12:
        raise PolicyBlocked("expected exactly twelve upgrade entries")
    found = set()
    stages = {}
    for item in items:
        if not isinstance(item, dict) or set(item) != {"id", "stage", "description", "enabled"}:
            raise PolicyBlocked("unexpected feature fields")
        fid = item["id"]
        if not isinstance(fid, str) or fid not in FEATURES or fid in found:
            raise PolicyBlocked("invalid or repeated upgrade identifier")
        if item["enabled"] is not False:
            raise PolicyBlocked("feature must remain disabled before release")
        if item["stage"] not in STAGES:
            raise PolicyBlocked("unknown implementation stage")
        if not isinstance(item["description"], str) or not 1 <= len(item["description"]) <= 200:
            raise PolicyBlocked("invalid description")
        found.add(fid)
        stages[fid] = item["stage"]
    if found != set(FEATURES):
        raise PolicyBlocked("missing upgrade identifiers")
    return {
        "schema": raw["schema"],
        "registered_upgrades": 12,
        "project_limit": 64,
        "monitor_limit": 32,
        "activated_upgrades": 0,
        "stages": stages,
        "execution_enabled": False,
    }


def load_feature_catalog(path: str | Path) -> dict[str, object]:
    try:
        with Path(path).open("r", encoding="utf-8-sig") as file:
            data = json.load(file, object_pairs_hook=_unique_pairs)
    except (OSError, json.JSONDecodeError) as exc:
        raise PolicyBlocked("catalog cannot be read") from exc
    return validate_feature_catalog(data)


def main(argv=None):
    parser = argparse.ArgumentParser(description="Read-only watcher v3 upgrade registry")
    parser.add_argument("--config", required=True)
    args = parser.parse_args(argv)
    try:
        result = load_feature_catalog(args.config)
    except PolicyBlocked as exc:
        print("UPAB_WATCHER_V3_BLOCKED: " + str(exc), file=sys.stderr)
        return 7
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
