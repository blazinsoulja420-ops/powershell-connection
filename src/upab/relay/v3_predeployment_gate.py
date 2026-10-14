"""Watcher v3 Stage 22 — unified FAIL-CLOSED predeployment evidence assessment.

This module combines *partial, untrusted* Windows-readiness observations into
a bounded report. It does not confer authority, even if ALL observable checks
return normally. Only explicit opt-in (--collect-windows) runs read-only local
Windows snapshots. State and backup paths are never discovered automatically.

No network, server, process stop, scheduled-task edit, migration, Windows Hello
prompt, credential creation, repository connection, worker or task execution.
An observed SCM/task/ACL snapshot is NOT evidence that v1 is quiescent,
that the actual owner consented, or that state is safe to migrate.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys
from typing import Callable

from .v3_features import load_feature_catalog
from .v3_policy import PolicyBlocked

_SCHEMA = "upab.watcher-v3.predeployment-evidence.v1"
_CHECKS = (
    "win32_process_snapshot",
    "service_control_manager",
    "task_scheduler",
    "registry_startup_surfaces",
    "backup_tree_acls",
    "backup_checksum_comparison",
    "legacy_migration_history",
    "windows_hello_preflight",
)
_STATES = frozenset({"NOT_REQUESTED", "OBSERVED_PARTIAL", "BLOCKED"})
_BASE_BLOCKERS = (
    "OWNER_WINDOWS_HELLO_REGISTRATION_NOT_VERIFIED",
    "TRUSTED_CREDENTIAL_BROKER_NOT_ACTIVE",
    "SCOPE_BOUND_SINGLE_USE_OWNER_APPROVAL_NOT_VERIFIED",
    "OLD_V1_PROCESS_QUIESCENCE_NOT_PROVEN",
    "ALL_LEGACY_LAUNCH_PATHS_DISABLED_NOT_PROVEN",
    "PROTECTED_BACKUP_AND_RESTORE_NOT_VERIFIED",
    "LIVE_REPOSITORY_AND_EXECUTOR_ISOLATION_NOT_VERIFIED",
    "OWNER_LAPTOP_ACCEPTANCE_NOT_VERIFIED",
)
# Each observed input must carry a known schema, never claim owner or
# execution authority, and preserve its own important caveats.
_CONTRACTS = {
    "win32_process_snapshot": (
        "upab.watcher-v3.windows-cutover-survey.v1",
        ("old_watcher_not_running_proven", "in_flight_v1_task_absence_proven",
         "migration_authorized", "execution_authorized", "processes_stopped",
         "startup_modified"),
    ),
    "service_control_manager": (
        "upab.watcher-v3.scm-snapshot.v1",
        ("service_processes_proven_stopped", "v1_quiescence_proven",
         "migration_authorized", "execution_authorized",
         "windows_changes_performed"),
    ),
    "task_scheduler": (
        "upab.watcher-v3.scheduler-snapshot.v1",
        ("task_actions_absence_proven", "scheduler_access_scope_complete",
         "startup_disablement_proven", "running_task_instances_excluded",
         "v1_quiescence_proven", "migration_authorized",
         "execution_authorized", "windows_changes_performed"),
    ),
    "registry_startup_surfaces": (
        "upab.watcher-v3.windows-startup-surfaces.v1",
        ("startup_discovery_exhaustive", "all_legacy_launch_paths_disabled_proven",
         "v1_quiescence_proven", "migration_authorized",
         "system_settings_changed"),
    ),
    "backup_tree_acls": (
        "upab.watcher-v3.backup-tree-acl-preview.v1",
        ("backup_contents_proven_restorable", "acl_sampling_race_free",
         "effective_windows_rights_verified", "full_backup_integrity_proven",
         "tamper_protected_backup_proven", "owner_authenticated",
         "migration_authorized", "task_execution_authorized",
         "filesystem_changes_performed"),
    ),
    "backup_checksum_comparison": (
        "upab.watcher-v3.backup-comparison.v1",
        ("source_quiescence_proven", "backup_protected_by_verified_acl",
         "backup_authenticity_proven", "backup_immutable",
         "backup_restoration_test_passed", "migration_authorized",
         "file_changes_performed"),
    ),
    "legacy_migration_history": (
        "upab.watcher-v3.legacy-migration-risk-audit.v1",
        ("v1_quiescence_proven", "owner_approval_proven", "migration_allowed",
         "task_execution_allowed", "writes_performed"),
    ),
    "windows_hello_preflight": (
        "upab.watcher-v3.owner-enrollment-preflight.v1",
        ("interactive_user_presence_proven", "rp_ownership_proven",
         "trusted_rp_configuration", "protected_challenge_issuer_connected",
         "credential_registered", "windows_hello_prompt_displayed",
         "owner_approval_issued", "execution_authorized",
         "safe_to_invoke_make_credential"),
    ),
}


def _require_inert_report(kind: str, raw: object) -> None:
    schema, flags = _CONTRACTS[kind]
    if type(raw) is not dict or raw.get("schema") != schema:
        raise PolicyBlocked("unexpected predeployment evidence schema")
    for key in flags:
        if raw.get(key) is not False or type(raw.get(key)) is not bool:
            raise PolicyBlocked("predeployment evidence claims unsupported authority")
    # Untrusted receipt content is never used to grant safety. Avoid retaining
    # arbitrary extra fields from the original source in aggregate receipts.


def _feature_invariants(report: object) -> None:
    if type(report) is not dict:
        raise PolicyBlocked("feature catalog evidence missing")
    expected = {
        "schema": "upab.watcher-v3.features.v1",
        "registered_upgrades": 12, "activated_upgrades": 0,
        "project_limit": 64, "monitor_limit": 32,
        "execution_enabled": False,
    }
    for field, value in expected.items():
        if field not in report or type(report[field]) is not type(value) or (
            report[field] != value
        ):
            raise PolicyBlocked("feature activation or fixed capacity invariant broken")
    stages = report.get("stages")
    if type(stages) is not dict or len(stages) != 12:
        raise PolicyBlocked("feature staging evidence malformed")


def evaluate_predeployment(
    *, feature_report: object,
    observations: object | None = None,
) -> dict[str, object]:
    """Strict, deterministic, deny-only consolidation of in-memory evidence."""
    _feature_invariants(feature_report)
    entries = {} if observations is None else observations
    if type(entries) is not dict or not set(entries).issubset(_CHECKS):
        raise PolicyBlocked("unrecognized predeployment evidence source")
    summary: dict[str, str] = {}
    failed: list[str] = []
    for check in _CHECKS:
        observation = entries.get(check)
        if observation is None:
            state = "NOT_REQUESTED"
        elif type(observation) is dict and set(observation) == {"state"}:
            state = observation["state"]
            if state != "BLOCKED":
                raise PolicyBlocked("bare observation may report BLOCKED only")
        else:
            _require_inert_report(check, observation)
            state = "OBSERVED_PARTIAL"
        if type(state) is not str or state not in _STATES:
            raise PolicyBlocked("unknown predeployment source state")
        summary[check] = state
        if state == "BLOCKED":
            failed.append(check)
    observed_count = sum(s == "OBSERVED_PARTIAL" for s in summary.values())
    missing = [f"OBSERVATION_NOT_REQUESTED:{name}" for name, value
               in summary.items() if value == "NOT_REQUESTED"]
    stopped = [f"OBSERVATION_BLOCKED:{name}" for name in failed]
    blockers = list(_BASE_BLOCKERS) + missing + stopped
    # This digest identifies an UNTRUSTED, sanitized report only; it is not
    # a signature, owner approval, or a replacement for protected evidence.
    canonical = json.dumps(
        {"sources": summary, "blockers": blockers},
        sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return {
        "schema": _SCHEMA,
        "status": "BLOCKED_NOT_DEPLOYABLE",
        "feature_flags_enabled": 0,
        "registered_project_limit": 64,
        "active_folder_monitor_limit": 32,
        "checks_defined": len(_CHECKS),
        "checks_partially_observed": observed_count,
        "checks_blocked": len(failed),
        "checks_not_requested": len(missing),
        "evidence_sources": summary,
        "blockers": blockers,
        "sanitized_untrusted_report_sha256": hashlib.sha256(canonical).hexdigest(),
        "report_is_authenticated_approval": False,
        "actual_owner_authenticated": False,
        "legacy_watcher_stopped_proven": False,
        "backup_protected_and_restored_proven": False,
        "live_repository_attested": False,
        "safe_to_migrate": False,
        "safe_to_enable_features": False,
        "safe_to_install": False,
        "task_execution_authorized": False,
        "changes_performed": False,
    }


def _capture(name: str, callback: Callable[[], object]) -> dict[str, object]:
    # Failure details are intentionally not retained or printed: exception
    # messages can embed sensitive paths, local service names or processes.
    try:
        value = callback()
    except (OSError, UnicodeError, ValueError, PolicyBlocked):
        return {"state": "BLOCKED"}
    _require_inert_report(name, value)
    return value


def collect_local_predeployment(
    *, feature_config: str | Path,
    collect_windows: bool = False,
    backup_root: str | Path | None = None,
    source_state: str | Path | None = None,
) -> dict[str, object]:
    """Opt-in, explicit-path, read-only collection. Never runs live tasks."""
    if type(collect_windows) is not bool:
        raise PolicyBlocked("Windows collection flag must be a boolean")
    if (backup_root is not None or source_state is not None) and not collect_windows:
        raise PolicyBlocked("explicit Windows opt-in required for local state scans")
    feature = load_feature_catalog(feature_config)
    results: dict[str, object] = {}
    if collect_windows:
        if sys.platform != "win32":
            raise PolicyBlocked("Windows scans can only run on Windows")
        from .v3_windows_cutover_preflight import (
            snapshot_possible_host_processes, compare_existing_backup
        )
        from .v3_authoritative_launch_snapshot import (
            observe_scm_services, observe_registered_tasks
        )
        from .v3_windows_startup_surfaces import observe_known_startup_surfaces
        from .v3_backup_tree_acl_preview import inspect_backup_tree
        from .v3_migration_risk_audit import audit_migration_risks
        from .v3_owner_enrollment_preflight import preflight_owner_enrollment

        results["win32_process_snapshot"] = _capture(
            "win32_process_snapshot", snapshot_possible_host_processes
        )
        results["service_control_manager"] = _capture(
            "service_control_manager", observe_scm_services
        )
        results["task_scheduler"] = _capture(
            "task_scheduler", observe_registered_tasks
        )
        results["registry_startup_surfaces"] = _capture(
            "registry_startup_surfaces", observe_known_startup_surfaces
        )
        results["windows_hello_preflight"] = _capture(
            "windows_hello_preflight", preflight_owner_enrollment
        )
        if backup_root is not None:
            results["backup_tree_acls"] = _capture(
                "backup_tree_acls", lambda: inspect_backup_tree(backup_root)
            )
        if source_state is not None:
            results["legacy_migration_history"] = _capture(
                "legacy_migration_history",
                lambda: audit_migration_risks(source_state)
            )
        if backup_root is not None and source_state is not None:
            results["backup_checksum_comparison"] = _capture(
                "backup_checksum_comparison",
                lambda: compare_existing_backup(
                    source_state=source_state, backup_state=backup_root
                )
            )
    return evaluate_predeployment(feature_report=feature, observations=results)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="READ ONLY Watcher v3 predeployment blockers")
    p.add_argument("--features", required=True,
                   help="Existing disabled-by-default v3 feature JSON")
    p.add_argument("--collect-windows", action="store_true",
                   help="Explicit opt-in: observe read-only Windows surfaces")
    p.add_argument("--backup-root", default=None,
                   help="Existing backup state root; never auto-discovered")
    p.add_argument("--source-state", default=None,
                   help="Existing v1 state root; never auto-discovered")
    args = p.parse_args(argv)
    try:
        result = collect_local_predeployment(
            feature_config=args.features, collect_windows=args.collect_windows,
            backup_root=args.backup_root, source_state=args.source_state,
        )
    except (OSError, UnicodeError, ValueError, PolicyBlocked) as exc:
        print("UPAB_V3_PREDEPLOYMENT_BLOCKED: " +
              type(exc).__name__, file=sys.stderr)
        return 7
    print(json.dumps(result, indent=2, sort_keys=True))
    # Exit code 0 means the *blocker report was generated*, not deployable.
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
