"""Stage 35: bounded watcher-scope REVIEW planning for owner-selected portfolio.

This is NOT monitoring. It takes the fixed owner-selected Stage 33 portfolio
and a synthetic request for review scope, but no paths, tokens, remote API
endpoints, task commands or activation fields. It does not inspect the OS,
connect to GitHub, create a project, add a scheduled task or enable a monitor.

Poindexter's 19 nested features never consume independent watcher slots.
Restricted projects (NSFW, Kali) and the Watcher itself require additional
separate reviews; these safeguards cannot be changed in a request.
"""
from __future__ import annotations

from .v3_policy import PolicyBlocked
from .v3_portfolio_review import (
    PROJECTS, POINDEXTER_MODULES, PROJECT_CAPACITY, MONITOR_CAPACITY,
    validate_portfolio_preview,
)

SCHEMA = "upab.watcher-v3.scope-review-request.v1"
REPORT_SCHEMA = "upab.watcher-v3.monitoring-scope-review-result.v1"
_RESTRICTED = frozenset({"NSFW", "Kali-Linux-"})
_SELF_REFERENCE = "powershell-connection"
_MAX_MODULES = len(POINDEXTER_MODULES)


def review_monitoring_scope(*, portfolio: object, request: object) -> dict[str, object]:
    """Evaluate an inert intent; never determine that watching is authorized."""
    baseline = validate_portfolio_preview(portfolio)
    if type(request) is not dict or set(request) != {
        "schema", "requested_repositories", "requested_poindexter_module_ids",
        "preview_only",
    }:
        raise PolicyBlocked("monitoring scope proposal schema invalid")
    if request["schema"] != SCHEMA or request["preview_only"] is not True:
        raise PolicyBlocked("scope preview cannot enable actual monitoring")
    names = request["requested_repositories"]
    module_ids = request["requested_poindexter_module_ids"]
    if (type(names) is not list or len(names) > len(PROJECTS)
            or type(module_ids) is not list or len(module_ids) > _MAX_MODULES):
        raise PolicyBlocked("monitoring scope list exceeds fixed portfolio")
    if (any(type(name) is not str or name not in PROJECTS for name in names)
            or len(names) != len(set(names))):
        raise PolicyBlocked("unknown or duplicate selected project")
    allowed_modules = {id for id, _ in POINDEXTER_MODULES}
    if (any(type(id) is not str or id not in allowed_modules for id in module_ids)
            or len(module_ids) != len(set(module_ids))):
        raise PolicyBlocked("unknown or duplicate nested module")
    if module_ids and "UP-UHAIB-001-Poindexter" not in names:
        raise PolicyBlocked("nested Poindexter modules require Poindexter in the proposal")
    # There is one potential scoped filesystem root per explicitly selected
    # repository, never one per module. These are capacity estimates ONLY.
    potential_roots = len(names)
    if (potential_roots > MONITOR_CAPACITY
            or potential_roots > PROJECT_CAPACITY
            or potential_roots > baseline["project_limit"]
            or potential_roots > baseline["monitor_limit"]):
        raise PolicyBlocked("monitoring scope exceeds portfolio capacity")
    sensitive = sum(name in _RESTRICTED for name in names)
    self_reference = _SELF_REFERENCE in names
    # Every root, not only sensitive ones, needs an exact owner-reviewed local
    # path, identity, read-only profile, evidence and separate activation.
    return {
        "schema": REPORT_SCHEMA,
        "status": "SCOPE_PREVIEW_NEEDS_INDEPENDENT_OWNER_AND_DEVICE_APPROVAL",
        "selected_portfolio_projects": len(PROJECTS),
        "selected_poindexter_modules": len(POINDEXTER_MODULES),
        "requested_repository_scope_reviews": potential_roots,
        "requested_nested_module_reviews": len(module_ids),
        "additional_watch_roots_for_nested_modules": 0,
        "potential_watch_roots_after_separate_approval": potential_roots,
        "restricted_project_scope_reviews": sensitive,
        "watcher_self_monitoring_scope_reviews": int(self_reference),
        "other_scope_reviews": potential_roots - sensitive - int(self_reference),
        "maximum_registered_project_capacity": PROJECT_CAPACITY,
        "maximum_concurrent_monitor_capacity": MONITOR_CAPACITY,
        "owner_selected_repositories_are_connected": False,
        "requested_paths_present": False,
        "approved_local_directory_roots": 0,
        "live_monitoring_enabled": False,
        "actual_monitored_root_count": 0,
        "verified_project_health": False,
        "restricted_repo_access_granted": False,
        "cross_repository_access_granted": False,
        "online_store_included": False,
        "chat_or_folder_creation_authorized": False,
        "task_execution_authorized": False,
        "owner_authenticated": False,
        "settings_changed": False,
    }
