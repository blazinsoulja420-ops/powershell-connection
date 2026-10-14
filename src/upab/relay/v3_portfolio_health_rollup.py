"""Stage 34: bounded and UNTRUSTED portfolio health roll-up (review only).

The selected nine repo identities and 19 Poindexter module identities are
validated with Stage 33. This function does not monitor their directories,
read GitHub, subscribe to events, query a device or authenticate evidence.
Caller-provided health claims cannot become VERIFIED health, even if they
say OK; unknown, missing, future, or stale observations must never become
HEALTHY. Outputs are counts only, not project names or source payloads.

No accounts, secrets, user project folders, network, tasks, installer,
permission changes, or watcher activation are used in this module.
"""
from __future__ import annotations

from .v3_policy import PolicyBlocked
from .v3_portfolio_review import (
    PROJECTS, POINDEXTER_MODULES, validate_portfolio_preview
)

SCHEMA = "upab.watcher-v3.portfolio-health-rollup.v1"
OBSERVATION_SCHEMA = "upab.watcher-v3.untrusted-health-observation.v1"
CONDITIONS = frozenset({"OK", "ALERT", "DEGRADED", "PAUSED", "UNKNOWN"})
MAX_OBSERVATIONS = len(PROJECTS) + len(POINDEXTER_MODULES)
MAX_EPOCH = 2**53 - 1


def _epoch(value: object) -> bool:
    return type(value) is int and 0 <= value <= MAX_EPOCH


def review_health_rollup(
    *,
    portfolio: object,
    observations: object,
    now_epoch_s: int,
    max_age_s: int = 300,
) -> dict[str, object]:
    """Summarize inert, unverified statements without trusting any of them."""
    validate_portfolio_preview(portfolio)
    if not _epoch(now_epoch_s):
        raise PolicyBlocked("observation clock out of range")
    if type(max_age_s) is not int or not 1 <= max_age_s <= 3600:
        raise PolicyBlocked("bounded observation freshness required")
    if type(observations) is not list or len(observations) > MAX_OBSERVATIONS:
        raise PolicyBlocked("unbounded health review evidence")

    projects = set(PROJECTS)
    modules = {key for key, _ in POINDEXTER_MODULES}
    seen: set[tuple[str, str | None]] = set()
    counts = {
        "reported_ok_unverified": 0,
        "reported_alert_unverified": 0,
        "reported_degraded_unverified": 0,
        "reported_paused_unverified": 0,
        "reported_unknown": 0,
        "stale_unknown": 0,
    }
    observed_projects = 0
    observed_modules = 0
    for observation in observations:
        if type(observation) is not dict or set(observation) != {
            "schema", "repository", "module_id", "condition",
            "observed_at_epoch_s", "origin",
        }:
            raise PolicyBlocked("untrusted health observation schema invalid")
        if observation["schema"] != OBSERVATION_SCHEMA:
            raise PolicyBlocked("unknown health observation schema")
        if observation["origin"] != "UNTRUSTED_REVIEW_FIXTURE":
            raise PolicyBlocked("health source authenticity is not established")
        repo = observation["repository"]
        mod_id = observation["module_id"]
        condition = observation["condition"]
        when = observation["observed_at_epoch_s"]
        if type(repo) is not str or repo not in projects:
            raise PolicyBlocked("unselected health project")
        if mod_id is not None and (
            repo != "UP-UHAIB-001-Poindexter"
            or type(mod_id) is not str or mod_id not in modules
        ):
            raise PolicyBlocked("unapproved or misplaced module identity")
        identity = (repo, mod_id)
        if identity in seen:
            raise PolicyBlocked("duplicate health observation")
        seen.add(identity)
        if type(condition) is not str or condition not in CONDITIONS:
            raise PolicyBlocked("health claim condition invalid")
        if not _epoch(when) or when > now_epoch_s:
            raise PolicyBlocked("observation timestamp future or malformed")
        if mod_id is None:
            observed_projects += 1
        else:
            observed_modules += 1
        if now_epoch_s - when > max_age_s:
            counts["stale_unknown"] += 1
        elif condition == "UNKNOWN":
            counts["reported_unknown"] += 1
        else:
            counts["reported_" + condition.lower() + "_unverified"] += 1

    missing_projects = len(PROJECTS) - observed_projects
    missing_modules = len(POINDEXTER_MODULES) - observed_modules
    if missing_projects < 0 or missing_modules < 0:
        raise PolicyBlocked("health observation cardinality mismatch")
    return {
        "schema": SCHEMA,
        "status": "CALLER_REPORTED_DATA_ONLY_NO_VERIFIED_HEALTH",
        "selected_repository_count": len(PROJECTS),
        "nested_poindexter_module_count": len(POINDEXTER_MODULES),
        "reported_observations": len(observations),
        "missing_project_observations_unknown": missing_projects,
        "missing_module_observations_unknown": missing_modules,
        "fresh_unverified_ok": counts["reported_ok_unverified"],
        "fresh_unverified_alert": counts["reported_alert_unverified"],
        "fresh_unverified_degraded": counts["reported_degraded_unverified"],
        "fresh_unverified_paused": counts["reported_paused_unverified"],
        "explicit_unknown": counts["reported_unknown"],
        "stale_unknown": counts["stale_unknown"],
        "unknown_total": (
            missing_projects + missing_modules
            + counts["reported_unknown"] + counts["stale_unknown"]
        ),
        "all_project_data_sources_authenticated": False,
        "verified_healthy_projects": 0,
        "verified_healthy_modules": 0,
        "watcher_running_verified": False,
        "live_monitoring_enabled": False,
        "cross_project_access_enabled": False,
        "online_store_included": False,
        "owner_authenticated": False,
        "installation_authorized": False,
        "task_execution_authorized": False,
        "settings_changed": False,
    }
