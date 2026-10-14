"""Stage 33: READ-ONLY proposed project/module portfolio validation.

An owner-selected roster in a review file is not a watcher installation,
directory access grant, project intake approval, scheduler task, credential,
repository connector or source of execution authority. The 19 Poindexter
categories are nested MODULES, not 19 new repositories or watch roots.

This initial frozen owner-selected roster is deliberately strict. Future
new project selections require separate human-reviewed source changes and
new tests; they are never inferred from arbitrary filesystem folders.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import stat
import sys

from .v3_features import _unique_pairs
from .v3_policy import PolicyBlocked

SCHEMA = "upab.watcher-v3.owner-selected-portfolio-preview.v1"
BASIS = "owner-selected-2026-10-14"
OWNER = "blazinsoulja420-ops"
PROJECT_CAPACITY = 64
MONITOR_CAPACITY = 32
MAX_CONFIG_BYTES = 16384

# Exact existing GitHub repository names; project selection does not
# imply permission to fetch, read, clone, subscribe or monitor them.
PROJECTS = (
    "UP-UHAIB-001-Poindexter",
    "Universal-AI-",
    "UP-RES-001-Autonomous-Research-System",
    "UASN-AI-Specialist",
    "powershell-connection",
    "P-DT-001-Digital-Twin",
    "Universal-AI-Behavior-Requirements-Registry",
    "NSFW",
    "Kali-Linux-",
)
SCOPES = {
    "NSFW": "INDEPENDENT_RESTRICTED",
    "Kali-Linux-": "DEFENSIVE_OFFLINE_ONLY",
    "Universal-AI-Behavior-Requirements-Registry": "REQUIREMENTS_ONLY",
}
# Canonical ID mapping from the October 14, 2026 Master Plan's 19-category
# TABLE. The companion software-map diagram arranges categories in a
# different visual order; no diagram position becomes an identity key.
POINDEXTER_MODULES = (
    ("001", "AI Chat / Space"),
    ("002", "Browser"),
    ("003", "Digital Twin"),
    ("004", "Managed Software"),
    ("005", "Software Design"),
    ("006", "Software & AI Health"),
    ("007", "Local Events"),
    ("008", "Restaurants"),
    ("009", "Local Stores"),
    ("010", "Meal Suggestions"),
    ("011", "Shopping"),
    ("012", "Rewards"),
    ("013", "Community Chat"),
    ("014", "Fame"),
    ("015", "Games"),
    ("016", "Developer Workspace"),
    ("017", "Support Chat"),
    ("018", "Wallet"),
    ("019", "Auction / Yard Sale"),
)
EXCLUDED_REPOSITORIES = frozenset({"online-store"})


def validate_portfolio_preview(raw: object) -> dict[str, object]:
    """Validate only an inert proposal: all monitoring/integrations OFF."""
    if type(raw) is not dict or set(raw) != {
        "schema", "basis", "owner", "project_limit", "monitor_limit",
        "auto_activation", "connections", "projects",
    }:
        raise PolicyBlocked("portfolio top-level schema invalid")
    if raw["schema"] != SCHEMA or raw["basis"] != BASIS or raw["owner"] != OWNER:
        raise PolicyBlocked("portfolio source label or repository owner unexpected")
    if (type(raw["project_limit"]) is not int or raw["project_limit"] != PROJECT_CAPACITY
            or type(raw["monitor_limit"]) is not int
            or raw["monitor_limit"] != MONITOR_CAPACITY):
        raise PolicyBlocked("project or monitor capacity changed")
    if raw["auto_activation"] is not False:
        raise PolicyBlocked("automatic monitoring activation forbidden")
    if type(raw["connections"]) is not list or raw["connections"]:
        raise PolicyBlocked("interproject connections require separate approval")
    entries = raw["projects"]
    if type(entries) is not list or len(entries) != len(PROJECTS):
        raise PolicyBlocked("exact owner-selected roster not supplied")
    seen: set[str] = set()
    for entry in entries:
        if type(entry) is not dict or set(entry) != {
            "repository", "monitor_enabled", "scope", "modules",
        }:
            raise PolicyBlocked("project entry contains unapproved fields")
        name = entry["repository"]
        if (type(name) is not str or name not in PROJECTS
                or name in EXCLUDED_REPOSITORIES or name in seen):
            raise PolicyBlocked("unknown, excluded or duplicate project")
        seen.add(name)
        if entry["monitor_enabled"] is not False:
            raise PolicyBlocked("project monitoring may not be activated by this file")
        scope = SCOPES.get(name, "STANDALONE")
        if type(entry["scope"]) is not str or entry["scope"] != scope:
            raise PolicyBlocked("project security isolation scope invalid")
        modules = entry["modules"]
        if type(modules) is not list:
            raise PolicyBlocked("modules must be a list")
        if name == "UP-UHAIB-001-Poindexter":
            if len(modules) != len(POINDEXTER_MODULES):
                raise PolicyBlocked("Poindexter must contain exactly 19 modules")
            expected = dict(POINDEXTER_MODULES)
            module_seen: set[str] = set()
            for module in modules:
                if type(module) is not dict or set(module) != {
                    "id", "category", "monitor_enabled",
                }:
                    raise PolicyBlocked("module schema invalid")
                mod_id = module["id"]
                if (type(mod_id) is not str or mod_id in module_seen
                        or mod_id not in expected
                        or type(module["category"]) is not str
                        or module["category"] != expected[mod_id]):
                    raise PolicyBlocked("module name, ID, or identity invalid")
                if module["monitor_enabled"] is not False:
                    raise PolicyBlocked("module monitoring activation requires approval")
                module_seen.add(mod_id)
            if module_seen != set(expected):
                raise PolicyBlocked("Poindexter module set mismatch")
        elif modules:
            raise PolicyBlocked("module category cannot become another repository")
    if seen != set(PROJECTS):
        raise PolicyBlocked("approved owner-selected project set mismatch")
    return {
        "schema": "upab.watcher-v3.portfolio-review-result.v1",
        "status": "OWNER_SELECTED_ROSTER_VALIDATED_NOT_ACTIVATED",
        "selected_repository_count": len(PROJECTS),
        "poindexter_module_category_count": len(POINDEXTER_MODULES),
        "additional_repositories_from_modules": 0,
        "project_limit": PROJECT_CAPACITY,
        "monitor_limit": MONITOR_CAPACITY,
        "monitoring_enabled_count": 0,
        "connections_enabled_count": 0,
        "excluded_online_store": True,
        "restricted_projects_retain_boundaries": True,
        "github_repository_permission_granted": False,
        "chat_creation_authorized": False,
        "local_folder_creation_authorized": False,
        "owner_authenticated": False,
        "monitoring_installed": False,
        "task_execution_authorized": False,
        "settings_changed": False,
    }


def load_portfolio_preview(path: str | Path) -> dict[str, object]:
    """Explicit absolute existing JSON fixture; no paths leave the process."""
    if not isinstance(path, (str, Path)):
        raise PolicyBlocked("portfolio path invalid")
    candidate = Path(path).expanduser()
    if not candidate.is_absolute():
        raise PolicyBlocked("portfolio path must be absolute")
    for part in (*candidate.parents, candidate):
        try:
            meta = part.lstat()
        except (OSError, ValueError) as exc:
            raise PolicyBlocked("portfolio source unavailable") from exc
        if (stat.S_ISLNK(meta.st_mode)
                or getattr(meta, "st_file_attributes", 0) & 0x400
                or (stat.S_ISREG(meta.st_mode) if part != candidate
                    else not stat.S_ISREG(meta.st_mode))):
            raise PolicyBlocked("portfolio path type or redirection forbidden")
        if part != candidate and not stat.S_ISDIR(meta.st_mode):
            raise PolicyBlocked("portfolio parent is not directory")
    before = candidate.stat()
    if not 1 <= before.st_size <= MAX_CONFIG_BYTES:
        raise PolicyBlocked("portfolio file size outside bound")
    with candidate.open("rb") as reader:
        content = reader.read(MAX_CONFIG_BYTES + 1)
    after = candidate.stat()
    if (len(content) != before.st_size or len(content) > MAX_CONFIG_BYTES
            or before.st_mtime_ns != after.st_mtime_ns
            or before.st_size != after.st_size):
        raise PolicyBlocked("portfolio file unstable")
    try:
        data = json.loads(content, object_pairs_hook=_unique_pairs)
    except (ValueError, UnicodeError) as exc:
        raise PolicyBlocked("portfolio input JSON malformed") from exc
    return validate_portfolio_preview(data)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Review selected project/modules; DOES NOT start monitors"
    )
    parser.add_argument("--config", required=True)
    args = parser.parse_args(argv)
    try:
        result = load_portfolio_preview(args.config)
    except (OSError, ValueError, PolicyBlocked) as exc:
        print("WATCHER_V3_PORTFOLIO_PREVIEW_BLOCKED: " +
              type(exc).__name__, file=sys.stderr)
        return 7
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
