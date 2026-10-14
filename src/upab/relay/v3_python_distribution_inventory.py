"""Stage 28 — explicit Python distribution and source-declaration evidence.

Only reads installed Python *distribution metadata* in the inspecting
interpreter and, optionally, a narrowly selected existing pyproject.toml.
It does not import the target package, resolve arbitrary entry points,
inspect private configs, run scripts, install/uninstall, or enumerate drives.

An absent distribution does not prove absence of portable installations or
other Python environments. A matching version/entry point does not prove
source authenticity, actual runtime identity, owner approval, or safety.
"""
from __future__ import annotations

import argparse
import importlib.metadata as metadata
import json
from pathlib import Path
import re
import stat
import sys
import tomllib

from .v3_policy import PolicyBlocked

_SCHEMA = "upab.watcher-v3.python-distribution-inventory.v1"
_DIST = "universal-powershell-agent-bridge"
_ENTRY_GROUP = "console_scripts"
_ENTRY_NAME = "upab"
_ENTRY_TARGET = "upab.cli:main"
_MAX_CONFIG_SIZE = 65536
_VERSION = re.compile(r"[0-9A-Za-z][0-9A-Za-z.!+_-]{0,63}\Z")


def _existing_pyproject(checkout: str | Path) -> Path:
    if not isinstance(checkout, (str, Path)):
        raise PolicyBlocked("explicit root must be a path")
    root = Path(checkout).expanduser()
    if not root.is_absolute():
        raise PolicyBlocked("source checkout must be an absolute path")
    for parent in (root, *root.parents):
        try:
            info = parent.lstat()
        except OSError as exc:
            raise PolicyBlocked("selected source directory unavailable") from exc
        if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode) or (
            getattr(info, "st_file_attributes", 0) & 0x400
        ):
            raise PolicyBlocked("selected source directory redirected")
    path = root / "pyproject.toml"
    try:
        info = path.lstat()
    except OSError as exc:
        raise PolicyBlocked("selected source metadata unavailable") from exc
    if (not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode)
            or getattr(info, "st_file_attributes", 0) & 0x400
            or not 1 <= info.st_size <= _MAX_CONFIG_SIZE):
        raise PolicyBlocked("source metadata not ordinary or exceeds bound")
    return path


def _source_declaration(root: str | Path) -> tuple[str, bool]:
    file = _existing_pyproject(root)
    before = file.stat()
    with file.open("rb") as stream:
        data = stream.read(_MAX_CONFIG_SIZE + 1)
    after = file.stat()
    if (len(data) != before.st_size or len(data) > _MAX_CONFIG_SIZE
            or after.st_size != before.st_size
            or after.st_mtime_ns != before.st_mtime_ns):
        raise PolicyBlocked("source metadata changed during read")
    try:
        tree = tomllib.loads(data.decode("utf-8"))
        project = tree["project"]
        name, version = project["name"], project["version"]
        entry = project.get("scripts", {}).get(_ENTRY_NAME)
    except (UnicodeError, ValueError, KeyError, TypeError, AttributeError) as exc:
        raise PolicyBlocked("source package metadata malformed") from exc
    if (type(name) is not str or name.casefold() != _DIST
            or type(version) is not str or not _VERSION.fullmatch(version)):
        raise PolicyBlocked("source project identity or version invalid")
    return version, entry == _ENTRY_TARGET


def inspect_python_distribution(
    *, inspect_environment: bool = False,
    checkout: str | Path | None = None,
) -> dict[str, object]:
    """Sanitized metadata only, deliberately cannot authorize anything."""
    if type(inspect_environment) is not bool:
        raise PolicyBlocked("explicit Python environment opt-in must be boolean")
    if checkout is not None and not inspect_environment:
        raise PolicyBlocked("checkout comparison requires explicit opt-in")
    source_version: str | None = None
    source_entry = False
    if checkout is not None:
        source_version, source_entry = _source_declaration(checkout)
    found = False
    dist_version: str | None = None
    exact_entry = False
    if inspect_environment:
        try:
            dist = metadata.distribution(_DIST)
        except metadata.PackageNotFoundError:
            pass
        except (OSError, ValueError, PermissionError) as exc:
            raise PolicyBlocked("distribution metadata cannot be inspected") from exc
        else:
            found = True
            version = dist.version
            if type(version) is not str or not _VERSION.fullmatch(version):
                raise PolicyBlocked("installed metadata version malformed")
            dist_version = version
            try:
                name = dist.metadata["Name"]
                entries = list(dist.entry_points)
            except (OSError, ValueError, TypeError, KeyError) as exc:
                raise PolicyBlocked("installed distribution metadata malformed") from exc
            if (type(name) is not str or name.casefold() != _DIST
                    or len(entries) > 256):
                raise PolicyBlocked("installed package identity invalid")
            exact_entry = any(
                ep.group == _ENTRY_GROUP and ep.name == _ENTRY_NAME
                and ep.value == _ENTRY_TARGET for ep in entries
            )
    return {
        "schema": _SCHEMA,
        "status": "METADATA_OBSERVED_NOT_INSTALLATION_PROOF",
        "environment_scan_requested": inspect_environment,
        "target_distribution_registered_here": found,
        "registered_version": dist_version,
        "expected_source_version": source_version,
        "expected_source_entrypoint_declared": source_entry,
        "registered_entrypoint_matches": exact_entry,
        "registered_version_matches_selected_source": (
            None if checkout is None or not found
            else dist_version == source_version
        ),
        "other_interpreters_inspected": False,
        "portable_script_checkout_excluded": False,
        "live_process_watcher_identity_proven": False,
        "distribution_source_authenticity_proven": False,
        "installed_runtime_proven": False,
        "owner_authenticated": False,
        "migration_authorized": False,
        "task_execution_authorized": False,
        "files_or_settings_changed": False,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Explicit read-only Python distribution metadata preview"
    )
    parser.add_argument("--inspect-python-env", action="store_true")
    parser.add_argument("--checkout", default=None)
    args = parser.parse_args(argv)
    try:
        report = inspect_python_distribution(
            inspect_environment=args.inspect_python_env,
            checkout=args.checkout,
        )
    except (OSError, UnicodeError, ValueError, PolicyBlocked) as exc:
        print("WATCHER_V3_DISTRIBUTION_PREVIEW_BLOCKED: " +
              type(exc).__name__, file=sys.stderr)
        return 7
    print(json.dumps(report, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
