"""Stage 19: bounded read-only Windows startup *surface* observation.

Scans only classic HKCU/HKLM Run/RunOnce registry keys and the standard
per-user/all-user Startup directory filenames. No command content, full
paths, registry values, arbitrary file bytes, identifiers or PIDs are
returned. Missing permissions make the survey incomplete, never SAFE.

This does NOT inspect Windows Scheduled Tasks, services, WMI events,
AppInit hooks, other accounts, arbitrary logon scripts or already running
processes. No negative result can prove legacy watcher launchers disabled.
"""
from __future__ import annotations

import os
from pathlib import Path
import re
import stat
import sys

from .v3_policy import PolicyBlocked

_PATTERN = re.compile(r"(?:upab|exact[-_ ]?relay|powershell[-_ ]?connection)", re.I)
_RUN_SUBKEYS = (
    r"Software\Microsoft\Windows\CurrentVersion\Run",
    r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
    r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
    r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce",
)
_MAX_ITEMS_PER_SURFACE = 1024
_MAX_VALUE_CHARS = 8192
_AUTOSTART_EXTENSIONS = frozenset({".lnk", ".ps1", ".bat", ".cmd", ".vbs"})


def observe_known_startup_surfaces() -> dict[str, object]:
    if sys.platform != "win32":
        raise PolicyBlocked("Windows startup survey requires Windows")
    import winreg

    surface_count = 0
    incomplete_count = 0
    potential_count = 0
    for hive in (winreg.HKEY_CURRENT_USER, winreg.HKEY_LOCAL_MACHINE):
        for key_path in _RUN_SUBKEYS:
            try:
                reg = winreg.OpenKey(hive, key_path, 0, winreg.KEY_READ)
            except FileNotFoundError:
                surface_count += 1
                continue
            except OSError:
                incomplete_count += 1
                continue
            with reg:
                surface_count += 1
                for i in range(_MAX_ITEMS_PER_SURFACE):
                    try:
                        name, raw_value, typ = winreg.EnumValue(reg, i)
                    except OSError as exc:
                        if getattr(exc, "winerror", None) == 259:
                            break
                        raise PolicyBlocked("Windows Run registry surface incomplete") from exc
                    if not isinstance(name, str) or len(name) > 512:
                        raise PolicyBlocked("unbounded registry entry name")
                    if typ in (winreg.REG_SZ, winreg.REG_EXPAND_SZ):
                        if not isinstance(raw_value, str) or len(raw_value) > _MAX_VALUE_CHARS:
                            raise PolicyBlocked("unbounded startup registry entry")
                        if _PATTERN.search(name) or _PATTERN.search(raw_value):
                            potential_count += 1
                    elif _PATTERN.search(name):
                        # Nontext registry entries cannot be interpreted.
                        incomplete_count += 1
                else:
                    raise PolicyBlocked("too many registry startup entries")
    startup_path_suffix = ("Microsoft", "Windows", "Start Menu", "Programs", "Startup")
    for var in ("APPDATA", "PROGRAMDATA"):
        base = os.environ.get(var)
        if not base:
            incomplete_count += 1
            continue
        root = Path(base).joinpath(*startup_path_suffix)
        try:
            details = root.lstat()
        except FileNotFoundError:
            surface_count += 1
            continue
        except OSError:
            incomplete_count += 1
            continue
        if (not stat.S_ISDIR(details.st_mode) or stat.S_ISLNK(details.st_mode)
                or getattr(details, "st_file_attributes", 0) & 0x400):
            raise PolicyBlocked("Startup folder redirected or invalid")
        surface_count += 1
        count = 0
        try:
            entries = root.iterdir()
            for item in entries:
                count += 1
                if count > _MAX_ITEMS_PER_SURFACE:
                    raise PolicyBlocked("too many Startup entries")
                metadata = item.lstat()
                if stat.S_ISLNK(metadata.st_mode) or (
                    getattr(metadata, "st_file_attributes", 0) & 0x400
                ):
                    incomplete_count += 1
                    continue
                if item.suffix.casefold() in _AUTOSTART_EXTENSIONS and _PATTERN.search(item.name):
                    potential_count += 1
        except OSError as exc:
            raise PolicyBlocked("Startup folder enumeration incomplete") from exc
    return {
        "schema": "upab.watcher-v3.windows-startup-surfaces.v1",
        "bounded_surface_count": surface_count,
        "unreadable_or_uninterpretable_surface_count": incomplete_count,
        "potential_watcher_autostart_entry_count": potential_count,
        "commands_returned": False,
        "scheduled_tasks_inspected": False,
        "windows_services_inspected": False,
        "logon_scripts_inspected": False,
        "other_user_accounts_fully_inspected": False,
        "startup_discovery_exhaustive": False,
        "all_legacy_launch_paths_disabled_proven": False,
        "v1_quiescence_proven": False,
        "migration_authorized": False,
        "system_settings_changed": False,
    }
