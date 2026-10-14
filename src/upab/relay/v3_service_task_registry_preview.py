"""Stage 20: read-only *partial* Windows service / scheduled task registration scan.

HKLM Services registers services/drivers, not proof of running state.
Task Scheduler TaskCache Tree stores task metadata, not necessarily actions.
The inspector counts likely UPAB references from bounded registry names and
service ImagePath strings, never returns the values, names, paths, SIDs or PIDs.
It cannot prove shutdown, completeness, disabled startup or migration safety.
"""
from __future__ import annotations

import re
import sys

from .v3_policy import PolicyBlocked

_MATCH = re.compile(r"(?:upab|exact[-_ ]?relay|powershell[-_ ]?connection)", re.I)
_MAX_ITEMS = 8192
_MAX_DEPTH = 18
_MAX_STRING = 16384
_SERVICES_KEY = r"SYSTEM\CurrentControlSet\Services"
_TASK_TREE = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree"


def _read_short(reg, key, name, *, default=""):
    try:
        value, kind = reg.QueryValueEx(key, name)
    except FileNotFoundError:
        return default, False
    except OSError:
        return "", True
    if kind not in (reg.REG_SZ, reg.REG_EXPAND_SZ) or type(value) is not str:
        return "", True
    if len(value) > _MAX_STRING:
        raise PolicyBlocked("bounded startup registry string exceeded")
    return value, False


def observe_service_task_registrations() -> dict[str, object]:
    if sys.platform != "win32":
        raise PolicyBlocked("Windows registry inventory requires Windows")
    import winreg

    services_seen = tasks_seen = 0
    potential_services = potential_tasks = 0
    unreadable = 0
    truncated = False

    try:
        services = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, _SERVICES_KEY, 0,
                                  winreg.KEY_READ)
    except OSError as exc:
        raise PolicyBlocked("unable to enumerate Windows service registry") from exc
    with services:
        for i in range(_MAX_ITEMS):
            try:
                name = winreg.EnumKey(services, i)
            except OSError as exc:
                if getattr(exc, "winerror", None) == 259:
                    break
                raise PolicyBlocked("service enumeration incomplete") from exc
            if len(name) > 256:
                raise PolicyBlocked("service registry name exceeds bound")
            services_seen += 1
            hit = bool(_MATCH.search(name))
            try:
                key = winreg.OpenKey(services, name, 0, winreg.KEY_READ)
            except OSError:
                unreadable += 1
                continue
            with key:
                command, bad_cmd = _read_short(winreg, key, "ImagePath")
                display, bad_display = _read_short(winreg, key, "DisplayName")
                if bad_cmd or bad_display:
                    unreadable += 1
                hit = hit or bool(_MATCH.search(command) or _MATCH.search(display))
            potential_services += int(hit)
        else:
            truncated = True

    try:
        tree = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, _TASK_TREE, 0,
                              winreg.KEY_READ)
    except OSError:
        # Scheduler registry access is commonly restricted. This always
        # remains a partial report, never a clean or safe result.
        unreadable += 1
    else:
        with tree:
            pending = [(tree, 0)]
            # Never recurse into unbounded task tree; close every owned key.
            while pending:
                parent, depth = pending.pop()
                # Root is owned by with; descendants must be closed.
                try:
                    if depth >= _MAX_DEPTH:
                        truncated = True
                        continue
                    for i in range(_MAX_ITEMS - tasks_seen):
                        try:
                            child = winreg.EnumKey(parent, i)
                        except OSError as exc:
                            if getattr(exc, "winerror", None) == 259:
                                break
                            unreadable += 1
                            break
                        if len(child) > 512:
                            truncated = True
                            break
                        tasks_seen += 1
                        if _MATCH.search(child):
                            potential_tasks += 1
                        try:
                            handle = winreg.OpenKey(parent, child, 0, winreg.KEY_READ)
                        except OSError:
                            unreadable += 1
                            continue
                        pending.append((handle, depth + 1))
                    else:
                        truncated = True
                finally:
                    if depth != 0:
                        parent.Close()
                if tasks_seen >= _MAX_ITEMS:
                    truncated = True
                    for handle, _ in pending:
                        handle.Close()
                    pending.clear()
                    break

    return {
        "schema": "upab.watcher-v3.service-task-registry-preview.v1",
        "service_registration_entries_observed": services_seen,
        "task_tree_entries_observed": tasks_seen,
        "possible_watcher_service_entries": potential_services,
        "possible_watcher_task_names": potential_tasks,
        "unreadable_or_uninterpretable_entries": unreadable,
        "enumeration_bounded_or_truncated": truncated,
        "service_registry_observed": True,
        "task_definitions_or_actions_verified": False,
        "service_process_liveness_verified": False,
        "task_scheduler_api_enumeration_complete": False,
        "all_accounts_and_scheduled_actions_covered": False,
        "watcher_absent_proven": False,
        "startup_sources_disabled_proven": False,
        "v1_quiescence_proven": False,
        "owner_authenticated": False,
        "migration_authorized": False,
        "changes_performed": False,
    }
