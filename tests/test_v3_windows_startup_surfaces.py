from __future__ import annotations

import sys
import unittest
from unittest import mock

from upab.relay.v3_policy import PolicyBlocked
from upab.relay.v3_windows_startup_surfaces import (
    _PATTERN, observe_known_startup_surfaces,
)


class Stage19WindowsStartupSurfaceTests(unittest.TestCase):
    def test_native_startup_scan_never_proves_launcher_disabled(self):
        if sys.platform != "win32":
            with self.assertRaises(PolicyBlocked):
                observe_known_startup_surfaces()
            return
        data=observe_known_startup_surfaces()
        self.assertGreaterEqual(data["bounded_surface_count"], 0)
        self.assertGreaterEqual(data["potential_watcher_autostart_entry_count"], 0)
        self.assertGreaterEqual(data["unreadable_or_uninterpretable_surface_count"], 0)
        for key in (
            "commands_returned", "scheduled_tasks_inspected",
            "windows_services_inspected", "logon_scripts_inspected",
            "other_user_accounts_fully_inspected",
            "startup_discovery_exhaustive",
            "all_legacy_launch_paths_disabled_proven",
            "v1_quiescence_proven", "migration_authorized",
            "system_settings_changed",
        ):
            self.assertFalse(data[key], key)
        self.assertNotIn("registry_values", data)
        self.assertNotIn("command_lines", data)
        self.assertNotIn("usernames", data)

    def test_known_launcher_spelling_is_recognized_but_generic_names_not(self):
        self.assertTrue(_PATTERN.search("Enable-UPAB-ExactRelay.ps1"))
        self.assertTrue(_PATTERN.search("Start-UPAB-ExactRelay.ps1"))
        self.assertTrue(_PATTERN.search("C:\\scripts\\upab.ps1"))
        self.assertFalse(_PATTERN.search("notepad.exe"))
        self.assertFalse(_PATTERN.search("python.exe"))

    @unittest.skipUnless(sys.platform == "win32", "native Win32 scan only")
    def test_incomplete_environment_fails_safe_not_to_success(self):
        # Missing both Startup base variables cannot turn a partial scan
        # into any evidence that all launch paths were disabled.
        with mock.patch.dict("os.environ", {"APPDATA":"", "PROGRAMDATA":""}):
            report = observe_known_startup_surfaces()
        self.assertGreaterEqual(
            report["unreadable_or_uninterpretable_surface_count"], 2
        )
        self.assertFalse(report["all_legacy_launch_paths_disabled_proven"])
        self.assertFalse(report["migration_authorized"])

    def test_no_start_stop_registry_write_or_task_scheduler_methods(self):
        import upab.relay.v3_windows_startup_surfaces as survey
        for forbidden in (
            "disable_task", "delete_run_key", "update_registry",
            "kill_process", "create_service", "stop_watcher",
            "migrate_state", "enable_watcher", "write_task", "authorize",
        ):
            self.assertFalse(hasattr(survey, forbidden))


if __name__ == "__main__":
    unittest.main()
