from __future__ import annotations

import sys
import unittest

from upab.relay.v3_policy import PolicyBlocked
from upab.relay.v3_service_task_registry_preview import (
    _MATCH, observe_service_task_registrations,
)


class Stage20ServiceTaskRegistryPreviewTests(unittest.TestCase):
    def test_native_service_task_registry_is_read_only_and_non_authorizing(self):
        if sys.platform != "win32":
            with self.assertRaises(PolicyBlocked):
                observe_service_task_registrations()
            return
        result = observe_service_task_registrations()
        self.assertGreater(result["service_registration_entries_observed"],0)
        for field in (
            "task_tree_entries_observed", "possible_watcher_task_names",
            "possible_watcher_service_entries", "unreadable_or_uninterpretable_entries",
        ):
            self.assertGreaterEqual(result[field],0)
        for key in (
            "task_definitions_or_actions_verified",
            "service_process_liveness_verified",
            "task_scheduler_api_enumeration_complete",
            "all_accounts_and_scheduled_actions_covered",
            "watcher_absent_proven", "startup_sources_disabled_proven",
            "v1_quiescence_proven", "owner_authenticated",
            "migration_authorized", "changes_performed",
        ):
            self.assertFalse(result[key], key)
        for secret in ("service_names", "task_names", "image_paths",
                       "command_lines", "pids", "registry_values"):
            self.assertNotIn(secret,result)

    def test_names_and_image_paths_are_candidate_filters_only(self):
        self.assertTrue(_MATCH.search("UPAB.ExactRelay"))
        self.assertTrue(_MATCH.search("Start-UPAB-ExactRelay.ps1"))
        self.assertFalse(_MATCH.search("Windows Defender"))
        self.assertFalse(_MATCH.search("powershell.exe"))
        self.assertFalse(_MATCH.search("python.exe"))

    def test_only_read_only_surface_functions_exist(self):
        import upab.relay.v3_service_task_registry_preview as module
        for name in ("disable_task", "stop_service", "restart_service",
                     "delete_registry_key", "run", "activate",
                     "authorize", "execute_task"):
            self.assertFalse(hasattr(module,name))


if __name__ == "__main__":
    unittest.main()
