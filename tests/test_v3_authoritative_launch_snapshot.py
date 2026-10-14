from __future__ import annotations

import csv
import io
import sys
import unittest
from unittest import mock

from upab.relay.v3_policy import PolicyBlocked
from upab.relay.v3_authoritative_launch_snapshot import (
    _count_csv_task_names, observe_scm_services, observe_registered_tasks,
    MATCH, SERVICE_STATUS_PROCESS, ENUM_SERVICE_STATUS_PROCESSW,
)


class Stage21AuthoritativeLaunchSnapshotTests(unittest.TestCase):
    def test_scm_native_snapshot_always_denies_cutover(self):
        if sys.platform != "win32":
            with self.assertRaises(PolicyBlocked):
                observe_scm_services()
            return
        try:
            report=observe_scm_services()
        except PolicyBlocked:
            # An inaccessible SCM is a BLOCKED condition, never SAFE.
            return
        self.assertGreater(report["win32_service_entries_observed"], 1)
        self.assertGreaterEqual(report["possible_watcher_services_observed"], 0)
        self.assertGreaterEqual(
            report["possible_watcher_services_running_at_sample"], 0
        )
        for field in ("service_names_or_pids_exposed","driver_services_included",
                      "service_processes_proven_stopped",
                      "all_watcher_launchers_known",
                      "v1_quiescence_proven", "migration_authorized",
                      "execution_authorized", "windows_changes_performed"):
            self.assertIs(report[field],False,field)
        self.assertNotIn("service_names",report)
        self.assertNotIn("service_pids",report)

    def test_task_csv_parser_bounded_and_matches_task_name_only(self):
        fixture = (
            '"\\Microsoft\\Windows\\Foo","Never","Ready"\n'
            '"\\UPAB-ExactRelay-old","Tomorrow","Ready"\n'
            '"\\WindowsService","Soon","Ready"\n'
        )
        self.assertEqual(_count_csv_task_names(fixture), (3, 1))
        for invalid in ("Not a task\n", '"no backslash","ready"\n',
                        "x"*(2*1024*1024+1)):
            with self.subTest(invalid_len=len(invalid)):
                with self.assertRaises(PolicyBlocked):
                    _count_csv_task_names(invalid)

    def test_native_task_query_does_not_expose_actions_or_authorize(self):
        if sys.platform != "win32":
            with self.assertRaises(PolicyBlocked):
                observe_registered_tasks()
            return
        try:
            report = observe_registered_tasks()
        except PolicyBlocked:
            # Missing CI Task Scheduler permissions/service is a safe DENY.
            return
        self.assertGreaterEqual(report["registered_task_names_observed"], 0)
        self.assertGreaterEqual(report["possible_watcher_task_names"], 0)
        for key in (
            "task_actions_read_or_exported", "task_actions_absence_proven",
            "scheduler_access_scope_complete", "startup_disablement_proven",
            "running_task_instances_excluded", "v1_quiescence_proven",
            "migration_authorized", "execution_authorized",
            "windows_changes_performed",
        ):
            self.assertIs(report[key],False,key)
        self.assertNotIn("task_names",report)
        self.assertNotIn("task_actions",report)

    def test_fixed_query_does_not_shell_or_accept_user_commands(self):
        import upab.relay.v3_authoritative_launch_snapshot as m
        for forbidden in (
            "disable_task","create_task","delete_task","restart_service",
            "stop_service","run_command","approve", "execute_task",
            "migrate","connect_repo",
        ):
            self.assertFalse(hasattr(m,forbidden))
        self.assertTrue(MATCH.search("Watcher-UPAB"))
        self.assertFalse(MATCH.search("Windows Update"))
        import ctypes
        self.assertGreater(ctypes.sizeof(ENUM_SERVICE_STATUS_PROCESSW),
                           ctypes.sizeof(SERVICE_STATUS_PROCESS))

    def test_query_failure_is_policy_blocked_not_success(self):
        if sys.platform != "win32":
            self.skipTest("native schtasks binary only on Windows")
        import upab.relay.v3_authoritative_launch_snapshot as module
        failed=mock.Mock(returncode=1,stdout="",stderr="access denied")
        with mock.patch.object(module.subprocess,"run",return_value=failed):
            with self.assertRaises(PolicyBlocked):
                observe_registered_tasks()
        with mock.patch.object(
            module.subprocess,"run",side_effect=module.subprocess.TimeoutExpired(
                cmd="schtasks",timeout=0.001
            )
        ):
            with self.assertRaises(PolicyBlocked):
                observe_registered_tasks()


if __name__ == "__main__":
    unittest.main()
