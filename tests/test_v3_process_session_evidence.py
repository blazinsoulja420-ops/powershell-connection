from __future__ import annotations

import sys
import unittest

from upab.relay.v3_policy import PolicyBlocked
from upab.relay.v3_process_session_evidence import (
    FILETIME, MAX_RELEVANT, classify_host_sessions,
    observe_process_sessions,
)


class Stage24Win32SessionEvidenceTests(unittest.TestCase):
    def test_public_fixture_counts_are_bounded_and_not_owner_proof(self):
        report = classify_host_sessions(
            candidates=[7, 7, 3, None, 9, 3],
            current_session=7, active_console_session=3,
        )
        self.assertEqual(report["candidate_host_instances_observed"],6)
        self.assertEqual(report["candidate_hosts_in_process_session"],2)
        self.assertEqual(report["candidate_hosts_in_other_sessions"],3)
        self.assertEqual(report["candidate_host_sessions_inaccessible"],1)
        self.assertEqual(report["candidate_hosts_in_active_console_session"],2)
        self.assertTrue(report["active_console_session_observed"])
        self.assertFalse(report["current_session_is_active_console"])
        self.assertFalse(report["old_watcher_process_absence_proven"])
        self.assertFalse(report["owner_interactive_presence_proven"])
        self.assertFalse(report["task_execution_authorized"])

    def test_absent_console_session_does_not_imply_no_owner(self):
        report = classify_host_sessions(
            candidates=[0, None], current_session=0,
            active_console_session=None
        )
        self.assertFalse(report["active_console_session_observed"])
        self.assertFalse(report["current_session_is_active_console"])
        self.assertEqual(report["candidate_hosts_in_active_console_session"],0)
        self.assertEqual(report["candidate_host_sessions_inaccessible"],1)
        self.assertFalse(report["old_watcher_process_absence_proven"])

    def test_zero_hosts_does_not_prove_legacy_watcher_exit(self):
        report = classify_host_sessions(
            candidates=[], current_session=0, active_console_session=0
        )
        self.assertEqual(report["candidate_host_instances_observed"],0)
        self.assertTrue(report["current_session_is_active_console"])
        self.assertFalse(report["old_watcher_process_absence_proven"])
        self.assertFalse(report["owner_interactive_presence_proven"])

    def test_invalid_session_inputs_fail_closed(self):
        for kwargs in (
            {"candidates":"not a list", "current_session":0, "active_console_session":0},
            {"candidates":[-1], "current_session":0, "active_console_session":0},
            {"candidates":[4294967295], "current_session":0, "active_console_session":0},
            {"candidates":[True], "current_session":0, "active_console_session":0},
            {"candidates":[0], "current_session":True, "active_console_session":0},
            {"candidates":[0], "current_session":-1, "active_console_session":0},
            {"candidates":[0], "current_session":0, "active_console_session":4294967295},
            {"candidates":[0], "current_session":0, "active_console_session":"console"},
        ):
            with self.subTest(kwargs=kwargs):
                with self.assertRaises(PolicyBlocked):
                    classify_host_sessions(**kwargs)

    def test_large_candidate_list_fails_before_aggregation(self):
        with self.assertRaises(PolicyBlocked):
            classify_host_sessions(
                candidates=[0] * (MAX_RELEVANT + 1),
                current_session=0, active_console_session=0
            )

    def test_current_process_is_not_an_authenticator(self):
        if sys.platform != "win32":
            with self.assertRaises(PolicyBlocked):
                observe_process_sessions()
            return
        report = observe_process_sessions()
        self.assertTrue(report["session_evidence_sampled"])
        self.assertGreater(report["total_process_entries_in_snapshot"], 1)
        self.assertGreaterEqual(report["candidate_host_instances_observed"],0)
        for field in (
            "process_image_paths_or_args_exposed", "raw_pids_or_session_ids_exposed",
            "user_sid_or_tokens_exposed",
            "renamed_or_generic_hosts_exhaustively_identified",
            "in_flight_task_absence_proven",
            "v1_shutdown_and_restart_prevention_proven",
            "owner_windows_hello_verified", "deployment_authorized",
            "processes_stopped", "settings_changed",
            "old_watcher_process_absence_proven",
            "owner_interactive_presence_proven", "task_execution_authorized",
        ):
            self.assertIs(report[field],False,field)
        for forbidden in ("pids","process_names","full_paths","command_lines",
                          "arguments", "session_ids","owner_sid","tokens"):
            self.assertNotIn(forbidden,report)

    @unittest.skipUnless(sys.platform == "win32", "native Windows only")
    def test_windows_filetime_abi_shape(self):
        import ctypes
        self.assertEqual(ctypes.sizeof(FILETIME),8)

    def test_no_process_termination_or_owner_enrollment_api(self):
        import upab.relay.v3_process_session_evidence as m
        for forbidden in (
            "stop_watcher","kill_process","suspend_process","create_service",
            "start_windows_hello","enroll_owner","issue_token",
            "execute_task","authorize_migration","enable_feature",
            "connect_repository","merge_pull_request",
        ):
            self.assertFalse(hasattr(m,forbidden))


if __name__=="__main__":
    unittest.main()
