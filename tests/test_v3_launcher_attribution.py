from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys
import unittest

from upab.relay.v3_launcher_attribution import (
    MAX_CHARS, MAX_ITEMS, classify_description, count_launch_descriptions,
)
from upab.relay.v3_policy import PolicyBlocked

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "Get-UPABWatcherLauncherEvidence.ps1"


class Stage25LauncherAttributionTests(unittest.TestCase):
    def test_known_v1_script_and_module_signatures_are_candidates_only(self):
        descriptions = [
            "python -m upab relay-watch --config public",
            "powershell -File C:\\repo\\scripts\\Start-UPAB-ExactRelay.ps1",
            "powershell -File C:\\repo\\scripts\\upab.ps1",
            "Unrelated UPAB idea, not a task",
            "python app.py",
            None,
        ]
        report = count_launch_descriptions(descriptions, source="process")
        self.assertEqual(report["items_examined"], 6)
        self.assertEqual(report["candidate_signatures"], 3)
        self.assertEqual(report["ambiguous_hints"], 1)
        self.assertEqual(report["other"], 1)
        self.assertEqual(report["unreadable"], 1)
        for guard in (
            "raw_command_lines_exposed", "watcher_identity_proven",
            "old_watcher_stopped_proven", "owner_authenticated",
            "migration_authorized", "execution_authorized", "changes_performed",
        ):
            self.assertIs(report[guard], False, guard)
        self.assertNotIn("command_lines", report)

    def test_no_match_not_evidence_of_shutdown(self):
        for source in ("process", "service", "task"):
            report = count_launch_descriptions([], source=source)
            self.assertEqual(report["candidate_signatures"], 0)
            self.assertFalse(report["old_watcher_stopped_proven"])

    def test_invalid_sources_and_oversized_records_blocked(self):
        for bad in ((), {}, "string", None, [0], ["X" * (MAX_CHARS + 1)],
                    [None] * (MAX_ITEMS + 1)):
            with self.subTest(bad_type=type(bad).__name__):
                with self.assertRaises(PolicyBlocked):
                    count_launch_descriptions(bad, source="process")
        with self.assertRaises(PolicyBlocked):
            count_launch_descriptions([], source="made-up")
        self.assertEqual(classify_description(""), "UNREADABLE")

    @unittest.skipUnless(sys.platform == "win32", "PowerShell 5.1 integration")
    def test_powershell_public_fixture_never_authorizes(self):
        self.assertTrue(SCRIPT.is_file())
        proc = subprocess.run(
            ["powershell.exe", "-NoProfile", "-NonInteractive",
             "-File", str(SCRIPT), "-FixtureOnly"],
            check=False, capture_output=True, text=True, timeout=40
        )
        self.assertEqual(proc.returncode, 0, proc.stderr[-1000:])
        report = json.loads(proc.stdout.strip())
        self.assertTrue(report["FixtureOnly"])
        self.assertFalse(report["LocalInspectionRequested"])
        self.assertEqual(report["SourceStatuses"]["Process"], "SYNTHETIC_FIXTURE")
        self.assertEqual(report["AggregateCounts"]["Process"]["KnownSignatureCandidates"], 2)
        self.assertEqual(report["AggregateCounts"]["Process"]["AmbiguousHints"], 1)
        self.assertEqual(report["AggregateCounts"]["Process"]["Unreadable"], 1)
        self.assertFalse(report["MigrationAuthorized"])
        self.assertFalse(report["OldWatcherQuiescenceProven"])
        self.assertFalse(report["RealTaskExecutionAuthorized"])
        self.assertFalse(report["SystemChangesPerformed"])
        self.assertNotIn("python.exe -m upab",proc.stdout)

    @unittest.skipUnless(sys.platform == "win32", "PowerShell 5.1 integration")
    def test_powershell_default_mode_never_scans_device(self):
        proc = subprocess.run(
            ["powershell.exe", "-NoProfile", "-NonInteractive",
             "-File", str(SCRIPT)],
            check=False, capture_output=True, text=True, timeout=40
        )
        self.assertEqual(proc.returncode, 0, proc.stderr[-1000:])
        report = json.loads(proc.stdout.strip())
        self.assertEqual(report["SourceStatuses"]["Process"],"NOT_REQUESTED")
        self.assertEqual(report["SourceStatuses"]["ScheduledTask"],"NOT_REQUESTED")
        self.assertEqual(report["SourceStatuses"]["Service"],"NOT_REQUESTED")
        self.assertIsNone(report["AggregateCounts"]["Process"])
        self.assertFalse(report["SystemChangesPerformed"])

    @unittest.skipUnless(sys.platform == "win32", "PowerShell 5.1 integration")
    def test_conflicting_read_only_modes_fail_closed(self):
        proc = subprocess.run(
            ["powershell.exe", "-NoProfile", "-NonInteractive",
             "-File", str(SCRIPT), "-FixtureOnly", "-InspectLocal"],
            check=False, capture_output=True, text=True, timeout=40
        )
        self.assertNotEqual(proc.returncode,0)

    def test_script_only_calls_read_only_system_discovery(self):
        text = SCRIPT.read_text(encoding="utf-8")
        self.assertIn("Get-CimInstance Win32_Process",text)
        self.assertIn("Get-ScheduledTask",text)
        self.assertIn("Get-CimInstance Win32_Service",text)
        self.assertIn("$p.ProcessId -eq $PID",text)
        for dangerous in (
            "Stop-Process ", "Stop-Service ", "Set-ScheduledTask ",
            "Register-ScheduledTask ", "Set-ItemProperty ",
            "Remove-Item ", "Invoke-Expression ", "Start-Process ",
        ):
            self.assertNotIn(dangerous,text)

    def test_no_realtime_executor_method(self):
        import upab.relay.v3_launcher_attribution as module
        for method in ("kill_process","authorize_migration","execute_task",
                       "approve","deploy","connect_repo","create_task"):
            self.assertFalse(hasattr(module,method))


if __name__=="__main__":
    unittest.main()
