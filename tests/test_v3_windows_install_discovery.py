from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "Get-UPABWatcherInstallCandidates.ps1"


class Stage28WindowsDiscoveryTests(unittest.TestCase):
    def test_discovery_script_uses_metadata_not_content_or_execution(self):
        code=SCRIPT.read_text(encoding="utf-8")
        self.assertIn("Get-ChildItem",code)
        self.assertIn("Test-Path",code)
        self.assertIn("Get-Item",code)
        self.assertIn("BOUNDED_PARTIAL_OBSERVATION",code)
        self.assertIn("SourceOriginVerified = $false",code)
        self.assertIn("InstalledRuntimeIdentified = $false",code)
        for forbidden in (
            "Get-Content ", "Invoke-Expression ", "Stop-Process ",
            "Start-Process ", "Set-ScheduledTask ", "Disable-ScheduledTask ",
            "Remove-Item ", "New-Item ", "Register-ScheduledTask ",
            "Set-ItemProperty ", "Invoke-WebRequest ",
            "git clone", "pip install", "Invoke-RestMethod ",
        ):
            self.assertNotIn(forbidden,code)

    @unittest.skipUnless(sys.platform=="win32", "native PowerShell fixture")
    def test_public_fixture_is_not_installation_authority(self):
        result=subprocess.run(
            ["powershell.exe","-NoProfile","-NonInteractive",
             "-File",str(SCRIPT),"-FixtureOnly"],
            capture_output=True,text=True,timeout=40,check=False
        )
        self.assertEqual(result.returncode,0,result.stderr[-600:])
        data=json.loads(result.stdout.strip())
        self.assertEqual(data["Mode"],"SYNTHETIC_FIXTURE")
        self.assertEqual(data["Counts"]["CandidateFoldersExamined"],4)
        self.assertEqual(data["Counts"]["ThreeMarkerSourceCandidates"],1)
        self.assertEqual(data["Counts"]["PartialMarkerCandidates"],2)
        self.assertEqual(data["Counts"]["NoMarkerFolders"],1)
        for guard in (
            "PathsOrFileContentsReturned","SourceOriginVerified",
            "InstalledRuntimeIdentified",
            "AllInstallationLocationsCovered",
            "OldWatcherStoppedProven",
            "TaskExecutionAuthorized","ChangesPerformed",
        ):
            self.assertIs(data[guard],False,guard)

    @unittest.skipUnless(sys.platform=="win32", "native PowerShell default")
    def test_default_does_not_inspect_os(self):
        result=subprocess.run(
            ["powershell.exe","-NoProfile","-NonInteractive",
             "-File",str(SCRIPT)],
            capture_output=True,text=True,timeout=40,check=False
        )
        self.assertEqual(result.returncode,0,result.stderr[-600:])
        data=json.loads(result.stdout.strip())
        self.assertEqual(data["Mode"],"NOT_REQUESTED")
        self.assertIsNone(data["Counts"])
        self.assertFalse(data["ChangesPerformed"])

    @unittest.skipUnless(sys.platform=="win32", "native PowerShell argument rejection")
    def test_conflicting_modes_blocked(self):
        result=subprocess.run(
            ["powershell.exe","-NoProfile","-NonInteractive",
             "-File",str(SCRIPT),"-FixtureOnly","-InspectLocal"],
            capture_output=True,text=True,timeout=40,check=False
        )
        self.assertNotEqual(result.returncode,0)


if __name__=="__main__":
    unittest.main()
