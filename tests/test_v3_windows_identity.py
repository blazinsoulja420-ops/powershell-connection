from __future__ import annotations

import sys
import unittest

from upab.relay.v3_policy import PolicyBlocked
from upab.relay.v3_windows_identity import read_windows_identity_evidence


class WindowsIdentityEvidenceTests(unittest.TestCase):
    def test_real_windows_process_token_or_explicit_platform_denial(self):
        if sys.platform != "win32":
            with self.assertRaises(PolicyBlocked):
                read_windows_identity_evidence()
            return
        report = read_windows_identity_evidence()
        self.assertEqual(
            report["schema"], "upab.watcher-v3.windows-identity-evidence.v1"
        )
        self.assertTrue(report["process_user_sid"].startswith("S-1-"))
        self.assertGreaterEqual(report["process_session_id"], 0)
        self.assertTrue(report["process_identity_observed"])
        self.assertFalse(report["owner_authenticated"])
        self.assertFalse(report["human_present"])
        self.assertFalse(report["task_approved"])
        self.assertFalse(report["execution_allowed"])
        self.assertNotIn("password", report)
        self.assertNotIn("token", report)
        self.assertNotIn("approval", report)

    def test_identity_is_observational_not_an_authenticator(self):
        if sys.platform != "win32":
            self.skipTest("native Windows SID/session test")
        first = read_windows_identity_evidence()
        second = read_windows_identity_evidence()
        self.assertEqual(first["process_user_sid"],second["process_user_sid"])
        self.assertEqual(first["process_session_id"],second["process_session_id"])
        self.assertFalse(first["owner_authenticated"])
        self.assertFalse(second["execution_allowed"])


if __name__ == "__main__":
    unittest.main()
