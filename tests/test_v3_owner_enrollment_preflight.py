from __future__ import annotations

import sys
import unittest

from upab.relay.v3_owner_enrollment_preflight import (
    main, preflight_owner_enrollment, validate_rp_candidate,
)
from upab.relay.v3_policy import PolicyBlocked


class Stage16OwnerEnrollmentPreflightTests(unittest.TestCase):
    def test_valid_candidate_rp_never_establishes_ownership(self):
        report = validate_rp_candidate(
            rp_id="auth.watcher-secure.org",
            origin="https://auth.watcher-secure.org"
        )
        self.assertTrue(report["rp_syntax_accepted"])
        self.assertFalse(report["rp_domain_ownership_verified"])
        self.assertFalse(report["https_origin_ownership_verified"])
        self.assertFalse(report["owner_approved_this_rp"])
        self.assertFalse(report["allow_credential_creation"])

    def test_noncanonical_untrusted_and_reserved_domains_blocked(self):
        cases = [
            ("upab.example.test", "https://upab.example.test"),
            ("example.com", "https://example.com"),
            ("auth.example.org", "https://auth.example.org"),
            ("example.invalid", "https://example.invalid"),
            ("localhost", "https://localhost"),
            ("127.0.0.1", "https://127.0.0.1"),
            ("AUTH.WATCHER.org", "https://AUTH.WATCHER.org"),
            ("auth.example.com", "http://auth.example.com"),
            ("safe.org", "https://safe.org:443"),
            ("safe.org", "https://safe.org/path"),
            ("foo..org", "https://foo..org"),
            ("-bad.org", "https://-bad.org"),
            ("bad-.org", "https://bad-.org"),
        ]
        for rp, origin in cases:
            with self.subTest(rp=rp, origin=origin):
                with self.assertRaises(PolicyBlocked):
                    validate_rp_candidate(rp_id=rp, origin=origin)

    def test_native_system_api_preflight_never_prompts_or_approves(self):
        if sys.platform != "win32":
            with self.assertRaises(PolicyBlocked):
                preflight_owner_enrollment()
            return
        report = preflight_owner_enrollment()
        self.assertEqual(report["platform"], "Windows")
        self.assertFalse(report["rp_candidate_syntax_accepted"])
        self.assertEqual(report["status"], "BLOCKED_NEEDS_TRUSTED_RP_AND_OWNER_CEREMONY")
        self.assertGreaterEqual(len(report["missing_gates"]), 5)
        for attribute in (
            "interactive_user_presence_proven",
            "rp_ownership_proven", "trusted_rp_configuration",
            "protected_challenge_issuer_connected",
            "credential_registered", "windows_hello_prompt_displayed",
            "owner_approval_issued", "execution_authorized",
            "safe_to_invoke_make_credential",
        ):
            self.assertIs(report[attribute], False)
        self.assertEqual(main([]), 0)

    @unittest.skipUnless(sys.platform == "win32", "native Windows-only candidate")
    def test_candidate_rp_in_windows_readiness_still_denies_all_actions(self):
        report = preflight_owner_enrollment(
            rp_id="auth.watcher-secure.org",
            origin="https://auth.watcher-secure.org",
        )
        self.assertTrue(report["rp_candidate_syntax_accepted"])
        self.assertFalse(report["trusted_rp_configuration"])
        self.assertFalse(report["safe_to_invoke_make_credential"])
        self.assertFalse(report["execution_authorized"])

    def test_mismatched_partial_origin_parameters_fail_closed(self):
        if sys.platform != "win32":
            self.skipTest("native Windows-only candidate")
        for kwargs in (
            {"rp_id": "safe.org"},
            {"origin": "https://safe.org"},
            {"rp_id": "safe.org", "origin": "http://safe.org"},
            {"rp_id": "safe.example.test", "origin": "https://safe.example.test"},
        ):
            with self.subTest(kwargs=kwargs):
                with self.assertRaises(PolicyBlocked):
                    preflight_owner_enrollment(**kwargs)

    def test_no_credential_creation_or_signing_api_in_preflight(self):
        import upab.relay.v3_owner_enrollment_preflight as m
        for name in (
            "enroll", "make_credential", "WebAuthNAuthenticatorMakeCredential",
            "issue_approval", "verify_owner", "execute_task", "start_watcher",
        ):
            self.assertFalse(hasattr(m, name))
        self.assertFalse(validate_rp_candidate(
            rp_id="mydomain.info", origin="https://mydomain.info"
        )["allow_credential_creation"])


if __name__ == "__main__":
    unittest.main()
