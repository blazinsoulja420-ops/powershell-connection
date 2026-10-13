from __future__ import annotations

from datetime import datetime, timedelta, timezone
import unittest

from upab.relay.v3_policy import PolicyBlocked
from upab.relay.v3_webauthn_preflight import windows_webauthn_preflight
from upab.relay.v3_presence_challenge import (
    create_challenge_preview, inspect_challenge_preview
)

NOW = datetime(2026,10,13,19,0,tzinfo=timezone.utc)


class NativeWebAuthnPreflightTests(unittest.TestCase):
    def test_native_webauthn_discovery_never_authenticates(self):
        import sys
        if sys.platform != "win32":
            with self.assertRaises(PolicyBlocked):
                windows_webauthn_preflight()
            return
        report = windows_webauthn_preflight()
        self.assertIn(report["os_webauthn_api"], ("PRESENT","UNAVAILABLE"))
        self.assertIn(report["platform_authenticator"],
                      ("UNKNOWN","REPORTED_AVAILABLE","REPORTED_UNAVAILABLE"))
        if report["os_webauthn_api"] == "PRESENT":
            self.assertIsInstance(report["api_version"],int)
            self.assertGreater(report["api_version"],0)
        self.assertEqual(report["credential_enrolled"],"UNKNOWN")
        for key in ("user_verification_performed","owner_authenticated",
                    "approval_issued","execution_authorized"):
            self.assertFalse(report[key])

    def test_discovery_has_no_prompt_or_approval_hooks(self):
        import upab.relay.v3_webauthn_preflight as module
        for key in ("WebAuthNAuthenticatorGetAssertion","enroll",
                    "approve","sign","execute_task"):
            self.assertFalse(hasattr(module,key))


class OwnerPresenceChallengePreviewTests(unittest.TestCase):
    @staticmethod
    def issue(**kwargs):
        request = {
            "project_id":"universal-ai", "task_id":"task-42",
            "task_sha256":"B"*64, "now":NOW,
        }
        request.update(kwargs)
        return create_challenge_preview(**request)

    def test_preview_context_validates_without_owner_approval(self):
        plan=self.issue()
        self.assertEqual(len(plan["challenge_hex"]),64)
        self.assertEqual(plan["scope"],"review_only")
        self.assertFalse(plan["owner_verified"])
        self.assertFalse(plan["execution_authorized"])
        receipt=inspect_challenge_preview(plan,now=NOW+timedelta(seconds=5))
        self.assertEqual(receipt["status"],"VALID_UNAUTHENTICATED_CHALLENGE_PREVIEW")
        self.assertEqual(receipt["challenge_age_seconds"],5)
        self.assertFalse(receipt["assertion_signature_verified"])
        self.assertFalse(receipt["execution_authorized"])

    def test_independent_challenges_unique_for_same_task(self):
        a,b=self.issue(),self.issue()
        self.assertNotEqual(a["challenge_hex"],b["challenge_hex"])
        self.assertNotEqual(a["context_sha256"],b["context_sha256"])

    def test_time_window_is_exact_and_limited(self):
        challenge=self.issue()
        self.assertFalse(inspect_challenge_preview(challenge,now=NOW)["owner_verified"])
        for time in (NOW-timedelta(seconds=1),NOW+timedelta(seconds=90),
                     NOW+timedelta(hours=1)):
            with self.subTest(time=time):
                with self.assertRaises(PolicyBlocked):
                    inspect_challenge_preview(challenge,now=time)

    def test_task_identity_scope_and_digest_binding_cannot_change(self):
        proposal=self.issue()
        for name,value in (
            ("project_id","researchos"),
            ("task_id","task-43"),
            ("task_sha256","C"*64),
            ("scope","execute"),
            ("expires_at_utc",(NOW+timedelta(seconds=45)).isoformat()),
            ("challenge_hex","0"*64),
            ("context_sha256","0"*64),
        ):
            with self.subTest(name=name):
                edited=dict(proposal)
                edited[name]=value
                with self.assertRaises(PolicyBlocked):
                    inspect_challenge_preview(edited,now=NOW)

    def test_forged_authority_or_extra_fields_denied(self):
        proposal=self.issue()
        for name in ("owner_verified", "execution_authorized",
                     "credential_assertion_available"):
            with self.subTest(name=name):
                edited=dict(proposal)
                edited[name]=True
                with self.assertRaises(PolicyBlocked):
                    inspect_challenge_preview(edited,now=NOW)
        with self.assertRaises(PolicyBlocked):
            inspect_challenge_preview(dict(proposal,approved=True),now=NOW)

    def test_generation_invalid_context_denied(self):
        for key,value in (
            ("project_id","../evil"),
            ("project_id","A"*66),
            ("task_id","folder/task"),
            ("task_sha256","0"*63),
            ("scope","read_and_write"),
            ("now",NOW.replace(tzinfo=None)),
        ):
            with self.subTest(key=key):
                with self.assertRaises(PolicyBlocked):
                    self.issue(**{key:value})

    def test_noncanonical_time_and_no_reusable_authorization_method(self):
        proposal=self.issue()
        edited=dict(proposal, requested_at_utc="2026-10-13T19:00:00")
        with self.assertRaises(PolicyBlocked):
            inspect_challenge_preview(edited,now=NOW)
        import upab.relay.v3_presence_challenge as module
        for name in ("verify_assertion","authenticate_owner","approve_task",
                     "execute_task","issue_execution_token"):
            self.assertFalse(hasattr(module,name))


if __name__ == "__main__":
    unittest.main()
