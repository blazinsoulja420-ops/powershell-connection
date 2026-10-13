from __future__ import annotations

import json
import unittest

from upab.relay.v3_broker_contract import (
    PIPE_NAME, MAX_FRAME_BYTES, SCHEMA,
    broker_security_requirements, validate_untrusted_frame,
)
from upab.relay.v3_policy import PolicyBlocked


def wire(method="status", payload=None, ref="a"*32):
    return json.dumps({
        "schema": SCHEMA, "method": method, "request_id": ref,
        "payload": {} if payload is None else payload,
    }, separators=(",", ":")).encode("utf-8")


class V3BrokerContractTests(unittest.TestCase):
    def test_status_and_preview_never_grant_authority(self):
        for request in (
            wire("status"),
            wire("review_preview", {"task_id": "test-1", "task_sha256": "B"*64}),
        ):
            with self.subTest(request=request):
                result = validate_untrusted_frame(request)
                for key in (
                    "owner_authenticated", "peer_authenticated", "presence_verified",
                    "approval_issued", "execution_authorized",
                    "listener_running", "changes_performed",
                ):
                    self.assertFalse(result[key])
                self.assertNotIn("task_sha256", result)

    def test_command_like_broker_methods_are_refused(self):
        for method in ("approve", "execute", "run_shell", "deploy", "connect_repo",
                       "issue_proof", "read_secret", "", "request_approval"):
            with self.subTest(method=method):
                with self.assertRaises(PolicyBlocked):
                    validate_untrusted_frame(wire(method))

    def test_unknown_fields_and_claimed_permissions_are_refused(self):
        good=json.loads(wire().decode("utf-8"))
        for key,value in (
            ("owner_authenticated", True), ("signature", "fake"),
            ("task_payload", "Invoke-Expression dangerous"),
        ):
            bad=dict(good)
            bad[key]=value
            with self.assertRaises(PolicyBlocked):
                validate_untrusted_frame(json.dumps(bad).encode("utf-8"))

    def test_duplicate_json_properties_and_invalid_unicode_are_refused(self):
        for data in (
            b'{"schema":"a","schema":"b"}',
            b'{"schema":',
            b'\xff\xff',
            b"x"*(MAX_FRAME_BYTES+1),
            b"",
        ):
            with self.subTest(data=data[:30]):
                with self.assertRaises(PolicyBlocked):
                    validate_untrusted_frame(data)

    def test_bad_preview_payloads_are_refused(self):
        for payload in (
            {"task_id":"test", "task_sha256":"bad"},
            {"task_id":"../path", "task_sha256":"A"*64},
            {"task_id":"test", "task_sha256":"A"*64, "approved":True},
            {"script":"powershell.exe"},
        ):
            with self.subTest(payload=payload):
                with self.assertRaises(PolicyBlocked):
                    validate_untrusted_frame(wire("review_preview",payload))

    def test_requirements_are_explicit_but_not_implemented(self):
        security=broker_security_requirements()
        self.assertEqual(security["pipe_name"],PIPE_NAME)
        self.assertLessEqual(security["max_request_bytes"],65536)
        self.assertFalse(security["service_implemented"])
        self.assertFalse(security["production_execution_enabled"])
        for key in ("require_explicit_owner_only_dacl",
                    "impersonate_and_verify_peer_token",
                    "human_presence_requires_windows_hello_or_verified_equivalent",
                    "deny_remote_pipe_clients"):
            self.assertTrue(security[key])


if __name__ == "__main__":
    unittest.main()
