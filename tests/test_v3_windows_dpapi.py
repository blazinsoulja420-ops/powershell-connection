from __future__ import annotations

import sys
import unittest

from upab.relay.v3_policy import PolicyBlocked
from upab.relay.v3_windows_dpapi import (
    protect_for_current_user, unprotect_for_current_user,
)


class CurrentUserDPAPITests(unittest.TestCase):
    def test_win32_native_roundtrip_and_randomized_ciphertext(self):
        if sys.platform != "win32":
            with self.assertRaises(PolicyBlocked):
                protect_for_current_user(b"public-fixture")
            return
        plaintext = b"UPAB-WATCHER-V3-PUBLIC-NON-SECRET-TEST"
        first = protect_for_current_user(plaintext)
        second = protect_for_current_user(plaintext)
        self.assertNotEqual(first, plaintext)
        self.assertNotEqual(first, second)
        self.assertEqual(unprotect_for_current_user(first), plaintext)
        self.assertEqual(unprotect_for_current_user(second), plaintext)
        self.assertGreater(len(first), len(plaintext))

    def test_corrupt_ciphertext_is_denied(self):
        if sys.platform != "win32":
            self.skipTest("Windows DPAPI only")
        valid = protect_for_current_user(b"public-fixture-bounded")
        corrupted = bytearray(valid)
        corrupted[-5] ^= 0x7F
        with self.assertRaises(PolicyBlocked):
            unprotect_for_current_user(bytes(corrupted))
        with self.assertRaises(PolicyBlocked):
            unprotect_for_current_user(b"not-a-DPAPI-blob")

    def test_reject_unbounded_inputs(self):
        for invalid in (b"", b"x" * 65537, "text", 123, None):
            with self.subTest(invalid=str(type(invalid))):
                with self.assertRaises(PolicyBlocked):
                    protect_for_current_user(invalid)
                with self.assertRaises(PolicyBlocked):
                    unprotect_for_current_user(invalid)

    def test_no_files_or_approval_methods(self):
        import upab.relay.v3_windows_dpapi as dpapi
        for forbidden in ("write_key_file", "authenticate_owner",
                          "approve_task", "grant_execution", "start_server"):
            self.assertFalse(hasattr(dpapi, forbidden))


if __name__ == "__main__":
    unittest.main()
