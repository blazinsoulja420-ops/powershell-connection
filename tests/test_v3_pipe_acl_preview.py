from __future__ import annotations

import sys
import unittest

from upab.relay.v3_policy import PolicyBlocked
from upab.relay.v3_pipe_acl_preview import preview_owner_pipe_security


class NamedPipeAclPreviewTests(unittest.TestCase):
    def test_windows_native_sddl_conversion_is_strictly_nonactivating(self):
        if sys.platform != "win32":
            with self.assertRaises(PolicyBlocked):
                preview_owner_pipe_security()
            return
        result = preview_owner_pipe_security()
        self.assertTrue(result["native_sddl_accepted"])
        self.assertTrue(result["protected_dacl_present"])
        self.assertTrue(result["explicit_current_token_user_ace"])
        self.assertFalse(result["broad_principal_aces_requested"])
        for field in (
            "pipe_created", "security_descriptor_applied",
            "peer_authenticated", "owner_authenticated",
            "execution_authorized",
        ):
            self.assertFalse(result[field])

    def test_no_listener_or_acl_apply_hook(self):
        import upab.relay.v3_pipe_acl_preview as component
        for attr in ("CreateNamedPipe", "start_broker", "issue_approval",
                     "execute_task", "authenticate_owner"):
            self.assertFalse(hasattr(component, attr))


if __name__ == "__main__":
    unittest.main()
