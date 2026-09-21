from __future__ import annotations

import unittest

from upab.security import redact, sanitized_env


class SecurityTests(unittest.TestCase):
    def test_redacts_common_secrets(self):
        text = "Authorization: Bearer abcdefghijklmnop token=supersecret sk-abcdefghijklmnop"
        out = redact(text)
        self.assertNotIn("supersecret", out)
        self.assertNotIn("sk-abcdefghijklmnop", out)
        self.assertNotIn("abcdefghijklmnop", out)

    def test_sanitized_env_drops_secret_named_keys(self):
        env = {
            "PATH": "x",
            "OPENAI_API_KEY": "secret",
            "MY_PASSWORD": "pw",
            "NORMAL": "ok",
        }
        clean = sanitized_env(env)
        self.assertIn("PATH", clean)
        self.assertIn("NORMAL", clean)
        self.assertNotIn("OPENAI_API_KEY", clean)
        self.assertNotIn("MY_PASSWORD", clean)


if __name__ == "__main__":
    unittest.main()
