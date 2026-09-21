from __future__ import annotations

import tempfile
import unittest

from upab.relay.ledger import RelayLedger


class RelayLedgerTests(unittest.TestCase):
    def test_consume_rotates_nonce_and_blocks_replay(self):
        with tempfile.TemporaryDirectory() as td:
            ledger = RelayLedger(td)
            nonce = ledger.current_nonce()
            next_nonce = ledger.consume("task-1", "A" * 64, nonce)
            self.assertNotEqual(nonce, next_nonce)
            self.assertEqual(ledger.current_nonce(), next_nonce)
            with self.assertRaises(ValueError):
                ledger.consume("task-1", "A" * 64, next_nonce)


if __name__ == "__main__":
    unittest.main()
