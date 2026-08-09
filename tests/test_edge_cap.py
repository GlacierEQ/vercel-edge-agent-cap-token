from __future__ import annotations
import unittest
from src.edge_cap import CapStatus, EdgeCapMint

class EdgeCapTests(unittest.TestCase):
    def setUp(self):
        self.mint = EdgeCapMint(b"v-secret")
        self.body = {"q": 1}
        self.tok = self.mint.mint("/api/agent", self.body, {"llm:complete"}, 1000.0)

    def test_allow(self):
        st, _ = self.mint.verify(self.tok, "/api/agent", self.body, "llm:complete", 900.0)
        self.assertEqual(st, CapStatus.ALLOW)

    def test_body_mismatch(self):
        st, r = self.mint.verify(self.tok, "/api/agent", {"q": 2}, "llm:complete", 900.0)
        self.assertEqual(r, "BODY_MISMATCH")

if __name__ == "__main__":
    unittest.main()
