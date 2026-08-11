from __future__ import annotations

import math
import unittest

from src.edge_cap import CapStatus, EdgeCapMint, EdgeCapToken, digest


NESTED_BODY = {"q": 1, "nested": {"b": 2, "a": [True, None, 1.5]}, "z": "ok"}
NESTED_DIGEST = "c6b19cf225ceae830a0dc80a6e6dc5774f7ddac7be39ba7f4bf3f5755bbcf848"
NESTED_MAC = "7bd5c4fa9c2442da76bfbed9721a501faedfa8b466c59ba517ea98d7c86b4762"


class EdgeCapTests(unittest.TestCase):
    def setUp(self):
        self.mint = EdgeCapMint(b"v-secret")
        self.body = {"q": 1}
        self.tok = self.mint.mint("/api/agent", self.body, {"llm:complete"}, 1000.0)

    def test_allow(self):
        st, reason = self.mint.verify(self.tok, "/api/agent", self.body, "llm:complete", 900.0)
        self.assertEqual((st, reason), (CapStatus.ALLOW, None))

    def test_body_mismatch(self):
        st, reason = self.mint.verify(self.tok, "/api/agent", {"q": 2}, "llm:complete", 900.0)
        self.assertEqual((st, reason), (CapStatus.REFUSE, "BODY_MISMATCH"))

    def test_nested_body_digest_known_vector_and_key_order(self):
        reordered = {"z": "ok", "nested": {"a": [True, None, 1.5], "b": 2}, "q": 1}
        self.assertEqual(digest(NESTED_BODY), NESTED_DIGEST)
        self.assertEqual(digest(reordered), NESTED_DIGEST)
        mutated = {"q": 1, "nested": {"b": 3, "a": [True, None, 1.5]}, "z": "ok"}
        self.assertNotEqual(digest(mutated), NESTED_DIGEST)

    def test_cross_language_known_mac_vector(self):
        tok = self.mint.mint("/api/agent", NESTED_BODY, {"tool:read", "llm:complete"}, 1000.0)
        self.assertEqual(tok.body_digest, NESTED_DIGEST)
        self.assertEqual(tok.mac, NESTED_MAC)
        self.assertEqual(
            self.mint.verify(tok, "/api/agent", NESTED_BODY, "tool:read", 999.0),
            (CapStatus.ALLOW, None),
        )

    def test_structured_payload_blocks_delimiter_ambiguity(self):
        tok = self.mint.mint("/api/agent", self.body, {"a|b", "c"}, 1000.0)
        structurally_different = EdgeCapToken(
            path=tok.path,
            body_digest=tok.body_digest,
            capabilities=frozenset({"a", "b|c"}),
            not_after=tok.not_after,
            mac=tok.mac,
        )
        st, reason = self.mint.verify(structurally_different, "/api/agent", self.body, "a", 900.0)
        self.assertEqual((st, reason), (CapStatus.REFUSE, "BAD_MAC"))

    def test_expired_fails_closed(self):
        st, reason = self.mint.verify(self.tok, "/api/agent", self.body, "llm:complete", 1000.01)
        self.assertEqual((st, reason), (CapStatus.REFUSE, "EXPIRED"))

    def test_malformed_inputs_fail_closed(self):
        with self.assertRaises(ValueError):
            EdgeCapMint(b"")
        with self.assertRaises(ValueError):
            self.mint.mint("", self.body, {"llm:complete"}, 1000.0)
        with self.assertRaises(ValueError):
            self.mint.mint("relative", self.body, {"llm:complete"}, 1000.0)
        with self.assertRaises(ValueError):
            self.mint.mint("/api/agent", self.body, set(), 1000.0)
        with self.assertRaises(ValueError):
            self.mint.mint("/api/agent", self.body, {""}, 1000.0)
        with self.assertRaises(ValueError):
            self.mint.mint("/api/agent", self.body, {"llm:complete"}, math.nan)
        with self.assertRaises(ValueError):
            digest({"bad": math.inf})

        st, reason = self.mint.verify(self.tok, "/api/agent", self.body, "llm:complete", math.nan)
        self.assertEqual((st, reason), (CapStatus.REFUSE, "MALFORMED_REQUEST_OR_TOKEN"))
        malformed = EdgeCapToken(self.tok.path, self.tok.body_digest, self.tok.capabilities, self.tok.not_after, "zz")
        st, reason = self.mint.verify(malformed, "/api/agent", self.body, "llm:complete", 900.0)
        self.assertEqual((st, reason), (CapStatus.REFUSE, "MALFORMED_REQUEST_OR_TOKEN"))


if __name__ == "__main__":
    unittest.main()
