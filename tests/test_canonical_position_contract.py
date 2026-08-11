from __future__ import annotations

import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
STATE = json.loads((ROOT / "machine" / "excellence-state.json").read_text(encoding="utf-8"))
POSITION = json.loads((ROOT / "machine" / "canonical-position.json").read_text(encoding="utf-8"))
PROOF = json.loads((ROOT / "machine" / "canonical-position-proof.json").read_text(encoding="utf-8"))
CONTRACT = json.loads((ROOT / "machine" / "target-contract.json").read_text(encoding="utf-8"))


class CanonicalPositionContractTests(unittest.TestCase):
    def test_state_advances_only_with_exact_hardening_proof(self):
        self.assertEqual(STATE["principal_state"], "EVOLVING")
        self.assertEqual(STATE["gates"]["CANONICAL_POSITION_RESOLVED"]["status"], "PASS")
        self.assertEqual(STATE["gates"]["EVOLUTION_CURSOR_DEFINED"]["status"], "PASS")
        self.assertEqual(PROOF["source_sha"], "1b854a21c37767657b4c8622f69ad3b65ca0e6f5")
        self.assertEqual(PROOF["workflow"]["run_id"], 31450885196)
        self.assertEqual(PROOF["workflow"]["conclusion"], "success")
        self.assertEqual(set(PROOF["workflow"]["jobs"]), {"py", "node"})

    def test_identity_lineage_and_claim_boundary_are_preserved(self):
        self.assertEqual(POSITION["repository"], STATE["repository"])
        self.assertEqual(POSITION["role"], "CANONICAL_SPECIALIST")
        policy = POSITION["integration_policy"]
        self.assertTrue(policy["preserve_repository_identity"])
        self.assertTrue(policy["preserve_lineage"])
        self.assertTrue(policy["presentation_independent"])
        self.assertTrue(policy["absorption_requires_functional_equivalence"])
        self.assertTrue(policy["absorption_requires_proof_equivalence"])
        self.assertEqual(STATE["claim_ceiling"], "PROMOTED")

    def test_replay_nonclaim_remains_explicit(self):
        text = " ".join(CONTRACT["nonclaims"]).lower()
        self.assertIn("replay", text)
        self.assertIn("separate tested consumption ledger", text)
        self.assertIn("replay", PROOF["replay_boundary"].lower())
        self.assertIn("replay", " ".join(POSITION["does_not_own"]).lower())

    def test_next_evolution_is_material_without_weakening_current_authority(self):
        self.assertTrue(STATE["evolution_cursor"].startswith("next:"))
        self.assertIn("single-use", POSITION["next_evolution"])
        self.assertIn("attenuation", POSITION["next_evolution"])


if __name__ == "__main__":
    unittest.main()
