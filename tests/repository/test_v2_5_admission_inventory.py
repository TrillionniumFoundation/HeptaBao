from __future__ import annotations

import importlib.util
import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "verify_external_completion_v2_5.py"
SPEC = importlib.util.spec_from_file_location("verify_external_completion_v2_5", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
verifier = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(verifier)


class V25AdmissionInventoryTests(unittest.TestCase):
    def test_required_files_are_present(self) -> None:
        required = {
            "scripts/verify_external_completion_v2_5.py",
            "scripts/verify_main_protection_v2_5.py",
            "tests/repository/test_verify_external_completion_v2_5.py",
            "tests/repository/test_verify_main_protection_v2_5.py",
            "planning/HEPTABAO_EXTERNAL_COMPLETION_POLICY_V2_5.json",
            "docs/plan/HEPTABAO_EXTERNAL_COMPLETION_ADMISSION_V2_5.md",
            "docs/operations/HEPTABAO_MAIN_PROTECTION_ADMISSION_V2_5.md",
        }
        missing = sorted(path for path in required if not (ROOT / path).is_file())
        self.assertEqual(missing, [])

    def test_machine_policy_matches_executable_denominator(self) -> None:
        policy = json.loads(
            (ROOT / "planning/HEPTABAO_EXTERNAL_COMPLETION_POLICY_V2_5.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual(policy["schema"], "heptabao.external-completion-policy.v2.5")
        self.assertEqual(policy["authority_effect"], "NONE")
        observed_cases = {
            gate["id"]: frozenset(gate["cases"]) for gate in policy["gates"]
        }
        observed_roles = {gate["id"]: gate["roles"] for gate in policy["gates"]}
        self.assertEqual(observed_cases, verifier._REQUIRED_CASES)
        self.assertEqual(observed_roles, verifier._REQUIRED_ROLE_COUNTS)

    def test_documentation_preserves_non_authority_boundary(self) -> None:
        documents = [
            ROOT / "docs/plan/HEPTABAO_EXTERNAL_COMPLETION_ADMISSION_V2_5.md",
            ROOT / "docs/operations/HEPTABAO_MAIN_PROTECTION_ADMISSION_V2_5.md",
        ]
        for document in documents:
            with self.subTest(document=document.name):
                text = document.read_text(encoding="utf-8")
                for sentinel in (
                    "qualification=false",
                    "compatibility_claim=false",
                    "migration_authority=false",
                    "release_authority=false",
                    "production_authority=false",
                    "authority_effect=NONE",
                ):
                    self.assertIn(sentinel, text)

    def test_verifiers_do_not_contain_signing_or_authority_grant_entrypoints(self) -> None:
        for relative in (
            "scripts/verify_external_completion_v2_5.py",
            "scripts/verify_main_protection_v2_5.py",
        ):
            text = (ROOT / relative).read_text(encoding="utf-8")
            lowered = text.lower()
            with self.subTest(relative=relative):
                self.assertNotIn("def sign(", lowered)
                self.assertNotIn("def generate_key", lowered)
                self.assertNotIn("production_authority\": true", lowered)
                self.assertNotIn("authority_effect\": \"grant", lowered)


if __name__ == "__main__":
    unittest.main()
