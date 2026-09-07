from __future__ import annotations

import copy
import importlib.util
import json
import unittest
from pathlib import Path

from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[2]


def load_module(name: str, path: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader
    spec.loader.exec_module(module)
    return module


validator = load_module("plan_v121", "scripts/validate_plan_v1_2_1.py")


def digest(value: str) -> str:
    return "sha256:" + value * 64


def valid_receipt(result: str = "EXACT_HEAD_EXECUTED") -> dict:
    return {
        "schema": "heptabao.blocker-closure-receipt.v1",
        "receipt_id": "HB-BCR-REPO-012-TEST-0001",
        "blocker_id": "HB-BLK-REPO-012",
        "blocker_class": "REPOSITORY_CONTROLLED",
        "source_binding": {
            "repository": "ProfHepta/HeptaBao",
            "ref": "codex/test",
            "commit": "1" * 40,
            "tree": "2" * 40,
            "clean_tree": True,
        },
        "plan_binding": {
            "plan_id": "HEPTABAO-PLAN-2026-08-28",
            "revision": "1.2.1",
            "normative_manifest_digest": digest("a"),
            "blocker_register_digest": digest("b"),
            "validator_digest": digest("c"),
            "dependency_lock_digest": digest("d"),
        },
        "execution": {
            "environment_id": "test-environment",
            "operator_identity": "test-operator",
            "credential_root_id": "credential-root-a",
            "artifact_custody_id": "artifact-custody-a",
            "started_at": "2026-08-30T00:00:00Z",
            "completed_at": "2026-08-30T00:01:00Z",
            "jobs": [
                {
                    "workflow": "plan-integrity-v4",
                    "run_id": "1",
                    "attempt": 1,
                    "job_id": "1",
                    "runner_id": "1",
                    "runner_name": "test-runner",
                    "os": "Linux",
                    "arch": "X64",
                    "toolchain": "1.98.0",
                    "target": "x86_64-unknown-linux-gnu",
                    "seed": None,
                    "conclusion": "PASS",
                    "exit_code": 0,
                    "result_digest": digest("e"),
                }
            ],
            "required_entry_count": 1,
            "executed_entry_count": 1,
            "failed": 0,
            "blocked": 0,
            "unknown": 0,
            "unexecuted": 0,
            "artifact_digests": [digest("e")],
        },
        "criteria": [
            {
                "id": "CRIT-01",
                "statement": "The declared exact-head validation entry passed",
                "result": "PASS",
                "evidence_digests": [digest("e")],
            }
        ],
        "findings": {
            "critical_open": 0,
            "high_open": 0,
            "unclassified": 0,
        },
        "independence": {
            "review_required": False,
            "author_identities": ["test-author"],
            "reviewer_identities": [],
            "operator_separate_from_reviewer": True,
            "credential_root_separate": False,
            "artifact_custody_separate": False,
            "conflict_dispositions": [],
        },
        "result": result,
        "issued_at": "2026-08-30T00:02:00Z",
        "expires_at": "2026-11-28T00:02:00Z",
        "revocation_lookup_key": "revocation-test-0001",
        "signatures": [],
        "qualification": False,
        "compatibility_claim": False,
        "selection_effect": "NONE",
        "authority_effect": "NONE",
    }


class PlanV121Tests(unittest.TestCase):
    def test_checked_in_v121_contract_passes(self):
        result = validator.run_all()
        self.assertEqual(result["work_packages"], 301)
        self.assertEqual(result["blockers"], 21)
        self.assertEqual(result["external_action_packages"], 8)
        self.assertFalse(result["qualification"])
        self.assertEqual(result["authority_effect"], "NONE")

    def test_external_action_package_coverage_is_exact(self):
        catalog = validator.load_yaml(
            "planning/HEPTABAO_EXTERNAL_ACTION_PACKAGE_CATALOG_V1.yaml"
        )
        catalog = copy.deepcopy(catalog)
        catalog["packages"].pop()
        with self.assertRaises(validator.base.ValidationFailure):
            validator.validate_external_action_packages(catalog)

    def test_external_action_package_cannot_self_close(self):
        catalog = validator.load_yaml(
            "planning/HEPTABAO_EXTERNAL_ACTION_PACKAGE_CATALOG_V1.yaml"
        )
        catalog = copy.deepcopy(catalog)
        catalog["packages"][0]["state"] = "CLOSED"
        with self.assertRaises(validator.base.ValidationFailure):
            validator.validate_external_action_packages(catalog)

    def test_external_blocker_must_reference_its_unique_package(self):
        register = validator.load_yaml("planning/HEPTABAO_BLOCKER_REGISTER_V1.yaml")
        register = copy.deepcopy(register)
        register["blockers"][-1]["action_package_id"] = "HB-EAP-EXT-001"
        with self.assertRaises(validator.base.ValidationFailure):
            validator.validate_blocker_register_deepening(register)

    def test_repository_blocker_cannot_be_preclosed_in_source(self):
        register = validator.load_yaml("planning/HEPTABAO_BLOCKER_REGISTER_V1.yaml")
        register = copy.deepcopy(register)
        repository = next(
            item for item in register["blockers"]
            if item["class"] == "REPOSITORY_CONTROLLED"
        )
        repository["state"] = "CLOSED"
        with self.assertRaises(validator.base.ValidationFailure):
            validator.validate_blocker_register_deepening(register)

    def test_receipt_schema_rejects_authority(self):
        schema = validator.validate_closure_receipt_schema()
        receipt = valid_receipt()
        receipt["authority_effect"] = "GRANT"
        errors = list(Draft202012Validator(schema).iter_errors(receipt))
        self.assertTrue(errors)

    def test_closed_receipt_requires_signature(self):
        schema = validator.validate_closure_receipt_schema()
        receipt = valid_receipt("CLOSED")
        errors = list(Draft202012Validator(schema).iter_errors(receipt))
        self.assertTrue(errors)

    def test_closed_receipt_rejects_unknown_entries(self):
        schema = validator.validate_closure_receipt_schema()
        receipt = valid_receipt("CLOSED")
        receipt["signatures"] = [
            {
                "key_id": "test-key",
                "signer_identity": "independent-reviewer",
                "signer_role": "security",
                "algorithm": "ed25519",
                "signature": "0" * 64,
                "transparency_reference": None,
            }
        ]
        receipt["execution"]["unknown"] = 1
        errors = list(Draft202012Validator(schema).iter_errors(receipt))
        self.assertTrue(errors)

    def test_workflow_must_execute_v121_validator(self):
        text = (
            ROOT / ".github/workflows/plan-v1.2.1-operational-integrity.yml"
        ).read_text(encoding="utf-8")
        text = text.replace("python3 scripts/validate_plan_v1_2_1.py\n", "")
        with self.assertRaises(validator.base.ValidationFailure):
            validator.validate_workflow_entry(text)


if __name__ == "__main__":
    unittest.main()
