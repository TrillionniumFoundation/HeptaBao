from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

from jsonschema import Draft202012Validator
import yaml

ROOT = Path(__file__).resolve().parents[2]
VALIDATOR_PATH = ROOT / "scripts/validate_h02_pr40_reconciliation_v1.py"


def load_validator():
    spec = importlib.util.spec_from_file_location("pr40_reconciliation", VALIDATOR_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader
    spec.loader.exec_module(module)
    return module


class PR40ReconciliationTests(unittest.TestCase):
    def test_checked_in_reconciliation_passes(self):
        validator = load_validator()
        validator.validate()

    def test_status_schema_rejects_authority(self):
        schema = json.loads(validator_path("schemas/heptabao_pr40_reconciliation_status_v1.schema.json").read_text(encoding="utf-8"))
        status = yaml.safe_load(validator_path("planning/HEPTABAO_PR40_RECONCILIATION_STATUS_V1.yaml").read_text(encoding="utf-8"))
        status["authority_effect"] = "GRANT"
        self.assertTrue(list(Draft202012Validator(schema).iter_errors(status)))

    def test_status_schema_rejects_false_rust_execution(self):
        schema = json.loads(validator_path("schemas/heptabao_pr40_reconciliation_status_v1.schema.json").read_text(encoding="utf-8"))
        status = yaml.safe_load(validator_path("planning/HEPTABAO_PR40_RECONCILIATION_STATUS_V1.yaml").read_text(encoding="utf-8"))
        status["local_evidence"]["rust_compile_test_clippy"] = "PASS"
        self.assertTrue(list(Draft202012Validator(schema).iter_errors(status)))

    def test_missing_generation_token_is_rejected(self):
        validator = load_validator()
        original = validator.STORE.read_text(encoding="utf-8")
        mutated = original.replace("missing_initialized_log_generation_fails_closed", "removed_generation_test", 1)
        self.assertNotEqual(original, mutated)
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "store.rs"
            path.write_text(mutated, encoding="utf-8")
            validator.STORE = path
            with self.assertRaises(validator.Failure):
                validator.validate_durable_guard()

    def test_write_capable_workflow_is_rejected(self):
        validator = load_validator()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            workflow_dir = root / ".github/workflows"
            workflow_dir.mkdir(parents=True)
            (workflow_dir / "bad.yml").write_text("permissions:\n  contents: write\n", encoding="utf-8")
            original_root = validator.ROOT
            original_fallback = validator.FALLBACK_WORKFLOW
            validator.ROOT = root
            validator.FALLBACK_WORKFLOW = workflow_dir / "bad.yml"
            try:
                with self.assertRaises(validator.Failure):
                    validator.validate_workflow_boundary()
            finally:
                validator.ROOT = original_root
                validator.FALLBACK_WORKFLOW = original_fallback


def validator_path(relative: str) -> Path:
    return ROOT / relative


if __name__ == "__main__":
    unittest.main()
