from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

import yaml
from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[2]
VALIDATOR = ROOT / "scripts/validate_plan_v1_2_2.py"

def load_validator():
    spec = importlib.util.spec_from_file_location("v122", VALIDATOR)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader
    spec.loader.exec_module(module)
    return module

class PlanV122Tests(unittest.TestCase):
    def test_checked_in_package_passes(self):
        load_validator().validate()

    def test_status_rejects_false_authority(self):
        schema = json.loads((ROOT / "schemas/heptabao_v1_2_2_unified_closure_status_v1.schema.json").read_text(encoding="utf-8"))
        status = yaml.safe_load((ROOT / "planning/HEPTABAO_V1_2_2_UNIFIED_CLOSURE_STATUS_V1.yaml").read_text(encoding="utf-8"))
        status["authority_effect"] = "GRANT"
        self.assertTrue(list(Draft202012Validator(schema).iter_errors(status)))

    def test_status_rejects_false_remote_execution(self):
        schema = json.loads((ROOT / "schemas/heptabao_v1_2_2_unified_closure_status_v1.schema.json").read_text(encoding="utf-8"))
        status = yaml.safe_load((ROOT / "planning/HEPTABAO_V1_2_2_UNIFIED_CLOSURE_STATUS_V1.yaml").read_text(encoding="utf-8"))
        status["local_candidate"]["remote_materialization"] = "PASS"
        self.assertTrue(list(Draft202012Validator(schema).iter_errors(status)))

    def test_missing_explicit_lifecycle_token_is_rejected(self):
        validator = load_validator()
        original = validator.STORE
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "store.rs"
            path.write_text(original.read_text(encoding="utf-8").replace("fresh_create_and_existing_reopen_are_explicit", "removed_explicit_lifecycle_test", 1), encoding="utf-8")
            validator.STORE = path
            try:
                with self.assertRaises(validator.Failure):
                    validator.validate_composition()
            finally:
                validator.STORE = original

if __name__ == "__main__":
    unittest.main()
