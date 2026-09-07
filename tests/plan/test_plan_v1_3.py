from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

import yaml
from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[2]
VALIDATOR = ROOT / "scripts/validate_plan_v1_3.py"


def load_validator():
    spec = importlib.util.spec_from_file_location("v13", VALIDATOR)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader
    spec.loader.exec_module(module)
    return module


def temp_text(content: str, suffix: str) -> tuple[tempfile.TemporaryDirectory, Path]:
    temporary = tempfile.TemporaryDirectory()
    path = Path(temporary.name) / f"value{suffix}"
    path.write_text(content, encoding="utf-8")
    return temporary, path


class PlanV13Tests(unittest.TestCase):
    def test_checked_in_v13_passes(self):
        load_validator().validate()

    def test_status_rejects_authority(self):
        schema = json.loads((ROOT / "schemas/heptabao_v1_3_foundation_status_v1.schema.json").read_text(encoding="utf-8"))
        status = yaml.safe_load((ROOT / "planning/HEPTABAO_PLAN_V1_3_STATUS_V1.yaml").read_text(encoding="utf-8"))
        status["authority_effect"] = "GRANT"
        self.assertTrue(list(Draft202012Validator(schema).iter_errors(status)))

    def test_work_package_count_drift_rejected(self):
        validator = load_validator()
        value = yaml.safe_load(validator.WP_EXTENSION.read_text(encoding="utf-8"))
        value["effective_package_count"] = 305
        temporary, path = temp_text(yaml.safe_dump(value), ".yaml")
        self.addCleanup(temporary.cleanup)
        with self.assertRaises(validator.Failure):
            validator.validate_work_packages(path, validator.P0_CONTRACTS)

    def test_unmaterialized_oracle_claim_cannot_be_transferred(self):
        validator = load_validator()
        value = yaml.safe_load(validator.ORACLE.read_text(encoding="utf-8"))
        value["repository_observation"]["repository_verifiable_transferred_vectors"] = 4
        temporary, path = temp_text(yaml.safe_dump(value), ".yaml")
        self.addCleanup(temporary.cleanup)
        with self.assertRaises(validator.Failure):
            validator.validate_oracle(path)

    def test_external_blocker_cannot_be_self_closed(self):
        validator = load_validator()
        value = yaml.safe_load(validator.INHERITED_BLOCKERS.read_text(encoding="utf-8"))
        for blocker in value["blockers"]:
            if blocker["id"] == "HB-BLK-EXT-005":
                blocker["state"] = "CLOSED"
        temporary, path = temp_text(yaml.safe_dump(value), ".yaml")
        self.addCleanup(temporary.cleanup)
        with self.assertRaises(validator.Failure):
            validator.validate_blockers(validator.BLOCKERS, path)

    def test_authbus_authorization_grant_rejected(self):
        validator = load_validator()
        text = validator.AUTHBUS.read_text(encoding="utf-8").replace(
            "pub enum AuthorizationEffect {\n    None,\n}",
            "pub enum AuthorizationEffect {\n    None,\n    Grant,\n}",
            1,
        )
        temporary, path = temp_text(text, ".rs")
        self.addCleanup(temporary.cleanup)
        with self.assertRaises(validator.Failure):
            validator.validate_authbus(path)

    def test_secret_derive_debug_rejected(self):
        validator = load_validator()
        text = validator.PROTOCOL.read_text(encoding="utf-8").replace(
            "#[derive(Eq, PartialEq)]\npub struct SecretBytes",
            "#[derive(Clone, Debug, Eq, PartialEq)]\npub struct SecretBytes",
            1,
        )
        self.assertNotEqual(text, validator.PROTOCOL.read_text(encoding="utf-8"))
        temporary, path = temp_text(text, ".rs")
        self.addCleanup(temporary.cleanup)
        with self.assertRaises(validator.Failure):
            validator.validate_protocol(path)

    def test_automatic_snapshot_purge_rejected(self):
        validator = load_validator()
        text = validator.H02_CLUSTER.read_text(encoding="utf-8").replace(
            "snapshot_policy: SnapshotPolicy::Never",
            "snapshot_policy: SnapshotPolicy::LogsSinceLast(3)",
            1,
        )
        temporary, path = temp_text(text, ".rs")
        self.addCleanup(temporary.cleanup)
        with self.assertRaises(validator.Failure):
            validator.validate_h02(path, validator.H02_CLOCK, validator.H02_CLOCK_CLUSTER)

    def test_fixed_post_resume_leader_rejected(self):
        validator = load_validator()
        text = validator.H02_CLOCK_CLUSTER.read_text(encoding="utf-8") + "\n// cluster.nodes[&1].raft.current_leader\n"
        temporary, path = temp_text(text, ".rs")
        self.addCleanup(temporary.cleanup)
        with self.assertRaises(validator.Failure):
            validator.validate_h02(validator.H02_CLUSTER, validator.H02_CLOCK, path)

    def test_write_capable_workflow_rejected(self):
        validator = load_validator()
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        path = Path(temporary.name) / "bad.yml"
        path.write_text("permissions:\n  contents: write\n", encoding="utf-8")
        with self.assertRaises(validator.Failure):
            validator.validate_workflow_directory(Path(temporary.name))


if __name__ == "__main__":
    unittest.main()
