from __future__ import annotations

import importlib.util
import tempfile
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "delivery_gate_ownership", ROOT / "scripts/validate_delivery_gate_ownership.py"
)
assert SPEC and SPEC.loader
mod = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(mod)


class DeliveryGateOwnershipTests(unittest.TestCase):
    def fixture(self, full: str, trust: str) -> Path:
        root = Path(self.temp.name)
        workflows = root / ".github/workflows"
        workflows.mkdir(parents=True)
        (workflows / "codex-openbao-replacement-ci.yml").write_text(full, encoding="utf-8")
        (workflows / "workflow-trust-boundary.yml").write_text(trust, encoding="utf-8")
        return root

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.temp.cleanup()

    def good_full(self) -> str:
        return 'matrix: ${{ fromJSON(\'["head","merge"]\') }}\n' + "\n".join(mod.REQUIRED_NATIVE_GATES)

    def good_trust(self) -> str:
        return "Verify actual Git identities before candidate execution\npython scripts/validate_workflow_trust.py\n"

    def test_current_repository_ownership_is_valid(self):
        self.assertEqual([], mod.validate(ROOT))

    def test_missing_native_gate_fails(self):
        full = self.good_full().replace(mod.REQUIRED_NATIVE_GATES[1], "")
        errors = mod.validate(self.fixture(full, self.good_trust()))
        self.assertTrue(any("lost native gate" in error for error in errors))

    def test_duplicate_native_gate_in_trust_fails(self):
        trust = self.good_trust() + mod.REQUIRED_NATIVE_GATES[1]
        errors = mod.validate(self.fixture(self.good_full(), trust))
        self.assertTrue(any("duplicates native gate" in error for error in errors))

    def test_continue_after_failure_fails(self):
        full = self.good_full() + "\nif: ${{ success() || failure() }}\n"
        errors = mod.validate(self.fixture(full, self.good_trust()))
        self.assertTrue(any("diagnostic continuation" in error for error in errors))

    def workflow_with_step(self, command: str) -> str:
        workflow = yaml.safe_load((ROOT / ".github/workflows/workflow-trust-boundary.yml").read_text())
        # PyYAML's YAML 1.1 resolver treats GitHub's "on" key as a boolean.
        workflow["on"] = workflow.pop(True)
        workflow["jobs"]["verify"]["steps"].append({"name": "Ownership regression", "run": command})
        rendered = yaml.safe_dump(workflow, sort_keys=False)
        self.assertEqual(command, yaml.safe_load(rendered)["jobs"]["verify"]["steps"][-1]["run"])
        return rendered

    def check_real_workflow_step(self, command: str) -> list[str]:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            workflows = root / ".github/workflows"
            workflows.mkdir(parents=True)
            (workflows / "codex-openbao-replacement-ci.yml").write_text(
                (ROOT / ".github/workflows/codex-openbao-replacement-ci.yml").read_text())
            (workflows / "workflow-trust-boundary.yml").write_text(self.workflow_with_step(command))
            return mod.validate(root)

    def test_real_old_and_current_native_steps_are_rejected(self):
        for version in ("1.98.0", "1.99.0"):
            for gate in mod.REQUIRED_NATIVE_GATES:
                command = gate.replace("1.99.0", version)
                with self.subTest(command=command):
                    errors = self.check_real_workflow_step(command)
                    self.assertTrue(any("duplicates" in error for error in errors), errors)

    def test_real_ordinary_non_native_step_is_allowed(self):
        self.assertEqual([], self.check_real_workflow_step("python --version"))


if __name__ == "__main__":
    unittest.main()
