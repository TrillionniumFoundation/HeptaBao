from __future__ import annotations

import importlib.util
import shlex
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

    def test_current_multiplatform_lint_has_the_same_vendor_boundary(self):
        path = ROOT / ".github/workflows/v2-5-multiplatform-repository-qualification.yml"
        jobs = yaml.safe_load(path.read_text(encoding="utf-8"))["jobs"]
        lint_jobs = 0
        for name, job in jobs.items():
            commands = [
                shlex.split(line)
                for step in job["steps"] for line in step.get("run", "").splitlines()
                if line.strip().startswith("cargo +1.98.0 ")
            ]
            lints = [command for command in commands if command[2] == "clippy"]
            if not lints:
                continue
            lint_jobs += 1
            with self.subTest(job=name):
                for command in lints:
                    split = command.index("--")
                    self.assertEqual(set(command[3:split]), {
                        "--workspace", "--all-targets", "--locked", "--exclude", "qrcode",
                    })
                    self.assertEqual(command[command.index("--exclude") + 1], "qrcode")
                    self.assertEqual(command[split + 1:], ["-D", "warnings"])
                # The only exclusion is third-party lint ownership. qrcode
                # still compiles/tests with the complete workspace on each OS.
                tests = [command for command in commands if command[2] == "test"]
                self.assertTrue(any("--workspace" in command and "--all-targets" in command
                                    for command in tests))
                self.assertTrue(all("--exclude" not in command for command in tests))
                self.assertNotIn("continue-on-error", job)
                for step in job["steps"]:
                    self.assertNotIn("continue-on-error", step)
        self.assertGreater(lint_jobs, 0)


if __name__ == "__main__":
    unittest.main()
