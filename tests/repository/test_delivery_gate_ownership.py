from __future__ import annotations

import importlib.util
import tempfile
import unittest
from pathlib import Path

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
        return mod.FULL.read_text(encoding="utf-8")

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

    def test_current_renewal_cannot_be_replaced_with_provider_free_history(self):
        full = self.good_full().replace("kubernetes_renewal_271_cluster_live.py", "kubernetes_renewal_live.py")
        errors = mod.validate_kubernetes_renewal_gate(full)
        self.assertTrue(any("historical 2.6.2" in error for error in errors))

    def test_current_renewal_requires_receipt_pins_and_real_cluster_permission(self):
        for required in (
            '--expected-native-build-receipt-sha256 "$receipt_digest"',
            '--expected-binary-sha256 "$binary_digest"',
            '--source-commit "$EXPECTED_SOURCE"',
            '--allow-disposable-cluster',
        ):
            with self.subTest(required=required):
                self.assertTrue(mod.validate_kubernetes_renewal_gate(self.good_full().replace(required, "")))

    def test_current_renewal_cannot_ignore_failure_or_use_an_older_reference(self):
        for old, new in (
            ("id: kubernetes271_renewal", "id: kubernetes271_renewal\n        continue-on-error: true"),
            (mod.KUBERNETES271_CONDITION, "${{ false }}"),
            ("heptabao-official-oracle271/bao", "heptabao-official-oracle/bao"),
        ):
            with self.subTest(mutation=old):
                self.assertTrue(mod.validate_kubernetes_renewal_gate(self.good_full().replace(old, new)))

    def test_current_renewal_requires_actual_native_build_receipt(self):
        full = self.good_full().replace('"schema": "heptabao.native-build.v1"', '"schema": "invented"')
        self.assertTrue(any("actual native build receipt" in error
                            for error in mod.validate_kubernetes_renewal_gate(full)))


if __name__ == "__main__":
    unittest.main()
