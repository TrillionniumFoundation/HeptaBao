"""Historical upgrade evidence must reject invented provenance and failed calls."""
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from bao_http import Response
from core_isolation import ScenarioFailure
from kubernetes_native_upgrade import LEGACY_SHA256, LEGACY_SOURCE, Trace, admit_legacy


class KubernetesNativeUpgradeTests(unittest.TestCase):
    def receipt(self):
        return {"build_source_commit": LEGACY_SOURCE, "harness_source_commit": LEGACY_SOURCE,
                "harness_source_dirty": False, "harness_source_unchanged": True,
                "candidate_binary_unchanged": True, "candidate_binary_sha256": LEGACY_SHA256,
                "status": "passed"}

    def test_old_binary_requires_the_observed_clean_build(self):
        for field, wrong in [("build_source_commit", "other"), ("harness_source_dirty", True),
                             ("harness_source_unchanged", False), ("candidate_binary_unchanged", False),
                             ("candidate_binary_sha256", "0" * 64), ("status", "failed")]:
            with self.assertRaises(ValueError):
                admit_legacy(Path("new"), Path("old"), LEGACY_SHA256,
                             dict(self.receipt(), **{field: wrong}))
        with self.assertRaises(ValueError):
            admit_legacy(Path("new"), Path("old"), "0" * 64, self.receipt())
        with patch("kubernetes_native_upgrade.validate_binary_pins", return_value=("current", "legacy")) as pins:
            self.assertEqual(admit_legacy(Path("new"), Path("old"), LEGACY_SHA256, self.receipt()),
                             ("current", "legacy"))
            pins.assert_called_once_with(Path("new"), Path("old"), LEGACY_SHA256)

    def test_failed_unseal_cannot_continue_as_success_or_print_credentials(self):
        class Client:
            def request(self, *args, **kwargs):
                return Response(200, {"auth": {"client_token": "private-bearer"},
                                      "errors": ["private-error"]})
        cases = []
        with self.assertRaisesRegex(ScenarioFailure, "^kubernetes_native_upgrade.downgrade$"):
            Trace(Client(), cases).call("downgrade", "sys/unseal", {"key": "private-key"}, expected=503)
        self.assertEqual(cases, [{"case": "kubernetes_native_upgrade.downgrade", "status": 200, "passed": False}])
        self.assertNotIn("private", json.dumps(cases))

    def test_bad_side_effect_aborts_even_after_successful_status(self):
        cases = []
        trace = Trace(None, cases)
        trace.check("unsealed", True, status=200)
        with self.assertRaises(ScenarioFailure):
            trace.check("application_unchanged", False)
        self.assertFalse(cases[-1]["passed"])


if __name__ == "__main__":
    unittest.main()
