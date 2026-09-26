"""Historical upgrade evidence must reject invented provenance and failed calls."""
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from bao_http import Response
from core_isolation import ScenarioFailure
from radius_native_upgrade import LEGACY_SHA256, LEGACY_SOURCE, Trace, admit_legacy, cap_preserved


class RadiusNativeUpgradeTests(unittest.TestCase):
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
        with patch("radius_native_upgrade.validate_binary_pins", return_value=("current", "legacy")) as pins:
            self.assertEqual(admit_legacy(Path("new"), Path("old"), LEGACY_SHA256, self.receipt()),
                             ("current", "legacy"))
            pins.assert_called_once_with(Path("new"), Path("old"), LEGACY_SHA256)

    def test_failed_unseal_cannot_continue_as_success_or_print_credentials(self):
        class Client:
            def request(self, *args, **kwargs):
                return Response(200, {"auth": {"client_token": "private-bearer"},
                                      "errors": ["private-error"]})
        cases = []
        with self.assertRaisesRegex(ScenarioFailure, "^radius_native_upgrade.downgrade$"):
            Trace(Client(), cases).call("downgrade", "sys/unseal", {"key": "private-key"}, expected=503)
        self.assertEqual(cases, [{"case": "radius_native_upgrade.downgrade", "status": 200, "passed": False}])
        self.assertNotIn("private", json.dumps(cases))

    def test_bad_side_effect_aborts_even_after_successful_status(self):
        cases = []
        trace = Trace(None, cases)
        trace.check("unsealed", True, status=200)
        with self.assertRaises(ScenarioFailure):
            trace.check("application_unchanged", False)
        self.assertFalse(cases[-1]["passed"])

    def test_success_without_exactly_one_provider_check_cannot_qualify(self):
        class Responder:
            calls = 0
            def count(self): return self.calls
            def observed(self, before, *, accepted): return True
        for request_count in [0, 2]:
            responder, rows = Responder(), []
            class Client:
                def request(self, *args, **kwargs):
                    responder.calls += request_count
                    return Response(200, {"auth": {"client_token": "private-bearer"}})
            with self.assertRaises(ScenarioFailure):
                Trace(Client(), rows, responder).call("renew", "auth/token/renew-self", provider=True)
            self.assertFalse(rows[-1]["provider_checked"])
            self.assertNotIn("private", json.dumps(rows))

    def test_new_config_must_not_change_captured_period_or_absolute_cap(self):
        value = {"period": 60, "explicit_max_ttl": 120, "creation_time": 1000, "expire_time_unix": 1120}
        self.assertTrue(cap_preserved(value, period=60, cap=120))
        for field, changed in [("period", 300), ("explicit_max_ttl", 600),
                               ("expire_time_unix", 1600), ("creation_time", "1000")]:
            self.assertFalse(cap_preserved(dict(value, **{field: changed}), period=60, cap=120))


if __name__ == "__main__":
    unittest.main()
