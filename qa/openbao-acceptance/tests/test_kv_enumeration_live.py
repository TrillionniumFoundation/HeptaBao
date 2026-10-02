"""Enumeration receipts must reject incomplete or incorrect responses safely."""
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from bao_http import Response
from core_isolation import ScenarioFailure, successful_comparison
from kv_enumeration_live import run_scenarios


class UnavailableClient:
    def request(self, method, path, payload=None, **kwargs):
        return Response(503, {"errors": ["private-sentinel"], "auth": {"client_token": "private-token"}})


class IncorrectListClient:
    def request(self, method, path, payload=None, **kwargs):
        if method == "POST":
            return Response(204, {})
        return Response(200, {"data": {"keys": ["private-secret"]}})


class EnumerationHarnessTests(unittest.TestCase):
    def assert_rejected_receipt(self, client, failure):
        observations = []
        with self.assertRaisesRegex(ScenarioFailure, "^kv_enumeration." + failure + "$"):
            run_scenarios(client, observations)
        self.assertFalse(observations[-1]["passed"])
        self.assertNotIn("private", json.dumps(observations))
        self.assertFalse(successful_comparison({"candidate": observations, "oracle": observations}, {}))
        return observations

    def test_failed_prefix_cannot_qualify_or_leak(self):
        observations = self.assert_rejected_receipt(UnavailableClient(), "v1.mount")
        self.assertEqual(observations, [{"case": "kv_enumeration.v1.mount", "status": 503, "passed": False}])

    def test_wrong_keys_cannot_qualify_or_leak(self):
        observations = self.assert_rejected_receipt(IncorrectListClient(), "v1.list.root")
        self.assertEqual(observations[-1], {"case": "kv_enumeration.v1.list.root", "status": 200,
                                           "passed": False, "data_matches": False})


if __name__ == "__main__":
    unittest.main()
