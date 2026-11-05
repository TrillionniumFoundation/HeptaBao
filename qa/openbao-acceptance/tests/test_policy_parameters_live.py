"""Verdict-shape tests only; no provider or product process is executed here."""
from pathlib import Path
import importlib.util
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

PATH = Path(__file__).resolve().parents[1] / "policy_parameters_live.py"
SPEC = importlib.util.spec_from_file_location("policy_parameters_live", PATH)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class Response:
    def __init__(self, status, body=None):
        self.status = status
        self.body = {} if body is None else body


class Client:
    def __init__(self, statuses):
        self.statuses = iter(statuses)
        self.calls = []

    def request(self, method, path, body=None, token=None):
        self.calls.append((method, path, body, token))
        status, response = next(self.statuses)
        return Response(status, response)


class PolicyParameterHarnessTests(unittest.TestCase):
    def successful(self):
        return [
            (204, {}),
            (204, {}),
            (200, {"auth": {"client_token": "synthetic-token"}}),
            (204, {}),
            (403, {}),
            (200, {"data": {"keys": ["item"]}}),
            (200, {"data": {"keys": ["item"]}}),
            *[(403, {}) for _ in range(7)],
            (200, {"data": {"foo": "good-value"}}),
            (204, {}),
            (404, {}),
            (204, {}),
            (204, {}),
            (200, {"auth": {"client_token": "synthetic-list-token"}}),
            (200, {"data": {"keys": ["item"]}}),
            (403, {}),
            (204, {}),
            (200, {"data": {"foo": "good-map", "flag": False, "map": {"good": "one"}}}),
        ]

    def test_complete_ordered_profile_has_terminal_marker_and_no_live_endpoint_option(self):
        client = Client(self.successful())
        rows = MODULE.run_scenarios(client)
        names = [row["case"] for row in rows]
        self.assertEqual(names[-1], "acl_parameters.complete")
        self.assertEqual(len(names), len(set(names)))
        self.assertEqual(len(names), 25)
        self.assertTrue(all(row["passed"] is True for row in rows))
        self.assertTrue(all(path.startswith("/v1/") for _, path, _, _ in client.calls))
        self.assertNotIn("address", PATH.read_text())

    def test_one_wrong_observation_fails_at_its_named_case(self):
        statuses = self.successful()
        statuses[3] = (403, {})
        with self.assertRaisesRegex(MODULE.ScenarioFailure, "acl_parameters.allowed_string_glob"):
            MODULE.run_scenarios(Client(statuses))


if __name__ == "__main__":
    unittest.main()
