"""Harness failures preserve partial observations without copying secrets."""
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import core_isolation
from bao_http import Response


class FailingClient:
    def request(self, method, path, payload=None, *, token=None):
        return Response(503, {"errors": ["sentinel-private-response"], "auth": {"client_token": "do-not-log"}})


class CoreIsolationHarnessTests(unittest.TestCase):
    def test_failure_records_only_fixed_case_and_status(self):
        observations = []
        with self.assertRaisesRegex(core_isolation.ScenarioFailure, "^token.alice$"):
            core_isolation.run_scenarios(FailingClient(), observations)
        self.assertEqual(observations, [{"case": "token.alice", "status": 503, "passed": False}])
        self.assertNotIn("sentinel-private-response", json.dumps(observations))
        self.assertNotIn("do-not-log", json.dumps(observations))

    def test_partial_observation_sink_is_not_replaced(self):
        observations = [{"case": "previous", "passed": True}]
        with self.assertRaises(core_isolation.ScenarioFailure):
            core_isolation.run_scenarios(FailingClient(), observations)
        self.assertEqual(len(observations), 2)
        self.assertFalse(observations[-1]["passed"])

    def test_binary_binding_hashes_file_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "synthetic"
            path.write_bytes(b"not-an-executable")
            self.assertEqual(core_isolation.file_hash(path), hashlib.sha256(b"not-an-executable").hexdigest())


if __name__ == "__main__":
    unittest.main()
