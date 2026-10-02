"""A rejected request must not produce an apparently passing comparison trace."""
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from bao_http import Response
from core_isolation import ScenarioFailure, successful_comparison
from kv_metadata_cas_live import run_scenarios


class FailingClient:
    def request(self, method, path, payload=None, **kwargs):
        return Response(503, {"errors": ["private-sentinel"], "auth": {"client_token": "private-token"}})


class MetadataCasHarnessTests(unittest.TestCase):
    def test_failed_prefix_is_not_qualified_or_leaked(self):
        observations = []
        with self.assertRaisesRegex(ScenarioFailure, "^metadata_cas.mount$"):
            run_scenarios(FailingClient(), observations)
        self.assertEqual(observations, [{"case": "metadata_cas.mount", "status": 503, "passed": False}])
        self.assertNotIn("private", json.dumps(observations))
        self.assertFalse(successful_comparison({"candidate": observations, "oracle": observations}, {}))


if __name__ == "__main__":
    unittest.main()
