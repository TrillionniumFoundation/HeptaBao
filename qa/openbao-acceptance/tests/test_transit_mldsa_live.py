"""Harness rejection and privacy checks; native comparisons remain mandatory."""
from pathlib import Path
from types import SimpleNamespace
import json
import sys
import tempfile
import unittest
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import core_isolation
import transit_mldsa_live as profile

class MldsaProfileTests(unittest.TestCase):
    def tearDown(self):
        profile._CONTEXT.clear()

    def test_failure_reports_neither_seed_nor_body(self):
        class Client:
            def request(self, *args, **kwargs):
                return SimpleNamespace(status=500, body={"private": "synthetic-secret-canary"})
        rows=[]
        with self.assertRaisesRegex(profile.ScenarioFailure, "mldsa270.create"):
            profile.Trace(Client(),rows).call("create","POST","mlfixture/keys/test",200)
        self.assertEqual(rows,[{"case":"mldsa270.create","status":500,"passed":False}])
        self.assertNotIn("synthetic-secret-canary",json.dumps(rows))

    def test_restart_cannot_pass_without_all_three_parameter_sets(self):
        rows=[]
        for contexts in [None, [], [("one",)]]:
            if contexts is not None:
                profile._CONTEXT[id(rows)]=contexts
            with self.assertRaisesRegex(profile.ScenarioFailure,"restart_context_missing"):
                profile.run_after_restart(None,rows)

    def test_same_failed_prefix_is_not_qualification(self):
        rows=[{"case":"mldsa270.create","status":501,"passed":False}]
        self.assertFalse(core_isolation.successful_comparison({"candidate":rows,"oracle":rows},{}))

    def test_old_oracle_rejected_before_allocation(self):
        with tempfile.TemporaryDirectory() as root:
            args=["mldsa270","--binary",sys.executable,"--output",root+"/report.json","--oracle-version","2.6.2"]
            with patch.object(sys,"argv",args), patch.object(core_isolation.tempfile,"mkdtemp") as allocate:
                with self.assertRaises(SystemExit) as result:
                    profile.main()
                self.assertEqual(result.exception.code,2)
                allocate.assert_not_called()

if __name__ == "__main__":
    unittest.main()
