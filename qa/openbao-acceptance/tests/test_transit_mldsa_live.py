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

    def test_options_case_set_keeps_exact_rejections_and_all_wire_formats(self):
        cases = list(profile.signing_options_cases())
        self.assertEqual(len({case[0] for case in cases}), len(cases))
        wire = next(case for case in cases if case[0] == "pki_wire")
        self.assertEqual(wire[1], {"key_version":"1", "prehashed":False, "signature_algorithm":"pkcs1v15"})
        self.assertEqual(wire[2], 200)
        self.assertTrue(any(options.get("marshaling_algorithm") == "jws" and status == 200 for _,options,status,_ in cases))
        for field, value in (("marshaling_algorithm", None), ("marshaling_algorithm", "garbage"), ("hash_algorithm", "garbage"), ("prehashed", 2)):
            self.assertTrue(any(field in options and options[field] == value and status == 400 for _,options,status,_ in cases))

    def test_options_fail_on_matching_status_but_invalid_actual_signature(self):
        class Client:
            def request(self, *args, **kwargs):
                if "/sign/" in args[1]:
                    return SimpleNamespace(status=200, body={"data":{"signature":"vault:v1:" + "AA==", "key_version":1}})
                return SimpleNamespace(status=200, body={"data":{"valid":False}})
        rows=[]
        with self.assertRaisesRegex(profile.ScenarioFailure, "ed25519.options.pki_wire.valid"):
            profile.run_signing_options(profile.Trace(Client(),rows), "ed25519", "eA==", "vault:v1:AA==", 64)
        self.assertEqual(rows[-1], {"case":"mldsa270.ed25519.options.pki_wire.valid", "passed":False})
        self.assertNotIn("vault:v1:", json.dumps(rows))

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
