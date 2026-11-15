import importlib.util
from pathlib import Path
import unittest
import sys

sys.path.insert(0, str(Path(__file__).parents[1]))

spec = importlib.util.spec_from_file_location("convergent_aad_live", Path(__file__).parents[1]/"transit_convergent_aad_live.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class FixedTraceTests(unittest.TestCase):
    def test_empty_prefix_missing_duplicate_and_reordered_traces_cannot_pass(self):
        names = module.expected_case_names()
        self.assertEqual(len(names), 246)
        self.assertEqual(len(set(names)), 246)
        rows = [{"case": name, "passed": True} for name in names]
        self.assertTrue(module.complete_trace(rows))
        for bad in ([], rows[:-1], rows[1:], rows+[rows[-1]], [rows[1], rows[0], *rows[2:]]):
            self.assertFalse(module.complete_trace(bad))
        failed = list(rows)
        failed[5] = {"case": names[5], "passed": False}
        self.assertFalse(module.complete_trace(failed))

    def test_failure_contains_only_fixed_case_name(self):
        class Fixture:
            def call(self, *args):
                return 503, {"errors": ["synthetic-sensitive-service-body"]}
        rows = []
        trace = module.Trace(Fixture(), rows)
        with self.assertRaises(module.Failure) as caught:
            trace.call("fixed_status_case", "POST", "synthetic", 200)
        self.assertEqual(str(caught.exception), "fixed_status_case")
        self.assertEqual(rows, [{"case": "fixed_status_case", "status": 503, "passed": False}])
