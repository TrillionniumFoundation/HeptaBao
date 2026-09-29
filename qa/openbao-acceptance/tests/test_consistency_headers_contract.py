from pathlib import Path
import sys
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import consistency_headers_live as profile
from online_evidence import complete_checks


class ConsistencyHeaderContractTests(unittest.TestCase):
    def test_common_cases_and_real_ha_have_fixed_complete_denominators(self):
        self.assertEqual(len(profile.COMMON_REQUIRED),49)
        self.assertEqual(len(profile.VALID_HEADERS),12)
        self.assertEqual(len(profile.INVALID_HEADERS),12)
        for required in (profile.COMMON_REQUIRED,profile.HA_REQUIRED):
            rows=[{"case":name,"passed":True} for name in sorted(required)]
            self.assertTrue(complete_checks(rows,len(required),required_cases=required))
            self.assertFalse(complete_checks(rows[:-1],len(required),required_cases=required))
            self.assertFalse(complete_checks(rows+[rows[0]],len(required),required_cases=required))
            rows[0]["passed"]=False
            self.assertFalse(complete_checks(rows,len(required),required_cases=required))

    def test_index_requires_exact_cluster_canonical_integer_and_backend_prefix(self):
        valid=profile.encoded({"cluster":"synthetic","value":"heptabao-raft-v1:42"})
        self.assertEqual(profile.response_index({"x-vault-index":valid},"synthetic"),(valid,42))
        for value in ("42","heptabao-raft-v1:01","heptabao-raft-v1:-1","heptabao-raft-v1:18446744073709551616"):
            with self.subTest(value=value),self.assertRaises(Exception):
                profile.response_index({"x-vault-index":profile.encoded({"cluster":"synthetic","value":value})},"synthetic")
        with self.assertRaises(Exception):profile.response_index({"x-vault-index":valid},"foreign")

    def test_future_reject_forward_restart_handoff_and_quorum_are_required(self):
        for name in ("future_fail","future_forward","forward_index","finite_unchanged",
                     "restart_local_frontier","successor","partitioned_watermark_not_authority"):
            self.assertIn(name,profile.HA_REQUIRED)

    def test_recorded_status_failure_is_terminal_not_a_passing_prefix(self):
        trace=profile.Trace()
        with self.assertRaises(profile.FixtureError):trace.check("complete",False)
        self.assertEqual(trace.checks,[{"case":"complete","passed":False}])
        self.assertFalse(complete_checks(trace.checks,len(profile.COMMON_REQUIRED),required_cases=profile.COMMON_REQUIRED))

    def test_native_comparison_is_mandatory_in_the_27_lane(self):
        root=Path(__file__).resolve().parents[3]
        workflow=(root/".github/workflows/codex-openbao-replacement-ci.yml").read_text()
        loop=next(line for line in workflow.splitlines() if "for profile in core_isolation" in line)
        self.assertIn("consistency_headers_live",loop.split())
        self.assertIn("--oracle-version 2.7.0",workflow)
