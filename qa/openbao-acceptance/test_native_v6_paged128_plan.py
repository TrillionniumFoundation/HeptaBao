"""Ingress-safe complete history plan; never starts a server or touches data."""
import ast
import functools
import importlib.util
from pathlib import Path
import sys
import unittest
from unittest import mock

sys.dont_write_bytecode = True
PATH=Path(__file__).with_name('native_v6_paged128_lifecycle.py')
spec=importlib.util.spec_from_file_location('paged_history_plan_under_test',PATH)
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)

class HistoryPlanTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.plan=m.fixture_plan()

    def test_real_distinct_json_above_original_threshold(self):
        self.assertGreater(self.plan['history_json_bytes'],128*1024*1024)
        self.assertEqual(self.plan['history_versions'],66)
        self.assertEqual(self.plan['minimum_history_bytes_unchanged'],128*1024*1024)

    def test_enveloped_requests_fit_existing_ingress(self):
        self.assertLess(self.plan['maximum_request_bytes'],3*1024*1024)
        self.assertEqual(self.plan['existing_ingress_limit_bytes'],3*1024*1024)

    def test_retention_preserves_history_point_and_patch(self):
        self.assertEqual(self.plan['point_version'],67)
        self.assertEqual(self.plan['patch_version'],68)
        self.assertGreaterEqual(self.plan['retained_versions'],68)

    def test_original_timeout_is_unchanged(self):
        self.assertEqual(self.plan['server_timeout_seconds_unchanged'],15)
        with mock.patch.object(m,'SERVER_DEFAULT_TIMEOUT',60):
            with self.assertRaises(m.TrialFailure):m.fixture_plan()

    def test_old_oversized_fixture_fails_before_any_process(self):
        original=m.fixture
        oversized=functools.partial(original,payload_bytes=(33*1024*1024//10)//4*4)
        with mock.patch.object(m,'fixture',oversized),mock.patch.object(m.subprocess,'Popen') as process:
            with self.assertRaisesRegex(m.TrialFailure,'exceeds existing'):m.fixture_plan()
            process.assert_not_called()

    def test_small_history_cannot_satisfy_total_by_configuration(self):
        small=functools.partial(m.fixture,payload_bytes=1024)
        with mock.patch.object(m,'fixture',small):
            with self.assertRaisesRegex(m.TrialFailure,'above 128'):m.fixture_plan()

    def test_repeated_payloads_do_not_satisfy_distinct_history(self):
        one=m.fixture(1)
        with mock.patch.object(m,'fixture',lambda version:one):
            with self.assertRaisesRegex(m.TrialFailure,'distinct'):m.fixture_plan()

    def test_insufficient_retention_is_rejected(self):
        with mock.patch.object(m,'RETAINED_VERSIONS',64):
            with self.assertRaises(m.TrialFailure):m.fixture_plan()

    def test_stale_post_cold_version_anchor_is_rejected(self):
        with mock.patch.object(m,'POINT_VERSION',41):
            with self.assertRaises(m.TrialFailure):m.fixture_plan()
        with mock.patch.object(m,'PATCH_VERSION',42):
            with self.assertRaises(m.TrialFailure):m.fixture_plan()

    def test_lowered_total_threshold_is_rejected(self):
        with mock.patch.object(m,'MIN_HISTORY_BYTES',64*1024*1024):
            with self.assertRaises(m.TrialFailure):m.fixture_plan()

    def test_widened_ingress_is_rejected(self):
        with mock.patch.object(m,'MAX_KV2_REQUEST_BYTES',4*1024*1024):
            with self.assertRaises(m.TrialFailure):m.fixture_plan()

    def test_exact_case_names_and_resource_snapshots_are_unique(self):
        cases=m.required_case_names();snapshots=m.required_resource_snapshot_names()
        self.assertEqual(len(cases),len(set(cases)))
        self.assertEqual(len(snapshots),len(set(snapshots)))
        for v in range(1,67):
            self.assertIn('write-history-%d'%v,cases)
            self.assertIn('all-committed-history-version-%d'%v,cases)
        self.assertNotIn('write-history-67',cases)
        self.assertIn('second-cold-cas-history-to-point',cases)
        self.assertIn('second-cold-patch-point-to-next-resource-before',snapshots)
        self.assertIn('second-cold-patch-point-to-next-resource-after',snapshots)

    def test_scenario_has_no_stale_literal_version_operands(self):
        tree=ast.parse(PATH.read_text())
        trial=next(n for n in tree.body if isinstance(n,ast.ClassDef) and n.name=='Trial')
        run=next(n for n in trial.body if isinstance(n,ast.FunctionDef) and n.name=='run')
        numbers={n.value for n in ast.walk(run) if isinstance(n,ast.Constant) and type(n.value)is int}
        self.assertFalse(numbers & {39,40,41,42,64})
        # SHA admission lengths must not change when fixture versions change.
        admit=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='admit')
        self.assertIn(40,{n.value for n in ast.walk(admit) if isinstance(n,ast.Constant) and type(n.value)is int})

if __name__=='__main__':unittest.main(verbosity=2)
