import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('surface_work', ROOT / 'scripts/surface_work.py')
work = importlib.util.module_from_spec(spec)
spec.loader.exec_module(work)


class SurfaceWorkTests(unittest.TestCase):
    def setUp(self):
        self.original = work.read_json
        self.doc = self.original(ROOT / work.MANIFEST)

    def validate_mutation(self, mutate):
        doc = copy.deepcopy(self.doc)
        mutate(doc)
        with patch.object(work, 'read_json', side_effect=lambda p: doc if p == ROOT / work.MANIFEST else self.original(p)):
            return work.validate(ROOT)

    def test_current_exact_denominator_and_sources(self):
        self.assertEqual(work.validate(ROOT), [])
        self.assertEqual(len(self.doc['surfaces']), 60)

    def test_removed_surface_rejects(self):
        self.assertTrue(self.validate_mutation(lambda d: d['surfaces'].pop()))

    def test_duplicate_surface_rejects(self):
        self.assertTrue(self.validate_mutation(lambda d: d['surfaces'].append(d['surfaces'][0])))

    def test_missing_behavior_dimension_rejects(self):
        self.assertTrue(self.validate_mutation(lambda d: d['surfaces'][0]['technical_contract'].pop('crash_reopen')))

    def test_self_issued_admission_rejects(self):
        self.assertTrue(self.validate_mutation(lambda d: d['surfaces'][0].update(whole_surface_admitted=True)))

    def test_unbound_profile_rejects(self):
        self.assertTrue(self.validate_mutation(lambda d: d['surfaces'][0]['available_scoped_profiles'].append('invented')))

    def test_case_promotion_cannot_rewrite_original_corpus(self):
        self.assertTrue(self.validate_mutation(lambda d: d['surfaces'][0]['fixture_case_ids'].append('invented.case')))

    def test_corpus_digest_drift_rejects(self):
        self.assertTrue(self.validate_mutation(lambda d: d.update(corpus_sha256='0' * 64)))

    def test_runtime_claim_needs_existing_owner(self):
        self.assertTrue(self.validate_mutation(lambda d: d['surfaces'][0].update(runtime_source=None)))

    def test_evidence_dimensions_cannot_be_dropped(self):
        self.assertTrue(self.validate_mutation(lambda d: d['required_completion_evidence'].remove('independent_admission')))

    def test_profile_path_escape_rejects(self):
        self.assertTrue(self.validate_mutation(lambda d: d['profile_definitions']['fixed'].update(script='../outside.py')))

    def test_duplicate_json_fields_are_not_last_wins(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'duplicate.json'
            path.write_text('{"status":false,"status":true}')
            with self.assertRaises(ValueError):
                work.read_json(path)

    def test_runtime_complete_requires_executable_evidence(self):
        self.assertTrue(self.validate_mutation(lambda d: d['surfaces'][0].pop('implementation_evidence')))
        self.assertTrue(self.validate_mutation(lambda d: d['surfaces'][0]['implementation_evidence']['test_anchors'][0].update(name='missing_anchor')))
