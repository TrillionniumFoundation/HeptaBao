"""Negative controls for the OpenBao 2.7.x release denominator validator."""
from __future__ import annotations
import copy
import json
from pathlib import Path
import sys
import unittest

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'scripts'))
import validate_openbao_271_release_denominator as validator


class DenominatorControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.original=json.loads(validator.MANIFEST.read_text())

    def fresh(self):
        return copy.deepcopy(self.original)

    def test_manifest_is_structurally_complete_but_not_qualified(self):
        doc=self.fresh()
        self.assertEqual([],validator.validate(doc))
        self.assertFalse(doc['replacement_authority'])

    def test_missing_openbao_270_security_entry_rejected(self):
        doc=self.fresh()
        doc['security_delta']=[x for x in doc['security_delta'] if x['id']!='sdk_malformed_audit_redaction']
        self.assertTrue(any('sdk_malformed_audit_redaction' in x for x in validator.validate(doc)))

    def test_duplicate_security_entry_rejected(self):
        doc=self.fresh()
        doc['security_delta'].append(copy.deepcopy(doc['security_delta'][0]))
        self.assertTrue(any('duplicate' in x for x in validator.validate(doc)))

    def test_unwitnessed_admitted_security_entry_rejected(self):
        doc=self.fresh()
        doc['security_delta'][0]['status']='ADMITTED'
        self.assertTrue(any('admitted without evidence receipt' in x for x in validator.validate(doc)))

    def test_missing_271_change_entry_rejected(self):
        doc=self.fresh()
        doc['feature_and_correctness_delta']=[x for x in doc['feature_and_correctness_delta'] if x['id']!='barrier_rotation_disabled_field_persistence']
        self.assertTrue(any('barrier_rotation_disabled_field_persistence' in x for x in validator.validate(doc)))

    def test_each_openbao_270_feature_entry_is_required(self):
        # These reviewed 2.7.0 baseline entries must not disappear while the
        # two supplemental 2.7.1 changes still make the document look complete.
        for missing_id in (
            'postgresql_horizontal_scale',
            'external_kms_hsm_pki_transit',
            'pqc_tls_mldsa',
            'pebble_storage',
            'indexed_consistency',
            'grpc_invalidation',
            'raft_auto_join_provider_port',
            'sdk_lifetime_watcher_backoff',
        ):
            with self.subTest(missing_id=missing_id):
                doc=self.fresh()
                doc['feature_and_correctness_delta']=[
                    row for row in doc['feature_and_correctness_delta']
                    if row['id']!=missing_id
                ]
                self.assertTrue(any(
                    'missing required ids' in error and missing_id in error
                    for error in validator.validate(doc)
                ))

    def test_missing_271_packaged_default_entry_rejected(self):
        doc=self.fresh()
        doc['feature_and_correctness_delta']=[
            row for row in doc['feature_and_correctness_delta']
            if row['id']!='linux_package_default_pebbledb'
        ]
        self.assertTrue(any(
            'missing required ids' in error and 'linux_package_default_pebbledb' in error
            for error in validator.validate(doc)
        ))

    def test_unwitnessed_admitted_gate_rejected(self):
        doc=self.fresh()
        doc['required_gates'][0]['status']='ADMITTED'
        self.assertTrue(any('admitted without exact candidate receipt' in x for x in validator.validate(doc)))

    def test_missing_required_gate_rejected(self):
        doc=self.fresh()
        doc['required_gates']=[x for x in doc['required_gates'] if x['id']!='full_asset_migration']
        self.assertTrue(any('full_asset_migration' in x for x in validator.validate(doc)))

    def test_premature_release_authority_rejected(self):
        doc=self.fresh()
        doc['replacement_authority']=True
        doc['authority']='ADMITTED'
        self.assertTrue(any('cannot authorize replacement' in x for x in validator.validate(doc)))

    def test_baseline_commit_drift_rejected(self):
        doc=self.fresh()
        doc['baseline']['commit']='0'*40
        self.assertTrue(any('baseline mismatch' in x for x in validator.validate(doc)))


if __name__=='__main__':
    unittest.main()
