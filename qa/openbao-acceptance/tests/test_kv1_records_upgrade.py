from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import patch
from bao_http import Response
import kv1_records_upgrade as fixture
from kv1_record_scale_live import Dataset


class Kv1RecordsUpgradeGuards(unittest.TestCase):
    def receipt(self):
        return {'status':'passed','cases_match':True,'build_source_commit':fixture.LEGACY_SOURCE,
                'source_and_binary_unchanged':True,'runner_unchanged':True,
                'candidate_source':{'source_commit':fixture.LEGACY_SOURCE,'source_dirty':False,
                                    'binary_sha256':fixture.LEGACY_SHA256}}

    def test_only_actual_pinned_clean_successful_old_runtime_is_admitted(self):
        fixture.admit_legacy_receipt(fixture.LEGACY_SHA256,self.receipt())
        for field,value in (('status','failed'),('cases_match',False),('build_source_commit','0'*40),
                            ('source_and_binary_unchanged',False),('runner_unchanged',False)):
            with self.assertRaises(ValueError):
                fixture.admit_legacy_receipt(fixture.LEGACY_SHA256,self.receipt()|{field:value})
        for field,value in (('source_commit','0'*40),('source_dirty',True),('source_dirty',0),('binary_sha256','0'*64)):
            receipt=self.receipt();receipt['candidate_source'][field]=value
            with self.assertRaises(ValueError):fixture.admit_legacy_receipt(fixture.LEGACY_SHA256,receipt)
        for field in ('LEGACY_SOURCE','LEGACY_SHA256','LEGACY_RECEIPT'):
            with patch.object(fixture,field,None):
                with self.assertRaisesRegex(ValueError,'pin_not_available'):
                    fixture.admit_legacy_receipt(fixture.LEGACY_SHA256,self.receipt())

    def test_format_observation_is_actual_storage_not_just_current_schema(self):
        with tempfile.TemporaryDirectory() as directory:
            instance=SimpleNamespace(root=Path(directory),address='https://localhost:443',token='synthetic')
            with patch.object(fixture,'Client',return_value=SimpleNamespace(request=lambda *a,**k:
                Response(200,{'data':{'state_schema':36,'state_storage_format':fixture.LEGACY_FORMAT}}))):
                trace=fixture.Trace(instance,[])
            trace.format('pure_read',fixture.LEGACY_FORMAT)
            with self.assertRaises(fixture.ScenarioFailure):trace.format('not_migrated',fixture.CURRENT_FORMAT)

    def test_real_pure_phase_calls_require_v4_and_byte_identity_before_first_mutation(self):
        class FirstWrite(Exception):pass
        dataset=Dataset();dataset.remember('bulk/0000',{'synthetic':7})
        def request(method,path,body=None,**kwargs):
            if method=='PUT':raise FirstWrite
            if path=='/v1/sys/internal/capacity':
                return Response(200,{'data':{'state_storage_format':fixture.LEGACY_FORMAT}})
            if path=='/v1/'+fixture.MOUNT+'/bulk/0000':return Response(200,{'data':{'synthetic':7}})
            if path=='/v1/secret/data/record-migration-control':return Response(200,{'data':{'data':{'synthetic':True}}})
            return Response(200,{})
        rows=[]
        with tempfile.TemporaryDirectory() as directory:
            instance=SimpleNamespace(root=Path(directory),address='https://localhost:443',token='synthetic',
                                     start=lambda:None,stop=lambda:None)
            with patch.object(fixture,'Client',return_value=SimpleNamespace(request=request)):
                trace=fixture.Trace(instance,rows)
            with patch.object(fixture,'prepare_legacy',return_value=(trace,'synthetic-key',dataset)), \
                 patch.object(fixture,'durable_manifest',return_value='unchanged'):
                with self.assertRaises(FirstWrite):fixture.run_upgrade(instance,Path('new'),Path('old'),rows)
        names=[row['case'] for row in rows]
        self.assertEqual(len(names),len(set(names)))
        self.assertTrue(all(row['passed'] is True for row in rows))
        for phase in ('current','untouched_restart'):
            self.assertIn(fixture.PREFIX+phase+'.reads_preserve_entire_store',names)
            self.assertIn(fixture.PREFIX+phase+'.format_v4',names)

    def test_completion_requires_migration_and_downgrade_preservation_not_fixed_count(self):
        for prepare in (False,True):
            required={'legacy.complete','legacy.format_v4','legacy.plaintext_credentials_absent'} if prepare else fixture.REQUIRED
            end='legacy.plaintext_credentials_absent' if prepare else 'complete'
            rows=[{'case':fixture.PREFIX+name,'passed':True} for name in sorted(required-{end})]
            rows.append({'case':fixture.PREFIX+end,'passed':True})
            self.assertTrue(fixture.complete(rows,prepare))
            self.assertTrue(fixture.complete(rows[:-1]+[{'case':fixture.PREFIX+'extra','passed':True}]+rows[-1:],prepare))
            for i in range(len(rows)):
                self.assertFalse(fixture.complete(rows[:i]+rows[i+1:],prepare),rows[i])
            self.assertFalse(fixture.complete(rows+[rows[0]],prepare))
            self.assertFalse(fixture.complete(rows[:-1]+[dict(rows[-1],passed=1)],prepare))


if __name__=='__main__':unittest.main()
