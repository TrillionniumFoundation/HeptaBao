import copy
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import patch

from bao_http import Response, canonical
import kv1_packed_upgrade as fixture


class PackedUpgradeGuards(unittest.TestCase):
    def receipt(self):
        source = {'source_commit':fixture.LEGACY_SOURCE,'source_dirty':False,
                  'binary_sha256':fixture.LEGACY_SHA256}
        return {'schema':'heptabao.kv1-record-backup.v1','status':'passed',
                'build_source_commit':fixture.LEGACY_SOURCE,'source_and_binary_unchanged':True,
                'runner_unchanged':True,'source_identity':source,'source_identity_after':dict(source)}

    def test_actual_qualified_legacy36_identity_is_required(self):
        fixture.admit_legacy_receipt(fixture.LEGACY_SHA256,self.receipt())
        for key,value in [('status','failed'),('build_source_commit','0'*40),
                          ('source_and_binary_unchanged',False),('runner_unchanged',1),
                          ('schema','unrelated.receipt')]:
            with self.assertRaises(ValueError):
                fixture.admit_legacy_receipt(fixture.LEGACY_SHA256,self.receipt()|{key:value})
        for key,value in [('source_dirty',True),('source_dirty',0),('source_commit','0'*40),
                          ('binary_sha256','0'*64)]:
            receipt = self.receipt();receipt['source_identity'][key]=value
            with self.assertRaises(ValueError):fixture.admit_legacy_receipt(fixture.LEGACY_SHA256,receipt)
        with self.assertRaises(ValueError):fixture.admit_legacy_receipt('0'*64,self.receipt())

    def test_dense_values_are_exactly600_distinct_and_hash_every_returned_byte(self):
        data = fixture.DenseData()
        for ordinal in (0,1,255,4096,19999):
            value = data.make(ordinal);data.remember(ordinal,value)
            self.assertEqual(len(canonical(value)),600)
            self.assertTrue(data.matches(ordinal,Response(200,{'data':value})))
            corrupted = copy.deepcopy(value);corrupted['payload']='z'+corrupted['payload'][1:]
            self.assertFalse(data.matches(ordinal,Response(200,{'data':corrupted})))
            self.assertFalse(data.matches(ordinal,Response(404,{'data':value})))
        self.assertEqual(len(set(data.hashes.values())),5)
        self.assertLessEqual(len(data.samples),8)

    def test_required_milestones_cannot_be_replaced_by_total_check_count(self):
        rows = [{'case':name,'passed':True} for name in sorted(fixture.REQUIRED-{'complete'})]
        rows.append({'case':'complete','passed':True})
        observation = {'legacy_records_written':256,'candidate_records_present':20000,
                       'canonical_value_bytes':600,'all_hashes_verified_after_restart':True}
        self.assertTrue(fixture.complete(rows,observation,256,20000))
        self.assertTrue(fixture.complete(rows[:-1]+[{'case':'additional_valid_observation','passed':True}]+rows[-1:],observation,256,20000))
        for index in range(len(rows)):
            self.assertFalse(fixture.complete(rows[:index]+rows[index+1:],observation,256,20000))
        self.assertFalse(fixture.complete(rows+[rows[0]],observation,256,20000))
        self.assertFalse(fixture.complete(rows[:-1]+[{'case':'complete','passed':1}],observation,256,20000))
        self.assertFalse(fixture.complete(rows,observation|{'candidate_records_present':19999},256,20000))
        self.assertFalse(fixture.complete(rows,observation|{'all_hashes_verified_after_restart':1},256,20000))

    def test_unknown_mutation_outcome_is_never_retried_and_secrets_never_form_failure_text(self):
        with tempfile.TemporaryDirectory() as directory:
            instance=SimpleNamespace(root=Path(directory),address='https://localhost:443',token='synthetic')
            with patch.object(fixture,'Client') as client:
                client.return_value.request.side_effect=TimeoutError('hvs.secret-sentinel')
                trace=fixture.Trace(instance,[])
                with self.assertRaises(TimeoutError) as caught:
                    trace.request('PUT','unused',{'private':'secret-sentinel'},expected=204)
                self.assertEqual(client.return_value.request.call_count,1)
                self.assertEqual(client.call_args.kwargs['timeout'],5)
                self.assertEqual(fixture.safe_failure(caught.exception,[]),'fixture_TimeoutError')
        self.assertEqual(fixture.safe_failure(fixture.ScenarioFailure('secret_sentinel'),[]),'fixture_ScenarioFailure')
        self.assertEqual(fixture.safe_failure(fixture.ScenarioFailure('unexpected_http_status_507'),[]),'unexpected_http_status_507')

    def test_pure_phase_performs_noop_and_failed_write_before_migration(self):
        class StopAtFirstMutation(Exception):pass
        calls=[];rows=[];values={};versions=[]
        def request(method,path,body=None):
            calls.append((method,path))
            if path.endswith('/sys/init'):
                return Response(200,{'root_token':'synthetic-token','keys_base64':['synthetic-key']})
            if path.endswith('/sys/unseal'):return Response(200,{})
            if '/sys/mounts/' in path:return Response(204,{})
            if path.endswith('/sys/internal/storage/capacity'):
                return Response(200,{'data':{'state_storage_format':'heptabao-state-records-v5'}})
            if path.endswith('/secret/data/packed-control'):
                return Response(200,{'data':{'data':{'retained':True}}})
            if path.endswith('/rejected'):return Response(400,{})
            if '/dense/' in path:
                if method=='PUT':
                    if path in values and body != values[path]:raise StopAtFirstMutation
                    values[path]=body;return Response(204,{})
                return Response(200,{'data':values[path]})
            raise AssertionError('unexpected_mock_route')
        with tempfile.TemporaryDirectory() as directory:
            instance=SimpleNamespace(root=Path(directory),address='https://localhost:443',token='',
                process=SimpleNamespace(pid=123),start=lambda:None,stop=lambda:None,
                call=lambda method,path,body:(lambda r:(r.status,r.body))(request(method,'/v1/'+path,body)))
            counters={'cpu_ticks':1,'write_bytes':0,'wchar':0,'rss_kib':1,'peak_rss_kib':1}
            with patch.object(fixture,'Client',return_value=SimpleNamespace(request=request)), \
                 patch.object(fixture,'durable_manifest',return_value='unchanged'), \
                 patch.object(fixture,'process_observation',return_value=counters), \
                 patch.object(fixture,'disk_observation',return_value={'largest_file_bytes':1}):
                with self.assertRaises(StopAtFirstMutation):
                    fixture.run(instance,Path('new'),Path('old'),2,2,rows,[],{},lambda v:None)
        names={row['case'] for row in rows}
        self.assertIn('current_reads_noop_rejection_unchanged',names)
        self.assertIn('second_open_reads_unchanged',names)
        self.assertNotIn('first_mutation_succeeded',names)
        self.assertIn(('PUT','/v1/'+fixture.MOUNT+'/rejected'),calls)

    def test_pacing_cannot_burst_after_slow_io_or_retry_a_failed_read(self):
        with tempfile.TemporaryDirectory() as directory:
            instance=SimpleNamespace(root=Path(directory),address='https://localhost:443',token='synthetic')
            with patch.object(fixture,'Client') as client, \
                 patch.object(fixture.time,'monotonic',side_effect=[10,10,10.001,10.01,15,15]), \
                 patch.object(fixture.time,'sleep') as sleep:
                trace=fixture.Trace(instance,[])
                trace.response('GET','first')
                trace.response('GET','second')
                client.return_value.request.side_effect=fixture.BaoError('transport_read_failed')
                with self.assertRaises(fixture.BaoError) as caught:
                    trace.response('GET','third')
                self.assertEqual(client.return_value.request.call_count,3)
                sleep.assert_called_once()
                self.assertAlmostEqual(sleep.call_args.args[0],0.009)
                self.assertAlmostEqual(trace.next_start,15.01)
                self.assertEqual(fixture.safe_failure(caught.exception,[]),'client_transport_read_failed')
                self.assertEqual(fixture.safe_failure(fixture.BaoError('synthetic-secret'),[]),'fixture_BaoError')

    def test_verification_progress_records_only_completed_hash_checks(self):
        data=fixture.DenseData()
        values=[data.make(i) for i in range(2)]
        for i,value in enumerate(values):data.remember(i,value)
        progress=[];checks=[]
        with tempfile.TemporaryDirectory() as directory:
            instance=SimpleNamespace(root=Path(directory),address='https://localhost:443',token='synthetic')
            with patch.object(fixture,'Client'), patch.object(fixture.Trace,'response',
                side_effect=[Response(200,{'data':values[0]}),Response(429,{})]):
                trace=fixture.Trace(instance,checks,progress.append)
                with self.assertRaises(fixture.ScenarioFailure):trace.verify('dense_all_hashes',data)
        self.assertEqual(checks,[{'case':'dense_all_hashes_record_1','passed':False}])
        self.assertEqual(progress,[{'status':'in_progress','phase':'dense_all_hashes',
                                    'records_verified':0,'records_present':2}])


if __name__=='__main__':unittest.main()
