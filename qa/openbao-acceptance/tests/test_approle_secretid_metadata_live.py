import copy
import json
from pathlib import Path
import unittest
import tempfile
import sys
from types import SimpleNamespace
from unittest.mock import patch
import approle_secretid_metadata_live as f

class MetadataComparisonTests(unittest.TestCase):
    def calibration(self):
        value=json.loads(f.CALIBRATION_PATH.read_text())
        return f.calibrated_rows(), value['completed_scenarios']
    def test_real_calibration_and_named_phases(self):
        rows,phases=self.calibration()
        self.assertTrue(f.complete(rows,phases,rows))
        self.assertEqual(set(phases),f.contract.SCENARIOS)
        self.assertTrue(any(r.get('status')==400 for r in rows))
        self.assertTrue(any(r.get('token_type')=='batch' for r in rows))
    def test_equal_failures_cannot_replace_official_success(self):
        rows,phases=self.calibration()
        for case,update in (
            ('parse.random.service.json_map.issue',{'status':400}),
            ('parse.custom.batch.json_duplicate.login',{'auth_metadata':{'shape':'missing'}}),
            ('lifecycle.random.service.stored.raw',{'data_metadata':{'shape':'map','value':{'role_name':'meta-random-service-life'}}}),
            ('lifecycle.custom.service.renew_after_delete.accessor',{'auth_metadata':{'shape':'missing'}}),
            ('restart.random.batch.old.kv',{'status':403}),
            ('lifecycle.random.service.after_fresh.alias',{'custom_metadata':{'shape':'null'}})):
            wrong=copy.deepcopy(rows);next(r for r in wrong if r['case']==case).update(update)
            self.assertFalse(f.complete(wrong,phases,rows),case)
            self.assertEqual(wrong,copy.deepcopy(wrong))
    def test_omissions_duplicates_and_reordering_cannot_pass(self):
        rows,phases=self.calibration()
        for changed in ([],rows[:-1],rows+rows[:1],list(reversed(rows))):
            self.assertFalse(f.complete(changed,phases,rows))
        for changed in ([],phases[:-1],phases+phases[:1],None):
            self.assertFalse(f.complete(rows,changed,rows))
    def test_safe_projection_never_accepts_secret_raw_fields(self):
        rows,_=self.calibration()
        for update in ({'status':True},{'token':'private'},{'raw_errors':['private']},
                       {'auth_metadata':{'shape':'map','value':{'env':'private-canary'}}}):
            bad=copy.deepcopy(rows);bad[0].update(update)
            self.assertFalse(f.safe_rows(bad))
        self.assertFalse(f.safe_metadata({'shape':'map','value':{'unknown-key':'prod'}}))
        self.assertFalse(f.safe_rows([{'case':'madeup','passed':True}]))
    def test_batch_absent_accessor_cannot_become_bearer_test(self):
        rows,phases=self.calibration()
        row=next(r for r in rows if r['case'].endswith('.accessor_not_applicable'))
        self.assertEqual(set(row),{'case','absent_accessor','endpoint_not_called'})
        wrong=copy.deepcopy(rows)
        next(r for r in wrong if r['case']==row['case'])['endpoint_not_called']=False
        self.assertFalse(f.complete(wrong,phases,rows))
    def test_calibration_rejects_changed_or_unqualified_inputs(self):
        original=json.loads(f.CALIBRATION_PATH.read_text())
        def digest(path):return f.CONTRACT_SHA256 if Path(path)==Path(f.contract.__file__) else f.CALIBRATION_SHA256
        for key,value in [('status','passed'),('oracle_only',False),('candidate_executed',True),
                          ('source_qualified',True),('inputs_unchanged',False),('secrets_absent',False),
                          ('processes_stopped',False),('failure','failed'),('completed_scenarios',[])]:
            bad=copy.deepcopy(original);bad[key]=value
            with patch.object(f,'file_hash',digest),patch.object(Path,'read_text',return_value=json.dumps(bad)):
                with self.assertRaises(ValueError,msg=key):f.calibrated_rows()

class SupplementaryProfileTests(unittest.TestCase):
    def test_both_profiles_are_exact_immutable_receipts(self):
        self.assertEqual(set(f.PROFILES), {'primary','supplementary'})
        for profile,(module,path,digest,runner_digest,_) in f.PROFILES.items():
            with self.subTest(profile=profile):
                rows=f.calibrated_rows(profile);phases=json.loads(path.read_text())['completed_scenarios']
                self.assertEqual(f.file_hash(path),digest)
                self.assertEqual(f.file_hash(Path(module.__file__)),runner_digest)
                self.assertTrue(f.complete(rows,phases,rows,profile))
                self.assertFalse(f.complete(rows[:-1],phases,rows,profile))
                self.assertFalse(f.complete(rows,phases[:-1],rows,profile))
    def test_supplementary_limits_control_and_base64_cannot_be_filtered(self):
        rows=f.calibrated_rows('supplementary')
        phases=json.loads(f.PROFILES['supplementary'][1].read_text())['completed_scenarios']
        for case,update in (
            ('parser.base64_json.issue',{'status':400}),
            ('parser.base64_unpadded.issue',{'status':200}),
            ('parser.csv_reverse_duplicate.stored.raw',{'data_metadata':{'shape':'map','value':{'env':'first'}}}),
            ('parser.json_empty_both.login',{'status':400}),
            ('parser.json_control.bearer',{'status':403}),
            ('parser.json_65_keys.issue',{'status':400}),
            ('parser.json_long_value.login',{'status':400})):
            wrong=copy.deepcopy(rows);next(r for r in wrong if r['case']==case).update(update)
            self.assertFalse(f.complete(wrong,phases,rows,'supplementary'),case)
        wrong=copy.deepcopy(rows)
        target=next(r for r in wrong if r['case']=='parser.json_control.stored.raw')
        target['data_metadata']['value']['env']['sha256']='0'*64
        self.assertFalse(f.complete(wrong,phases,rows,'supplementary'))
    def test_main_allocates_fresh_instance_for_each_profile_and_side(self):
        expected={name:f.calibrated_rows(name) for name in f.PROFILES}
        phases={name:json.loads(values[1].read_text())['completed_scenarios'] for name,values in f.PROFILES.items()}
        created=[]
        def trace_run(name):
            def run(trace,restart):
                trace.rows.extend(copy.deepcopy(expected[name]));trace.finished.extend(phases[name])
            return run
        with tempfile.TemporaryDirectory() as temporary:
            parent=Path(temporary);parent.chmod(0o700);binary=parent/'binary';binary.write_bytes(b'not-executed')
            output=parent/'report.json'
            def make_files(root):
                root.mkdir(mode=0o700)
                for name,data in [('root.token','synthetic-root-token-01234567890'),('unseal.key','synthetic-unseal-key-01234567890')]:
                    p=root/name;p.write_text(data);p.chmod(0o600)
            def oracle(port):
                root=parent/('oracle-'+str(len(created)));make_files(root);created.append(root)
                return dict(root=str(root),token_file=str(root/'root.token'),ca_file=str(root/'ca.crt'),
                    address='https://127.0.0.1:1',process=SimpleNamespace(poll=lambda:0))
            class Instance:
                def __init__(self,binary,root):
                    self.root=root;make_files(root);created.append(root)
                    (root/'server.json').write_text('{}');(root/'server.json').chmod(0o600)
                    self.address='https://127.0.0.1:1';self.process=SimpleNamespace(poll=lambda:0)
                def start(self):pass
                def stop(self):pass
                def call(self,method,path,body):
                    return (200,{'root_token':'synthetic-root-token-01234567890','keys_base64':['synthetic-unseal-key-01234567890']}) if path=='sys/init' else (200,{})
            argv=['fixture','--binary',str(binary),'--build-source-commit','a'*40,
                  '--expected-binary-sha256',f.file_hash(binary),'--work-parent',str(parent),'--output',str(output)]
            with (patch('builtins.print'),patch.object(sys,'argv',argv),patch.object(f,'verify_inputs',return_value=binary),
                  patch.object(f,'source_identity',return_value={'source_dirty':False}),
                  patch.object(f,'start_oracle',side_effect=oracle),patch.object(f,'stop_oracle'),
                  patch.object(f,'Instance',Instance),patch.object(f,'SourceClient'),patch.object(f,'safe_files',return_value=True),
                  patch.object(f.contract,'run',side_effect=trace_run('primary')),
                  patch.object(f.supplementary,'run',side_effect=trace_run('supplementary'))):
                self.assertEqual(f.main(),0)
            report=json.loads(output.read_text())
            self.assertEqual(set(report['cases']),{name+'.'+side for name in f.PROFILES for side in ('oracle','candidate')})
            self.assertEqual(len(created),4);self.assertEqual(len(set(created)),4)
            self.assertEqual({p.name for p in created if p.name.endswith('-candidate')},{'primary-candidate','supplementary-candidate'})

    def test_profiles_cannot_substitute_for_each_other(self):
        primary=f.calibrated_rows('primary');supplement=f.calibrated_rows('supplementary')
        pphases=json.loads(f.PROFILES['primary'][1].read_text())['completed_scenarios']
        sphases=json.loads(f.PROFILES['supplementary'][1].read_text())['completed_scenarios']
        self.assertFalse(f.complete(primary,sphases,primary,'primary'))
        self.assertFalse(f.complete(supplement,pphases,supplement,'supplementary'))
        self.assertFalse(f.complete(primary,pphases,supplement,'primary'))

if __name__=='__main__':unittest.main()
