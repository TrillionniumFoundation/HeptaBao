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
    def test_all_profiles_are_exact_immutable_receipts(self):
        self.assertEqual(set(f.PROFILES), {'primary','supplementary','partial_json','denial'})
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
                  patch.object(f.supplementary,'run',side_effect=trace_run('supplementary')),
                  patch.object(f.partial_json,'run',side_effect=trace_run('partial_json')),
                  patch.object(f.denial,'run',side_effect=trace_run('denial'))):
                self.assertEqual(f.main(),0)
            report=json.loads(output.read_text())
            self.assertEqual(set(report['cases']),{name+'.'+side for name in f.PROFILES for side in ('oracle','candidate')})
            self.assertEqual(len(created),2*len(f.PROFILES));self.assertEqual(len(set(created)),2*len(f.PROFILES))
            self.assertEqual({p.name for p in created if p.name.endswith('-candidate')},{name+'-candidate' for name in f.PROFILES})

    def test_profiles_cannot_substitute_for_each_other(self):
        primary=f.calibrated_rows('primary');supplement=f.calibrated_rows('supplementary')
        pphases=json.loads(f.PROFILES['primary'][1].read_text())['completed_scenarios']
        sphases=json.loads(f.PROFILES['supplementary'][1].read_text())['completed_scenarios']
        self.assertFalse(f.complete(primary,sphases,primary,'primary'))
        self.assertFalse(f.complete(supplement,pphases,supplement,'supplementary'))
        self.assertFalse(f.complete(primary,pphases,supplement,'primary'))


class PartialJsonProfileTests(unittest.TestCase):
    def test_type_failure_and_fresh_alias_login_failure_are_exact(self):
        rows=f.calibrated_rows('partial_json')
        phases=json.loads(f.PROFILES['partial_json'][1].read_text())['completed_scenarios']
        for case,update in (
            ('parser.type_number.issue',{'status':200}),
            ('parser.type_nested.issue',{'status':200}),
            ('parser.type_array.issue',{'status':200}),
            ('parser.type_number_first.issue',{'status':200}),
            ('parser.malformed_json.issue',{'status':400}),
            ('parser.malformed_json.login',{'status':200,'auth':True}),
            ('parser.malformed_json.no_issued_bearer',{'credential_issued':True}),
            ('parser.json_strings_control.bearer',{'status':403})):
            wrong=copy.deepcopy(rows);next(row for row in wrong if row['case']==case).update(update)
            self.assertFalse(f.complete(wrong,phases,rows,'partial_json'),case)
        no_bearer=next(row for row in rows if row['case'].endswith('.no_issued_bearer'))
        self.assertEqual(no_bearer,{'case':'parser.malformed_json.no_issued_bearer','credential_issued':False})
        self.assertFalse(any(row['case']=='parser.malformed_json.bearer' for row in rows))
        login=next(row for row in rows if row['case']=='parser.malformed_json.login')
        self.assertFalse(login['auth'] or login['data'] or login['wrap'])
        self.assertEqual(login['status'],500)

    def test_partial_profile_cannot_use_previous_alias_or_drop_rejection(self):
        rows=f.calibrated_rows('partial_json')
        phases=json.loads(f.PROFILES['partial_json'][1].read_text())['completed_scenarios']
        self.assertTrue(f.complete(rows,phases,rows,'partial_json'))
        for name in ('parser.malformed_json.login','parser.malformed_json.no_issued_bearer'):
            self.assertFalse(f.complete([row for row in rows if row['case']!=name],phases,rows,'partial_json'))
        self.assertFalse(f.complete(rows,json.loads(f.PROFILES['supplementary'][1].read_text())['completed_scenarios'],rows,'partial_json'))
        with patch.object(f,'file_hash',return_value='0'*64):
            with self.assertRaises(ValueError):f.calibrated_rows('partial_json')



class DenialProfileTests(unittest.TestCase):
    def calibration(self):
        rows=f.calibrated_rows('denial')
        phases=json.loads(f.PROFILES['denial'][1].read_text())['completed_scenarios']
        return rows,phases

    def test_denial_retains_native_alias_update_consumption_and_restart(self):
        rows,phases=self.calibration()
        self.assertEqual(set(phases), {'denial.service','denial.batch','restart'})
        for kind in ('service','batch'):
            prefix='denial.'+kind
            by_name={row['case']:row for row in rows}
            rejected=by_name[prefix+'.rejected_login']
            self.assertEqual(rejected['status'],403)
            self.assertFalse(rejected['auth'] or rejected['data'] or rejected['wrap'])
            self.assertEqual(by_name[prefix+'.rejection'], {'case':prefix+'.rejection',
                'permission_denied':True,'no_credential':True,'no_wrapper':True})
            for suffix in ('.after_alias',):
                self.assertEqual(by_name[prefix+suffix]['data_metadata']['value']['env'],'two')
                self.assertEqual(by_name[prefix+suffix]['custom_metadata']['value']['owner'],'control')
            self.assertEqual(by_name['restart.'+prefix+'.alias']['data_metadata']['value']['env'],'two')
            for field in ('raw','accessor'):
                self.assertEqual(by_name[prefix+'.before_sid.'+field]['secret_id_num_uses'],2)
                self.assertEqual(by_name[prefix+'.after_sid.'+field]['secret_id_num_uses'],1)
                self.assertEqual(by_name['restart.'+prefix+'.sid.'+field]['secret_id_num_uses'],1)
        self.assertTrue(f.complete(rows,phases,rows,'denial'))

    def test_equal_403_is_insufficient_when_native_sideeffects_differ(self):
        rows,phases=self.calibration()
        changes=(
            ('denial.service.after_alias',{'data_metadata':{'shape':'map','value':{'env':'one'}}}),
            ('denial.batch.after_alias',{'custom_metadata':{'shape':'missing'}}),
            ('denial.service.after_sid.raw',{'secret_id_num_uses':2}),
            ('restart.denial.batch.sid.accessor',{'secret_id_num_uses':0}),
            ('restart.denial.service.alias',{'data_metadata':{'shape':'missing'}}),
            ('denial.batch.rejection',{'no_credential':False}),
            ('denial.service.rejected_login',{'status':200,'auth':True}))
        for case,update in changes:
            wrong=copy.deepcopy(rows);next(row for row in wrong if row['case']==case).update(update)
            self.assertFalse(f.complete(wrong,phases,rows,'denial'),case)
        self.assertFalse(f.complete(rows,[p for p in phases if p!='restart'],rows,'denial'))

    def test_rejection_projection_allows_only_exact_names_and_booleans(self):
        rows,_=self.calibration()
        row=next(row for row in rows if row['case']=='denial.service.rejection')
        self.assertTrue(f.safe_rows([row]))
        for update in ({'case':'other.rejection'},{'no_credential':1}, {'no_wrapper':'true'},
                       {'permission_denied':None},{'raw_error':'private'}, {'token':'private'}):
            self.assertFalse(f.safe_rows([{**row,**update}]),update)
        for key in ('permission_denied','no_credential','no_wrapper'):
            missing=dict(row);del missing[key]
            self.assertFalse(f.safe_rows([missing]),key)

if __name__=='__main__':unittest.main()
