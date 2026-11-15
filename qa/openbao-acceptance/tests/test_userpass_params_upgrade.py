import copy
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest

import userpass_params_upgrade as fixture


class ParamsUpgradeGuards(unittest.TestCase):
    def test_legacy_admission_requires_real_clean_matching_comparison(self):
        receipt=json.loads(fixture.LEGACY_RECEIPT.read_text())
        fixture.admit_legacy_receipt(fixture.LEGACY_SHA256,receipt)
        for key,value in [('status','failed'),('build_source_commit','0'*40),('runner_unchanged',1),('oracle_only',True)]:
            with self.subTest(key=key),self.assertRaises(ValueError):
                fixture.admit_legacy_receipt(fixture.LEGACY_SHA256,receipt|{key:value})
        for change in ('dirty','binary','milestone','false_pass','different_sides'):
            damaged=copy.deepcopy(receipt)
            if change=='dirty':damaged['candidate_source']['source_dirty']=True
            elif change=='binary':damaged['candidate_source']['binary_sha256']='0'*64
            elif change=='milestone':
                for rows in damaged['cases'].values():
                    for row in rows:
                        if row['case']=='userpass_password.restart.old_token.valid':row['case']='case_214'
            elif change=='false_pass':
                for rows in damaged['cases'].values():rows[0]['passed']=1
            else:damaged['cases']['candidate'].pop(0)
            damaged['candidate_source_after']=dict(damaged['candidate_source'])
            with self.subTest(change=change),self.assertRaises(ValueError):
                fixture.admit_legacy_receipt(fixture.LEGACY_SHA256,damaged)

    def test_completion_accepts_extra_real_observations_not_fabricated_counts(self):
        rows=[{'case':name,'passed':True} for name in sorted(fixture.REQUIRED)]
        self.assertTrue(fixture.complete_checks(rows+[{'case':'additional_valid_observation','passed':True}],required_cases=fixture.REQUIRED))
        for name in ('pure_restart_reads_unchanged','current_legacy_nil_root_renew_token_shape',
                     'current_fresh_nil_renew_token_rejected','current_child_wrong_source_rejected',
                     'downgrade_unseal_rejected','recovery_old_bound_wrong_source_rejected'):
            missing=[r for r in rows if r['case']!=name]+[{'case':'case_214','passed':True}]
            self.assertFalse(fixture.complete_checks(missing,required_cases=fixture.REQUIRED))
        self.assertFalse(fixture.complete_checks(rows+[rows[0]],required_cases=fixture.REQUIRED))
        self.assertFalse(fixture.complete_checks(rows+[{'case':'additional_failure','passed':False}],required_cases=fixture.REQUIRED))

    def test_renew_uses_token_peer_but_root_management_from_other_peer(self):
        class Client:
            last_family=4
            def __init__(self):self.calls=[]
            def request(self,method,path,body,**kwargs):
                self.calls.append((path,body,kwargs))
                auth={'policies':['up-user'],'renewable':True}
                if path!='auth/token/renew-accessor':auth['client_token']='synthetic-token'
                return SimpleNamespace(status=200,body={'auth':auth})
        client=Client();trace=fixture.Trace(SimpleNamespace(token='root-synthetic'),[],client)
        trace.renew('observed',{'client_token':'synthetic-token','accessor':'synthetic-accessor'},['up-user'])
        self.assertEqual([c[2]['source'] for c in client.calls],['127.0.0.1','127.0.0.2','127.0.0.2'])
        self.assertEqual([c[2]['token'] for c in client.calls],['synthetic-token',None,None])
        self.assertEqual(client.calls[-1][1]['accessor'],'synthetic-accessor')

    def test_failed_requests_are_not_retried_or_allowed_to_return_credentials(self):
        class Client:
            last_family=4
            def __init__(self):self.calls=0
            def request(self,*args,**kwargs):
                self.calls+=1
                return SimpleNamespace(status=403,body={'auth':{'client_token':'private-secret'}})
        client=Client();rows=[];trace=fixture.Trace(SimpleNamespace(token='root'),rows,client)
        with self.assertRaises(fixture.ScenarioFailure):trace.login('denied','user','private-password',[],status=403)
        self.assertEqual(client.calls,1)
        self.assertEqual(rows[-1],{'case':'denied_rejected','passed':False})
        self.assertNotIn('private',json.dumps(rows))
        client.last_family=6
        with self.assertRaises(fixture.ScenarioFailure):trace.call('wrong_family','GET','sys/health',status=403)
        self.assertEqual(rows[-1],{'case':'wrong_family_source','passed':False})

    def test_application_manifest_exempts_only_root_ledger(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);(root/'records').mkdir()
            for name in ('ledger.hbl','snapshot.hbs','records/ledger.hbl'):(root/name).write_bytes(b'old')
            app=fixture.durable_manifest(root,application_only=True);full=fixture.durable_manifest(root)
            (root/'ledger.hbl').write_bytes(b'new')
            self.assertEqual(app,fixture.durable_manifest(root,application_only=True))
            self.assertNotEqual(full,fixture.durable_manifest(root))
            (root/'records/ledger.hbl').write_bytes(b'new')
            self.assertNotEqual(app,fixture.durable_manifest(root,application_only=True))


if __name__=='__main__':unittest.main()
