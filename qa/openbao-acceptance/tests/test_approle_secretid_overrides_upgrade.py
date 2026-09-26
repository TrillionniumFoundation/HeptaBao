import copy
import json
from pathlib import Path
import unittest
from unittest.mock import patch

import approle_secretid_overrides_upgrade as f
import approle_secretid_overrides_upgrade_contract as contract


class SecretIdOverridesUpgradeGuards(unittest.TestCase):
    def test_actual_qualified_old45_receipt_and_exact_cli_pins(self):
        receipt = Path(f.legacy_comparison.__file__).parent/'evidence/approle-secret-cidrs-live-e39fe66.json'
        value = json.loads(receipt.read_text())
        expected = f.legacy_comparison.calibrated_rows()
        digest = '417745f5760f31df17f6da8554baaba6207841ea9f395e4291f8ed397ce1d2f4'
        source = 'e39fe66c778ee2dce6708c9b65cef982c366845d'
        binary = '89c41282eeaed00e6836752d37033865c559886fdd083395b4225ea86b4bfd30'
        def admit(body, actual=digest, src=source, sha=binary):
            contract.admit_legacy(body, actual, digest, src, sha, expected, f.legacy_comparison.complete)
        self.assertEqual(f.file_hash(receipt), digest)
        admit(value)
        for field, bad in [('status','failed'), ('oracle_only',True), ('processes_stopped',False),
                           ('source_and_binary_unchanged',False), ('inputs_unchanged',False),
                           ('build_source_commit','0'*40), ('cases_match',False)]:
            changed=copy.deepcopy(value);changed[field]=bad
            with self.assertRaises(ValueError,msg=field):admit(changed)
        changed=copy.deepcopy(value);changed['cases']['candidate']=changed['cases']['candidate'][:-1]
        with self.assertRaises(ValueError):admit(changed)
        with self.assertRaises(ValueError):admit(value, actual='0'*64)
        with self.assertRaises(ValueError):admit(value, sha='0'*64)
        with self.assertRaises(ValueError):admit(value, src='0'*40)

    def test_four_option_gates_are_independent_and_raw_custom_does_not_leak(self):
        self.assertEqual({(v[0], bool(v[1])) for v in contract.PROFILES.values()},
                         {(field, bound) for field in ('cidr_list','token_bound_cidrs') for bound in (False,True)})
        self.assertEqual({v[2] for v in contract.PROFILES.values()}, {'random','custom'})
        self.assertEqual({v[3] for v in contract.PROFILES.values()}, {'service','batch'})
        class T:
            sensitive=[]
            def call(self, name, method, route, body):
                self.seen=(name,method,route,copy.deepcopy(body))
                return {'data':{'secret_id':body.get('secret_id','generated')}}
        t=T();t.sensitive=[]
        with patch.object(f.secrets,'token_urlsafe',return_value='safe-synthetic'):
            value=f.issue(t,'first','rid','custom',{'cidr_list':[]})
        self.assertEqual(t.seen[2],f.ROLE+'/custom-secret-id')
        self.assertEqual(set(t.seen[3]),{'cidr_list','secret_id'})
        self.assertEqual(t.seen[3]['cidr_list'],[])
        self.assertIn(value['secret_id'],t.sensitive)

    def test_pure_read_contract_rejects_any_invented_or_changed_old_sid_metadata(self):
        old={'secret_id_accessor':'synthetic','secret_id_num_uses':5,'secret_id_ttl':1800,
             'cidr_list':[],'token_bound_cidrs':[],'last_updated_time':'2026-01-01T00:00:00Z'}
        self.assertTrue(contract.old_secret_preserved(copy.deepcopy(old),old))
        for field,value in [('cidr_list',None),('token_bound_cidrs',['127.0.0.1/32']),
                            ('secret_id_num_uses',4),('secret_id_ttl',1799),('extra',True)]:
            self.assertFalse(contract.old_secret_preserved({**old,field:value},old))
        self.assertFalse(contract.old_secret_preserved(old,{**old,'cidr_list':None}))
        self.assertFalse(contract.old_secret_preserved({k:v for k,v in old.items() if k!='last_updated_time'},old))

    def test_required_named_milestones_allow_extra_success_but_no_skipped_gate(self):
        rows=[{'case':name,'passed':True} for name in sorted(contract.REQUIRED-{'complete'})]
        rows.append({'case':'complete','passed':True})
        self.assertTrue(contract.complete(rows))
        self.assertTrue(contract.complete(rows[:-1]+[{'case':'new_actual_observation','passed':True}]+rows[-1:]))
        for name in contract.REQUIRED:
            self.assertFalse(contract.complete([r for r in rows if r['case']!=name]),name)
        for bad in (rows+rows[:1],rows[:-1]+[{'case':'complete','passed':1}],
                    rows[:-1]+[{'case':'complete','passed':True,'secret':'no'}]):
            self.assertFalse(contract.complete(bad))
        self.assertFalse(contract.old_reader_observed(rows))
        self.assertTrue(contract.old_reader_observed([{'case':'source_empty_downgrade_unseal_status','passed':False,'status':200}]))

    def test_first_option_issue_is_immediately_followed_by_real_old_reader(self):
        # Execute real run_store orchestration up to first old-reader handoff.
        # No source-order assertion: any intervening login/write reaches the fake transport.
        events=[]
        class ReachedOldReader(Exception): pass
        old={'cidr_list':[],'token_bound_cidrs':[],'secret_id_num_uses':5}
        saved={'role':{'bind_secret_id':True},'sid':old,'creds':{'secret_id':'safe','role_id':'rid'},
               'auth':{'client_token':'safe'},'kind':'service','rid':'rid'}
        class T:
            sensitive=[]
            def call(self,name,method,route,body=None,**kwargs):
                events.append(('request',method,route))
                if route==f.ROLE:return {'data':saved['role']}
                if route.endswith('/secret-id/lookup'):return {'data':old}
                if route.endswith('/secret-id'):return {'data':{'secret_id':'first'}}
                raise AssertionError('unexpected request')
            def check(self,name,condition,**kwargs):
                if not condition:raise AssertionError(name)
            def lookup(self,*args):pass
        t=T()
        class Instance:
            root=Path('/synthetic-unused')
            def stop(self):pass
        def downgrade(*args):
            events.append(('old-reader',));raise ReachedOldReader
        with patch.object(f,'seed',return_value=(t,'key',saved)), \
             patch.object(f,'restart',side_effect=lambda *a:events.append(('reopen',))), \
             patch.object(f,'durable_manifest',return_value='same'),patch.object(f,'use'), \
             patch.object(f.previous,'downgrade',side_effect=downgrade):
            with self.assertRaises(ReachedOldReader):
                f.run_store(Instance(),Path('new'),Path('old'),[],'source_empty',[])
        self.assertEqual(events[-2:],[('request','POST',f.ROLE+'/secret-id'),('old-reader',)])
        writes=[event for event in events if event[0]=='request' and event[1]!='GET' and not event[2].endswith('/lookup')]
        self.assertEqual(writes,[('request','POST',f.ROLE+'/secret-id')])


if __name__=='__main__':unittest.main()
