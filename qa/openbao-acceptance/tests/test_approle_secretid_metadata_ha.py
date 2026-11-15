import copy
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import approle_secretid_metadata_ha as f


class MetadataHaGuards(unittest.TestCase):
    def test_wide_map_is_only_applied_after_an_ordinary_alias_creation(self):
        self.assertEqual(f.metadata('one'), {'env':'one','role_name':'spoofed'})
        self.assertEqual(len(f.metadata('two')), 65)
        self.assertLess(len(f.json.dumps(f.metadata('two')).encode()), 4096)
        self.assertEqual(f.metadata('two','batch')['role_name'],'batch')
        self.assertEqual(f.metadata('two')['role_name'],'spoofed')

    def test_failed_wrapped_login_uses_real_origin_once_and_cannot_return_secret_or_wrapper(self):
        class Client:
            last_family=4
            def __init__(self,status,body): self.status,self.body,self.calls=status,body,[]
            def request(self,*args,**kwargs):
                self.calls.append((args,kwargs)); return SimpleNamespace(status=self.status,body=self.body)
        creds={'role_id':'synthetic-role-id','secret_id':'synthetic-secret-id'}
        for status in (400,403):
            client=Client(status,{'errors':['denied']}); rows=[]
            f.Trace(client,rows,[]).call('failed','POST',f'auth/{f.MOUNT}/login',creds,
                token='',source='127.0.0.2',spoof=True,wrap_ttl='30s',status=status)
            self.assertEqual(client.calls,[(('POST',f'auth/{f.MOUNT}/login',creds),
                {'token':'','source':'127.0.0.2','wrap_ttl':'30s','spoof':True})])
            for extra in ({'auth':{'client_token':'private'}},{'wrap_info':{'token':'private'}},
                          {'data':{'secret_id':'private'}},{'errors':[]}):
                client=Client(status,{'errors':['denied'],**extra})
                with self.assertRaises(f.ScenarioFailure):
                    f.Trace(client,[],[]).call('bad','POST',f'auth/{f.MOUNT}/login',creds,status=status,wrap_ttl='30s')
                self.assertEqual(len(client.calls),1)

    def test_disabled_alias_refresh_rejects_old_unchanged_metadata_and_preserves_custom_binding(self):
        for kind in f.KINDS:
            original={'id':'synthetic-alias','name':'synthetic-role-id','canonical_id':'synthetic-entity',
                'mount_accessor':'synthetic-mount','metadata':f.metadata('one',kind),
                'custom_metadata':dict(f.CUSTOM),'last_update_time':'same-second'}
            valid={**original,'metadata':f.metadata('two',kind)}
            class Client:
                last_family=4
                def __init__(self,data):self.data,self.calls=data,[]
                def request(self,*args,**kwargs):
                    self.calls.append((args,kwargs))
                    return SimpleNamespace(status=200,body={'data':self.data})
            client=Client(valid); rows=[]
            observed=f.Trace(client,rows,[]).disabled_alias_refresh('disabled_alias',original,kind)
            self.assertEqual(observed,valid)
            self.assertEqual(len(client.calls),1)
            self.assertEqual(client.calls[0][0],('GET','identity/entity-alias/id/synthetic-alias',None))
            self.assertTrue(all(row['passed'] for row in rows))
            for invalid in (original,{**valid,'metadata':f.metadata('two')},
                {**valid,'custom_metadata':{}},{**valid,'canonical_id':'other'},
                {**valid,'mount_accessor':'other'},{**valid,'name':'other'}):
                client=Client(invalid)
                with self.assertRaises(f.ScenarioFailure):
                    f.Trace(client,[],[]).disabled_alias_refresh('disabled_alias',original,kind)
                self.assertEqual(len(client.calls),1)

    def test_service_renewals_keep_first_metadata_and_batch_never_calls_accessor_route(self):
        calls=[];checks=[]
        class Trace:
            def check(self,name,ok):
                checks.append((name,ok))
                if not ok: raise f.ScenarioFailure(name)
            def call(self,name,method,path,body,**kwargs):
                calls.append((name,path,body,kwargs))
                auth={'metadata':f.metadata('one','service')}
                if not path.endswith('renew-accessor'):auth['client_token']='synthetic-private-token'
                return {'auth':auth}
        service={'client_token':'synthetic-private-token','accessor':'synthetic-private-accessor'}
        f.renew_one(Trace(),'test','service',service)
        self.assertEqual([c[1] for c in calls],['auth/token/renew-self','auth/token/renew','auth/token/renew-accessor'])
        calls.clear();checks.clear()
        f.renew_one(Trace(),'test','batch',{'client_token':'synthetic-private-batch','accessor':''})
        self.assertEqual([c[1] for c in calls],['auth/token/renew-self','auth/token/renew'])
        self.assertTrue(all(c[3]['status']==400 for c in calls))
        self.assertEqual(calls[0][3]['token'],'synthetic-private-batch')
        self.assertEqual(checks,[('test_batch_no_accessor_route',True)])
        with self.assertRaises(f.ScenarioFailure): f.renew_one(Trace(),'bad','batch',service)

    def test_immutable_token_snapshot_rejects_new_alias_metadata_or_wrong_issuer(self):
        for kind in f.KINDS:
            auth={'client_token':'private','entity_id':'synthetic-entity','accessor':'private-accessor' if kind=='service' else ''}
            data={'id':auth['client_token'],'entity_id':auth['entity_id'],'type':kind,'meta':f.metadata('one',kind),
                'ttl':100,'renewable':kind=='service','accessor':auth['accessor']}
            self.assertTrue(f.lookup_matches(data,auth,kind,'one'))
            for bad in ({'meta':f.metadata('two',kind)},{'meta':f.metadata('one')},{'ttl':True},
                        {'entity_id':'other'},{'id':'root-substitute'},{'renewable':kind!='service'}):
                self.assertFalse(f.lookup_matches({**data,**bad},auth,kind,'one'))
        cluster=SimpleNamespace(nodes=[SimpleNamespace(node_id=i) for i in (1,2,2)])
        with self.assertRaises(f.ScenarioFailure): f.verify_voters(cluster,lambda _:self.fail('must not request'),{},'snapshot')
        cluster.nodes[-1].node_id=3
        with self.assertRaises(f.ScenarioFailure): f.verify_voters(cluster,lambda _:self.fail('must not request'),{},'snapshot')

    def test_snapshot_wait_only_waits_pending_not_corruption_and_keeps_required_frontier(self):
        node=SimpleNamespace(root=Path('/synthetic-private/node3'))
        with patch.object(f,'inspect_record_bundle',side_effect=[f.SnapshotPending(),{'snapshot_index':40}]) as inspect, \
             patch.object(f.time,'sleep'),patch.object(f.time,'monotonic',side_effect=[0,1]):
            self.assertEqual(f.wait_snapshot(node,40),{'snapshot_index':40})
            self.assertEqual(inspect.call_count,2)
            self.assertTrue(all(c.kwargs=={'minimum_index':40} for c in inspect.call_args_list))
        with patch.object(f,'inspect_record_bundle',side_effect=ValueError('bad_checksum')) as inspect:
            with self.assertRaises(ValueError): f.wait_snapshot(node,40)
            self.assertEqual(inspect.call_count,1)
        with patch.object(f,'inspect_record_bundle',side_effect=f.SnapshotPending()), \
             patch.object(f.time,'monotonic',side_effect=[0,16]):
            with self.assertRaises(f.ScenarioFailure): f.wait_snapshot(node,40)

    def test_completion_needs_real_named_phases_not_an_arbitrary_total(self):
        rows=[{'case':c,'passed':True} for c in sorted(f.REQUIRED-{'complete'})]+[{'case':'complete','passed':True}]
        self.assertTrue(f.complete(rows))
        for name in f.REQUIRED:self.assertFalse(f.complete([r for r in rows if r['case']!=name]),name)
        for bad in (rows+rows[:1],rows[:-1]+[{'case':'complete','passed':1}],
                    rows[:-1]+[{'case':'exception','passed':False}]+rows[-1:]):self.assertFalse(f.complete(bad))
        self.assertTrue(f.complete(rows[:-1]+[{'case':'additional','passed':True}]+rows[-1:]))

    def test_bootstrap_failure_closes_owned_cluster_and_report_scanner_covers_binary_key(self):
        closed=[]
        class Cluster:
            def __init__(self,*args):pass
            def bootstrap(self):raise f.ScenarioFailure('bootstrap_failed')
            def close(self):closed.append(True)
        with patch.object(f,'SaveCluster',Cluster),self.assertRaises(f.ScenarioFailure):
            f.run(Path('/unused'),Path('/unused'),[],[],{},[])
        self.assertEqual(closed,[True])
        self.assertFalse(f.report_secret_free({'raw':'synthetic-private-bearer'},['synthetic-private-bearer']))
        self.assertFalse(f.report_secret_free({'raw':'synthetic-binary-key'},[b'synthetic-binary-key']))
        self.assertEqual(f.helpers()['official_metadata_calibration'],f.CALIBRATION_SHA)


if __name__=='__main__':unittest.main()
