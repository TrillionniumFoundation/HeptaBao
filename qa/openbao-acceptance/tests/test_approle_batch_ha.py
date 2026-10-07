import hashlib
from types import SimpleNamespace
import unittest
import approle_batch_ha as f

class AppRoleBatchHaGuards(unittest.TestCase):
    def test_named_milestones_require_consume_failover_restart_and_no_secret_leak(self):
        rows=[{'case':n,'passed':True} for n in sorted(f.REQUIRED-{'complete'})]+[{'case':'complete','passed':True}]
        self.assertTrue(f.complete(rows))
        for name in f.REQUIRED:
            self.assertFalse(f.complete([r for r in rows if r['case']!=name]),name)
        for bad in (rows+rows[-1:],rows[:-1]+[{'case':'complete','passed':1}],
                    rows[:-1]+[{'case':'complete','passed':True,'secret_id':'sentinel'}]):
            self.assertFalse(f.complete(bad))
        self.assertTrue(f.complete(rows[:-1]+[{'case':'new_real_observation','passed':True}]+rows[-1:]))

    def test_exhaustion_is_not_transport_failure_or_credential_bearing_denial(self):
        self.assertTrue(f.secret_state(200,{'data':{'secret_id_num_uses':1}},1))
        self.assertFalse(f.secret_state(200,{'data':{'secret_id_num_uses':True}},1))
        self.assertTrue(f.secret_state(204,{},0))
        self.assertFalse(f.secret_state(200,{},0))
        self.assertFalse(f.secret_state(204,{'data':{'secret_id':'sentinel'}},0))
        self.assertTrue(f.rejected_secret(400,{'errors':['invalid credentials']}))
        for status in (200,403,404,500,503):
            self.assertFalse(f.rejected_secret(status,{'errors':['invalid credentials']}))
        self.assertFalse(f.rejected_secret(400,{'errors':['denied'],'auth':{'client_token':'sentinel'}}))

    def fixture(self,phase,corrupt=False):
        calls=[];rows=[];data={'value':'synthetic'};digest=hashlib.sha256(f.canonical(data)).hexdigest()
        class Node:
            def __init__(self,n):self.node_id=n
            def call(self,method,path,body=None,*,token):
                calls.append((self.node_id,method,path))
                if path==f.ROLE+'/secret-id/lookup':
                    return (200,{'data':{'secret_id_num_uses':1}}) if phase=='issued' else (204,{})
                if path==f.LOGIN:return 400,{'errors':['invalid credentials']}
                if phase=='disabled':return 403,{'errors':['permission denied']}
                if path==f.PATH:return 200,{'data':{'value':'wrong'} if corrupt and self.node_id==2 else data}
                if path=='auth/token/lookup-self':return 200,{'data':{'id':'hvb.synthetic','type':'batch','accessor':'','renewable':False,'ttl':500,'entity_id':'entity'}}
                raise AssertionError('unexpected request')
        def check(case,passed):
            rows.append({'case':case,'passed':passed})
            if not passed:raise f.FixtureError(case)
        cluster=SimpleNamespace(nodes=[Node(n) for n in (1,2,3)],root_token='hvs.root')
        return cluster,digest,check,calls,rows

    def test_public_verifier_checks_each_voter_and_exactly_one_exhausted_login_per_phase(self):
        for phase in f.PHASES:
            cluster,digest,check,calls,rows=self.fixture(phase)
            f.verify_voters(cluster,'hvb.synthetic','entity',{'role_id':'role','secret_id':'synthetic'},digest,phase,check)
            for n in (1,2,3):
                for method,path in [('GET',f.PATH),('GET','auth/token/lookup-self'),('POST',f.ROLE+'/secret-id/lookup')]:
                    self.assertEqual(calls.count((n,method,path)),1)
                self.assertEqual(calls.count((n,'POST',f.LOGIN)),int(phase in ('successor','restarted')))
            self.assertEqual(rows[-1],{'case':phase+'_all_voters','passed':True})
            self.assertTrue({r['case'] for r in rows}.issubset(f.REQUIRED))

    def test_failed_voter_or_missing_voter_never_produces_complete_phase(self):
        cluster,digest,check,_,rows=self.fixture('restarted',True)
        with self.assertRaises(f.FixtureError):
            f.verify_voters(cluster,'hvb.synthetic','entity',{'secret_id':'synthetic'},digest,'restarted',check)
        self.assertNotIn({'case':'restarted_all_voters','passed':True},rows)
        cluster,digest,check,_,rows=self.fixture('restarted');cluster.nodes.pop()
        with self.assertRaises(f.FixtureError):
            f.verify_voters(cluster,'hvb.synthetic','entity',{'secret_id':'synthetic'},digest,'restarted',check)
        self.assertEqual(rows,[])

if __name__=='__main__':unittest.main()
