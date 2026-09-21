import unittest
import sys_leader_live as fixture


class FakeLifecycle:
    address='https://127.0.0.1:8200'
    def __init__(self,ha):self.ha=ha;self.sealed=True;self.calls=[]
    def call(self,method,path='sys/leader',body=None,*,token='',headers=None):
        self.calls.append((method,path,token,headers))
        if path=='sys/leader':
            if method=='HEAD':return 405,{}
            if method!='GET':return 405,{'errors':[]}
            if not self.ha:return 200,{'ha_enabled':False}
            if self.sealed:return 503,{'errors':['Vault is sealed']}
            return 200,{'ha_enabled':True,'is_self':True,'leader_address':self.address,
                'raft_committed_index':10,'raft_applied_index':10}
        if path=='sys/init':return 200,{'root_token':'synthetic-root','keys_base64':['synthetic-share']}
        if path=='sys/unseal':self.sealed=False;return 200,{}
        if path=='sys/seal':self.sealed=True;return 204,{}
        if path=='sys/health':return 503 if self.sealed else 200,{}
        if path=='auth/token/create':return 200,{'auth':{'client_token':'synthetic-finite'}}
        if path=='auth/token/lookup':return 200,{'data':{'num_uses':2}}
        raise AssertionError('unexpected path')


class LeaderGuards(unittest.TestCase):
    def test_non_ha_exact_shape_including_sealed(self):
        self.assertTrue(fixture.shape(200,{'ha_enabled':False},ha=False,sealed=True))
        self.assertFalse(fixture.shape(200,{'ha_enabled':False,'is_self':True},ha=False))
        self.assertFalse(fixture.shape(503,{'errors':['server is sealed']},ha=False,sealed=True))

    def test_sealed_and_method_shapes_are_not_generic_unavailability(self):
        self.assertTrue(fixture.shape(503,{'errors':['Vault is sealed']},ha=True,sealed=True))
        self.assertFalse(fixture.shape(500,{'errors':['Vault is sealed']},ha=True,sealed=True))
        self.assertFalse(fixture.shape(503,{'errors':['forwarding unavailable']},ha=True,sealed=True))

    def test_standby_cannot_pass_forwarded_leader_shape_or_fabricated_indexes(self):
        body={'ha_enabled':True,'leader_address':'https://127.0.0.1:8200',
            'raft_committed_index':10,'raft_applied_index':9}
        self.assertTrue(fixture.shape(200,body,ha=True,is_self=False,address=body['leader_address']))
        self.assertFalse(fixture.shape(200,{**body,'is_self':True},ha=True,is_self=False))
        self.assertFalse(fixture.shape(200,{**body,'is_self':False},ha=True,is_self=False))
        self.assertFalse(fixture.shape(200,{**body,'raft_applied_index':11},ha=True))
        self.assertFalse(fixture.shape(200,{**body,'raft_committed_index':True},ha=True))
        self.assertFalse(fixture.shape(200,{**body,'auth':{'token':'sentinel'}},ha=True))

    def test_known_unsupported_fields_only_allowed_for_official_observation(self):
        body={'ha_enabled':True,'is_self':True,'active_time':'2026-01-01T00:00:00Z',
            'leader_cluster_address':'https://127.0.0.1:8201'}
        self.assertTrue(fixture.shape(200,body,ha=True,official=True))
        self.assertFalse(fixture.shape(200,body,ha=True))

    def test_actual_lifecycle_generates_unique_complete_phase_names_without_credentials_in_rows(self):
        rows=[];observations=[]
        def check(name,condition):
            self.assertIs(condition,True,name);rows.append({'case':name,'passed':condition})
        for name,ha in [('official_file',False),('official_raft',True)]:
            endpoint=FakeLifecycle(ha)
            fixture.lifecycle(endpoint,name,ha,check,observations)
            self.assertTrue(any(token=='' for method,path,token,headers in endpoint.calls if path=='sys/leader'))
            self.assertTrue(any(token=='synthetic-finite' for method,path,token,headers in endpoint.calls if path=='sys/leader'))
        rows.append({'case':'complete','passed':True})
        self.assertTrue(fixture.complete(rows,oracle_only=True))
        self.assertNotIn('synthetic-root',repr(observations))
        self.assertNotIn('synthetic-finite',repr(observations))
        self.assertFalse(fixture.complete(rows,oracle_only=False))
        self.assertFalse(fixture.complete([r for r in rows if r['case']!='official_raft_sealed'],oracle_only=True))
        self.assertFalse(fixture.complete(rows+[rows[-1]],oracle_only=True))
        self.assertFalse(fixture.complete([],oracle_only=True))

if __name__=='__main__':unittest.main()
