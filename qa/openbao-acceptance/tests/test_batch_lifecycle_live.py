import json
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import batch_lifecycle_contract as contract

class BatchLifecycleGuards(unittest.TestCase):
    def rows(self):
        return [{'case':name,'scope':contract.lane(name),'passed':True}
                for name in sorted(contract.REQUIRED-{'complete'})]+[
                    {'case':'complete','scope':'same','passed':True}]

    def test_business_milestones_and_terminal_success_are_required_not_fixed_count(self):
        rows=self.rows()
        self.assertTrue(contract.complete(rows))
        self.assertTrue(contract.complete(rows[:-1]+[{'case':'additional.success','scope':'same','passed':True}]+rows[-1:]))
        for index in range(len(rows)):
            self.assertFalse(contract.complete(rows[:index]+rows[index+1:]))
        self.assertFalse(contract.complete(rows+[rows[0]]))
        self.assertFalse(contract.complete([{'case':'padding.'+str(i),'scope':'same','passed':True} for i in range(600)]+rows[-1:]))

    def test_scope_failures_and_unbounded_or_secret_observations_cannot_pass(self):
        for field,value in [('passed',False),('passed',1),('scope','same'),('raw_token','private'),('status',True),('status',900),('source_family',5),('nonrenewable',1)]:
            rows=self.rows();index=next(i for i,r in enumerate(rows) if r['case'].startswith('cidr.'))
            rows[index][field]=value
            self.assertFalse(contract.complete(rows),(field,value))

    def test_secret_projection_captures_credentials_even_on_wrong_status(self):
        secret='sensitive-bearer';accessor='sensitive-accessor';otp='sensitive-otp'
        response=SimpleNamespace(status=200,body={'errors':['unsafe '+secret],
            'auth':{'client_token':secret,'accessor':accessor},'data':{'key':otp}})
        trace=contract.Trace(SimpleNamespace(request=lambda *a,**kw:response,last_family=4))
        with self.assertRaises(contract.ScenarioFailure):trace.call('expected_rejection','POST','ignored',status=400)
        for value in (secret,accessor,otp):
            self.assertIn(value,trace.sensitive);self.assertNotIn(value,json.dumps(trace.rows))

    def test_expiry_wait_retries_only_read_only_lookup_and_records_no_poll_count(self):
        calls=[];responses=iter([SimpleNamespace(status=200),SimpleNamespace(status=403)])
        def request(*args,**kw):calls.append(args);return next(responses)
        trace=contract.Trace(SimpleNamespace(request=request))
        with patch.object(contract.time,'sleep'):
            trace.wait_absent('parent.expired','auth/token/lookup',{'token':'sensitive'})
        self.assertEqual(calls,[('POST','auth/token/lookup',{'token':'sensitive'})]*2)
        self.assertEqual(trace.rows,[{'case':'parent.expired','scope':'same','passed':True,'status':403,'absence_observed':True}])
        with self.assertRaises(ValueError):trace.wait_absent('invalid','auth/token/revoke',{})
        self.assertEqual(len(calls),2)

    def test_lookup_wait_does_not_hide_unexpected_status(self):
        calls=[]
        def request(*args,**kw):calls.append(args);return SimpleNamespace(status=503)
        trace=contract.Trace(SimpleNamespace(request=request))
        with self.assertRaises(contract.ScenarioFailure):trace.wait_absent('lease.expired','sys/leases/lookup',{'lease_id':'public-locator'})
        self.assertEqual(len(calls),1)
        self.assertFalse(trace.rows[0]['passed'])

    def test_nonrenewable_otp_cap_checks_batch_window_not_parent_lifetime(self):
        response=SimpleNamespace(status=200,body={'lease_id':'public-lease','lease_duration':60,
            'renewable':False,'data':{'key':'sensitive-otp'}})
        trace=contract.Trace(SimpleNamespace(request=lambda *a,**kw:response,last_family=4))
        self.assertEqual(trace.otp('parent_expiry.child.held','private-batch',60),('public-lease','sensitive-otp'))
        self.assertTrue(trace.rows[-1]['ttl_matches_batch_window'])
        self.assertTrue(trace.rows[-1]['nonrenewable'])
        self.assertNotIn('sensitive-otp',json.dumps(trace.rows))
        response.body['lease_duration']=6
        with self.assertRaises(contract.ScenarioFailure):trace.otp('wrong_parent_clamp','private-batch',60)

if __name__=='__main__':unittest.main()
