import json
from types import SimpleNamespace
import unittest
from unittest.mock import Mock

import cert_native_ttl_probe as f


class CertNativeTtlProbeTests(unittest.TestCase):
    def test_create_accepts_only_empty_204_or_valid_warning_200(self):
        private_warning='synthetic-secret-warning-text'
        for status,body in ((204,{}),(200,{'warnings':[private_warning], 'auth':None,'data':None,'wrap_info':None})):
            client=Mock();client.request.return_value=SimpleNamespace(status=status,body=body)
            trace=f.Trace(client)
            self.assertEqual(f.create(trace,'new.role','private-certificate'),'new-role')
            self.assertEqual(client.request.call_count,1)
            self.assertEqual(trace.rows[-1]['warnings_present'],status==200)
            self.assertNotIn(private_warning,json.dumps(trace.rows))
            self.assertNotIn('private-certificate',json.dumps(trace.rows))

    def test_create_rejects_missing_malformed_warning_payload_and_http_failure(self):
        invalid=[(200,{}),(200,{'warnings':[]}),(200,{'warnings':'warning'}),
            (200,{'warnings':['']}),(200,{'warnings':['   ']}),(200,{'warnings':[1]}),
            (200,{'warnings':['valid',None]}),(400,{'warnings':['valid']}),
            (503,{'warnings':['valid']}),
            *[(200,{'warnings':['valid'],field:value}) for field,value in (
                ('auth',{'client_token':'private'}),('data',{'value':'private'}),
                ('wrap_info',{'token':'private'}),('errors',['private']))]]
        for status,body in invalid:
            with self.subTest(status=status,fields=sorted(body)):
                client=Mock();client.request.return_value=SimpleNamespace(status=status,body=body)
                trace=f.Trace(client)
                with self.assertRaises(f.ScenarioFailure):f.create(trace,'new.role','private-certificate')
                self.assertEqual(client.request.call_count,1)

    def test_projection_preserves_unexpected_status_without_secrets(self):
        secret='synthetic-private-do-not-publish-abcdef'
        client=Mock()
        client.request.return_value=SimpleNamespace(status=500,body={
            'errors':[secret], 'data':{'certificate':secret,'token_ttl':0,'ttl':7,'period':None},
            'auth':{'client_token':secret,'accessor':secret+'-accessor','lease_duration':3}})
        trace=f.Trace(client)
        status,_=trace.read('role.read','held')
        self.assertEqual(status,500)
        projection=trace.rows[-1]
        self.assertEqual(projection['token_ttl'],0)
        self.assertTrue(projection['ttl_present'] and projection['period_present'])
        self.assertNotIn('period',projection)
        self.assertNotIn(secret,json.dumps(trace.rows))
        self.assertIn(secret,trace.sensitive)

    def test_three_routes_use_same_leaf_client_exact_target_and_never_retry(self):
        client=Mock()
        client.request.side_effect=[SimpleNamespace(status=500,body={'errors':['denied']}) for _ in range(3)]
        trace=f.Trace(client)
        auth={'client_token':'target-bearer-long-enough','accessor':'target-accessor'}
        f.renew_three(trace,'renew',auth,300)
        self.assertIs(trace.client,client)
        calls=client.request.call_args_list
        self.assertEqual(len(calls),3)
        for call,route in zip(calls,('renew-self','renew','renew-accessor')):
            self.assertEqual(call.args[:2],('POST','/v1/auth/token/'+route))
        self.assertEqual(calls[0].args[2],{'increment':300})
        self.assertEqual(calls[0].kwargs['token'],auth['client_token'])
        self.assertEqual(calls[1].args[2],{'increment':300,'token':auth['client_token']})
        self.assertEqual(calls[2].args[2],{'increment':300,'accessor':auth['accessor']})
        self.assertTrue(all(row['status']==500 for row in trace.rows))
        self.assertNotIn(auth['client_token'],json.dumps(trace.rows))
        self.assertNotIn(auth['accessor'],json.dumps(trace.rows))

    def test_known_age_uses_only_readback_and_accounts_for_fractional_issue_second(self):
        trace=Mock()
        trace.lookup.return_value=(200,{'creation_time':100})
        wall=Mock(side_effect=[101.999,102.0])
        pause=Mock()
        f.known_age(trace,'age',{},wall=wall,mono=Mock(side_effect=[0,0.1]),pause=pause)
        self.assertEqual(trace.lookup.call_count,2)
        pause.assert_called_once_with(.05)
        trace.observe.assert_called_once_with('age.ready',known_issue_age_at_least_one_second=True,read_only_polls=2)
        trace.call.assert_not_called()
        trace.require.assert_not_called()

    def test_unobserved_age_or_failed_lookup_cannot_be_reported_ready(self):
        for result in ((200,{'creation_time':100}),(403,{}),(200,{'creation_time':True})):
            trace=Mock();trace.lookup.return_value=result
            with self.assertRaises(f.ScenarioFailure):
                f.known_age(trace,'age',{},wall=lambda:100,mono=Mock(side_effect=[0,4]),pause=Mock())
            trace.observe.assert_not_called()
            trace.call.assert_not_called()
            self.assertEqual(trace.lookup.call_count,1)

    def test_partial_validation_failure_is_observed_once_with_exact_readback(self):
        trace=Mock()
        before={'token_ttl':300,'token_max_ttl':600,'certificate':'synthetic-private-certificate'}
        trace.read.side_effect=[(200,before),(200,dict(before))]
        trace.call.return_value=(400,{'errors':['synthetic-private-error']})
        result=f.mutate_observe(trace,'partial','held',{'ttl':30,'token_max_ttl':60})
        self.assertEqual(result,400)
        self.assertEqual(trace.call.call_count,1)
        trace.observe.assert_called_once_with('partial.effect',status=400,role_exactly_unchanged=True)

    def test_complete_requires_every_named_phase_and_rejects_duplicates(self):
        trace=f.Trace(Mock())
        self.assertEqual(len(f.SCENARIOS),14)
        for case in sorted(f.SCENARIOS):
            trace.observe(case+'.observed',status=500)
            trace.finish(case)
        # Observation completeness is intentionally distinct from parity/pass.
        self.assertTrue(f.complete(trace))
        with self.assertRaises(ValueError):trace.finish(trace.finished[0])
        with self.assertRaises(ValueError):trace.observe(trace.rows[0]['case'],status=200)
        trace.finished.pop()
        self.assertFalse(f.complete(trace))


if __name__=='__main__':unittest.main()
