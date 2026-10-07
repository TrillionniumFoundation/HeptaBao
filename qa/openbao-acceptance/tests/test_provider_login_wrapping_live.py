import unittest
from unittest.mock import Mock
import provider_login_wrapping_live as fixture

class EvidenceTests(unittest.TestCase):
    def test_three_provider_milestones_and_final_marker_are_required(self):
        names=sorted(fixture.MILESTONES-{'complete'})+['complete']
        rows=[{'case':'provider_login_wrapping.'+n,'passed':True} for n in names]
        self.assertTrue(fixture.complete(rows))
        for name in ['radius.wrapper_unbound','radius.denied_source_no_provider_or_publication','ldap.wrapped_survives_restart','kubernetes.inner']:
            self.assertFalse(fixture.complete([r for r in rows if r['case']!='provider_login_wrapping.'+name]))
        self.assertFalse(fixture.complete(rows+[rows[-1]]))
        rows[-1]['passed']=False;self.assertFalse(fixture.complete(rows))
    def test_trace_preserves_failed_status_without_response_secrets(self):
        client=Mock();client.request.return_value=Mock(status=403,body={'errors':['private provider response']})
        rows=[];trace=fixture.Trace(client,rows)
        with self.assertRaises(fixture.ScenarioFailure):trace.call('login','POST','auth/radius/login')
        self.assertEqual(rows,[{'case':'provider_login_wrapping.login','status':403,'passed':False}])
        with self.assertRaises(ValueError):trace.check('bad',True,token='private')
if __name__=='__main__':unittest.main()
