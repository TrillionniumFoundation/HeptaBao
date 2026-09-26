import unittest
from unittest.mock import Mock,patch
import ldap_cidrs_live as fixture

class LdapCidrEvidenceTests(unittest.TestCase):
    def test_missing_source_and_persisted_snapshot_milestones_are_required(self):
        names=sorted(fixture.MILESTONES-{'complete'})+['complete']
        rows=[{'case':'ldap_cidrs.'+name,'passed':True} for name in names]
        self.assertTrue(fixture.complete_scenarios(rows))
        for required in ['denied.login','actor_scope.accessor.shape','wrapped_login.token_denied_other_source','restart.old_renew.self.shape']:
            self.assertFalse(fixture.complete_scenarios([r for r in rows if r['case']!='ldap_cidrs.'+required]))
        self.assertFalse(fixture.complete_scenarios(rows+[rows[-1]]))
    def test_source_denial_must_precede_directory_protocol_io(self):
        client=Mock(last_family=4);client.request.return_value=Mock(status=403,body={'errors':['private response']})
        directory=Mock();directory.cursor.return_value=0;rows=[]
        with patch.object(fixture,'no_directory_requests',return_value=False):
            with self.assertRaises(fixture.ScenarioFailure):fixture.Trace(client,directory,{},rows).call('denied','POST','auth/ldap/login/alice',status=403)
        self.assertEqual(rows,[{'case':'ldap_cidrs.denied','status':403,'provider_contacted':True,'source_family':4,'passed':False}])
    def test_success_requires_real_bind_and_search_observation(self):
        client=Mock(last_family=4);client.request.return_value=Mock(status=200,body={})
        directory=Mock();directory.cursor.return_value=0;directory.observed.return_value=False
        with self.assertRaises(fixture.ScenarioFailure):fixture.Trace(client,directory,{},[]).call('login','POST','auth/ldap/login/alice',provider=True)
        directory.observed.assert_called_once_with(0,search=True)
if __name__=='__main__':unittest.main()
