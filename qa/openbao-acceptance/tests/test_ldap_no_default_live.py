import unittest
from unittest.mock import Mock,patch
import ldap_no_default_live as fixture
class LdapNoDefaultEvidenceTests(unittest.TestCase):
    def valid_rows(self):
        status={'nil.renew.token':500,'nil.old_after_empty.token':200,'null.renew.accessor':200,'group_empty.renew.token':500,'toggle.changed_renew.accessor':500,'wrap.unwrap':200,'wrap.single_use':400,'restart.old_zero_nil.token':500,'restart.old_zero_explicit.token':200}
        return [{'case':name,'status':status.get(name,200)} for name in sorted(fixture.MILESTONES-{'complete'})]+[{'case':'complete','completed':True}]
    def test_actual_nil_empty_restart_and_wrapper_milestones_are_required(self):
        rows=self.valid_rows();self.assertTrue(fixture.complete(rows))
        for name in ['nil.renew.token','nil.old_after_empty.token','restart.old_zero_nil.token','wrap.single_use']:
            self.assertFalse(fixture.complete([r for r in rows if r['case']!=name]))
            changed=[dict(r,status=200) if r['case']==name else r for r in rows]
            if name!='nil.old_after_empty.token':self.assertFalse(fixture.complete(changed))
        self.assertFalse(fixture.complete(rows+[rows[-1]]))
    def test_empty_token_policy_field_presence_remains_observable(self):
        client=Mock();directory=Mock();directory.cursor.return_value=0;directory.observed.return_value=True
        rows=[]
        with patch.object(fixture,'provider_idle',return_value=False):
            for auth in [{'policies':[]},{'policies':[],'token_policies':[]}]:
                client.request.return_value=Mock(status=200,body={'auth':auth})
                fixture.Probe(client,directory,{},rows).call('test','auth/ldap/login/alice')
        self.assertNotEqual(rows[0]['has_token_policies'],rows[1]['has_token_policies'])
    def test_private_values_cannot_be_policy_observations(self):
        with self.assertRaises(ValueError):fixture.safe_policy_set(['private-token'])
if __name__=='__main__':unittest.main()
