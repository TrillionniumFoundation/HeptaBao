import copy
import unittest
import ldap_no_default_upgrade as fixture
class LdapNoDefaultMigrationTests(unittest.TestCase):
    def test_old_receipt_must_bind_successful_clean_real_ldap_binary(self):
        receipt={'status':'passed','source_and_binary_unchanged':True,'cases_match':True,'build_source_commit':fixture.LEGACY_SOURCE,'source_identity':{'source_commit':fixture.LEGACY_HARNESS,'source_dirty':False,'binary_sha256':fixture.LEGACY_SHA256}}
        fixture.admit_legacy_receipt(fixture.LEGACY_SHA256,receipt)
        for field in ['build_source_commit','status','cases_match','source_and_binary_unchanged']:
            changed=copy.deepcopy(receipt);changed[field]=None
            with self.assertRaises(ValueError):fixture.admit_legacy_receipt(fixture.LEGACY_SHA256,changed)
        changed=copy.deepcopy(receipt);changed['source_identity']['source_dirty']=True
        with self.assertRaises(ValueError):fixture.admit_legacy_receipt(fixture.LEGACY_SHA256,changed)
    def test_actual_old_normalized_and_new_nil_behaviors_both_required(self):
        names=sorted(fixture.MILESTONES-{'upgrade.complete'})+['upgrade.complete']
        rows=[{'case':'ldap_no_default.'+n,'passed':True} for n in names]
        self.assertTrue(fixture.complete_scenarios(rows))
        for required in ['upgrade.old_profile.normalized_renew.renew.empty_policies','upgrade.new_profile.nil_renew.renew','upgrade.current.pure_reads_unchanged','upgrade.downgrade.no_application_change','upgrade.recover.empty_presence.renew.empty_policies']:
            self.assertFalse(fixture.complete_scenarios([r for r in rows if r['case']!='ldap_no_default.'+required]))
        self.assertFalse(fixture.complete_scenarios(rows+[rows[-1]]))
if __name__=='__main__':unittest.main()
