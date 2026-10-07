import copy
from pathlib import Path
import unittest
from unittest.mock import patch
import ldap_cidrs_upgrade as fixture

class LegacyLdapCidrAdmissionTests(unittest.TestCase):
    def receipt(self):
        return {'status':'passed','source_and_binary_unchanged':True,'cases_match':True,'build_source_commit':fixture.LEGACY_SOURCE,'source_identity':{'source_commit':'f'*40,'source_dirty':False,'binary_sha256':fixture.LEGACY_SHA256}}
    def test_missing_receipt_pin_cannot_admit_an_upgrade(self):
        with patch.object(fixture,'LEGACY_RECEIPT',None):
            with self.assertRaises(ValueError):fixture.admit_legacy_receipt(fixture.LEGACY_SHA256,self.receipt())
    def test_receipt_must_bind_old_binary_production_and_clean_harness(self):
        with patch.object(fixture,'LEGACY_HARNESS','f'*40),patch.object(fixture,'LEGACY_RECEIPT',Path('synthetic-receipt')):
            receipt=self.receipt();fixture.admit_legacy_receipt(fixture.LEGACY_SHA256,receipt)
            for field,value in [('build_source_commit','f'*40),('cases_match',False),('source_and_binary_unchanged',False)]:
                changed=copy.deepcopy(receipt);changed[field]=value
                with self.assertRaises(ValueError):fixture.admit_legacy_receipt(fixture.LEGACY_SHA256,changed)
            for field,value in [('source_commit',fixture.LEGACY_SOURCE),('source_dirty',True),('binary_sha256','0'*64)]:
                changed=copy.deepcopy(receipt);changed['source_identity'][field]=value
                with self.assertRaises(ValueError):fixture.admit_legacy_receipt(fixture.LEGACY_SHA256,changed)
    def test_upgrade_requires_old_pure_read_downgrade_and_recovered_constraint(self):
        names=sorted(fixture.MILESTONES-{'upgrade.complete'})+['upgrade.complete']
        rows=[{'case':'ldap_cidrs.'+n,'passed':True} for n in names]
        self.assertTrue(fixture.complete_scenarios(rows))
        for required in ['upgrade.downgrade.no_application_change','upgrade.recover.rejected','upgrade.current.pure_reads_unchanged']:
            self.assertFalse(fixture.complete_scenarios([r for r in rows if r['case']!='ldap_cidrs.'+required]))
if __name__=='__main__':unittest.main()
