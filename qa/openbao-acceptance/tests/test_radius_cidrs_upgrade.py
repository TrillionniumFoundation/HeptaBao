import copy
import unittest
import radius_cidrs_upgrade as fixture

class LegacyAdmissionTests(unittest.TestCase):
    def receipt(self):
        return {'status':'passed','source_and_binary_unchanged':True,'cases_match':True,'build_source_commit':fixture.LEGACY_SOURCE,'source_identity':{'source_commit':fixture.LEGACY_HARNESS,'source_dirty':False,'binary_sha256':fixture.LEGACY_SHA256}}
    def test_distinct_clean_harness_and_production_are_both_pinned(self):
        receipt=self.receipt();fixture.admit_legacy_receipt(fixture.LEGACY_SHA256,receipt)
        for field,value in [('build_source_commit',fixture.LEGACY_HARNESS),('cases_match',False),('source_and_binary_unchanged',False)]:
            changed=copy.deepcopy(receipt);changed[field]=value
            with self.assertRaises(ValueError):fixture.admit_legacy_receipt(fixture.LEGACY_SHA256,changed)
        for field,value in [('source_commit',fixture.LEGACY_SOURCE),('source_dirty',True),('binary_sha256','0'*64)]:
            changed=copy.deepcopy(receipt);changed['source_identity'][field]=value
            with self.assertRaises(ValueError):fixture.admit_legacy_receipt(fixture.LEGACY_SHA256,changed)
    def test_upgrade_requires_downgrade_and_recovered_constraint(self):
        names=sorted(fixture.MILESTONES-{'upgrade.complete'})+['upgrade.complete']
        rows=[{'case':'radius_cidrs.'+n,'passed':True} for n in names]
        self.assertTrue(fixture.complete_scenarios(rows))
        for required in ['upgrade.downgrade.no_application_change','upgrade.recover.rejected','upgrade.current.pure_reads_unchanged']:
            self.assertFalse(fixture.complete_scenarios([r for r in rows if r['case']!='radius_cidrs.'+required]))
if __name__=='__main__':unittest.main()
