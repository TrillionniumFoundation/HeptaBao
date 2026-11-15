import copy
import unittest
from online_evidence import complete_checks
import userpass_names_upgrade as fixture
import userpass_no_default_live as legacy

class UpgradeGuards(unittest.TestCase):
    def test_early_failure_never_claims_old_reader_execution(self):
        self.assertFalse(fixture.old_reader_observed([]))
        self.assertFalse(fixture.old_reader_observed([{"case":"legacy_unseal_status","passed":True}]))
        for result in [True,False]:
            self.assertTrue(fixture.old_reader_observed([{"case":"downgrade_unseal_status","passed":result}]))

    def receipt(self):
        rows=[{'case':legacy.PREFIX+n,'passed':True} for n in sorted(legacy.REQUIRED-{'complete'})]
        rows.append({'case':legacy.PREFIX+'complete','passed':True})
        before={'source_dirty':False,'source_commit':'a'*40,'binary_sha256':'b'*64}
        return {'schema':'heptabao.userpass-no-default-comparison.v1','status':'passed','oracle_only':False,
            'build_source_commit':'c'*40,'candidate_source':before,'candidate_source_after':dict(before),
            'cases_match':True,'source_and_binary_unchanged':True,'runner_unchanged':True,'oracle_binary_unchanged':True,
            'cases':{'oracle':rows,'candidate':copy.deepcopy(rows)},'failures':{}}
    def test_qualified_old_binary_receipt_is_bound_to_explicit_build_and_digest(self):
        receipt=self.receipt();fixture.admit_legacy_receipt('b'*64,'c'*40,receipt)
        for sha,source in [('d'*64,'c'*40),('b'*64,'d'*40)]:
            with self.assertRaises(ValueError):fixture.admit_legacy_receipt(sha,source,receipt)
        for field,value in [('oracle_only',True),('status','failed'),('cases_match',False),('runner_unchanged',False)]:
            bad=copy.deepcopy(receipt);bad[field]=value
            with self.assertRaises(ValueError):fixture.admit_legacy_receipt('b'*64,'c'*40,bad)
    def test_old_receipt_must_have_real_complete_profile_not_arbitrary_success_rows(self):
        for change in ['missing','fake','dirty','after']:
            bad=self.receipt()
            if change=='missing':bad['cases']['candidate'].pop(0)
            if change=='fake':bad['cases']={side:[{'case':'case_187','passed':True}] for side in ('oracle','candidate')}
            if change=='dirty':bad['candidate_source']['source_dirty']=True
            if change=='after':bad['candidate_source_after']['source_commit']='e'*40
            with self.assertRaises(ValueError):fixture.admit_legacy_receipt('b'*64,'c'*40,bad)
    def test_upgrade_requires_real_read_reopen_issued_provenance_and_downgrade_milestones(self):
        rows=[{'case':n,'passed':True} for n in sorted(fixture.REQUIRED-{'complete'})]+[{'case':'complete','passed':True}]
        self.assertTrue(complete_checks(rows,required_cases=fixture.REQUIRED))
        self.assertTrue(complete_checks(rows[:-1]+[{'case':'extra','passed':True}]+rows[-1:],required_cases=fixture.REQUIRED))
        for index in range(len(rows)):
            self.assertFalse(complete_checks(rows[:index]+rows[index+1:],required_cases=fixture.REQUIRED))
    def test_receipt_trace_rejects_sensitive_names_and_only_records_booleans(self):
        trace=object.__new__(fixture.Trace);trace.rows=[]
        with self.assertRaises(ValueError):trace.check('password/secret',True)
        self.assertEqual(trace.rows,[])
        trace.check('metadata_match',True)
        self.assertEqual(trace.rows,[{'case':'metadata_match','passed':True}])

if __name__=='__main__':unittest.main()
