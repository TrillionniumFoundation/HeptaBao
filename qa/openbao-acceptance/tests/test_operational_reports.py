import copy
import importlib.util
from pathlib import Path
import sys
import unittest
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
import compare_operational_reports as comparison


class OperationalReportTests(unittest.TestCase):
    def pair(self):
        common={'schema':'heptabao.operational-process-evidence.v1','status':'passed','source_dirty':False,
                'synthetic_only':True,'independent_qualification':False,'production_authority':False,
                'source_commit':'a'*40,'source_tree':'b'*40,'candidate_binary_sha256':'c'*64,
                'runner_sha256':'d'*64,'client_distribution':'source'}
        candidate={**common,'target':'heptabao-candidate','cases':[{'case':n,'passed':True} for n in sorted(comparison.EXPECTED_COMMON|comparison.CANDIDATE_ONLY)]}
        oracle={**common,'target':'official-openbao-2.6.2','cases':[{'case':n,'passed':True} for n in sorted(comparison.EXPECTED_COMMON)],
                'oracle_identity':{'version':'2.6.2','binary_sha256':comparison.BINARY_SHA256,'artifact_sha256':comparison.ARTIFACT_SHA256,'tls_verified':True}}
        return candidate,oracle
    def test_fixed_complete_profile_matches_without_qualification(self):
        result=comparison.compare(*self.pair());self.assertTrue(result['matched']);self.assertFalse(result['full_openbao_compatibility'])
    def test_empty_duplicate_or_missing_cases_reject(self):
        for action in ['empty','duplicate','missing']:
            c,o=self.pair()
            if action=='empty':c['cases']=[];o['cases']=[]
            elif action=='duplicate':c['cases'][0]=c['cases'][1]
            else:o['cases'].pop()
            with self.subTest(action=action),self.assertRaises(ValueError):comparison.compare(c,o)
    def test_false_or_nonboolean_cases_never_match_even_when_both_same(self):
        for value in [False,1,'true',None]:
            c,o=self.pair();c['cases'][0]['passed']=value;o['cases'][0]['passed']=value
            with self.assertRaises(ValueError):comparison.compare(c,o)
    def test_source_dirty_and_pair_or_oracle_rebinding_reject(self):
        for key,value in [('source_dirty',True),('source_commit','e'*40),('candidate_binary_sha256','f'*64)]:
            c,o=self.pair();c[key]=value
            with self.assertRaises(ValueError):comparison.compare(c,o)
        c,o=self.pair();o['oracle_identity']['binary_sha256']='0'*64
        with self.assertRaises(ValueError):comparison.compare(c,o)
    def test_extra_case_cannot_change_the_fixed_denominator(self):
        c,o=self.pair();c['cases'].append({'case':'new-waiver','passed':True})
        with self.assertRaises(ValueError):comparison.compare(c,o)


if __name__=='__main__':unittest.main()
