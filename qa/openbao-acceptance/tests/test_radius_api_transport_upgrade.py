"""Upgrade evidence must bind old authority and preserve failed-operation evidence."""
import copy
import json
from pathlib import Path
import sys
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from radius_api_transport_upgrade import admit_legacy_receipt,LEGACY_SHA256,LEGACY_SOURCE,complete_scenarios,MILESTONES,Trace
from bao_http import Response
from core_isolation import ScenarioFailure

class UpgradeTests(unittest.TestCase):
    def test_legacy_receipt_rejects_dirty_wrong_or_unmatched_build(self):
        receipt={'status':'passed','source_and_binary_unchanged':True,'cases_match':True,
                 'source_identity':{'source_commit':LEGACY_SOURCE,'binary_sha256':LEGACY_SHA256,'source_dirty':False}}
        admit_legacy_receipt(LEGACY_SHA256,receipt)
        for field,value in [('status','failed'),('source_and_binary_unchanged',False),('cases_match',False)]:
            bad=copy.deepcopy(receipt);bad[field]=value
            with self.assertRaises(ValueError):admit_legacy_receipt(LEGACY_SHA256,bad)
        for field,value in [('source_commit','0'*40),('binary_sha256','0'*64),('source_dirty',True)]:
            bad=copy.deepcopy(receipt);bad['source_identity'][field]=value
            with self.assertRaises(ValueError):admit_legacy_receipt(LEGACY_SHA256,bad)
        with self.assertRaises(ValueError):admit_legacy_receipt('0'*64,receipt)
    def test_completion_requires_authority_migration_downgrade_and_child_isolation(self):
        rows=[{'case':'radius_api_transport_upgrade.'+n,'passed':True} for n in sorted(MILESTONES-{'complete'})+['complete']]
        self.assertTrue(complete_scenarios(rows))
        for i in range(len(rows)):self.assertFalse(complete_scenarios(rows[:i]+rows[i+1:]))
        self.assertFalse(complete_scenarios(rows+[rows[-1]]))
        self.assertFalse(complete_scenarios([dict(rows[0],passed=False)]+rows[1:]))
    def test_failed_provider_result_is_redacted_and_cannot_claim_authority(self):
        class Client:
            def request(self,*args,**kwargs):return Response(400,{'errors':['private-secret'],'auth':{'client_token':'private-token'}})
        class Provider:
            def count(self):return 0
            def observed(self,*args,**kwargs):return False
        rows=[];t=Trace(Client(),Provider(),rows)
        with self.assertRaises(ScenarioFailure):t.call('reject','POST','auth/radius/login',contact=True)
        self.assertFalse(rows[-1]['passed']);self.assertNotIn('private',json.dumps(rows))
        with self.assertRaises(ValueError):t.check('unsafe',True,password='private')

if __name__=='__main__':unittest.main()
