"""Guard real schema23 provenance, PAP observations and atomic upgrade receipts."""
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from bao_http import Response
from core_isolation import ScenarioFailure
from radius_config_native_upgrade import LEGACY_SHA256,LEGACY_SOURCE,Trace,admit_legacy,complete_scenarios,MILESTONES
class Provider:
    def count(self):return 0
    def observed(self,cursor,*,accepted):return False
class Client:
    def request(self,*args,**kwargs):return Response(200,{'auth':{'client_token':'private-token'},'data':{'secret':'private-secret'},'errors':['private-error']})
class RadiusConfigUpgradeTests(unittest.TestCase):
    def receipt(self):
        return {'build_source_commit':LEGACY_SOURCE,'harness_source_commit':LEGACY_SOURCE,'harness_source_dirty':False,'harness_source_unchanged':True,'binaries_unchanged':True,'candidate_binary_sha256':LEGACY_SHA256,'status':'passed'}
    def test_pinned_legacy_requires_exact_clean_build_receipt(self):
        for key,value in [('build_source_commit','other'),('harness_source_commit','other'),('harness_source_dirty',True),('harness_source_unchanged',False),('binaries_unchanged',False),('candidate_binary_sha256','0'*64),('status','failed')]:
            with self.assertRaises(ValueError):admit_legacy(Path('new'),Path('old'),LEGACY_SHA256,dict(self.receipt(),**{key:value}))
        with self.assertRaises(ValueError):admit_legacy(Path('new'),Path('old'),'0'*64,self.receipt())
        with patch('radius_config_native_upgrade.validate_binary_pins',return_value=('new','old')) as pins:
            self.assertEqual(admit_legacy(Path('new'),Path('old'),LEGACY_SHA256,self.receipt()),('new','old'));pins.assert_called_once_with(Path('new'),Path('old'),LEGACY_SHA256)
    def test_wrong_status_never_reflects_secrets(self):
        rows=[]
        with self.assertRaisesRegex(ScenarioFailure,'^radius_config_native_upgrade.downgrade$'):
            Trace(Client(),rows,Provider()).call('downgrade','sys/unseal',{'key':'private'},expected=503)
        self.assertEqual(rows,[{'case':'radius_config_native_upgrade.downgrade','status':200,'passed':False}]);self.assertNotIn('private',json.dumps(rows))
    def test_cached_http_success_cannot_hide_missing_pap(self):
        rows=[]
        with self.assertRaises(ScenarioFailure):Trace(Client(),rows,Provider()).call('renew','auth/token/renew-self',provider=True)
        self.assertIs(rows[-1]['provider_checked'],False);self.assertNotIn('private',json.dumps(rows))
    def test_failed_store_invariant_aborts(self):
        rows=[];trace=Trace(Client(),rows,Provider());trace.check('ready',True)
        with self.assertRaises(ScenarioFailure):trace.check('application_unchanged',False)
        self.assertFalse(rows[-1]['passed'])
    def test_completion_needs_every_independent_milestone(self):
        rows=[{'case':'radius_config_native_upgrade.'+name,'passed':True} for name in sorted(MILESTONES-{'complete'})+['complete']]
        self.assertTrue(complete_scenarios(rows))
        for i in range(len(rows)):self.assertFalse(complete_scenarios(rows[:i]+rows[i+1:]))
        self.assertFalse(complete_scenarios(rows+[rows[-1]]));self.assertFalse(complete_scenarios([dict(rows[0],passed=False)]+rows[1:]))
if __name__=='__main__':unittest.main()
