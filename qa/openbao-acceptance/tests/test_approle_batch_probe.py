from types import SimpleNamespace
import json,unittest
import approle_batch_probe as probe

class ProbeGuards(unittest.TestCase):
 def test_all_mode_combinations_and_distinct_boundaries_are_named(self):
  names=probe.SCENARIOS
  self.assertEqual(len(names),len(set(names)))
  for mode in probe.MODES:
   for role in probe.ROLE_TYPES:self.assertIn('matrix.'+mode.replace('-','_')+'.'+role,names)
  for name in ('explicit.period','forced.period','secret.two_uses','identity.disabled_secret_use','batch.restart'):self.assertIn(name,names)
 def test_projection_never_exports_credentials_metadata_or_error_bodies(self):
  secret='private-credential'
  response=SimpleNamespace(status=200,body={'auth':{'client_token':secret,'accessor':secret,'token_type':'batch','metadata':{'role_name':'known','extra':secret},'lease_duration':17},'data':{'secret_id':secret,'role_id':secret},'errors':[secret]})
  trace=probe.Trace(SimpleNamespace(request=lambda *a,**k:response))
  trace.call('matrix.batch.batch','login','POST','auth/probe/login',role='known')
  self.assertNotIn(secret,json.dumps(trace.rows));self.assertIn(secret,trace.sensitive)
  self.assertTrue(trace.rows[0]['role_metadata']);self.assertTrue(trace.rows[0]['lease_le_20'])
 def test_repeated_observation_and_unknown_completed_scenario_rejected(self):
  trace=probe.Trace(SimpleNamespace(request=lambda *a,**k:SimpleNamespace(status=204,body={})))
  trace.call('setup','role','POST','ignored')
  with self.assertRaises(ValueError):trace.call('setup','role','POST','ignored')
  with self.assertRaises(ValueError):trace.finish('invented')
  trace.finish('batch.restart')
  with self.assertRaises(ValueError):trace.finish('batch.restart')
if __name__=='__main__':unittest.main()
