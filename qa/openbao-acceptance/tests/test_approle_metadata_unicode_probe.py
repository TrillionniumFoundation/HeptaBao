import copy,json,unittest,hashlib
from pathlib import Path
import approle_metadata_unicode_probe as f
class UnicodeProbeTests(unittest.TestCase):
 def test_inputs_are_outer_json_safe_but_preserve_inner_surrogates_and_bytes(self):
  cases=dict(f.INPUTS)
  self.assertEqual(cases['json_lone_high'],r'{"env":"\ud800"}')
  self.assertEqual(cases['csv_literal'],r'env=\ud800')
  for value in cases.values():self.assertEqual(json.loads(json.dumps({'metadata':value}))['metadata'],value)
  self.assertEqual(f.base64.b64decode(cases['base64_invalid_json_string']),b'{"env":"\xff"}')
  self.assertEqual(f.base64.b64decode(cases['base64_invalid_before_json']),b'\xff{"env":"good"}')
 def test_named_completeness_rejects_missing_duplicate_and_no_observations(self):
  trace=f.Trace(None);trace.rows=[{'case':'safe'}];trace.finished=list(f.SCENARIOS)
  self.assertTrue(f.complete(trace))
  trace.finished.pop();self.assertFalse(f.complete(trace))
  trace.finished=list(f.SCENARIOS);trace.rows.append({'case':'safe'});self.assertFalse(f.complete(trace))
  trace.rows=[];self.assertFalse(f.complete(trace))
 def test_unicode_projection_hashes_values_without_exposing_them(self):
  projected=f.contract.metadata_projection({'env':'\ufffd','\ufffdenv':'good'})
  self.assertNotIn('\ufffd',json.dumps(projected,ensure_ascii=False))
  self.assertIn('sha256',projected['value']['env'])
  self.assertTrue(any(key.startswith('key_sha256_') for key in projected['value']))

 def test_original_official_receipt_preserves_exact_replacement_maps_and_rejections(self):
  receipt=Path(f.__file__).parent/'evidence/approle-metadata-unicode-official-9d079ca.json'
  self.assertEqual(hashlib.sha256(receipt.read_bytes()).hexdigest(),'44cc62f02af3be221cb7e08e3ddf23995eb7faf303e243e9f4d6b0ca66fe987d')
  value=json.loads(receipt.read_text());rows={row['case']:row for row in value['cases']}
  self.assertEqual(value['status'],'observed');self.assertIsNone(value['failure'])
  self.assertEqual(set(value['completed_scenarios']),f.SCENARIOS)
  for key in ('inputs_unchanged','secrets_absent','processes_stopped'):self.assertIs(value[key],True)
  self.assertEqual(value['runner_sha256'],hashlib.sha256(Path(f.__file__).read_bytes()).hexdigest())
  maps={
   'json_lone_high':{'env':'\ufffd'},'json_lone_low':{'env':'\ufffd'},
   'json_valid_pair':{'env':'😀'},'json_high_ascii':{'env':'\ufffdx'},
   'json_duplicate_good_last':{'env':'good'},'json_duplicate_high_last':{'env':'\ufffd'},
   'csv_literal':{'env':r'\ud800'},
   'base64_invalid_json_string':{'env':'\ufffd'},
   'base64_invalid_csv_key':{'\ufffdenv':'good'},
   'base64_invalid_csv_value':{'env':'\ufffd'},
  }
  for name,metadata in maps.items():
   prefix='parser.'+name
   self.assertEqual(rows[prefix+'.issue']['status'],200,name)
   for endpoint in ('raw','accessor'):
    self.assertEqual(rows[prefix+'.stored.'+endpoint]['data_metadata'],f.contract.metadata_projection(metadata),name)
   for endpoint in ('login','bearer','lookup'):self.assertEqual(rows[prefix+'.'+endpoint]['status'],200,name)
  for name in ('json_type_error','base64_invalid_before_json'):
   prefix='parser.'+name
   self.assertEqual(rows[prefix+'.issue']['status'],400,name)
   self.assertFalse(any(case.startswith(prefix+'.') and case!=prefix+'.issue' for case in rows))

if __name__=='__main__':unittest.main()
