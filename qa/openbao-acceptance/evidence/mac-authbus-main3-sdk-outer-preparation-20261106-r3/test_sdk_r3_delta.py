"""Qualify only the observed rule correction and separate attempt bindings."""
import ast,base64,hashlib,json,unittest
from pathlib import Path
from unittest.mock import patch
WORK=Path(__file__).resolve().parent
OLD=WORK.parent/'main3-sdk-outer-r2-work'
ROOT=Path('/Volumes/T5/hepta-vnext-recovery-20261013/mac-authbus-main3-sdk-20261106-r3')
OLD_ROOT=str(ROOT).removesuffix('-r3')+'-r2'
LIVE=Path('/Users/qianqi/.openclaw')
def need(value,code):
 if not value:raise RuntimeError(code)
def sha(raw):return hashlib.sha256(raw).hexdigest()
def profile(path):
 nodes=[n for n in ast.parse(path.read_bytes()).body if isinstance(n,ast.FunctionDef) and n.name=='sandbox_profile']
 assert len(nodes)==1
 scope={'ROOT':ROOT,'STATE':ROOT/'state','LIVE':LIVE,'Path':Path,'json':json,'need':need}
 exec(compile(ast.Module(body=nodes,type_ignores=[]),str(path),'exec'),scope)
 return scope['sandbox_profile']
class Delta(unittest.TestCase):
 def test_seed_policy_bytes_unchanged_after_root_mapping(self):
  with patch.object(Path,'cwd',return_value=LIVE.parent):
   self.assertEqual(profile(OLD/'main3_sdk_phase.py')(seed=True),profile(WORK/'main3_sdk_phase.py')(seed=True))
 def test_exactly_one_actual_qualified_tcp_localhost_rule(self):
  with patch.object(Path,'cwd',return_value=LIVE.parent):
   for port in (1024,50090,65535):
    before=profile(OLD/'main3_sdk_phase.py')(port).decode()
    after=profile(WORK/'main3_sdk_phase.py')(port).decode()
    old='(allow network-outbound (remote ip '+json.dumps('127.0.0.1:'+str(port))+'))'
    new='(allow network-outbound (remote tcp '+json.dumps('localhost:'+str(port))+'))'
    self.assertEqual(before.count(old),1);self.assertEqual(after,before.replace(old,new))
    self.assertEqual(sum('network-outbound' in line for line in after.splitlines()),1)
 def test_unobserved_cwd_and_out_of_range_ports_still_refuse(self):
  fn=profile(WORK/'main3_sdk_phase.py')
  with patch.object(Path,'cwd',return_value=ROOT/'qa'):
   with self.assertRaisesRegex(RuntimeError,'sdk_original_account_home_cwd'):fn(50090)
  with patch.object(Path,'cwd',return_value=LIVE.parent):
   for value in (True,0,1023,65536,'50090'):
    with self.assertRaisesRegex(RuntimeError,'sdk_one_owned_listener'):fn(value)
 def test_worker_seed_plugin_and_wire_changes_are_scope_only(self):
  for name in ('main3_sdk_cycle_r2.mjs','main3_auth_rows_cas_r1.mjs','main3_authbus_cache_cas_r1.mjs','main3_sdk_seed_r1.mjs'):
   before=(OLD/'assets/qa'/name).read_bytes();after=(WORK/'assets/qa'/name).read_bytes()
   self.assertEqual(before.count(OLD_ROOT.encode()),1)
   self.assertEqual(after,before.replace(OLD_ROOT.encode(),str(ROOT).encode()))
  self.assertEqual((OLD/'assets/qa/main3_sdk_wire_r2.mjs').read_bytes(),(WORK/'assets/qa/main3_sdk_wire_r2.mjs').read_bytes())
  self.assertEqual(sha((WORK/'assets/qa/main3_sdk_wire_r2.mjs').read_bytes()),'2b06342e30703611729788a522ba764ae30adfe1e47c4f4673b7aa8f647170e2')
  for source in (OLD/'assets/plugin').iterdir():self.assertEqual(source.read_bytes(),(WORK/'assets/plugin'/source.name).read_bytes())
 def test_whole_prepared_package_pins_and_original_budgets(self):
  old=json.loads((OLD/'manifest-sdk-r2.public.json').read_bytes())
  new=json.loads((WORK/'manifest-sdk-r3.public.json').read_bytes())
  raw=(WORK/'staging-sdk-r3.public.json').read_bytes();bundle=json.loads(raw)
  self.assertEqual(new['staging'],{'bytes':len(raw),'sha256':sha(raw)})
  self.assertEqual(new['budgets'],old['budgets']);self.assertEqual(new['sdkWireMaximumSeconds'],15)
  self.assertEqual(new['seedMaximumSeconds'],10)
  self.assertEqual(new['canonicalProductCommit'],old['canonicalProductCommit'])
  self.assertEqual(new['canonicalBinarySha256'],old['canonicalBinarySha256'])
  for key,pins in (('sources','sourcePins'),('assets','assetPins')):
   self.assertEqual(set(bundle[key]),set(new[pins]))
   for name,text in bundle[key].items():
    self.assertEqual(new[pins][name],{'bytes':len(text.encode()),'sha256':sha(text.encode())})
  self.assertEqual(len(bundle['sources']),27);self.assertEqual(len(bundle['assets']),13)
  self.assertEqual(new['preparer'],{'bytes':len(bundle['preparerSource'].encode()),'sha256':sha(bundle['preparerSource'].encode())})
  self.assertFalse(new['kernelIpv4OnlyDestinationClaimed']);self.assertFalse(new['kernelLocalLanDeniedClaimed'])
  self.assertEqual(new['sandboxAuthorityJob'],'1a1b27ad919-fc05-7e36')
  self.assertEqual(new['sandboxAuthorityResultSha256'],'9f389465f8df39807c6718a93bf34d1384838e35f76d07bccb60c4008da4ab43')
 def test_explicit_new_operation_label_and_capture_payload(self):
  bundle=json.loads((WORK/'staging-sdk-r3.public.json').read_bytes())
  source=bundle['sources']['main3_inline_capture.py'];tree=ast.parse(source)
  values=[ast.literal_eval(n.value) for n in tree.body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='OPERATION_KEY' for t in n.targets)]
  self.assertEqual(values,['heptabao-mac-authbus-main3-sdk-inline-capture-20261106-r3'])
  pieces=''.join(ast.literal_eval(ast.parse(bundle['sources'][name]).body[0].value) for name in sorted(bundle['sources']) if name.startswith('main3_capture_payload_'))
  payload=base64.b64decode(pieces,validate=True)
  old_capture=b'heptabao-authbus-main3-sdk-inline-capsule-20261106-r2'
  self.assertNotIn(old_capture,payload)
  self.assertIn(b'heptabao-authbus-main3-sdk-inline-capsule-20261106-r3',payload)
  self.assertNotIn(OLD_ROOT,json.dumps(bundle))
if __name__=='__main__':unittest.main(verbosity=2)
