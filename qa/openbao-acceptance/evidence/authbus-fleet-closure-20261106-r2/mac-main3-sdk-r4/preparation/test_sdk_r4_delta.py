"""Source-bound delta gates for the new SDK r4 attempt; no remote action."""
import ast,base64,hashlib,json,unittest
from pathlib import Path
from unittest.mock import patch
WORK=Path(__file__).resolve().parent
OLD=WORK.parent/'main3-sdk-outer-r3-work'
OLD_BUNDLE=json.loads((OLD/'staging-sdk-r3.public.json').read_bytes())
NEW_BUNDLE=json.loads((WORK/'staging-sdk-r4.public.json').read_bytes())
OLD_MANIFEST=json.loads((OLD/'manifest-sdk-r3.public.json').read_bytes())
NEW_MANIFEST=json.loads((WORK/'manifest-sdk-r4.public.json').read_bytes())
OLD_ROOT='/Volumes/T5/hepta-vnext-recovery-20261013/mac-authbus-main3-sdk-20261106-r3'
NEW_ROOT=OLD_ROOT[:-1]+'4'
LIVE=Path('/Users/qianqi/.openclaw')
def sha(b):return hashlib.sha256(b).hexdigest()
def normalize(text):
 for stem in (
  'mac-authbus-main3-sdk-preparation-20261106-r',
  'mac-authbus-main3-sdk-journal-20261106-r','mac-authbus-main3-sdk-20261106-r',
  'main3-sdk-inline-capture-20261106-r','heptabao-authbus-main3-sdk-inline-capsule-20261106-r',
  'heptabao.mac-main3-sdk-preparation-terminal.r','heptabao.mac-main3-sdk-preparation.r',
  'heptabao.mac-main3-sdk-journal.r','heptabao.mac-main3-current-sdk-qualification.r',
  'heptabao.current-sdk-selected-capsule-inline-owned-observation.sdk-r',
  'heptabao.current-sdk-selected-capsule-readonly.sdk-r'):
  text=text.replace(stem+'4',stem+'3')
 return text.replace('main3_sdk_wire_r3.mjs','main3_sdk_wire_r2.mjs')
def mask(text,names):
 lines=text.splitlines(True)
 nodes=[n for n in ast.parse(text).body if isinstance(n,ast.Assign)
  and any(isinstance(t,ast.Name) and t.id in names for t in n.targets)]
 for node in reversed(nodes):
  target=next(t.id for t in node.targets if isinstance(t,ast.Name) and t.id in names)
  lines[node.lineno-1:node.end_lineno]=[target+'=<explicitly-validated-pin>\n']
 return ''.join(lines)
def payload(bundle):
 pieces=''.join(ast.literal_eval(ast.parse(bundle['sources'][n]).body[0].value)
  for n in sorted(bundle['sources']) if n.startswith('main3_capture_payload_'))
 return base64.b64decode(pieces,validate=True)
def profile(source):
 nodes=[n for n in ast.parse(source).body if isinstance(n,ast.FunctionDef) and n.name=='sandbox_profile']
 assert len(nodes)==1
 def need(v,c):
  if not v:raise ValueError(c)
 scope={'ROOT':Path(NEW_ROOT),'STATE':Path(NEW_ROOT)/'state','LIVE':LIVE,'Path':Path,'json':json,'need':need}
 exec(compile(ast.Module(body=nodes,type_ignores=[]),'<only-pinned-profile>','exec'),scope)
 return scope['sandbox_profile']

class SdkR4Delta(unittest.TestCase):
 def test_complete_package_and_product_budget_pins(self):
  self.assertEqual(sha((OLD/'staging-sdk-r3.public.json').read_bytes()),'8cb911179b5e53822e364c467f10bf13cc0a23da833ee21ae3a12e124417adee')
  raw=(WORK/'staging-sdk-r4.public.json').read_bytes()
  self.assertLessEqual(len(raw),1048576)
  self.assertEqual(NEW_MANIFEST['staging'],{'bytes':len(raw),'sha256':sha(raw)})
  for kind,pins in (('sources','sourcePins'),('assets','assetPins')):
   self.assertEqual(set(NEW_BUNDLE[kind]),set(NEW_MANIFEST[pins]))
   for name,text in NEW_BUNDLE[kind].items():
    self.assertEqual(NEW_MANIFEST[pins][name],{'bytes':len(text.encode()),'sha256':sha(text.encode())})
  self.assertEqual(len(NEW_BUNDLE['sources']),27);self.assertEqual(len(NEW_BUNDLE['assets']),13)
  self.assertEqual(NEW_MANIFEST['budgets'],{'outer':600,'phase':120,'sourceObservationMaximum':45,
   'wrapperReady':30,'execObservation':10,'health':15,'singleOtherHttp':10,'failureCleanup':60})
  self.assertEqual(NEW_MANIFEST['sdkWireMaximumSeconds'],15);self.assertEqual(NEW_MANIFEST['seedMaximumSeconds'],10)
  self.assertEqual(NEW_MANIFEST['canonicalProductCommit'],OLD_MANIFEST['canonicalProductCommit'])
  self.assertEqual(NEW_MANIFEST['canonicalBinarySha256'],OLD_MANIFEST['canonicalBinarySha256'])
 def test_ownership_and_api_code_unchanged_except_new_identity_and_asset_binding(self):
  source=NEW_BUNDLE['sources'];old=OLD_BUNDLE['sources']
  for name,text in source.items():
   if name.startswith('main3_capture_payload_'):continue
   names={'ASSET_PINS'} if name=='main3_sdk_public_pins.py' else set()
   if name=='main3_capture_launcher.py':names={'PAYLOAD_PART_PINS'}
   if name=='main3_inline_capture.py':names=set(NEW_MANIFEST['capturePins'])
   changed=normalize(mask(text,names))
   before=mask(old[name],names)
   if name=='main3_capture_launcher.py':
    changed=changed.replace(NEW_MANIFEST['capturePins']['CAPTURE_PAYLOAD_SHA'],OLD_MANIFEST['capturePins']['CAPTURE_PAYLOAD_SHA'])
   self.assertEqual(changed,before,name)
 def test_preparer_logic_unchanged_except_namespace_and_exact_pin_tables(self):
  old=mask(OLD_BUNDLE['preparerSource'],{'EXPECTED_PINS','EXPECTED_ASSETS'})
  new=normalize(mask(NEW_BUNDLE['preparerSource'],{'EXPECTED_PINS','EXPECTED_ASSETS'}))
  self.assertEqual(new,old)
  self.assertEqual(NEW_MANIFEST['preparer'],{'bytes':len(NEW_BUNDLE['preparerSource'].encode()),
   'sha256':sha(NEW_BUNDLE['preparerSource'].encode())})
 def test_capture_payload_preserves_all_original_non_scope_bytes(self):
  old=json.loads(payload(OLD_BUNDLE));new_raw=payload(NEW_BUNDLE);new=json.loads(new_raw)
  self.assertEqual(set(new),set(old))
  for name,value in new.items():self.assertEqual(normalize(value) if isinstance(value,str) else value,old[name],name)
  self.assertEqual(sha(new_raw),NEW_MANIFEST['capturePins']['CAPTURE_PAYLOAD_SHA'])
  self.assertEqual(sha(new['worker'].encode()),NEW_MANIFEST['capturePins']['CAPTURE_WORKER_SHA'])
  self.assertEqual(sha(new['registryChild'].encode()),NEW_MANIFEST['capturePins']['CAPTURE_REGISTRY_SHA'])
  self.assertEqual(sha(new['guard'].encode()),NEW_MANIFEST['capturePins']['CAPTURE_GUARD_SHA'])
 def test_plugins_and_cas_have_no_business_semantic_changes(self):
  old=OLD_BUNDLE['assets'];new=NEW_BUNDLE['assets']
  for name,text in new.items():
   if name.startswith('plugin/'):self.assertEqual(text,old[name])
   elif 'wire_r3' not in name:self.assertEqual(normalize(text),old[name],name)
  self.assertEqual(new['qa/main3_sdk_cycle_r2.mjs'].count('main3_sdk_wire_r3.mjs'),2)
  self.assertEqual(sha(new['qa/main3_sdk_wire_r3.mjs'].encode()),'e80c7eb22e2cd2fbc547eb085b8eb0b482e8e656baa8a59520e0cb93a4c0396c')
  self.assertNotIn('qa/main3_sdk_wire_r2.mjs',new)
 def test_sandbox_profile_is_byte_identical_after_fixture_root_binding(self):
  old=profile(OLD_BUNDLE['sources']['main3_sdk_phase.py'])
  new=profile(NEW_BUNDLE['sources']['main3_sdk_phase.py'])
  with patch.object(Path,'cwd',return_value=LIVE.parent):
   self.assertEqual(new(seed=True),old(seed=True))
   for port in (1024,51603,65535):self.assertEqual(new(port),old(port))
   for port in (True,0,1023,65536,'51603'):
    with self.assertRaisesRegex(ValueError,'sdk_one_owned_listener'):new(port)
  with patch.object(Path,'cwd',return_value=Path(NEW_ROOT)):
   with self.assertRaisesRegex(ValueError,'sdk_original_account_home_cwd'):new(51603)
 def test_new_inline_key_and_roots_are_explicit_not_reused(self):
  source=NEW_BUNDLE['sources']['main3_inline_capture.py']
  values=[ast.literal_eval(n.value) for n in ast.parse(source).body if isinstance(n,ast.Assign)
   and any(isinstance(t,ast.Name) and t.id=='OPERATION_KEY' for t in n.targets)]
  self.assertEqual(values,['heptabao-mac-authbus-main3-sdk-inline-capture-20261106-r4'])
  self.assertNotIn(OLD_ROOT,json.dumps(NEW_BUNDLE));self.assertIn(NEW_ROOT,json.dumps(NEW_BUNDLE))
  self.assertIn(b'heptabao-authbus-main3-sdk-inline-capsule-20261106-r4',payload(NEW_BUNDLE))
  self.assertNotIn(b'heptabao-authbus-main3-sdk-inline-capsule-20261106-r3',payload(NEW_BUNDLE))
 def test_wire_original_budget_agent_and_failure_contract_are_retained(self):
  old=OLD_BUNDLE['assets']['qa/main3_sdk_wire_r2.mjs']
  new=NEW_BUNDLE['assets']['qa/main3_sdk_wire_r3.mjs']
  for literal in (
   'const MAX_BYTES=1048576;',
   'new https.Agent({keepAlive:false,maxCachedSessions:0,maxSockets:1,maxTotalSockets:1})',
   'const budget=remainingMs(15000);','options.timeout===15000',
   'row.outcomeUnknown=Boolean(row.dispatched&&!row.responseComplete);',
   'if(req&&row.requestClosed&&!row.requestError){',
   'allDispatchedResponsesComplete:rows.every(row=>!row.dispatched||row.responseComplete)'):
   self.assertEqual(old.count(literal),new.count(literal));self.assertGreater(new.count(literal),0)
  self.assertNotIn('pinVerified',new)
  self.assertIn('row.tlsHostMatched=tls.checkServerIdentity(target.hostname,peer)===undefined;',new)
  self.assertIn('row.tlsEndpointMatched=socket.remoteAddress===target.hostname&&socket.remotePort===Number(target.port);',new)
if __name__=='__main__':unittest.main(verbosity=2)
