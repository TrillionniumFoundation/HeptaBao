#!/usr/bin/env python3
"""Static contract, exact bytes and AST only. No candidate module execution."""
import ast,base64,hashlib,json,sys
p=json.loads(sys.stdin.read());checks=[]
def audit(event,args):
    if event in ('open','sqlite3.connect','subprocess.Popen','socket.__new__','os.system','os.fork','os.posix_spawn'):
        raise RuntimeError('static_verifier_io_prohibited:'+event)
sys.addaudithook(audit)
def check(name,value):
    assert value,name
    checks.append({'name':name,'passed':True})
def sha(raw):return hashlib.sha256(raw.encode() if isinstance(raw,str) else raw).hexdigest()
def definitions(raw):
    rows=raw.splitlines(keepends=True)
    return {n.name:''.join(rows[n.lineno-1:n.end_lineno]) for n in ast.parse(raw).body
            if isinstance(n,(ast.FunctionDef,ast.ClassDef))}
sources=p['sources'];pins=p['sourcePins'];docs=p['documents']
check('exact-ten-sources',len(sources)==10 and set(sources)==set(pins))
for name,raw in sources.items():
    check('whole-source:'+name,len(raw.encode())==pins[name]['bytes'] and sha(raw)==pins[name]['sha256'])
    compile(ast.parse(raw,filename=name),name,'exec')
    check('ast-compile-only:'+name,True)
compile(ast.parse(p['carrier']),'<inert-carrier>','exec')
check('carrier-ast-compile-only',True)
payload=json.loads(p['payload']);contract=json.loads(docs['candidate.public.json'])
check('payload-source-set',set(payload['files'])==set(sources))
for name,raw in sources.items():check('payload-source-bytes:'+name,base64.b64decode(payload['files'][name],validate=True)==raw.encode())
check('exact-two-documents',set(docs)=={'candidate.public.json','anchor.public.json'} and set(payload['documents'])==set(docs))
for name,raw in docs.items():check('payload-document-bytes:'+name,base64.b64decode(payload['documents'][name],validate=True)==raw.encode())
check('actual-anchor-raw',docs['anchor.public.json']==p['anchor'] and base64.b64decode(payload['anchorBase64'])==p['anchor'].encode())
check('candidate-source-order',contract['sourceOrder']==list(sources))
check('candidate-source-pins',contract['sourcePins']=={n:x['sha256'] for n,x in pins.items()})
check('candidate-anchor',contract['publicVolumeAnchorSha256']==sha(p['anchor'])==contract['documentPins']['anchor.public.json'])
ir=p['inertRequest'];sr=p['syntheticRequest']
check('inert-exact-source-stdin',ir['args']==['-I','-S','-B','-c',p['carrier']] and ir['stdin']==p['payload'])
check('inert-fixed-envelope',ir['host']=='mac' and ir['executable']=='/opt/homebrew/bin/python3'
      and ir['cwd']=='/Users/qianqi' and ir['timeout_seconds']==60)
root='/Volumes/T5/hepta-vnext-recovery-20261013/mac-current-registry-readonly-wal-synthetic-r1'
check('synthetic-exact-argv',sr['args']==['-I','-S','-B',root+'/qa/mac_wal_owned_synthetic_r1.py',
      '--candidate-sha256',sha(docs['candidate.public.json'])] and sr['stdin']=='')
check('synthetic-fixed-envelope',sr['host']=='mac' and sr['executable']=='/opt/homebrew/bin/python3'
      and sr['cwd']=='/Users/qianqi' and sr['timeout_seconds']==60)
check('distinct-fixed-keys',ir['idempotency_key']!=sr['idempotency_key'] and all('20261105-r1' in x for x in (ir['idempotency_key'],sr['idempotency_key'])))
old=p['oldSources']
unchanged=('mac_guarded_current_capture_r3.py','mac_darwin_owned_projection_r1.py','mac_native_owned_unreaped_r1.py',
           'mac_native_owned_commands_r1.py','mac_owned_unreaped_r1.py','mac_owned_commands_r1.py')
for name in unchanged:check('reference-whole-byte-equality:'+name,sources[name]==old[name])
old_root='/Volumes/T5/hepta-vnext-recovery-20261013/mac-authbus-r10-current-native-custody-r1'
check('t5-only-one-root-literal',old['mac_t5_volume_guard_r1.py'].count(old_root)==1
      and old['mac_t5_volume_guard_r1.py'].replace(old_root,root)==sources['mac_t5_volume_guard_r1.py'])
old_entry=definitions(old['mac_current_capture_entry_native_r1.py']);reader=definitions(sources['mac_wal_owned_reader_r1.py'])
for name in ('capture_profile','kernel_refusals'):check('original-function-byte-equality:'+name,old_entry[name]==reader[name])
before=definitions(p['oldCarrier']);after=definitions(p['carrier'])
helpers=sorted(set(before)-{'main'})
for name in helpers:check('inert-helper-byte-equality:'+name,before[name]==after[name])
inert_tree=ast.parse(p['carrier'])
assigns={n.targets[0].id:ast.literal_eval(n.value) for n in inert_tree.body if isinstance(n,ast.Assign)
         and len(n.targets)==1 and isinstance(n.targets[0],ast.Name) and n.targets[0].id in ('PINS','DOCUMENT_PINS','PAYLOAD_BYTES','PAYLOAD_SHA','ANCHOR_SHA')}
check('carrier-source-literals',assigns['PINS']=={n:[x['bytes'],x['sha256']] for n,x in pins.items()})
check('carrier-document-literals',assigns['DOCUMENT_PINS']=={n:[len(x.encode()),sha(x)] for n,x in docs.items()})
check('carrier-payload-literals',assigns['PAYLOAD_BYTES']==len(p['payload'].encode()) and assigns['PAYLOAD_SHA']==sha(p['payload']))
check('carrier-anchor-literal',assigns['ANCHOR_SHA']==sha(p['anchor']))

class NormalizeProof(ast.NodeTransformer):
    def visit_Attribute(self,node):
        if isinstance(node.value,ast.Name) and node.value.id=='base' and node.attr=='sha':return ast.Name(id='sha',ctx=ast.Load())
        if isinstance(node.value,ast.Name) and node.value.id=='base' and node.attr=='__file__':return ast.Name(id='__file__',ctx=ast.Load())
        return self.generic_visit(node)
    def visit_Call(self,node):
        name=node.func.id if isinstance(node.func,ast.Name) else None
        method=(node.func.value.id,node.func.attr) if isinstance(node.func,ast.Attribute) and isinstance(node.func.value,ast.Name) else None
        if name in ('runtime_identity','public_runtime_identity'):
            return ast.Call(func=ast.Name(id='TRACKED_RUNTIME',ctx=ast.Load()),args=[],keywords=[])
        if name=='public_code_pin' or method==('inputs','code_pin'):
            return ast.Call(func=ast.Name(id='TRACKED_CODE_PIN',ctx=ast.Load()),args=[self.visit(node.args[0])],keywords=[])
        return self.generic_visit(node)
def proof_predicates(raw,name):
    fn=next(x for x in ast.parse(raw).body if isinstance(x,ast.FunctionDef) and x.name==name)
    nodes=[x.value.args[0] for x in fn.body if isinstance(x,ast.Expr) and isinstance(x.value,ast.Call)
           and isinstance(x.value.func,ast.Name) and x.value.func.id=='need']
    return [ast.dump(NormalizeProof().visit(n),include_attributes=False) for n in nodes]
check('old-proof-three-predicates-equivalent-with-tracked-code-readers',
      proof_predicates(old['mac_guarded_current_capture_r3.py'],'validate_synthetic_proof')==
      proof_predicates(sources['mac_registry_readonly_wal_r1.py'],'validate_original_immutable_proof'))
lib=ast.parse(sources['mac_registry_readonly_wal_r1.py'])
check('new-library-no-old-untracked-code-reader-calls',not any(isinstance(n,ast.Call) and isinstance(n.func,ast.Attribute)
      and isinstance(n.func.value,ast.Name) and n.func.value.id=='base' and n.func.attr in ('public_code_pin','runtime_identity','validate_synthetic_proof') for n in ast.walk(lib)))
check('reader-has-no-process-module',not any(isinstance(n,ast.Import) and any(x.name in ('subprocess','multiprocessing') for x in n.names)
      for n in ast.walk(ast.parse(sources['mac_wal_owned_reader_r1.py']))))
check('only-public-source-request-no-private-phase',contract['qualification']=={'actual_owned_cases_passed':False,
      'production_capture_authorized':False,'consumer_authorized':False,'service_authorized':False})
check('original-budget-contract',contract['budget']=={'shared_seconds':45,'query_seconds':3,'outer_seconds':60,'volume_seconds':30,
      'row_bytes':1048576,'aggregate_returned_and_read_bytes':8388608,'registry_wal_maximum_bytes':5969912,'application_retries':0})
result={'schema':'heptabao.mac-owned-registry-wal-static-verification.r1','ok':True,'checks':checks,
        'checkCount':len(checks),'compiledCandidateFiles':11,'candidateModulesExecuted':0,
        'hostAccess':False,'sqliteConnections':0,'networkAccess':False,'ioAuditGuardInstalled':True,
        'inputSha256':sha(json.dumps(p,separators=(',',':'))),'sourceSha256':{n:sha(x) for n,x in sources.items()},
        'inertHelperCountUnchanged':len(helpers),'rawInputHashBoundByPacket':True}
print(json.dumps(result,sort_keys=True,indent=2))
