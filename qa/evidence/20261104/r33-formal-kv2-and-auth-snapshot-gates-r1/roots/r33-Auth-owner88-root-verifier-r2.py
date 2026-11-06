#!/usr/bin/env python3
"""Independent offline byte audit of AuthBus owner/renewal public source package.
Parses public JSON, base64 and Python AST; executes no author/candidate/SDK code.
The original stdin_text dispatch is explicitly rejected and never authorized here.
"""
import ast, base64, hashlib, json, os, pathlib, sys, traceback
BASE=pathlib.Path('/workspace/scratch/f86faac821c4')
PACK=BASE/'authbus_registration_body4_recovery_r1/owner-bound-renew-r1'
OUT=BASE/'r32_recovery/r33-Auth-owner88-root-result-r2.public.json'
checks=[]
def check(name, ok, detail=None):
    row={'name':name,'ok':bool(ok)}
    if detail is not None: row['detail']=detail
    checks.append(row)
def meta(b):
    return {'blob':hashlib.sha1(b'blob '+str(len(b)).encode()+b'\0'+b).hexdigest(),
            'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest()}
def jd(b): return json.loads(b)
def decode(s): return base64.b64decode(s,validate=True)
def native_binding(r):
    keys={'args':r.get('args',[]),'cpu_quota_percent':r.get('cpu_quota_percent'),
          'cwd':r.get('cwd'),'env':r.get('env',{}),'executable':r['executable'],
          'host':r['host'],'memory_max_bytes':r.get('memory_max_bytes'),
          'nice':r.get('nice'),'stdin':r.get('stdin'),'timeout_seconds':r.get('timeout_seconds')}
    raw=json.dumps(keys,ensure_ascii=False,sort_keys=True,separators=(',',':')).encode()
    digest=hashlib.sha256(raw).hexdigest()
    return {'canonicalBytes':len(raw),'sha256':digest,'native_fingerprint':str(int(digest[:16],16))}
def ast_assignments(s):
    return {n.targets[0].id:n for n in ast.parse(s).body
            if isinstance(n,ast.Assign) and isinstance(n.targets[0],ast.Name)}
def segment(s,n): return ast.get_source_segment(s,n)
result={'schema':'heptabao.r33.auth-owner88.independent-source-root-review.r1',
        'scope':'offline public bytes and dispatch proposal; no host or SDK execution',
        'authorCodeExecuted':False,'candidateCodeExecuted':False,'runtimeCalls':0,
        'privateCapsuleRead':False,'runtimeAuthorized':False,'inertAuthorized':False,
        'sourcePrerequisiteRoot':'65b6f2235fcf055ff15fc9177fd6f80727449462',
        'checks':checks}
try:
    plan=jd((PACK/'packet-plan.public.json').read_bytes())
    files=plan['files']; raw={}
    check('packet_88_files',len(files)==88)
    for k,v in files.items():
        b=pathlib.Path(v['local']).read_bytes(); raw[k]=b
        check('whole_blob:'+k,meta(b)=={a:v[a] for a in ['blob','bytes','sha256']})
    check('packet_total_2910122',sum(map(len,raw.values()))==2910122==plan['totalBytes'])
    manifest=jd(raw['MANIFEST.public.json'])['files']
    check('manifest_covers_other_87',len(manifest)==87 and {r['path'] for r in manifest}==set(files)-{'MANIFEST.public.json'})
    check('manifest_all_pins_match',all({a:r[a] for a in ['blob','bytes','sha256']}==meta(raw[r['path']]) for r in manifest))
    # Reconstruct every Git subtree from whole verified leaf bytes.
    nodes={}
    for k,v in files.items():
        d=nodes; parts=k.split('/')
        for part in parts[:-1]: d=d.setdefault(part,{})
        d[parts[-1]]=v['blob']
    tree_rows=[]
    def treehash(node,path=''):
        entries=[]
        for name,v in node.items():
            isdir=isinstance(v,dict)
            sha=treehash(v,path+'/'+name) if isdir else v
            entries.append((name,isdir,sha))
        entries.sort(key=lambda x:(x[0]+('/' if x[1] else '')).encode())
        data=b''.join((('40000' if isdir else '100644')+' '+name).encode()+b'\0'+bytes.fromhex(sha) for name,isdir,sha in entries)
        sha=hashlib.sha1(b'tree '+str(len(data)).encode()+b'\0'+data).hexdigest()
        tree_rows.append({'path':path.lstrip('/'),'sha':sha,'entries':len(entries)})
        return sha
    result['expectedPacketTree']=treehash(nodes)
    result['merkleTrees']=tree_rows
    old_payload=(BASE/'authbus_registration_body4_recovery_r1/blobs/931383bbc295b82ad7ff6cf57c33af3395e20966.txt').read_bytes()
    check('original_public_payload_identity',meta(old_payload)=={'blob':'931383bbc295b82ad7ff6cf57c33af3395e20966','bytes':780807,'sha256':'4cbfe07b6e0f504768fc52e1bab8dcbc7af0c9326e9db69c89b8b9bcc07283c4'})
    old=jd(old_payload); new=jd(raw['publisher-stdin.public.json'])
    check('payload_closed_schema',set(new)==set(old)=={'schema','files','documents','anchorBase64'} and new['schema']==old['schema'])
    check('payload_exact_22_plus_8',len(new['files'])==22 and len(new['documents'])==8 and set(new['files'])==set(old['files']) and set(new['documents'])==set(old['documents']))
    old_sources={k:decode(v) for k,v in old['files'].items()}
    source_pins=jd(raw['source-pins.public.json']); old_pins=jd(raw['reference/old-source-pins.public.json'])
    check('original_pins_cover_original_sources',old_pins=={k:meta(v)['sha256'] for k,v in old_sources.items()})
    check('new_source_pins_complete',source_pins=={k:meta(raw['source/'+k])['sha256'] for k in old_sources})
    oldslug='mac-authbus-4e808-current-registry-wal-r1'; newslug='mac-authbus-4e808-current-owner-bind-r1'
    oldroot='/Volumes/T5/hepta-vnext-recovery-20261013/'+oldslug
    newroot='/Volumes/T5/hepta-vnext-recovery-20261013/'+newslug
    reviewed={
      'mac_current_outer_inputs_r2.py':'1e2a0cfb1bdbaef2d418fd8eb941ac14ec28e9b6',
      'mac_current_fixture_materializer_r1.py':'570f9abdcad9cfdc4c2d06c3895f0f68a1bf8c1b',
      'mac_single_native_r2.mjs':'11d6b0bb0c26019b5a6e4035d42226b6666cab07',
      'mac_current_outer_wal_r1.py':'26622454186ba28ada489c9a10b34cf4ad254b97'}
    old_entry_block=("# Source-only successor: the Google declared entry has not yet been observed.\n"
                     "# A later exact public binding must fill OWNER_ENTRY_PINS before this can run.\n"
                     "OWNER_PUBLIC_BINDING_READY=False\nOWNER_ENTRY_PINS={}")
    new_entry_block=("# Current fixed public entry has been observed and whole-hash bound.\n"
                     "# This does not authorize execution or prove the selected owner.\n"
                     "OWNER_PUBLIC_BINDING_READY=True\nOWNER_ENTRY_PINS={\n"
                     '  "/opt/homebrew/lib/node_modules/openclaw/dist/extensions/google/index.js": "f245758337a55924518852f542a27d49bd786d8e4b80821dc5f98f825ec3fc60"\n}')
    old_ready='BINDING_READY=False  # Source-only renewal increment; no runtime request or fresh candidate is bound.'
    new_ready='BINDING_READY=True  # Actual source pins and fresh candidate are bound; host execution requires separate root GO.'
    changed=roots=labels=0; source_rows=[]
    for name,before in old_sources.items():
        after=raw['source/'+name]
        check('stdin_source_exact:'+name,decode(new['files'][name])==after)
        ref=raw['reference/reviewed/'+name] if name in reviewed else before
        if name in reviewed: check('reviewed_base_identity:'+name,meta(ref)['blob']==reviewed[name])
        baseline_key='reference/baseline/'+name
        if baseline_key in raw: check('baseline_reference_exact:'+name,raw[baseline_key]==before)
        s=ref.decode(); expected=s.replace(oldslug,newslug)
        roots+=s.count(oldslug)
        if name=='mac_owned_launchd_r3.py':
            for suffix in ['server','consumer']:
                a='org.heptabao.qa.mac-authbus-4e808-wal-r1.'+suffix
                b='org.heptabao.qa.mac-authbus-4e808-owner-r1.'+suffix
                check('single_old_label:'+suffix,expected.count(a)==1)
                expected=expected.replace(a,b); labels+=1
        if name=='mac_current_outer_inputs_r2.py':
            check('single_unbound_entry_block',expected.count(old_entry_block)==1)
            expected=expected.replace(old_entry_block,new_entry_block)
        if name=='mac_current_outer_wal_r1.py':
            check('single_unbound_outer_flag',expected.count(old_ready)==1)
            expected=expected.replace(old_ready,new_ready)
        check('only_reviewed_binding_changes:'+name,expected.encode()==after)
        if name.endswith('.py'):
            ast.parse(after.decode())
            before_defs={n.name:segment(s,n) for n in ast.parse(s).body if isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef,ast.ClassDef))}
            after_defs={n.name:segment(after.decode(),n) for n in ast.parse(after.decode()).body if isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef,ast.ClassDef))}
            check('all_function_class_bodies_unchanged:'+name,before_defs==after_defs,{'definitions':len(before_defs)})
        changed+=after!=before
        source_rows.append({'name':name,'baseline':meta(before),'reviewed':meta(ref),'bound':meta(after),'unchangedFromBaseline':before==after})
    check('exact_11_changed_11_unchanged',changed==11)
    check('exact_11_root_2_label_literals',roots==11 and labels==2)
    result['sources']=source_rows
    candidate=jd(raw['documents/candidate-current-manager-wal-r1.public.json'])
    old_candidate=jd(raw['reference/old-candidate.public.json'])
    check('candidate_matches_original_payload',decode(old['documents']['candidate-current-manager-wal-r1.public.json'])==raw['reference/old-candidate.public.json'])
    expected_candidate=dict(old_candidate); expected_candidate['sourcePins']=source_pins
    check('candidate_only_sourcePins_changed',candidate==expected_candidate)
    check('candidate_commit_tree_and_budgets_preserved',candidate['sourceCommit']=='4e808d0ecb1bcded22870a7ec960dfb2491cf6ec' and candidate['sourceTree']=='eba5e650bd080b8ad41ea52a2bc68867f541d255' and candidate['budgets']=={'outer':900,'manager':600,'managerFailureCleanup':60,'phase':120,'native':[15,8,3],'http':10,'capture':45,'listenerReady':30,'tlsCommand':30})
    for name,b64 in new['documents'].items():
        b=raw['documents/'+name]
        check('stdin_document_exact:'+name,decode(b64)==b)
        if name.startswith('proofs/'): check('original_proof_unchanged:'+name,b==decode(old['documents'][name]))
    check('anchor_exact_unchanged',decode(new['anchorBase64'])==decode(old['anchorBase64'])==raw['volume-anchor.original.json'])
    check('actual_google_entry_whole_pin',meta(raw['reference/entry.original.js'])=={'blob':'4a63cd4e06362ad36bb50c481315020b6aec94aa','bytes':10582,'sha256':'f245758337a55924518852f542a27d49bd786d8e4b80821dc5f98f825ec3fc60'})
    oldpub=raw['reference/old-inert-publisher.py'].decode(); pub=raw['dispatch/inert-publisher.py'].decode()
    oa=ast_assignments(oldpub); na=ast_assignments(pub)
    allow={'ROOT','PINS','DOCUMENT_PINS','PAYLOAD_BYTES','PAYLOAD_SHA'}
    replacements=[]
    for name in allow:
        o=oa[name]; n=na[name]
        check('publisher_binding_node_kind:'+name,type(o.value)==type(n.value))
        replacements.append((n.lineno,n.end_lineno,oldpub.splitlines(keepends=True)[o.lineno-1:o.end_lineno]))
    lines=pub.splitlines(keepends=True)
    for start,end,repl in sorted(replacements,reverse=True): lines[start-1:end]=repl
    check('publisher_whole_inverse_only_five_assignments',''.join(lines)==oldpub)
    pdefs=[n for n in ast.parse(pub).body if isinstance(n,(ast.FunctionDef,ast.ClassDef))]
    odefs=[n for n in ast.parse(oldpub).body if isinstance(n,(ast.FunctionDef,ast.ClassDef))]
    check('publisher_12_definitions_byte_identical',len(pdefs)==len(odefs)==12 and all(segment(pub,n)==segment(oldpub,o) for n,o in zip(pdefs,odefs)))
    pinmap=ast.literal_eval(na['PINS'].value); oldpinmap=ast.literal_eval(oa['PINS'].value)
    docmap=ast.literal_eval(na['DOCUMENT_PINS'].value); olddocmap=ast.literal_eval(oa['DOCUMENT_PINS'].value)
    check('publisher_original_insertion_order',list(pinmap)==list(oldpinmap) and list(docmap)==list(olddocmap))
    check('publisher_exact_22_source_pins',pinmap=={k:[len(raw['source/'+k]),meta(raw['source/'+k])['sha256']] for k in new['files']})
    check('publisher_exact_8_document_pins',docmap=={k:[len(raw['documents/'+k]),meta(raw['documents/'+k])['sha256']] for k in new['documents']})
    check('publisher_payload_size_sha',ast.literal_eval(na['PAYLOAD_BYTES'].value)==len(raw['publisher-stdin.public.json']) and ast.literal_eval(na['PAYLOAD_SHA'].value)==meta(raw['publisher-stdin.public.json'])['sha256'])
    check('publisher_original45s_shared_budget',ast.dump(na['UNTIL'].value)==ast.dump(ast.parse('START+45.0',mode='eval').body))
    # The submitted tool schema is stdin, not the legacy proposal's stdin_text.
    inert=jd(raw['dispatch/inert.exact-request.public.json'])
    check('legacy_inert_proposal_rejected_known_schema_mismatch','stdin_text' in inert and 'stdin' not in inert)
    fixed_inert={('stdin' if k=='stdin_text' else k):v for k,v in inert.items()}
    check('inert_inline_publisher_and_stdin_exact',fixed_inert['args']==['-I','-S','-B','-c',pub] and fixed_inert['stdin'].encode()==raw['publisher-stdin.public.json'])
    regular='/opt/homebrew/Cellar/python@3.14/3.14.3_1/Frameworks/Python.framework/Versions/3.14/bin/python3.14'
    check('inert_exact_control_fields',{k:v for k,v in fixed_inert.items() if k not in ['args','stdin']}=={'host':'mac','executable':regular,'cwd':'/Users/qianqi','timeout_seconds':60,'idempotency_key':'heptabao-mac-current-owner-renew-inert-d89e5169-20261105-r1'})
    result['correctedInertExpectedNativeBinding']=native_binding(fixed_inert)
    result['legacyInertProposalNotAuthorized']=True
    runtime=jd(raw['dispatch/runtime.exact-request.public.json']); old_runtime=jd(raw['reference/old-runtime.exact-request.json'])
    er=dict(old_runtime); er['args']=[s.replace(oldroot,newroot) for s in old_runtime['args']]
    er['executable']=regular; er['idempotency_key']='heptabao-mac-current-five-agent-owner-renew-6ad1b80a-20261105-r1'
    for opt,value in [('--candidate-sha256',meta(raw['documents/candidate-current-manager-wal-r1.public.json'])['sha256']),('--public-source-pins-base64',base64.b64encode(raw['source-pins.public.json']).decode()),('--public-source-pins-sha256',meta(raw['source-pins.public.json'])['sha256'])]:
        er['args'][er['args'].index(opt)+1]=value
    check('runtime_only_declared_fresh_bindings_and_regular_python',runtime==er)
    result['runtimeProposalNativeBinding']=native_binding(runtime)
    synthetic=jd(raw['documents/proofs/synthetic-r2.stdout.public.json'])
    check('actual_qualified_regular_python_pin',synthetic['runtime']['pythonExecutable']=={'bytes':34640,'path':regular,'sha256':'cebfcc4ac431ff7a2179bc6eff7e5c6bdae48b564eeab2d504bef6173a2cfc13'})
    targets=jd(raw['dispatch/post-inert-targets.public.json'])
    expected_targets={newroot+'/qa/'+k:{'bytes':len(raw['source/'+k]),'sha256':meta(raw['source/'+k])['sha256']} for k in new['files']}
    expected_targets.update({newroot+'/'+k:{'bytes':len(raw['documents/'+k]),'sha256':meta(raw['documents/'+k])['sha256']} for k in new['documents']})
    realtargets={r['path']:{k:r[k] for k in ['bytes','sha256']} for r in targets['targets'] if r['kind']!='inert_candidate_receipt'}
    check('source_only_31_targets_match_30_files_and_receipt',realtargets==expected_targets and len(targets['targets'])==31 and targets['status']=='SOURCE_ONLY_NO_READ_REQUESTS_BOUND')
    # Retain limits as explicit non-claims; actual source pin freshness, owner and credentials await original worker.
    result['notProved']=['host root or labels absent now','actual selected harness owner','AppRole/TLS/KV/Policy/renewal/revocation','cold restart/rollback','all-client migration','production cutover','old-version cleanup']
except Exception as e:
    check('verifier_exception',False,{'type':type(e).__name__,'message':str(e),'traceback':traceback.format_exc()})
result['passed']=sum(r['ok'] for r in checks); result['failed']=sum(not r['ok'] for r in checks)
result['ok']=result['failed']==0
data=(json.dumps(result,ensure_ascii=False,indent=2)+'\n').encode()
with OUT.open('wb') as f: f.write(data); f.flush(); os.fsync(f.fileno())
print(json.dumps({'ok':result['ok'],'passed':result['passed'],'failed':result['failed'],'failureDetails':[r for r in checks if not r['ok']],'expectedPacketTree':result.get('expectedPacketTree'),'merkleTrees':len(result.get('merkleTrees',[])),'result':meta(data),'resultPath':str(OUT)},ensure_ascii=False))
sys.exit(0 if result['ok'] else 1)

