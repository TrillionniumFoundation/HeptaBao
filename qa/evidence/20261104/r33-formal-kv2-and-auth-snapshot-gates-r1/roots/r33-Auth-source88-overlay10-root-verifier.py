#!/usr/bin/env python3
"""Independent public Git tree and corrected stdin proposal binding audit."""
import ast,base64,hashlib,json,os,pathlib,sys,traceback
B=pathlib.Path('/workspace/scratch/f86faac821c4');R=B/'r32_recovery';P=B/'authbus_registration_body4_recovery_r1/owner-bound-renew-r1'
checks=[]; result={'schema':'heptabao.r33.auth-owner88-and-stdin-overlay.root.r1','checks':checks,'runtimeCalls':0,'authorCodeExecuted':False,'sourcePrerequisiteRoot':'65b6f2235fcf055ff15fc9177fd6f80727449462','source218Root':'68838a0c45042258358892d20778b0aee3b14b27','inertAuthorized':False,'runtimeAuthorized':False}
def ck(n,v,d=None):
 r={'name':n,'ok':bool(v)}
 if d is not None:r['detail']=d
 checks.append(r)
def meta(b):return {'blob':hashlib.sha1(b'blob '+str(len(b)).encode()+b'\0'+b).hexdigest(),'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest()}
def jd(b):return json.loads(b)
def git_tree(sha):
 sdk=jd(jd((R/('r33-Auth-public-tree-'+sha+'-original-sdk.json')).read_bytes())['text'])
 if sdk.get('isError'):raise ValueError('Git SDK error')
 return jd(sdk['structuredContent']['content'])
def native_binding(r):
 o={k:r.get(k) for k in ['cpu_quota_percent','cwd','executable','host','memory_max_bytes','nice','stdin','timeout_seconds']};o.update(args=r.get('args',[]),env=r.get('env',{}))
 b=json.dumps(o,sort_keys=True,ensure_ascii=False,separators=(',',':')).encode();h=hashlib.sha256(b).hexdigest()
 return {'canonicalBytes':len(b),'sha256':h,'native_fingerprint':str(int(h[:16],16))}
try:
 oldreview=jd((R/'r33-Auth-owner88-root-result-r2.public.json').read_bytes())
 ck('source218_original_report_identity',meta((R/'r33-Auth-owner88-root-result-r2.public.json').read_bytes())['blob']=='68838a0c45042258358892d20778b0aee3b14b27' and oldreview['ok'] and oldreview['passed']==218 and oldreview['failed']==0)
 packets=[('source88',P,'71a1656fbe227fcea1e92558a5004e22eaab69c6',88,2910122,12),('stdin_overlay10',P/'stdin-schema-overlay-r1','2f213b0e8de72fac88fec0039761390f34f9e946',10,1662289,2)]
 decoded={}
 for label,d,sha,count,size,ntrees in packets:
  plan=jd((d/'packet-plan.public.json').read_bytes());files=plan['files']; raw={}
  for name,pin in files.items():
   b=pathlib.Path(pin['local']).read_bytes();raw[name]=b;ck(label+':whole:'+name,meta(b)=={k:pin[k] for k in ['blob','bytes','sha256']})
  t=git_tree(sha);leaves={e['path']:e for e in t['tree'] if e['type']=='blob'}
  ck(label+':actual_Git_tree_members',t['sha']==sha and not t['truncated'] and len(leaves)==count and len(t['tree'])==count+ntrees-1 and set(leaves)==set(files))
  ck(label+':actual_Git_blob_identity_and_size',all(leaves[k]['sha']==v['blob'] and leaves[k]['size']==v['bytes'] and leaves[k]['mode']=='100644' for k,v in files.items()))
  ck(label+':whole_totals',len(files)==count and sum(map(len,raw.values()))==size)
  directories={'':[]}
  for k,v in files.items():
   a=k.split('/')
   for i in range(1,len(a)):directories.setdefault('/'.join(a[:i]),[])
   directories['/'.join(a[:-1])].append((a[-1],False,v['blob']))
  merkle=[]
  for path in sorted(directories,key=lambda x:(x.count('/'),len(x)),reverse=True):
   entries=directories[path];entries.sort(key=lambda x:(x[0]+('/' if x[1] else '')).encode())
   data=b''.join((('40000' if it else '100644')+' '+name).encode()+b'\0'+bytes.fromhex(h) for name,it,h in entries)
   h=hashlib.sha1(b'tree '+str(len(data)).encode()+b'\0'+data).hexdigest()
   observed=t['sha'] if not path else next(e['sha'] for e in t['tree'] if e['path']==path and e['type']=='tree')
   ck(label+':actual_merkle:'+path,h==observed)
   merkle.append({'path':path,'sha':h})
   if path:
    a=path.split('/');directories['/'.join(a[:-1])].append((a[-1],True,h))
  ck(label+':merkle_count',len(merkle)==ntrees)
  decoded[label]=raw
  result[label]={'tree':sha,'files':count,'bytes':size,'merkle':ntrees}
 ov=decoded['stdin_overlay10'];s=decoded['source88']
 a=ov['reference/original-request.json'];b=ov['inert.exact-request.public.json']
 ck('original_wrong_proposal_preserved',a==s['dispatch/inert.exact-request.public.json'] and meta(a)['blob']=='850fdaf3c82e5067605494f5a8e8d8af3a1ab899')
 ck('exact_byte_key_only_patch',a.count(b'"stdin_text":')==1 and a.replace(b'"stdin_text":',b'"stdin":')==b and len(a)-len(b)==5)
 r=jd(b);old=jd(a);expected={('stdin' if k=='stdin_text' else k):v for k,v in old.items()}
 ck('exact_request_only_schema_key_rename',r==expected and set(r)=={'host','executable','args','cwd','stdin','timeout_seconds','idempotency_key'})
 ck('corrected_request_identity',meta(b)=={'blob':'521c4700c9896ef48c8b710f7b787b5cfb5d1504','bytes':818377,'sha256':'6ffc5db0c3d9cf79f00d9484b1d54162b75b7e975e594a1d5ca5d8566d3b9cf4'})
 ck('original_generator_preserved',ov['reference/original-generator.py']==s['generate_dispatch.py'])
 ck('generator_only_schema_key_literal',ov['reference/original-generator.py'].count(b'stdin_text')==1 and ov['reference/original-generator.py'].replace(b'stdin_text',b'stdin')==ov['generate_dispatch.py'])
 ast.parse(ov['generate_dispatch.py'].decode())
 ck('corrected_request_publisher_stdin_whole',r['stdin'].encode()==s['publisher-stdin.public.json'] and r['args']==['-I','-S','-B','-c',s['dispatch/inert-publisher.py'].decode()])
 nb=native_binding(r);ck('native_binding_matches_prior_independent_expected',nb==oldreview['correctedInertExpectedNativeBinding'])
 result['correctedInertRequest']=meta(b);result['correctedInertNativeBinding']=nb
 result['runtimeRequest']=meta(s['dispatch/runtime.exact-request.public.json'])
 result['runtimeNativeBinding']=native_binding(jd(s['dispatch/runtime.exact-request.public.json']))
 result['scope']='Corrected inert proposal ready for an exact lane admission; actual stage, credentials, ownership and replacement remain unproved.'
except Exception as e:ck('verifier_exception',False,{'type':type(e).__name__,'message':str(e),'traceback':traceback.format_exc()})
result['passed']=sum(x['ok'] for x in checks);result['failed']=sum(not x['ok'] for x in checks);result['ok']=result['failed']==0
data=(json.dumps(result,ensure_ascii=False,indent=2)+'\n').encode();out=R/'r33-Auth-source88-overlay10-root-result.public.json'
with out.open('wb') as f:f.write(data);f.flush();os.fsync(f.fileno())
print(json.dumps({'ok':result['ok'],'passed':result['passed'],'failed':result['failed'],'failureDetails':[r for r in checks if not r['ok']],'result':meta(data),'correctedNative':result.get('correctedInertNativeBinding'),'runtimeNative':result.get('runtimeNativeBinding')}))
sys.exit(0 if result['ok'] else 1)

