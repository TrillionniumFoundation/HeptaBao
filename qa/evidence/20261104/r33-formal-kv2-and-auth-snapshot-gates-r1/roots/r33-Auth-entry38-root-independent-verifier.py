"""Independent root verification of the fixed Google entry original read packet."""
import json,pathlib,hashlib,base64,os
B=pathlib.Path('/workspace/scratch/f86faac821c4/r32_recovery')
D=pathlib.Path('/workspace/scratch/f86faac821c4/authbus_registration_body4_recovery_r1/google-entry/actual-r1')
TREE='135407c6d3156a8602da63184c0df4143aa137ea'
GO='575b8d4e64924d9306677d80e615f1a1ee570bce'
PATH='/opt/homebrew/lib/node_modules/openclaw/dist/extensions/google/index.js'
VERSION='16777233:405237094:10582:1784843458496192413:1784843458496192413'
SHA='f245758337a55924518852f542a27d49bd786d8e4b80821dc5f98f825ec3fc60'
checks=[]
def ck(n,b):
    if b is not True:raise AssertionError(n)
    checks.append(n)
def meta(d):
    return {'blob':hashlib.sha1(b'blob '+str(len(d)).encode()+b'\0'+d).hexdigest(),'bytes':len(d),'sha256':hashlib.sha256(d).hexdigest()}
plan=json.loads((D/'packet-plan.public.json').read_text())
records=plan['files'];raw={}
ck('fixed38_and121330_plan',plan['fileCount']==len(records)==38 and plan['totalBytes']==121330)
for n,p in records.items():
    path=pathlib.Path(p['local'])
    ck('fixed_public_local_origin:'+n,path.is_relative_to('/workspace/scratch/f86faac821c4/authbus_registration_body4_recovery_r1'))
    d=path.read_bytes();ck('whole:'+n,all(meta(d)[k]==p[k] for k in ('blob','bytes','sha256')));raw[n]=d
ck('whole_total121330',sum(map(len,raw.values()))==121330)
tree_sdk=json.loads(json.loads((B/'r33-Auth-entry38-original-tree-sdk.json').read_text())['text'])
ck('original_tree_SDK_no_error',tree_sdk.get('isError') is False)
tree=json.loads(tree_sdk['structuredContent']['content'])
ck('exact_tree_untruncated',tree['sha']==TREE and tree['truncated'] is False)
leaves={x['path']:x for x in tree['tree'] if x['type']=='blob'}
ck('exact_tree38_leaf_set',set(leaves)==set(records))
for n,x in leaves.items():ck('tree_leaf:'+n,x['sha']==records[n]['blob'] and x['size']==records[n]['bytes'] and x['mode']=='100644')
top={}
for n,r in records.items():
    at=top;parts=n.split('/')
    for p in parts[:-1]:at=at.setdefault(p,{})
    at[parts[-1]]=r['blob']
nodes=[]
def walk(at,prefix=''):
    rows=[]
    for n,v in at.items():
        directory=isinstance(v,dict);h=walk(v,prefix+n+'/') if directory else v;rows.append((n,directory,h))
    rows.sort(key=lambda x:(x[0]+('/' if x[1] else '')).encode())
    body=b''.join(('40000' if d else '100644').encode()+b' '+n.encode()+b'\0'+bytes.fromhex(h) for n,d,h in rows)
    h=hashlib.sha1(b'tree '+str(len(body)).encode()+b'\0'+body).hexdigest();nodes.append({'path':prefix[:-1],'sha':h});return h
ck('rebuilt_Merkle_root',walk(top)==TREE)
ck('six_Merkle_nodes',len(nodes)==6)
for n in nodes:ck('Merkle:'+n['path'],n['sha']==TREE if n['path']=='' else any(x['type']=='tree' and x['path']==n['path'] and x['sha']==n['sha'] for x in tree['tree']))
def obj(n):return json.loads(raw[n])
def pe(p,n):return all(p[k]==records[n][k] for k in ('blob','bytes','sha256'))
def pair(s,n):
    sdk=obj(s);ck('SDK_no_error:'+s,sdk.get('isError') is False)
    ck('SDK_native_exact:'+s,len(sdk['content'])==1 and sdk['content'][0]['type']=='text' and sdk['content'][0]['text'].encode()==raw[n])
    return obj(n)
go=obj('reference/GO.original.json');contract=obj('reference/CONTRACT.source.json');package=obj('reference/Google.package.original.json')
ck('exact_GO_and_deriver',records['reference/GO.original.json']['blob']==GO and pe(go['metadata_request'],'observations/metadata/exact-request.json') and pe(go['conditional_body']['pure_deriver'],'reference/derive-entry-body.mjs'))
ck('actual_package_unique_declared_entry',records['reference/Google.package.original.json']['blob']=='eca1335cb1e73aafcb53f89bba324673f9fa4493' and package['openclaw']['extensions']==['./index.js'] and contract['source']['lexicalDerivedPath']==PATH)
ck('no_invented_historical_entry_pin',contract['source']['entryHistoricalSourcePin'] is None and contract['source']['entryExistenceObserved'] is False)
observers=[];page_count=0
for role,tool,total,offsets in [('metadata','file_info',578,[0]),('body','binary_read',14528,[0,8192])]:
    pre='observations/'+role+'/'
    request=obj(pre+'exact-request.json');intent=obj(pre+'intent.public.json')
    ck('original_request_and_intent:'+role,pe(intent['request'],pre+'exact-request.json') and intent['exact']==request and intent['go']['blob']==GO and intent['submissionState']=='NOT_SUBMITTED' and intent['operationId'] is None and intent['maxNativeFutures']==1 and intent['originalPageLimit']==8192)
    ck('fixed_host_path_tool:'+role,request['operation']['tool']==tool and request['operation']['arguments']['host']=='mac' and request['operation']['arguments']['path']==PATH)
    admission=pair(pre+'admission.original.sdk.json',pre+'admission.original.json');sid=admission['operation_id']
    ck('unique_original_admission:'+role,admission['tool_name']==tool and admission['reused'] is False and admission['idempotency_binding_retained'] is True)
    status=pair(pre+'status.original.sdk.json',pre+'status.original.json')
    ck('sameID_status_request:'+role,obj(pre+'status.exact-request.json')=={'operation_id':sid} and status['operation_id']==sid and status['tool_name']==tool)
    ck('original_observer_closed:'+role,status['async_state']=='completed' and status['result_state']=='stored_observed' and status['owned_future_active'] is False and status['payload_available'] is True)
    names=sorted(n for n in records if n.startswith(pre+'page-') and n.endswith('.exact-request.json'))
    ck('fixed_immutable_page_inventory:'+role,names==[pre+'page-'+str(o).zfill(6)+'.exact-request.json' for o in offsets])
    chunks=[];pins=[]
    for offset in offsets:
        stem=pre+'page-'+str(offset).zfill(6);q=obj(stem+'.exact-request.json')
        p=pair(stem+'.original.sdk.json',stem+'.original.json');d=base64.b64decode(p['data_base64'],validate=True)
        ck('exact_page_request:'+stem,q=={'operation_id':sid,'offset':offset,'limit':8192})
        ck('original_immutable_page_identity:'+stem,p['operation_id']==sid and p['offset']==offset and p['total_bytes']==total and p['immutable_snapshot'] is True and p['payload_kind']=='native_result')
        ck('page_extent_SHA_EOF:'+stem,len(d)==min(8192,total-offset) and p['next_offset']==offset+len(d) and p['eof'] is (offset+len(d)==total) and p['result_sha256']==records[pre+'payload.original.json']['sha256'])
        chunks.append(d);pins.append({'offset':offset,'bytes':len(d),'native':{k:records[stem+'.original.json'][k] for k in ('blob','bytes','sha256')}})
    ck('whole_original_payload:'+role,b''.join(chunks)==raw[pre+'payload.original.json'] and len(raw[pre+'payload.original.json'])==total)
    payload=obj(pre+'payload.original.json')
    ck('payload_to_native_exact:'+role,payload['resultType']=='complete' and payload['isError'] is False and len(payload['content'])==1 and payload['content'][0]['type']=='text' and payload['content'][0]['text'].encode()==raw[pre+'native.original.json'])
    observers.append({'role':role,'id':sid,'closed':True,'payload':{k:records[pre+'payload.original.json'][k] for k in ('blob','bytes','sha256')},'pages':pins})
    page_count+=len(offsets)
ck('two_unique_original_observers_three_pages',len({o['id'] for o in observers})==2 and page_count==3)
info=obj('observations/metadata/native.original.json');body=obj('observations/body/native.original.json');request=obj('observations/body/exact-request.json')
ck('current_exact_metadata',info['path']==PATH and info['size']==10582 and info['sha256']==SHA and info['version']==VERSION)
md=info['metadata']
ck('actual_regular_public_metadata_guards',info['mode']==md['mode']==420 and md['metadata_platform']=='darwin' and md['link_count']==1 and md['uid']==501 and md['gid']==80 and info['mode']&0o022==0)
ck('exact_current_version_size',int(VERSION.split(':')[2])==info['size'] and 0<info['size']<=65536)
expected_request={'idempotency_key':'heptabao-mac-google-declared-entry-body-eca1335c-20261105-r1','operation':{'tool':'binary_read','arguments':{'host':'mac','path':PATH,'expected_version':VERSION,'offset':0,'limit':10582}}}
ck('body_request_derived_from_actual_metadata',request==expected_request)
derived=obj('observations/body/derived.public.json')
ck('exact_derived_value',derived=={'request':expected_request,'expectedSha256':SHA,'expectedBytes':10582,'previousBodyBytes':382975,'newBodyBytes':10582,'cumulativeBodyBytes':393557})
it=obj('observations/body/intent.public.json')
ck('original_metadata_precedes_body_binding',it['metadataOriginalClosed']['operation_id']==observers[0]['id'] and pe(it['metadataOriginalClosed']['payload'],'observations/metadata/payload.original.json') and pe(it['metadataOriginalClosed']['native'],'observations/metadata/native.original.json') and pe(it['derived'],'observations/body/derived.public.json'))
d=base64.b64decode(body['data_base64'],validate=True)
ck('entry_whole_native_original_bytes',d==raw['actual/entry.original.js'] and len(d)==10582 and hashlib.sha256(d).hexdigest()==SHA==body['chunk_sha256'])
ck('native_body_exact_range_version_EOF',body['path']==PATH and body['version']==VERSION and body['size']==body['next_offset']==10582 and body['offset']==0 and body['eof'] is True)
release=obj('RELEASE.public.json')
ck('release_exact_source_and_counts',pe(release['entry']['source'],'actual/entry.original.js') and release['entry']['version']==VERSION and release['readOperationsSubmitted']==2 and release['allOriginalOperationsClosed'] is True and release['allOriginalPayloadsWhole'] is True)
ck('release_matches_original_observers',all(o['id']==x['id'] and o['role']==x['name'] and len(o['pages'])==x['pages'] for o,x in zip(observers,release['operations'])))
ck('bounded_cumulative_accounting',release['accounting']=={'previousBodyBytes':382975,'additionalBodyBytes':10582,'cumulativeBodyBytes':393557,'additionalBodyLimit':65536,'cumulativeBodyLimit':448511,'metadataHashWorkIsSeparate':True})
ck('scope_and_idle',release['runtimeCallsInFlight']==0 and release['knownNativeFuturesActive']==0 and release['runtimeErrors']==0 and release['reusedAdmissions']==0 and release['sameIdReconciliations']==0 and release['sdkExecutions']==0 and release['privateCapsuleReads']==0 and release['providerCalls']==0 and release['followedImports']==0 and release['actualSelectedOwnerProven'] is False)
result={'schema':'heptabao.Auth-Google-entry38.independent-root-original-chain.v1','ok':True,'checks_passed':len(checks),'checks':checks,'source_tree':TREE,'whole_files':38,'whole_bytes':121330,'Merkle_nodes':6,'original_observers':observers,'original_pages':3,'archived_readonly_calls':7,'entry':{k:records['actual/entry.original.js'][k] for k in ('blob','bytes','sha256')},'path':PATH,'version':VERSION,'cumulative_source_body_bytes':393557,'scope':{'Runtime_calls':0,'remote_source_body_reads':0,'SDK_or_plugin_execution':False,'author_deriver_executed':False,'candidate_executed':False,'current_public_entry_pinned':True,'historical_entry_pin_fabricated':False,'actual_selected_owner_proven':False,'credential_runtime_qualified':False,'wall_clock_archival_order_independently_proven':False},'inputs':[{'path':n,**{k:r[k] for k in ('blob','bytes','sha256')}} for n,r in records.items()]}
out=B/'r33-Auth-entry38-root-result.public.json';data=(json.dumps(result,indent=2)+'\n').encode()
fd=os.open(out,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
try:
    v=memoryview(data)
    while v:
        n=os.write(fd,v);assert n>0;v=v[n:]
    os.fsync(fd)
finally:os.close(fd)
print(json.dumps({'ok':True,'checks_passed':len(checks),'result_path':str(out),**meta(data)}))
