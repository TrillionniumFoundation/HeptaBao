"""Offline verification of one archived CLI stage and its two observers.

Input: fixed local JSON {text} blobs and the original packet/tree SDK.
No SDK, candidate, authored verifier, remote target, or network is invoked.
"""
import argparse,base64,hashlib,json,os,pathlib

P=argparse.ArgumentParser()
P.add_argument('--cache-root',type=pathlib.Path,required=True)
P.add_argument('--packet-index',type=pathlib.Path,required=True)
P.add_argument('--tree-sdk',type=pathlib.Path,required=True)
P.add_argument('--out',type=pathlib.Path,required=True)
A=P.parse_args()
TREE='3ec3bec37a6ef1270525c017618eda810edc8044'
JOB='1a1ada8b25f-fc05-5a8d'
GO='2e6623f5d7c9a05e66e4c22b1485dba8a1924d56'
REQUEST='ec3b323f77bfb2f111f5fc22a06f1bf30ea634eb'
DIGEST='8a10353c991430800ffe9e2c9ec33a375ff33a6254b3d335abebb8b14ac9c67e'
FINGERPRINT=9948510111243972736
checks=[];inputs=[]
def check(name,value):
    if value is not True:raise AssertionError(name)
    checks.append(name)
def unwrap(p):
    value=json.loads(p.read_text());assert isinstance(value,dict) and isinstance(value.get('text'),str)
    return value['text']
def meta(d):
    return {'blob':hashlib.sha1(b'blob '+str(len(d)).encode()+b'\0'+d).hexdigest(),
            'bytes':len(d),'sha256':hashlib.sha256(d).hexdigest()}
packet=json.loads(unwrap(A.packet_index));check('packet_tree_identity',packet['tree']==TREE)
records={r['path']:r for r in packet['records']};raw={}
check('63_unique_original_leaves',len(records)==len(packet['records'])==63)
for name,pin in records.items():
    local=A.cache_root/('blob-'+pin['blob']+'.json')
    d=unwrap(local).encode();actual=meta(d)
    check('whole:'+name,all(actual[k]==pin[k] for k in actual))
    raw[name]=d;inputs.append({'packetPath':name,'localWrapper':str(local),**actual})
check('whole_total_bytes',sum(len(v) for v in raw.values())==1007838)
tree_sdk=json.loads(unwrap(A.tree_sdk));check('tree_sdk_no_error',tree_sdk.get('isError') is not True)
tree=json.loads(tree_sdk['structuredContent']['content'])
check('whole_tree_not_truncated',tree['sha']==TREE and tree['truncated'] is False)
leaves={r['path']:r for r in tree['tree'] if r['type']=='blob'}
check('tree_exact_leaf_set',set(leaves)==set(records))
for name,v in leaves.items():check('tree_leaf:'+name,v['sha']==records[name]['blob'] and v['size']==records[name]['bytes'] and v['mode']=='100644')
top={}
for name,r in records.items():
    at=top;parts=name.split('/')
    for part in parts[:-1]:at=at.setdefault(part,{})
    at[parts[-1]]=r['blob']
tree_pins=[]
def walk(node,prefix=''):
    entries=[]
    for name,value in node.items():
        directory=isinstance(value,dict);h=walk(value,prefix+name+'/') if directory else value
        entries.append((name,directory,h))
    entries.sort(key=lambda v:(v[0]+('/' if v[1] else '')).encode())
    body=b''.join(('40000' if d else '100644').encode()+b' '+n.encode()+b'\0'+bytes.fromhex(h) for n,d,h in entries)
    h=hashlib.sha1(b'tree '+str(len(body)).encode()+b'\0'+body).hexdigest();tree_pins.append({'path':prefix[:-1],'sha':h});return h
check('whole_merkle_root',walk(top)==TREE)
check('21_merkle_nodes',len(tree_pins)==21)
for p in tree_pins:
    check('merkle:'+p['path'],p['sha']==TREE if not p['path'] else any(x['path']==p['path'] and x['type']=='tree' and x['sha']==p['sha'] for x in tree['tree']))
def obj(n):return json.loads(raw[n])
def pin_equal(pin,name):return all(pin[k]==records[name][k] for k in ('blob','bytes','sha256'))
def sdk_pair(sdk_path,native_path):
    sdk=obj(sdk_path);check('SDK_no_error:'+sdk_path,sdk.get('isError') is False)
    content=sdk.get('content');check('SDK_single_original_text:'+sdk_path,isinstance(content,list) and len(content)==1 and content[0].get('type')=='text')
    check('SDK_native_bytes_exact:'+native_path,content[0]['text'].encode()==raw[native_path])
    return obj(native_path)
go=obj('reference/root-GO.original.json');request=obj('source/exact-request.original.json');intent=obj('execution/intent.public.json')
check('exact_GO_request',records['reference/root-GO.original.json']['blob']==GO and records['source/exact-request.original.json']['blob']==REQUEST and pin_equal(go['request'],'source/exact-request.original.json'))
check('execution_intent_exact_request',pin_equal(intent['request'],'source/exact-request.original.json') and pin_equal(intent['go'],'reference/root-GO.original.json'))
check('execution_intent_source_carrier',pin_equal(intent['candidate'],'source/controller.py') and pin_equal(intent['stdin_carrier'],'source/carrier.original.json'))
check('controller_literal_bytes',request['args'][4].encode()==raw['source/controller.py'])
check('controller_exact_argv',request['args'][:4]==['-I','-S','-B','-c'] and request['args'][5:]==['--external-controller-sha256',records['source/controller.py']['sha256']])
check('carrier_exact_stdin',request['stdin'].encode()==raw['source/carrier.original.json'])
check('original_stage_bounds',request['timeout_seconds']==330 and go['controller_deadline_seconds']==300 and request['host']=='desktop' and request['executable']=='/usr/bin/python3.12')
check('stage_only_GO',go['prepare_authorized'] is False and go['live_authorized'] is False and go['production_cutover'] is False)
ack=sdk_pair('execution/ACK.original.sdk.json','execution/ACK.original.json');job=ack['job']
check('unique_original_job_ACK',ack['reused'] is False and ack['launch']['ok'] is True and job['id']==JOB and job['launch_state']=='launched')
for key in ('host','executable','args','cwd','idempotency_key'):check('ACK_request:'+key,job[key]==request[key])
check('lossless_native_fingerprint',type(job['request_fingerprint']) is int and job['request_fingerprint']==FINGERPRINT and go['native_fingerprint']==str(FINGERPRINT) and intent['native_fingerprint']==str(FINGERPRINT))
check('native_digest_root_binding',job['request_digest']==go['typed_request_sha256']==intent['typed_request_sha256']==DIGEST)
call_dirs=sorted({name.split('/')[1] for name in records if name.startswith('calls/')})
expected=['authority-admission','authority-status','authority-page-000000','streams0-admission','streams0-status']+['streams0-page-'+str(i).zfill(6) for i in range(0,40961,8192)]
check('exact_11_readonly_calls',set(call_dirs)==set(expected) and len(call_dirs)==11)
calls={};native_calls={}
for name in call_dirs:
    prefix='calls/'+name;req=obj(prefix+'/request.original.json');i=obj(prefix+'/intent.public.json')
    n=sdk_pair(prefix+'/result.original.sdk.json',prefix+'/result.original.json')
    check('call_exact_intent:'+name,pin_equal(i['request'],prefix+'/request.original.json') and i['GO']==GO and i['original_business_request']==REQUEST and i['original_job']==JOB and i['business_replay'] is False and i['external_before_call'] is True)
    kind='operation_start' if name.endswith('-admission') else ('operation_status' if name.endswith('-status') else 'operation_result')
    check('call_tool:'+name,i['tool']==kind)
    calls[name]=req;native_calls[name]=n
observers=[]
for role,tool,total,page_offsets in [('authority','process_status',912,[0]),('streams0','process_read',44216,list(range(0,40961,8192)))]:
    admit=calls[role+'-admission'];a=native_calls[role+'-admission'];status_req=calls[role+'-status'];s=native_calls[role+'-status'];op=a['operation_id']
    args=admit['operation']['arguments'];check('observer_same_job:'+role,admit['operation']['tool']==tool and args['host']=='desktop' and args['job_id']==JOB)
    if role=='streams0':check('one_bounded_both_stream_read',args=={'host':'desktop','job_id':JOB,'stdout_offset':0,'stderr_offset':0,'limit':16384})
    check('observer_single_admission:'+role,a['reused'] is False and a['tool_name']==tool and a['idempotency_binding_retained'] is True)
    check('observer_same_status_id:'+role,status_req=={'operation_id':op} and s['operation_id']==op and s['tool_name']==tool)
    check('observer_closed:'+role,s['async_state']=='completed' and s['result_state']=='stored_observed' and s['owned_future_active'] is False and s['payload_available'] is True)
    payload_path='observations/'+role+'/payload.original.json';native_path='observations/'+role+'/native.original.json';chunks=[];page_records=[]
    for offset in page_offsets:
        name=role+'-page-'+str(offset).zfill(6);req=calls[name];p=native_calls[name]
        check('page_same_exact_request:'+name,req=={'operation_id':op,'offset':offset,'limit':8192})
        d=base64.b64decode(p['data_base64'],validate=True)
        check('page_identity:'+name,p['operation_id']==op and p['offset']==offset and p['total_bytes']==total and p['immutable_snapshot'] is True and p['payload_kind']=='native_result')
        check('page_boundary:'+name,len(d)==min(8192,total-offset) and p['next_offset']==offset+len(d) and p['eof'] is (offset+len(d)==total))
        check('page_payload_SHA:'+name,p['result_sha256']==records[payload_path]['sha256'])
        chunks.append(d);page_records.append({'name':name,'offset':offset,'bytes':len(d),'eof':p['eof'],'native':records['calls/'+name+'/result.original.json']})
    check('whole_payload:'+role,b''.join(chunks)==raw[payload_path] and len(raw[payload_path])==total)
    payload=obj(payload_path);check('payload_complete_no_error:'+role,payload['resultType']=='complete' and payload['isError'] is False)
    check('payload_to_native_exact:'+role,len(payload['content'])==1 and payload['content'][0]['type']=='text' and payload['content'][0]['text'].encode()==raw[native_path])
    observers.append({'role':role,'operationId':op,'nativeTool':tool,'pages':page_records,'payload':records[payload_path],'native':records[native_path],'completedStoredInactive':True})
check('two_distinct_original_observers',len({o['operationId'] for o in observers})==2)
authority=obj('observations/authority/native.original.json');streams=obj('observations/streams0/native.original.json')
check('same_job_native_observations',authority['job_id']==streams['job_id']==JOB)
check('authority_zero_complete_durable',authority['state']=='succeeded' and authority['exit_code']==0 and authority['output_complete'] is True and authority['output_durable'] is True and authority['terminal_publication_confirmed'] is True and authority['timed_out'] is False and authority['cancelled'] is False)
for kind,size in [('stdout',13593),('stderr',0)]:
    row=streams[kind];d=bytes.fromhex(row['bytes_hex'])
    check('stream_hex_text_original:'+kind,d==row['text'].encode()==raw['actual/'+kind+'.original.txt'])
    check('stream_range_and_EOF:'+kind,row['offset']==0 and row['next_offset']==row['size']==size==len(d) and row['eof'] is True)
    check('authority_log_binding:'+kind,authority['log_bytes'][kind]=={'seen':size,'stored':size} and authority['log_errors'][kind] is None and authority['log_synced'][kind] is True and authority['log_truncated'][kind] is False)
stdout=obj('actual/stdout.original.txt')
check('post_finally_report_closed',stdout['status']=='passed' and stdout['all_stage_fds_closed'] is True and stdout['fd_close_pending'] is False and stdout['fd_close_errors']==[])
check('post_finally_original_deadline',stdout['within_stage_deadline'] is True and stdout['elapsed_after_closure_ms']==2139.90943 and stdout['elapsed_after_closure_ms']<300000)
check('reported_stage_only_no_candidate',stdout['children_spawned']==0 and stdout['network_calls']==0 and stdout['product_started'] is False and stdout['readonly_prepare_started'] is False and stdout['production_changed'] is False)
check('reported_source_and_carrier_SHA',stdout['external_controller_sha256']==records['source/controller.py']['sha256'] and stdout['source_carrier_sha256']==records['source/carrier.original.json']['sha256'])
result={'schema':'heptabao.cli-stage.authbus-peer.original-chain.v1','ok':True,'sourceTree':TREE,'checks':checks,'checksPassed':len(checks),'wholeFiles':63,'wholeBytes':1007838,'merkleNodes':21,
        'originalJob':'desktop/'+JOB,'originalReadCalls':11,'originalObservers':2,'originalImmutablePages':7,'observers':observers,'stdout':records['actual/stdout.original.txt'],'stderr':records['actual/stderr.original.txt'],
        'nativeFingerprintExactDecimal':str(FINGERPRINT),'nativeTypedDigestComparedToExactGO':DIGEST,'typedDigestAlgorithmReimplemented':False,
        'sourceBinding':'Exact original request argv controller bytes and stdin carrier bytes; native digest/fingerprint bound to root GO without floating-point conversion.',
        'inputs':inputs,'scope':{'RuntimeCalls':0,'remoteGitReads':0,'targetFileReads':0,'installedSdkExecution':0,'candidateExecution':0,'authorCheckerExecuted':False,'source41Or379Rerun':False,'productCasesClaimed':0,'independentFileReadbackQualified':False,'prepareOrLiveQualified':False}}
A.out.parent.mkdir(parents=True,exist_ok=True);data=(json.dumps(result,indent=2)+'\n').encode();fd=os.open(A.out,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
try:
    view=memoryview(data)
    while view:n=os.write(fd,view);assert n>0;view=view[n:]
    os.fsync(fd)
finally:os.close(fd)
print(json.dumps({'ok':True,'checksPassed':len(checks),'originalReadCalls':11,'observers':2,'pages':7,'resultPath':str(A.out),**meta(data)}))
