"""Independent offline root review of the one H2 stage and supplied observer records."""
import json,hashlib,base64,pathlib,os
B=pathlib.Path('/workspace/scratch/f86faac821c4/r32_recovery')
TREE='a78dc168435d5951385ef2a01d377524bfc68d83'
GO='065ae72edbb8f330b66f5a40ea4c0134891f60d8'
REQUEST='773c7e054a36dfc175632a83ed23db5b5600ad58'
JOB='1a1adb7c0f6-fc05-5ab6'
DIGEST='d09ca5bcec50de31ca854f1b2885ed117bd7a3c6f357d6db39fbc87cd6566a96'
FP=15032071887093030449
checks=[]
def ck(n,b):
    if b is not True:raise AssertionError(n)
    checks.append(n)
def wrapper(n):
    x=json.loads((B/n).read_text())
    assert isinstance(x,dict) and isinstance(x.get('text'),str)
    return x['text']
def meta(d):
    return {'blob':hashlib.sha1(b'blob '+str(len(d)).encode()+b'\0'+d).hexdigest(),'bytes':len(d),'sha256':hashlib.sha256(d).hexdigest()}
packet=json.loads(wrapper('ha-h2-stage-actual-packet.json'))
records={r['path']:r for r in packet['records']}
ck('fixed_tree_and106_unique_paths',packet['tree']==TREE and len(records)==len(packet['records'])==106)
raw={}
for n,pin in records.items():
    d=wrapper('blob-'+pin['blob']+'.json').encode()
    ck('whole:'+n,all(meta(d)[k]==pin[k] for k in ('blob','bytes','sha256')))
    raw[n]=d
ck('whole_total1058439',sum(map(len,raw.values()))==1058439)
ts=json.loads(wrapper('ha-h2-stage-actual-tree-sdk.json'))
ck('original_tree_SDK_no_error',ts.get('isError') is not True)
tree=json.loads(ts['structuredContent']['content'])
ck('exact_tree_full_not_truncated',tree['sha']==TREE and tree['truncated'] is False)
leaves={x['path']:x for x in tree['tree'] if x['type']=='blob'}
ck('exact_leaf_set',set(leaves)==set(records))
for n,x in leaves.items():
    ck('leaf:'+n,x['sha']==records[n]['blob'] and x['size']==len(raw[n]) and x['mode']=='100644')
top={}
for n,r in records.items():
    at=top;parts=n.split('/')
    for p in parts[:-1]:at=at.setdefault(p,{})
    at[parts[-1]]=r['blob']
treepins=[]
def walk(at,prefix=''):
    rows=[]
    for n,v in at.items():
        directory=isinstance(v,dict)
        h=walk(v,prefix+n+'/') if directory else v
        rows.append((n,directory,h))
    rows.sort(key=lambda x:(x[0]+('/' if x[1] else '')).encode())
    body=b''.join(('40000' if d else '100644').encode()+b' '+n.encode()+b'\0'+bytes.fromhex(h) for n,d,h in rows)
    h=hashlib.sha1(b'tree '+str(len(body)).encode()+b'\0'+body).hexdigest()
    treepins.append({'path':prefix[:-1],'sha':h});return h
ck('Merkle_rebuilt_root',walk(top)==TREE)
ck('17_Merkle_nodes',len(treepins)==17)
for p in treepins:
    ck('Merkle:'+p['path'],p['sha']==TREE if p['path']=='' else any(x['path']==p['path'] and x['type']=='tree' and x['sha']==p['sha'] for x in tree['tree']))
def obj(n):return json.loads(raw[n])
def pe(pin,n):return all(pin[k]==records[n][k] for k in ('blob','bytes','sha256'))
def pair(s,n):
    x=obj(s)
    ck('SDK_no_error:'+s,x.get('isError') is False)
    ck('SDK_native_exact:'+s,len(x['content'])==1 and x['content'][0]['type']=='text' and x['content'][0]['text'].encode()==raw[n])
    return obj(n)
go=obj('references/ROOT-GO.public.json')
req=obj('execution/request.original.json')
intent=obj('execution/intent.original.json')
ck('exact_original_GO_request',records['references/ROOT-GO.public.json']['blob']==GO and records['execution/request.original.json']['blob']==REQUEST and pe(go['request'],'execution/request.original.json'))
ck('exact_execution_intent',pe(intent['authorization'],'references/ROOT-GO.public.json') and pe(intent['original_raw_request'],'execution/request.original.json') and intent['one_start_only'] is True and intent['automatic_replay'] is False and intent['Runtime_START_submitted_before_this_intent'] is False)
ck('exact_controller_literal',req['args'][4].encode()==raw['references/stage-source.py'] and records['references/stage-source.py']['blob']=='678e519f17c474b5610651bcbb93b43d186124c5')
ck('exact_argv_and_stage_limits',req['args'][:4]==['-I','-S','-B','-c'] and req['args'][5:]==['--external-controller-sha256',go['candidate_sha256']] and req['timeout_seconds']==go['outer_timeout_seconds']==330 and go['controller_deadline_seconds']==300)
stdinmeta=meta(req['stdin'].encode())
ck('exact_whole_stdin',stdinmeta['blob']==go['carrier_blob']==intent['exact_stdin']['blob'] and stdinmeta['sha256']==go['carrier_sha256']==intent['exact_stdin']['sha256'] and stdinmeta['bytes']==321152)
typed={k:req.get(k) for k in ('cpu_quota_percent','cwd','memory_max_bytes','nice','stdin','timeout_seconds')}
typed.update(args=req.get('args',[]),env=req.get('env',{}),executable=req['executable'],host=req['host'])
canonical=json.dumps(typed,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()
digest=hashlib.sha256(canonical).hexdigest()
ck('independent_native_canonical_digest',digest==DIGEST==go['typed_request_sha256']==intent['expected_typed_request_sha256'])
ck('independent_native_fingerprint',int(digest[:16],16)==FP and go['native_fingerprint']==intent['expected_native_fingerprint_decimal']==str(FP))
ack=pair('execution/ACK.original.sdk.json','execution/ACK.original.native.json')
job=ack['job']
ck('single_unreused_successful_ACK',ack['reused'] is False and ack['launch']['ok'] is True and job['launch_state']=='launched' and job['id']==JOB)
for k in ('host','executable','args','cwd','idempotency_key'):ck('ACK_request:'+k,job[k]==req[k])
ck('ACK_exact_native_binding',job['request_digest']==DIGEST and type(job['request_fingerprint']) is int and job['request_fingerprint']==FP)
ck('stage_only_authority',go['prepare_authorized'] is False and go['live_authorized'] is False and go['product_cases_executed_by_this_GO']==0 and go['production_cutover'] is False)
observations=[];total_pages=0;archived_calls=0
for role,tool,streamoff,total in [('authority0','process_status',None,912),('streams0','process_read',0,53296),('streams1','process_read',16384,22218)]:
    pre='observations/'+role+'/'
    request=obj(pre+'request.original.json');it=obj(pre+'intent.original.json')
    admission=pair(pre+'admission.original.sdk.json',pre+'admission.original.native.json')
    sid=admission['operation_id']
    ck('observer_exact_intent:'+role,pe(it['request'],pre+'request.original.json') and (it.get('root_go')==GO or it.get('GO',{}).get('blob')==GO))
    args={'host':'desktop','job_id':JOB}
    if streamoff is not None:args.update(stdout_offset=streamoff,stderr_offset=0,limit=16384)
    ck('observer_fixed_same_job:'+role,request['operation']['tool']==tool and request['operation']['arguments']==args)
    ck('observer_unique_admission:'+role,admission['tool_name']==tool and admission['reused'] is False and admission['idempotency_binding_retained'] is True)
    statusreq=obj(pre+'status.request.original.json');statusintent=obj(pre+'status.intent.original.json')
    status=pair(pre+'status.original.sdk.json',pre+'status.original.native.json')
    ck('same_original_status_identity:'+role,statusreq=={'operation_id':sid} and status['operation_id']==sid and status['tool_name']==tool)
    ck('status_exact_intent:'+role,pe(statusintent['request'],pre+'status.request.original.json') and statusintent['root_go']==GO)
    ck('observer_closed:'+role,status['async_state']=='completed' and status['result_state']=='stored_observed' and status['owned_future_active'] is False and status['payload_available'] is True)
    if role=='authority0':
        ck('explicit_new_same_ID_reconciliation',statusintent['schema']=='heptabao.same-id-status.reconciliation.intent.v1' and statusintent['original_operation_id']==sid and statusintent['business_start'] is False and statusintent['operation_start'] is False and 'unknown' in statusintent['prior_query_boundary'])
    pagepaths=sorted(n for n in records if n.startswith(pre+'pages/') and n.endswith('.request.original.json'))
    expectedoffs=list(range(0,total,8192))
    ck('exact_page_inventory:'+role,[int(n.split('/')[-1].split('.')[0]) for n in pagepaths]==expectedoffs)
    chunks=[];pagepins=[]
    for name,offset in zip(pagepaths,expectedoffs):
        base=name[:-len('.request.original.json')]
        q=obj(name);pi=obj(base+'.intent.original.json')
        native=pair(base+'.original.sdk.json',base+'.original.native.json')
        ck('page_exact_intent:'+name,pe(pi['request'],name) and pi['root_go']==GO and pe(pi['closed_status'],pre+'status.original.native.json') and pi['new_native_admission'] is False)
        ck('page_exact_request:'+name,q=={'operation_id':sid,'offset':offset,'limit':8192})
        d=base64.b64decode(native['data_base64'],validate=True)
        ck('page_identity:'+name,native['operation_id']==sid and native['offset']==offset and native['total_bytes']==total and native['immutable_snapshot'] is True and native['payload_kind']=='native_result')
        ck('page_size_cursor_EOF:'+name,len(d)==min(8192,total-offset) and native['next_offset']==offset+len(d) and native['eof'] is (offset+len(d)==total))
        ck('page_whole_SHA:'+name,native['result_sha256']==records[pre+'payload.original.json']['sha256'])
        chunks.append(d);pagepins.append({'offset':offset,'bytes':len(d),'page':records[base+'.original.native.json']})
    payloadraw=b''.join(chunks);payload=obj(pre+'payload.original.json')
    ck('whole_payload:'+role,payloadraw==raw[pre+'payload.original.json'] and len(payloadraw)==total)
    ck('payload_to_native_exact:'+role,payload['resultType']=='complete' and payload['isError'] is False and len(payload['content'])==1 and payload['content'][0]['type']=='text' and payload['content'][0]['text'].encode()==raw[pre+'native.original.json'])
    observations.append({'role':role,'id':sid,'status':records[pre+'status.original.native.json'],'payload':records[pre+'payload.original.json'],'native':records[pre+'native.original.json'],'pages':pagepins,'closed':True})
    total_pages+=len(pagepaths);archived_calls+=2+len(pagepaths)
ck('three_distinct_returned_observers',len({o['id'] for o in observations})==3)
ck('11_pages_17_archived_readonly_calls',total_pages==11 and archived_calls==17)
authority=obj('observations/authority0/native.original.json')
ck('terminal_complete_durable_zero',authority['job_id']==JOB and authority['state']=='succeeded' and authority['exit_code']==0 and authority['output_complete'] is True and authority['output_durable'] is True and authority['terminal_publication_confirmed'] is True and authority['timed_out'] is False and authority['cancelled'] is False)
whole={'stdout':b'','stderr':b''}
for role,offset in [('streams0',0),('streams1',16384)]:
    x=obj('observations/'+role+'/native.original.json')
    ck('stream_job:'+role,x['job_id']==JOB)
    for kind,size,off in [('stdout',23147,offset),('stderr',0,0)]:
        r=x[kind];d=bytes.fromhex(r['bytes_hex'])
        ck('stream_hex_text:'+role+kind,d==r['text'].encode())
        ck('stream_cursor_EOF:'+role+kind,r['offset']==off and r['next_offset']==off+len(d) and r['size']==size and r['eof'] is (r['next_offset']==size))
        if kind=='stdout':whole[kind]+=d
        else:ck('stderr_empty:'+role,len(d)==0)
for kind,size,path in [('stdout',23147,'actual/stdout.original.json'),('stderr',0,'actual/stderr.original.txt')]:
    ck('stream_archived_whole:'+kind,whole[kind]==raw[path] and len(raw[path])==size)
    ck('authority_stream_binding:'+kind,authority['log_bytes'][kind]=={'seen':size,'stored':size} and authority['log_errors'][kind] is None and authority['log_synced'][kind] is True and authority['log_truncated'][kind] is False)
out=obj('actual/stdout.original.json')
ck('post_finally_owned_FD_closure',out['status']=='passed' and out['all_stage_fds_closed'] is True and out['fd_close_pending'] is False and out['fd_close_errors']==[])
ck('post_finally_original_bound',out['within_stage_deadline'] is True and out['elapsed_after_closure_ms']==2438.209864 and out['elapsed_after_closure_ms']<300000)
ck('stage_no_products_or_production',out['children_spawned']==0 and out['network_calls']==0 and out['product_started'] is False and out['readonly_prepare_started'] is False and out['production_changed'] is False)
ck('source_carrier_report',out['external_controller_sha256']==go['candidate_sha256'] and out['source_carrier_sha256']==go['carrier_sha256'] and out['source_commit']=='4e808d0ecb1bcded22870a7ec960dfb2491cf6ec' and out['source_tree']=='eba5e650bd080b8ad41ea52a2bc68867f541d255')
binding=out['binding']
ck('original_binding_exact_large_integers',binding['bytes']==10230 and binding['sha256']=='b241c6fc78bbe77ea69fc3b8a707b1747324a81f1da1ade3d9bb15c5cea5b7d8' and binding['mtime_ns']==binding['ctime_ns']==1793915867275098276)
boundary=obj('recovery/limited-boundary.public.json')
ck('explicit_preserved_unknown_status_boundary',boundary['original_stage_id']==JOB and boundary['original_authority_observer']==observations[0]['id'] and boundary['stage_restart'] is False and 'unknown' in boundary['before_new_reconciliation'])
result={'schema':'heptabao.H2-current-stage.independent-root-original-chain.v1','ok':True,'checks_passed':len(checks),'checks':checks,'source_tree':TREE,'whole_files':len(records),'whole_bytes':sum(map(len,raw.values())),'Merkle_nodes':len(treepins),'job':'desktop/'+JOB,'native_digest':digest,'native_fingerprint_decimal':str(FP),'returned_observers':observations,'original_immutable_pages':total_pages,'archived_readonly_calls':archived_calls,'stdout':records['actual/stdout.original.json'],'stderr':records['actual/stderr.original.txt'],'binding_writer':binding,'historical_boundary':boundary,'scope':{'returned_original_observers_payloads_qualified':True,'all_possible_prior_status_queries_recovered':False,'candidate_or_QA_or_author_checker_executed':False,'Runtime_calls':0,'remote_Git_reads':0,'target_file_reads':0,'prepare_live_qualified':False,'product_cases_added':0,'full_replacement':False},'inputs':[{'path':n,**{k:r[k] for k in ('blob','bytes','sha256')}} for n,r in records.items()]}
outpath=B/'r33-H2-stage-original-chain-root-result.public.json'
data=(json.dumps(result,indent=2)+'\n').encode()
fd=os.open(outpath,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
try:
    v=memoryview(data)
    while v:
        n=os.write(fd,v);assert n>0;v=v[n:]
    os.fsync(fd)
finally:os.close(fd)
print(json.dumps({'ok':True,'checks_passed':len(checks),'result_path':str(outpath),**meta(data)}))
