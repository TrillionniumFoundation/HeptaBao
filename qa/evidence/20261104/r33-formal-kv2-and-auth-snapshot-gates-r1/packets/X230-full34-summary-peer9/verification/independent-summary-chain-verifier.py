import base64, hashlib, json, pathlib, re

P = pathlib.Path('/workspace/scratch/f86faac821c4/r32_recovery')
OUT = pathlib.Path('/workspace/scratch/f86faac821c4/ha_x230_full34_peer_r1')
TREE = 'f0f0770bbd740583e9db906627efd57f8a296906'
GO = '773ffa99d027be4cd77e265b3a40f8432864139c'
JOB = '1a1ad5ffad0-fc05-599a'
SUMMARY_PATH = '/home/qian/heptabao-same-root-publication-normal-20261105-r1/evidence/full34-r1/summary.public.json'
VERSION = '2053:3066538:90926:1793910257046281214:1793910257046281214'
checks = []
def need(name, value):
    checks.append({'name': name, 'passed': bool(value)})
    if not value:
        raise AssertionError(name)
def wrapper(path):
    return json.loads(path.read_bytes())['text']
def meta(text):
    b=text.encode('utf-8')
    return {'blob':hashlib.sha1(b'blob '+str(len(b)).encode()+b'\0'+b).hexdigest(),'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest()}
def need_pin(name, text, pin):
    got=meta(text)
    need(name, all(got[k]==pin[k] for k in ('blob','bytes','sha256')))

packet=json.loads(wrapper(P/'x230-full34-summary-chains-packet.json'))
tree_sdk=json.loads(wrapper(P/'x230-full34-summary-chains-tree-sdk.json'))
need('tree_sdk_success',tree_sdk.get('isError',False) is False)
tree=json.loads(tree_sdk['structuredContent']['content'])
need('exact_tree_identity',tree['sha']==TREE and not tree.get('truncated',False))
entries=tree['tree']; leaves=[e for e in entries if e['type']=='blob']; dirs={e['path']:e['sha'] for e in entries if e['type']=='tree'}
dirs['']=TREE
need('exact_inventory',len(leaves)==107 and len(dirs)==31 and len(entries)==137)
need('safe_all_regular_packet',all(e['type'] in ('blob','tree') and '..' not in e['path'].split('/') and not e['path'].startswith('/') for e in entries))
F={}; actual_hash={}; records=[]
for e in leaves:
    path=e['path']; need('packet_path_pin:'+path,packet['files'][path]==e['sha'] and e['mode']=='100644')
    text=wrapper(P/('blob-'+e['sha']+'.json')); m=meta(text)
    need('whole_blob:'+path,m['blob']==e['sha'] and m['bytes']==e['size'])
    F[path]=text; actual_hash[path]=m['blob']; records.append({'path':path,**m})
need('whole_packet_bytes',sum(x['bytes'] for x in records)==781823)
need('whole_file_set',set(F)==set(packet['files']))
for r in packet['records']:
    need_pin('author_declared_pin:'+r['path'],F[r['path']],r)
for d in sorted(dirs,key=lambda x:(x.count('/'),len(x)),reverse=True):
    children=[e for e in entries if e['path'].rpartition('/')[0]==d]
    children.sort(key=lambda e:(e['path'].rsplit('/',1)[-1]+('/' if e['type']=='tree' else '')).encode())
    b=b''
    for e in children:
        name=e['path'].rsplit('/',1)[-1]
        b+=e['mode'].lstrip('0').encode()+b' '+name.encode()+b'\0'+bytes.fromhex(actual_hash[e['path']])
    sha=hashlib.sha1(b'tree '+str(len(b)).encode()+b'\0'+b).hexdigest()
    need('Merkle:'+(d or '<root>'),sha==dirs[d]); actual_hash[d]=sha

def read(path):
    return json.loads(F[path])
def call(label, method):
    p='calls/'+label+'/'
    rt=F[p+'request.original.json']; req=json.loads(rt); intent=read(p+'intent.public.json'); sdk=read(p+'result.original.sdk.json'); nt=F[p+'result.original.json']
    need(label+'.intent_request_value',intent['request']==req)
    need_pin(label+'.intent_request_pin',rt,{'blob':intent['request_blob'],'bytes':intent['request_bytes'],'sha256':intent['request_sha256']})
    need(label+'.intent_method_scope',intent['method']==method and intent['label']==label and intent['lane']=='B' and intent['GO']==GO and intent['process_start_authorized'] is False and intent['original_call_only'] is True)
    need(label+'.sdk_not_error',sdk.get('isError',False) is False and not sdk.get('transport_exception',False))
    need(label+'.sdk_text_exact',len(sdk['content'])==1 and sdk['content'][0]['type']=='text' and sdk['content'][0]['text']==nt)
    return req,intent,json.loads(nt)

expected=[
 ('summary-info','867d5e9f7afe790244296831583c76b72ded9f3c52e6bf2b2ad215288a4d600a','file_info',1,None,None),
 ('summary-body0','3791f6b9560e9c86be4b0ef8c4f152d8f99732c661d5ef115798f56e033fb9f9','binary_read',11,0,65536),
 ('summary-body1','6795dacaa192eda3e62bd6f3de615b035bc881b5bc5cc45e6e6cf989ed97cac2','binary_read',5,65536,25390)]
observers=[]; native={}; all_call_labels=[]
for label,oid,tool,page_count,offset,limit in expected:
    rq,it,ack=call(label+'-admission','operation_start'); all_call_labels.append(label+'-admission')
    args={'host':'x230','path':SUMMARY_PATH}
    if tool=='binary_read':args.update(offset=offset,limit=limit,expected_version=VERSION)
    need(label+'.exact_native_request',rq=={'idempotency_key':'heptabao-4e808-x230-full34-'+label+'-r1-20261105','operation':{'tool':tool,'arguments':args}})
    need(label+'.unique_admission',ack['operation_id']==oid and ack['tool_name']==tool and ack['reused'] is False and it['prior_active_operation_id'] is None)
    sr,si,status=call(label+'-status','operation_status'); all_call_labels.append(label+'-status')
    need(label+'.same_status_id',sr=={'operation_id':oid} and si['prior_active_operation_id']==oid and status['operation_id']==oid and status['tool_name']==tool)
    need(label+'.closed',status['async_state']=='completed' and status['result_state']=='stored_observed' and status['owned_future_active'] is False and status['payload_available'] is True)
    pages=sorted({p.split('/')[1] for p in F if p.startswith('calls/'+label+'-page-')})
    need(label+'.exact_page_count',len(pages)==page_count)
    joined=b''; total=None; digest=None; page_rows=[]
    for number,page_label in enumerate(pages):
        req,intent,page=call(page_label,'operation_result'); all_call_labels.append(page_label)
        want_offset=number*8192
        need(page_label+'.request_exact',req=={'operation_id':oid,'offset':want_offset,'limit':8192} and intent['prior_active_operation_id']==oid)
        need(page_label+'.immutable_id',page['operation_id']==oid and page['immutable_snapshot'] is True and page['payload_kind']=='native_result')
        if total is None:total=page['total_bytes']; digest=page['result_sha256']
        b=base64.b64decode(page['data_base64'],validate=True); want=min(8192,total-want_offset)
        need(page_label+'.whole_payload_binding',page['total_bytes']==total and page['result_sha256']==digest)
        need(page_label+'.original_geometry',page['offset']==want_offset and page['next_offset']==want_offset+want and len(b)==want and page['eof']==(want_offset+want==total))
        joined+=b; page_rows.append({'label':page_label,'offset':want_offset,'bytes':len(b)})
    payload_path='observations/'+label+'/payload.original.json'; native_path='observations/'+label+'/native.original.json'
    need(label+'.payload_length_digest',len(joined)==total and hashlib.sha256(joined).hexdigest()==digest)
    need(label+'.payload_original_exact',joined==F[payload_path].encode())
    payload=json.loads(joined)
    need(label+'.native_success',payload['resultType']=='complete' and payload['isError'] is False)
    need(label+'.native_text_exact',len(payload['content'])==1 and payload['content'][0]['type']=='text' and payload['content'][0]['text']==F[native_path])
    native[label]=read(native_path)
    observers.append({'label':label,'operation_id':oid,'tool':tool,'pages':page_count,'payload':meta(F[payload_path]),'native':meta(F[native_path]),'closed':True})
    if tool=='binary_read':
        c=read('observations/'+label+'/closure.public.json')
        need(label+'.closure_id_flags',c['job_id']==JOB and c['GO']==GO and c['active_operation_id']==oid and c['fully_closed'] is True and c['complete'] is True and c['halted'] is False and c['call_inflight'] is False)
        need(label+'.closure_extent',c['next_offset']==total and c['total_bytes']==total and c['result_sha256']==digest and len(c['pages'])==page_count)
        need_pin(label+'.closure_payload_pin',F[payload_path],c['payloadPin']); need_pin(label+'.closure_native_pin',F[native_path],c['nativePin'])
        for cr,pr in zip(c['pages'],page_rows):
            cp='calls/'+pr['label']+'/'
            need(pr['label']+'.closure_geometry',cr['offset']==pr['offset'] and cr['bytes']==pr['bytes'])
            need(pr['label']+'.closure_request_pins',cr['request_blob']==meta(F[cp+'request.original.json'])['blob'] and cr['intent_blob']==meta(F[cp+'intent.public.json'])['blob'])
            need_pin(pr['label']+'.closure_sdk_pin',F[cp+'result.original.sdk.json'],cr['sdk']); need_pin(pr['label']+'.closure_native_pin',F[cp+'result.original.json'],cr['native'])

all_actual_calls={p.split('/')[1] for p in F if p.startswith('calls/')}
need('exact_23_call_set',len(all_call_labels)==23 and set(all_call_labels)==all_actual_calls)
info=native['summary-info']
need('summary_info_identity',info['path']==SUMMARY_PATH and info['size']==90926 and info['version']==VERSION and info['sha256']=='b9966b600df2f2c681148b63d03dca3bbceabcdff3fb42dc1eb4bae73677ae9f')
data=b''
for label,offset,size,eof in [('summary-body0',0,65536,False),('summary-body1',65536,25390,True)]:
    n=native[label]; b=base64.b64decode(n['data_base64'],validate=True)
    need(label+'.native_version_extent',n['path']==SUMMARY_PATH and n['version']==VERSION and n['size']==90926 and n['offset']==offset and n['next_offset']==offset+size and len(b)==size and n['eof'] is eof)
    need(label+'.native_chunk_hash',hashlib.sha256(b).hexdigest()==n['chunk_sha256']); data+=b
need('summary_whole_native_exact',data==F['actual/summary.public.json'].encode() and len(data)==90926 and hashlib.sha256(data).hexdigest()==info['sha256'])
need('summary_content_address',meta(F['actual/summary.public.json'])['blob']=='1368fb13c2478606a2e730ef13f942ede824114b')

# Carry the already accepted base156 forward by its exact source/journal identities; do not rerun that checker.
base=json.loads((OUT/'base-input.json').read_bytes()); jt=base['reference/recovery-journal.public.json']; journal=json.loads(jt)
need('base_journal_exact',meta(jt)['blob']=='83f37c59fa1ca23c12b0583a256db89081ab4388')
pending=journal['next_exact_original_page']; pp='calls/summary-body0-page-000000/'
need('cache_boundary_same_original_page',pending=={'method':'operation_result','request_blob':meta(F[pp+'request.original.json'])['blob'],'intent_blob':meta(F[pp+'intent.public.json'])['blob'],'operation_id':expected[1][1],'offset':0,'limit':8192,'submitted':False})
need('cache_boundary_body1_not_yet_submitted',journal['next_new_body_chunk_submitted'] is False)
for path,sha in journal['known_blobs'].items():
    if path in F:need('pre_reset_known_exact:'+path,meta(F[path])['blob']==sha)
source=F['reference/post-reset-page-orchestrator.js']
need('page_recovery_source_only_result',re.findall(r'tools\.mcp__codex_apps__heptaruntime_mac_controller_(\w+)',source)==['operation_result'])
state=read('STATE.public.json')
need('state_narrow_three_ids',state['job_id']==JOB and state['body0_operation']==expected[1][1] and state['body1_operation']==expected[2][1] and state['immutable_page_count']==16 and state['meta_observer_pages']==1)
need('historical_unlocated_not_recovered',state['earliest_three_framework_indexes_unlocated'] is True and 'not a recovered SDK ID binding' in state['historical_ids_source'])
need('no_old_historical_calls_in_increment',not any('/authority0-' in p or '/authority1-' in p or '/streams0-' in p for p in F))
result={'schema':'heptabao.x230.full34.independent-summary-chain-increment.v1','passed':True,'source_tree':TREE,'source_files':107,'source_bytes':781823,'Merkle_trees':31,'checks':len(checks),'observers':observers,'native_operations':3,'immutable_pages':17,'native_summary_chunks':2,'native_summary_bytes':90926,'original_call_records':23,'carried_base_review':'390a10b882789b03c3a559cdfdfafb0f4573d107','base156_reexecuted':False,'prior39_unlocated_leaves_preserved':True,'new_current2_observation_packet_reviewed':False,'Runtime_calls_by_this_verifier':0,'author_checker_executed':False,'product_semantics_reviewed':False,'checks_detail':checks}
(OUT/'summary-increment-result.public.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n')
(OUT/'summary-increment-input-index.public.json').write_text(json.dumps({'tree':TREE,'files':records,'base_journal':meta(jt)},ensure_ascii=False,indent=2)+'\n')
print(json.dumps({k:v for k,v in result.items() if k not in ('checks_detail','observers')},ensure_ascii=False))
