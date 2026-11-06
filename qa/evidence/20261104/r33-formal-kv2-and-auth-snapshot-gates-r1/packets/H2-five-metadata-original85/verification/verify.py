import base64, hashlib, json, pathlib

ROOT = pathlib.Path('/workspace/scratch/f86faac821c4/ha_h2_metadata5_actual_r1')
F = json.loads((ROOT / 'input.json').read_text())['files']
checks = []
def need(name, value):
    checks.append({'name': name, 'passed': bool(value)})
    if not value:
        raise AssertionError(name)
def meta(text):
    b = text.encode('utf-8')
    return {'blob': hashlib.sha1(b'blob '+str(len(b)).encode()+b'\0'+b).hexdigest(), 'bytes': len(b), 'sha256': hashlib.sha256(b).hexdigest()}
def read(path):
    return json.loads(F[path])
def pin(name, text, expected):
    actual = meta(text)
    for k in ('blob', 'bytes', 'sha256'):
        need(name+'.'+k, actual[k] == expected[k])
def sdk_text(path):
    a = read(path)
    need(path+'.not_error', a.get('isError', False) is False and not a.get('transport_exception', False))
    need(path+'.one_text', len(a['content']) == 1 and a['content'][0]['type'] == 'text')
    return a['content'][0]['text']

GO = read('reference/GO.public.json')
PLAN = read('reference/SOURCE_PLAN.public.json')
TABLE = read('actual/metadata5.public.json')
RELEASE = read('actual/LANE_A_RELEASE.public.json')
pin('GO', F['reference/GO.public.json'], {'blob':'8c5542d05ace15c6d1405852ff69b091fa6c88ce','bytes':9259,'sha256':'5e7475c2e5cd149681e33bb12bb3a7f875168a12052a4e91a260fb41163bea45'})
need('exact_five_indices', [r['index'] for r in GO['requests']] == list(range(7,12)))
ids=[]
total_payload=0
for r in GO['requests']:
    i=r['index']; p=f'observations/{i:02d}-{r["role"]}/'
    req=read(p+'request.original.json'); intent=read(p+'intent.public.json')
    pin(str(i)+'.exact_request', F[p+'request.original.json'], r)
    need(str(i)+'.closed_file_info_shape', req == {'idempotency_key':r['idempotency_key'],'operation':{'tool':'file_info','arguments':{'host':'desktop','path':r['target_path']}}})
    intent_req=intent['request'] if i==7 else intent['exact_request']
    intent_pin=intent['request_pin'] if i==7 else intent['request']
    need(str(i)+'.intent_request', intent_req==req)
    pin(str(i)+'.intent_request_pin', F[p+'request.original.json'], intent_pin)
    need(str(i)+'.intent_prior_closed', intent.get('previous_in_sequence_closed_indices',intent.get('previous_closed_indices'))==list(range(7,i)))
    need(str(i)+'.intent_expected', intent['expected_historical_receiver']==r['expected_historical_receiver'])
    for k in ('admission','status'):
        need(str(i)+'.'+k+'_SDK_exact', sdk_text(p+k+'.original.sdk.json')==F[p+k+'.original.json'])
    need(str(i)+'.page_SDK_exact', sdk_text(p+'pages/000000.original.sdk.json')==F[p+'pages/000000.original.json'])
    a=read(p+'admission.original.json'); s=read(p+'status.original.json'); page=read(p+'pages/000000.original.json')
    oid=a['operation_id']; ids.append(oid)
    need(str(i)+'.admission_file_info', a['tool_name']=='file_info' and a['reused'] is False)
    need(str(i)+'.status_same_id', s['operation_id']==oid and s['tool_name']=='file_info')
    need(str(i)+'.closed', s['async_state']=='completed' and s['result_state']=='stored_observed' and s['owned_future_active'] is False and s['payload_available'] is True)
    need(str(i)+'.status_exact_request', read(p+'status.request.original.json')=={'operation_id':oid})
    need(str(i)+'.page_exact_request', read(p+'pages/000000.request.original.json')=={'operation_id':oid,'offset':0,'limit':8192})
    for prefix, tool, request in [('status','operation_status',read(p+'status.request.original.json')),('pages/000000','operation_result',read(p+'pages/000000.request.original.json'))]:
        it=read(p+prefix+'.intent.public.json')
        need(str(i)+'.'+tool+'_intent', it['index']==i and it['tool']==tool and it['request']==request and it['authorization']=='8c5542d05ace15c6d1405852ff69b091fa6c88ce')
    b=base64.b64decode(page['data_base64'],validate=True); total_payload+=len(b)
    need(str(i)+'.immutable_identity', page['operation_id']==oid and page['immutable_snapshot'] is True)
    need(str(i)+'.original_page_extent', page['offset']==0 and page['next_offset']==len(b) and page['total_bytes']==len(b) and page['eof'] is True and len(b)<=8192)
    need(str(i)+'.payload_hash', hashlib.sha256(b).hexdigest()==page['result_sha256'])
    need(str(i)+'.payload_exact', b==F[p+'payload.original.json'].encode())
    out=read(p+'payload.original.json')
    need(str(i)+'.native_original_success', out['resultType']=='complete' and out['isError'] is False)
    need(str(i)+'.native_exact', len(out['content'])==1 and out['content'][0]['type']=='text' and out['content'][0]['text']==F[p+'native.original.json'])
    n=read(p+'native.original.json'); e=r['expected_historical_receiver']; v=n['version'].split(':')
    need(str(i)+'.version_decimal_lossless', len(v)==5 and all(x.isdigit() for x in v))
    full9=[v[0],v[1],str(n['metadata']['uid']),str(n['metadata']['gid']),str(32768+n['mode']),str(n['metadata']['link_count']),str(n['size']),v[3],v[4]]
    for key, expected in [('path',e['path']),('size',e['bytes']),('sha256',e['sha256']),('version',e['version'])]:
        need(str(i)+'.actual_'+key,n[key]==expected)
    need(str(i)+'.actual_full9',full9==e['full9_decimal'])
    need(str(i)+'.actual_platform_mode',n['metadata']['metadata_platform']=='linux' and n['metadata']['mode']==256 and n['mode']==256)
    c=read(p+'closure.public.json'); tr=next(x for x in TABLE['rows'] if x['index']==i)
    need(str(i)+'.closure_actual',c['operation_id']==oid and c['actual']==dict(n,full9_decimal=full9))
    pin(str(i)+'.closure_native_pin',F[p+'native.original.json'],c['actual_file_info'])
    pin(str(i)+'.closure_payload_pin',F[p+'payload.original.json'],c['immutable_payload'])
    need(str(i)+'.table_actual',tr['operation_id']==oid and tr['actual']==c['actual'] and tr['matched_historical_receiver'] is True)
    pin(str(i)+'.table_info_pin',F[p+'native.original.json'],tr['actual_info'])
    pin(str(i)+'.table_closure_pin',F[p+'closure.public.json'],tr['closure'])
need('unique_five_operations',len(set(ids))==5)
need('old_unknowns_exact',TABLE['historical_unknowns']==PLAN['historical_unknowns'])
need('zero_body_or_process',TABLE['body_read_RPC']==0 and TABLE['process_start']==0)
need('five_only',TABLE['new_native_operations']==5 and TABLE['original_immutable_pages']==5 and TABLE['new_runtime_errors']==0)
need('unobserved_target_not_promoted',TABLE['all_22_H2_stage_target_identities']=='UNOBSERVED' and TABLE['H2_stage_executed'] is False and TABLE['H2_prepare_or_live_executed'] is False)
need('release_exact_ids',RELEASE['operation_ids']==ids and RELEASE['current_Runtime_calls_in_flight']==0 and RELEASE['current_native_futures_active']==0)
pin('release_table',F['actual/metadata5.public.json'],RELEASE['actual_table'])
result={'schema':'heptabao.h2qa.metadata5.original-chain.verification.v1','passed':True,'checks':len(checks),'operation_count':5,'immutable_pages':5,'payload_bytes':total_payload,'independent_info_bytes':sum(meta(F[f'observations/{r["index"]:02d}-{r["role"]}/native.original.json'])['bytes'] for r in GO['requests']),'new_native_operations_by_verifier':0,'product_tests':0,'historical_UNKNOWN_preserved':True,'results':checks}
(ROOT/'result.public.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n')
print(json.dumps({k:v for k,v in result.items() if k!='results'},ensure_ascii=False))
