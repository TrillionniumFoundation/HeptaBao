#!/usr/bin/env python3
"""Offline original native-page and semantic closure checks; no author execution."""
import base64,hashlib,json,os,pathlib,sys,traceback
B=pathlib.Path('/workspace/scratch/f86faac821c4'); R=B/'r32_recovery'
checks=[]; result={'schema':'heptabao.r33.comparison69-and-H2-read-closure.root.r1','checks':checks,'runtimeCalls':0,'authorCodeExecuted':False}
def ck(n,v,d=None):
 r={'name':n,'ok':bool(v)}
 if d is not None:r['detail']=d
 checks.append(r)
def meta(b):return {'blob':hashlib.sha1(b'blob '+str(len(b)).encode()+b'\0'+b).hexdigest(),'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest()}
def jd(b):return json.loads(b)
def localblob(s):
 for p in [R/('blob-'+s+'.json'),R/('pending-'+s+'.json')]:
  if p.exists():
   b=jd(p.read_bytes())['text'].encode();ck('local_blob_identity:'+s,meta(b)['blob']==s);return b
 raise FileNotFoundError(s)
def sdkfile(p):
 x=jd(p.read_bytes());return jd(x['text']) if set(x)=={'text'} else x
def native(sdk):
 if sdk.get('isError'):raise ValueError('original SDK isError')
 v=sdk.get('structuredContent')
 if v is not None:return v
 texts=[x['text'] for x in sdk['content'] if x['type']=='text']
 if len(texts)!=1:raise ValueError('not one original text')
 return jd(texts[0])
def pages(prefix,op,total,sha,count,naming):
 chunks=[];off=0
 for i in range(count):
  p=R/naming(prefix,off);s=sdkfile(p);n=native(s);data=base64.b64decode(n['data_base64'],validate=True)
  ck('native_page:'+prefix+':'+str(off),n['operation_id']==op and n['offset']==off and n['next_offset']==off+len(data) and n['total_bytes']==total and n['result_sha256']==sha and n['immutable_snapshot'] and n['payload_kind']=='native_result' and len(data)==min(8192,total-off) and n['eof']==(off+len(data)==total))
  chunks.append(data);off+=len(data)
 b=b''.join(chunks);ck('original_payload_whole:'+prefix,len(b)==total and meta(b)['sha256']==sha)
 return b,native(jd(b))
try:
 # H2 interrupted only by archival API errors, not by the native body observation.
 d=B/'ha_h2_target_reads_r2/pending-git-recovery';rec=jd((d/'RECOVERY.local.public.json').read_bytes())
 for name,pin in rec['files'].items():
  b=pathlib.Path(pin['local_path']).read_bytes();ck('h2_recovery_original:'+name,meta(b)=={'blob':pin['expected_git_blob'],'bytes':pin['bytes'],'sha256':pin['sha256']})
 st=jd(localblob(rec['original_status_pin']['blob']))
 ck('h2_body0_handler_closed',st['operation_id']==rec['original_operation_id'] and st['async_state']=='completed' and st['result_state']=='stored_observed' and st['owned_future_active'] is False and st['payload_available'])
 payload,n=pages('ha-h2-target-receipt-body0',rec['original_operation_id'],22291,'77a0c97d77d791f4b25b491429f92a8587af9f25b1158c7e5bd8aabc9e63c01f',3,lambda p,o:p+'-page'+str(o).zfill(6)+'-sdk-fsynced.json')
 ck('h2_payload_exact_local_original',payload==(d/'payload.original.json').read_bytes())
 ck('h2_native_equal_original',n==jd((d/'native.original.json').read_bytes()))
 body=base64.b64decode(n['data_base64'],validate=True)
 ck('h2_chunk_hash_and_actual_bytes',body==(d/'receipt.body0.bin').read_bytes() and len(body)==16384 and hashlib.sha256(body).hexdigest()==n['chunk_sha256']=='4266332e50569244fa1ee981b1b489c18a5fa68fb8e5f15339618f79194509e0')
 ck('h2_original_fixed_range_version',n['path']=='/home/qian-qi/heptabao-ha-closure-20261103-r1/normal-native-h2-gate-control-r2/stage.result.public.json' and n['version']=='2050:7874336:28615:1793915867295097739:1793915867295097739' and n['offset']==0 and n['next_offset']==16384 and n['size']==28615 and n['eof'] is False)
 errors={k:sdkfile(pathlib.Path(v['local_path'])) for k,v in rec['files'].items() if k in ['original_git_write_error','git_lookup_404','git_write_error_record_failure']}
 ck('h2_archive_errors_preserved_separately',len(errors)==3 and all(x.get('isError') for x in errors.values()))
 result['H2']={'body0OriginalObserverClosed':True,'wholeOriginalPayload':meta(payload),'originalChunk':meta(body),'noNewRuntimeOrPageReplay':True,'remainingOriginalBodyAdmissions':2,'archiveRestorationRequiredBeforeResume':True}
 # Original X230 job and seven read futures.
 c=B/'comparison69_closed_public_r1';closure=jd((c/'local-read-closure.public.json').read_bytes())
 for name,pin in closure['files'].items():
  b=(c/name).read_bytes();ck('comparison_whole:'+name,meta(b)=={k:pin[k] for k in ['blob','bytes','sha256']})
 auth=jd((c/'authority.original.json').read_bytes());report=jd((c/'result.public.json').read_bytes());summaryraw=(c/'summary.public.json').read_bytes();summary=jd(summaryraw)
 ck('comparison_original_durable_terminal',auth['job_id']=='1a1adc377a3-fc05-5acb' and auth['exit_code']==0 and auth['state']=='succeeded' and auth['output_complete'] and auth['output_durable'] and auth['terminal_publication_confirmed'] and not auth['timed_out'] and not auth['cancelled'] and not auth['automatic_retry'])
 ck('comparison_original_stream_counts',auth['log_bytes']=={'stderr':{'seen':0,'stored':0},'stdout':{'seen':561,'stored':561}} and all(auth['log_synced'].values()) and not any(auth['log_truncated'].values()) and not any(auth['log_errors'].values()))
 ck('comparison_7_observers_23_pages',len(closure['observations'])==7 and sum(o['pages'] for o in closure['observations'])==23)
 natives={}
 for o in closure['observations']:
  st=jd(localblob(o['status_native']['blob']))
  ck('comparison_closed:'+o['name'],st['operation_id']==o['operation_id'] and st['async_state']=='completed' and st['result_state']=='stored_observed' and st['owned_future_active'] is False and st['payload_available'])
  p,n=pages('comparison69-'+o['name'],o['operation_id'],o['payload_bytes'],o['payload_sha256'],o['pages'],lambda p,o:p+'-page-'+str(o).zfill(6)+'-original-SDK.json')
  natives[o['name']]=n
 ck('comparison_authority_exact_original_payload',natives['authority0']==auth)
 chunks=[]
 for key,offset,size,eof in [('summary-body0',0,65536,False),('summary-body1',65536,38498,True)]:
  n=natives[key];data=base64.b64decode(n['data_base64'],validate=True)
  ck('summary_actual_fixed_chunk:'+key,n['version']=='2053:3074869:104034:1793916669702610630:1793916669702610630' and n['path']==report['summary_path'] and n['size']==104034 and n['offset']==offset and n['next_offset']==offset+size and n['eof']==eof and len(data)==size and hashlib.sha256(data).hexdigest()==n['chunk_sha256'])
  chunks.append(data)
 ck('summary_whole_original_two_chunks',b''.join(chunks)==summaryraw and len(summaryraw)==104034 and hashlib.sha256(summaryraw).hexdigest()==report['summary_sha256']=='51dbe8ec85e7e18434e48ecf627107267fb49284d18408c448f01a7d38929bc5')
 ck('comparison_no_gap_or_production_claim',report['ok'] and report['cases_match'] and report['owned_cleanup_completed'] and report['cleanup_errors']==[] and report['mismatched_cases']==[] and report['child_exit_code']==0 and not report['production_changed'] and not report['production_qualified'] and not report['full_openbao_compatibility'])
 ck('comparison_native_nonfixture',summary['native_storage']['profile']=='native_v6_file' and summary['native_storage']['fixture_options'] is False and summary['native_storage']['activation_status']==204)
 binding=summary['execution_binding'];oracle=binding['official_oracle']
 ck('current_candidate_binding',binding['candidate_source_sha']=='4e808d0ecb1bcded22870a7ec960dfb2491cf6ec' and binding['candidate_binary_sha256']=='cb840a0f275f5c56c5b60e774d613020160853495f821975df7a1451522e15f0' and binding['candidate_source_has_uncommitted_changes'] is False)
 ck('official271_server_tls_archive_binding',oracle['version']=='2.7.1' and oracle['product']=='OpenBao' and oracle['tls_verified'] and oracle['server_mode']=='server_not_dev' and oracle['storage']=='pebbledb' and oracle['archive_member_matches_executable'] and oracle['binary_sha256']=='535cf827b13753046757f5ec8b97ae0ef21f10a40ffe673f0d5e75616170f5ea' and oracle['artifact_sha256']=='0e2f1ce10d124e03112b50dd2fbec6b78003783253bc3a91587938f39d1e2243')
 expected_scope=['approle','core','edge_tls','identity','kv','operations','pki','system','token','totp','transit','userpass','wrapping']
 ck('scope13_exact',report['scope']==summary['scope']==expected_scope)
 lhs=summary['candidate_results'];rhs=summary['oracle_results']
 ck('both_exact_69_case_names',len(lhs['cases'])==len(rhs['cases'])==69 and set(lhs['cases'])==set(rhs['cases']))
 for name,a in lhs['cases'].items():
  z=rhs['cases'][name]
  ck('case:'+name,a['result']==z['result']=='passed' and a['http_status']==z['http_status'] and ((isinstance(a['http_status'],int) and a['http_status'] in a['expected_http_status'] and z['http_status'] in z['expected_http_status']) or (name in {'pki.lease_expire_lookup':'rejected_after_ttl','pki.revoked_lease_absent':'rejected_400_or_404'} and a['http_status']=={'pki.lease_expire_lookup':'rejected_after_ttl','pki.revoked_lease_absent':'rejected_400_or_404'}[name] and a['expected_http_status']==z['expected_http_status']==[400,404])) and a['method']==z['method'] and a['path_template']==z['path_template'] and a['semantics']==z['semantics'])
 ck('both_owned_cleanup_passed',all(v['cleanup']['result']=='passed' and v['cleanup']['failure_count']==0 and v['cleanup']['scope']=='only_newly_created_synthetic_resources' for v in [lhs,rhs]))
 ck('source_and_binary_unchanged',report['source_before']==report['source_after'] and report['source_unchanged'] and report['source_before']['commit']=='4e808d0ecb1bcded22870a7ec960dfb2491cf6ec' and report['source_before']['tree']=='eba5e650bd080b8ad41ea52a2bc68867f541d255' and report['source_before']['dirty_including_untracked'] is False)
 result['comparison69']={'job':'x230/1a1adc377a3-fc05-5acb','casesPerSide':69,'numericHttpStatusMatches':67,'normalizedRejectionCases':{'pki.lease_expire_lookup':'rejected_after_ttl','pki.revoked_lease_absent':'rejected_400_or_404'},'exact400versus404ParityForNormalizedCasesProved':False,'scopes':expected_scope,'summary':meta(summaryraw),'originalNativeObservers':7,'originalImmutablePages':23,'nativeStorage':'native_v6_file','uncovered':summary['uncovered'],'fullReplacement':False,'productionQualified':False,'allHistoricalArchiveComplete':False,'archiveNote':'Runtime results and original pages independently verified locally; immutable Git archival restoration is separately tracked.'}
except Exception as e:
 ck('verifier_exception',False,{'type':type(e).__name__,'message':str(e),'traceback':traceback.format_exc()})
result['passed']=sum(x['ok'] for x in checks);result['failed']=sum(not x['ok'] for x in checks);result['ok']=result['failed']==0
raw=(json.dumps(result,ensure_ascii=False,indent=2)+'\n').encode();out=R/'r33-runtime-read-closures-root-result-r2.public.json'
with out.open('wb') as f:f.write(raw);f.flush();os.fsync(f.fileno())
print(json.dumps({'ok':result['ok'],'passed':result['passed'],'failed':result['failed'],'failureDetails':[x for x in checks if not x['ok']],'result':meta(raw),'resultPath':str(out)}))
sys.exit(0 if result['ok'] else 1)

