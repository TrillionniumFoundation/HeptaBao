import hashlib,json,sys
x=json.loads(sys.argv[1]);a=json.loads(x['authority']);s=json.loads(x['streams']);r=json.loads(x['receipt']);f=json.loads(x['files']);ack=json.loads(x['ack']);req=x['request'];checks=[]
def ok(name,value):
 assert value,name
 checks.append(name)
ok('single_expected_ack',ack['job']['id']==a['job_id']==s['job_id']=='1a1a92752aa-fc05-320d' and not ack['reused'])
ok('exact_request_identity',all(ack['job'][k]==req[k] for k in ('host','executable','args','cwd','idempotency_key')))
ok('authority_terminal',a['state']=='succeeded' and a['exit_code']==0 and not a['timed_out'] and not a['cancelled'] and a['output_complete'] and a['output_durable'] and a['terminal_publication_confirmed'])
for kind in ('stdout','stderr'):
 t=s[kind]
 ok(kind+'_complete',t['offset']==0 and t['eof'] and t['next_offset']==t['size']==len(bytes.fromhex(t['bytes_hex'])))
 ok(kind+'_lossless_hex',bytes.fromhex(t['bytes_hex'])==t['text'].encode())
 ok(kind+'_authority_binding',a['log_bytes'][kind]['seen']==a['log_bytes'][kind]['stored']==t['size'] and a['log_synced'][kind] and not a['log_truncated'][kind] and a['log_errors'][kind] is None)
ok('stderr_empty',s['stderr']['text']=='')
ok('stdout_receipt_equal',json.loads(s['stdout']['text'])==r)
ok('prepared_compile_only',r['status']=='prepared' and r['python_compile_only'] and not r['source_executed'] and not r['git_started'] and not r['compiler_started'] and not r['service_started'] and not r['artifact_transfer_started'])
ok('exact_stdin',r['stdin_bytes']==41278 and r['stdin_sha256']=='00f9a231803f2a006db80d1fe331364eba85bba7e9d109238cf917d113e5f99c')
ok('positive_bounded_elapsed',0<r['terminal_ns']-r['started_ns']<60*10**9)
ok('file_set',len(f['files'])==4 and len(r['files'])==3 and not f['truncated'])
versions={}
for name,pin in x['pins'].items():
 path=x['controls']+'/'+name+'.py'
 actual=next(v for v in f['files'] if v['path']==path);rfile=next(v for v in r['files'] if v['path']==path)
 raw=actual['text'].encode()
 ok(name+'_whole_source',actual['size']==len(raw)==pin['bytes'] and actual['sha256']==hashlib.sha256(raw).hexdigest()==pin['sha256'] and hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()==pin['blob'])
 v=list(map(int,actual['version'].split(':')));i=rfile['identity']
 ok(name+'_version_identity',v==[i[0],i[1],i[6],i[7],i[8]])
 ok(name+'_exclusive_custody',rfile['publication']=='created' and rfile['mode']=='0600' and i[2]==1000 and i[5]==1 and i[4]&0o777==0o600 and i[6]==pin['bytes'])
 versions[name]=actual['version']
receiptfile=next(v for v in f['files'] if v['path'].endswith('.json'))
ok('raw_receipt',receiptfile['text']==x['receipt'] and receiptfile['size']==len(x['receipt'].encode()) and receiptfile['sha256']==hashlib.sha256(x['receipt'].encode()).hexdigest())
print(json.dumps({'schema':'heptabao.phaseb3cb.artifact-inert-actual-review.v1','status':'passed','job_id':a['job_id'],'checks':checks,'elapsed_ns_decimal':str(r['terminal_ns']-r['started_ns']),'source_versions':versions,'receipt_sha256':receiptfile['sha256'],'stdout_bytes':s['stdout']['size'],'stderr_bytes':0,'candidate_modules_executed':False,'artifact_transfer_started':False,'phaseb_product_started':False,'qualification':'inert_public_source_distribution_and_compile_only'},sort_keys=True))
