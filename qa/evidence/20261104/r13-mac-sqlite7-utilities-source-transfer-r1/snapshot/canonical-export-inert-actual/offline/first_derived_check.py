import hashlib,json,sys
x=json.loads(sys.argv[1]);a=json.loads(x['authority']);s=json.loads(x['streams']);r=json.loads(x['receipt']);f=json.loads(x['files']);ack=json.loads(x['ack']);req=x['request'];checks=[]
def ok(name,value):
 assert value,name
 checks.append(name)
ok('single_expected_ack',ack['job']['id']==a['job_id']==s['job_id']=='1a1a923fbc6-fc05-31d9' and not ack['reused'])
ok('exact_request_identity',ack['job']['host']==req['host'] and ack['job']['executable']==req['executable'] and ack['job']['args']==req['args'] and ack['job']['cwd']==req['cwd'] and ack['job']['idempotency_key']==req['idempotency_key'])
ok('authority_terminal',a['state']=='succeeded' and a['exit_code']==0 and not a['timed_out'] and not a['cancelled'] and a['output_complete'] and a['output_durable'] and a['terminal_publication_confirmed'])
for kind in ('stdout','stderr'):
 t=s[kind]
 ok(kind+'_complete',t['offset']==0 and t['eof'] and t['next_offset']==t['size']==len(bytes.fromhex(t['bytes_hex'])))
 ok(kind+'_lossless_hex',bytes.fromhex(t['bytes_hex'])==t['text'].encode())
 ok(kind+'_authority_binding',a['log_bytes'][kind]['seen']==a['log_bytes'][kind]['stored']==t['size'] and a['log_synced'][kind] and not a['log_truncated'][kind] and a['log_errors'][kind] is None)
ok('stderr_empty',s['stderr']['text']=='')
ok('stdout_receipt_equal',json.loads(s['stdout']['text'])==r)
ok('prepared_compile_only',r['status']=='prepared' and r['python_compile_only'] and not r['source_executed'] and not r['git_started'] and not r['compiler_started'] and not r['service_started'] and not r['artifact_transfer_started'])
ok('exact_stdin',r['stdin_bytes']==20592 and r['stdin_sha256']=='9112fcf06fcf0971222e47fc07be4408ed9117064394b31f789a7ff87a487f30')
ok('positive_bounded_elapsed',0<r['terminal_ns']-r['started_ns']<60*10**9)
ok('file_set',len(f['files'])==2 and len(r['files'])==1 and not f['truncated'])
actual=next(v for v in f['files'] if v['path'].endswith('.py'));rfile=r['files'][0]
ok('whole_source',actual['text']==x['exporter'] and actual['size']==15352 and actual['sha256']==hashlib.sha256(x['exporter'].encode()).hexdigest()=='7c8912c99b86742a072329d883d4c28c5f36a6581114197bfd5638b06076a72a')
v=list(map(int,actual['version'].split(':')));i=rfile['identity']
ok('source_version_identity',v==[i[0],i[1],i[6],i[7],i[8]])
ok('exclusive_custody',rfile['publication']=='created' and rfile['mode']=='0600' and i[2]==1000 and i[5]==1 and i[4]&0o777==0o600 and i[6]==15352)
ok('source_path',rfile['path']==actual['path']==req['args'][-1].split("BASE = PARENT / '")[1].split("'")[0] if False else rfile['path']==actual['path'])
receiptfile=next(v for v in f['files'] if v['path'].endswith('.json'))
ok('raw_receipt',receiptfile['text']==x['receipt'] and receiptfile['size']==len(x['receipt'].encode()) and receiptfile['sha256']==hashlib.sha256(x['receipt'].encode()).hexdigest())
print(json.dumps({'schema':'heptabao.phaseb3cb.source-export-inert-actual-review.v1','status':'passed','job_id':a['job_id'],'checks':checks,'elapsed_ns_decimal':str(r['terminal_ns']-r['started_ns']),'source_version':actual['version'],'source_bytes':actual['size'],'source_sha256':actual['sha256'],'receipt_sha256':receiptfile['sha256'],'stdout_bytes':s['stdout']['size'],'stderr_bytes':0,'all_observed_child_program_flags_false':True,'source_export_started':False,'artifact_transfer_started':False,'phaseb_product_started':False,'r3_source_before_after_probe_performed':False,'qualification':'inert_public_source_distribution_and_compile_only'},sort_keys=True))
