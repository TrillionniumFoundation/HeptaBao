import hashlib,json,pathlib,sys
x=json.loads(pathlib.Path(sys.argv[1]).read_text())
sha=lambda v:hashlib.sha256(v.encode()).hexdigest()
a=json.loads(x['authority_raw']);ack=json.loads(x['ack_raw']);s=json.loads(x['streams_raw']);f=json.loads(x['files_raw'])
assert ack['reused'] is False and ack['job']['launch_state']=='launched'
for k in ('host','executable','args','cwd','idempotency_key'):assert ack['job'][k]==x['request'][k]
assert x['request']['timeout_seconds']==60
assert a['job_id']==s['job_id']==ack['job']['id']
assert a['state']=='succeeded' and a['exit_code']==0
assert a['output_complete'] and a['output_durable'] and a['terminal_publication_confirmed']
assert not any(a[k] for k in ('timed_out','cancelled','automatic_retry'))
for name in ('stdout','stderr'):
 v=s[name];raw=bytes.fromhex(v['bytes_hex'])
 assert v['offset']==0 and v['next_offset']==v['size']==len(raw) and v['eof']
 assert raw==v['text'].encode()
 assert a['log_bytes'][name]=={'seen':len(raw),'stored':len(raw)}
 assert a['log_synced'][name] and not a['log_truncated'][name] and a['log_errors'][name] is None
assert s['stderr']['text']==''
assert not f['truncated'] and len(f['files'])==4
read={pathlib.PurePosixPath(v['path']).name:v for v in f['files']}
for v in read.values():
 assert v['eof'] and len(v['text'].encode())==v['size'] and sha(v['text'])==v['sha256']
core=json.loads(read['inert-stage.result.public.json']['text'])
assert core==json.loads(s['stdout']['text'])
assert core['status']=='prepared' and core['python_compile_only'] is True
assert all(core[k] is False for k in ('source_executed','git_started','compiler_started','service_started','artifact_transfer_started'))
assert len(core['files'])==3
assert core['stdin_bytes']==len(x['request']['stdin'].encode()) and core['stdin_sha256']==sha(x['request']['stdin'])
for name,expected in x['expected_sources'].items():
 filename=name+'.py';r=read[filename]
 assert r['text']==expected
 pin=next(v for v in core['files'] if v['path']==r['path'])
 assert pin['bytes']==r['size'] and pin['sha256']==r['sha256']
 assert pin['publication']=='created' and pin['mode']=='0600'
 ident=pin['identity'];dev,ino,size,mtime,ctime=map(int,r['version'].split(':'))
 assert ident==[dev,ino,1000,1000,0o100600,1,size,mtime,ctime]
elapsed=core['terminal_ns']-core['started_ns']
assert 0<elapsed<60_000_000_000
out={'schema':'heptabao.df026.source-carrier-inert.offline-review.v1','status':'passed','job_id':a['job_id'],'elapsed_ns':str(elapsed),'core_sha256':sha(read['inert-stage.result.public.json']['text']),'actual_3_sources_exact':True,'unsafe_ns_identity_exact':True,'all_four_original_versions':{name:v['version'] for name,v in read.items()},'authority_exit_zero':True,'complete_durable_stdout':True,'original_60_second_supervisor':True,'target_source_executed':False,'transport_or_git_or_product_started':False,'read_operations':3,'immutable_pages':5}
pathlib.Path(sys.argv[2]).write_text(json.dumps(out,indent=2,sort_keys=True)+'\n')
print(json.dumps(out,sort_keys=True))
