import hashlib,json,pathlib,sys
x=json.loads(pathlib.Path(sys.argv[1]).read_text());checks=[]
sha=lambda s:hashlib.sha256(s.encode()).hexdigest()
def check(v,n):
 if not v:raise AssertionError(n)
 checks.append(n)
a=json.loads(x['authority_raw']);ack=json.loads(x['ack_raw']);streams=json.loads(x['streams_raw']);wrapper=json.loads(x['logs_raw'])
check(ack['reused'] is False and ack['job']['launch_state']=='launched','single_new_launch')
for k in ('host','executable','args','cwd','idempotency_key'):check(ack['job'][k]==x['request'][k],'exact_'+k)
check(x['request']['timeout_seconds']==360,'original_outer360')
check(a['job_id']==ack['job']['id']==streams['job_id'],'one_job')
check(a['state']=='succeeded' and a['exit_code']==0 and a['output_complete'] and a['output_durable'] and a['terminal_publication_confirmed'],'authority0_complete_durable')
check(not any(a[k] for k in ('timed_out','cancelled','automatic_retry')),'no_timeout_or_retry')
for name in ('stdout','stderr'):
 s=streams[name];raw=bytes.fromhex(s['bytes_hex'])
 check(raw==s['text'].encode() and s['offset']==0 and s['eof'] and s['next_offset']==s['size']==len(raw),'whole_stream_'+name)
 check(a['log_bytes'][name]=={'seen':len(raw),'stored':len(raw)} and not a['log_truncated'][name] and a['log_synced'][name] and a['log_errors'][name] is None,'authority_stream_'+name)
check(streams['stderr']['text']=='','stderr_empty')
terminal=json.loads(streams['stdout']['text'])
check(len(wrapper['files'])==10 and not wrapper['truncated'],'ten_complete_logs')
rows={}
for f in wrapper['files']:
 check(f['eof'] and len(f['text'].encode())==f['size'] and sha(f['text'])==f['sha256'],'file_whole_'+pathlib.PurePosixPath(f['path']).name)
 rows[pathlib.PurePosixPath(f['path']).name]=f
check(len(rows)==10,'unique_log_names')
c=json.loads(rows['result.public.json']['text']);inert=json.loads(x['inert_core_raw'])
check(c['status']==terminal['status']=='transferred' and c['all_owned_stopped'] and terminal['all_owned_stopped'],'transferred_owned')
check(c['overall_seconds']==300 and c['endpoint_seconds']==c['ssh_child_seconds']==90 and c['elapsed_seconds']<300 and terminal['publication_within_original_deadline'] and terminal['elapsed_after_publication_seconds']<300,'original_deadlines')
check(c['remote_endpoint_completion_verified'] and not c['remote_cleanup_unknown'] and not c['cleanup_errors'] and c['all_local_owned_stopped'],'known_endpoint_cleanup')
check(c['files']==x['source_files'],'exact_two_source_bindings')
check(c['source_commit']=='df026fe323dd7cf0f0ec57d7d2d9c5a79897053c' and c['source_tree']=='424463ccd2310ddc1e7b2bbcd7b7af29ae58c825','candidate_exact')
check(c['trust_before']==c['trust_after'] and c['original_ha_controller_before']==c['original_ha_controller_after'],'trust_and_original_control_unchanged')
check(c['git_operations']==0 and c['server_started'] is False and c['compiler_started'] is False and c['runtime_qualification'] is False and c['production_changed'] is False,'no_product_import_or_compile')
check(len(c['cleanup'])==len(c['commands'])==3 and len({v['pid'] for v in c['cleanup']})==3,'three_unique_owned_children')
for cmd in c['commands']:
 label=cmd['label'];record=json.loads(rows[label+'.public.json']['text'])
 check(record==cmd,'original_child_record_'+label)
 check(cmd['exit_code']==0 and cmd['direct_child_reaped'] and cmd['remaining']==[] and not cmd['timed_out'] and cmd['limit_seconds']==90 and cmd['elapsed_seconds']<90,'child_terminal_'+label)
 cleaned=next(v for v in c['cleanup'] if v['pid']==cmd['pid'])
 check(cleaned=={k:cmd[k] for k in ('pid','label','exit_code','direct_child_reaped','remaining')},'cleanup_exact_'+label)
check({v['label'] for v in c['commands']}=={'rog-ts-effective-config','send-rog','receive-desktop'},'exact_owned_labels')
check(json.loads(rows['send-rog.stderr']['text'])==c['sender'] and json.loads(rows['receive-desktop.stderr']['text'])==c['receiver'],'original_endpoint_receipts')
check(rows['receive-desktop.stdout']['text']==rows['rog-ts-effective-config.stderr']['text']=='','empty_required_streams')
for label in ('sender','receiver'):
 endpoint=c[label]
 check(endpoint['status']=='complete' and endpoint['role']==label and endpoint['all_owned_stopped'] and endpoint['cleanup']==[] and endpoint['cleanup_errors']==[],'endpoint_complete_'+label)
 check(endpoint['within_original_deadline'] and endpoint['request_seconds']==90 and endpoint['elapsed_seconds']<90,'endpoint_deadline_'+label)
 check(endpoint['source_commit']==c['source_commit'] and endpoint['source_tree']==c['source_tree'] and endpoint['git_operations']==0 and not endpoint['compiler_started'] and not endpoint['server_started'],'endpoint_scope_'+label)
receiver=c['receiver']
check(receiver['destination_created_exclusive'] and receiver['destination_directory_mode']==0o500 and receiver['destination_fsynced'] and receiver['raw_receipts_preserved'] and receiver['source_export_provenance_verified'],'receiver_custody_provenance')
infos=[json.loads(x['bundle_info_raw']),json.loads(x['export_info_raw'])]
for original,sent,received,info in zip(x['source_files'],c['sender']['files'],receiver['files'],infos,strict=True):
 name=original['name'];dev,ino,size,mtime,ctime=map(int,original['version'].split(':'))
 expected_source=[dev,ino,1000,1000,0o100600,1,size,mtime,ctime]
 check(sent['source_identity_before']==sent['source_identity_after']==expected_source and sent['source_version']==original['version'] and sent['source']==original['path'],'exact_original_source_identity_'+name)
 expected={'bytes':original['bytes'],'sha256':original['sha256']}
 check(sent['initial_file']==sent['stream']==received['same_fd_readback']==expected,'three_whole_hashes_'+name)
 check(sent['name']==received['name']==name and received['bytes']==info['size']==original['bytes'] and received['sha256']==info['sha256']==original['sha256'],'received_whole_'+name)
 check(received['path']==info['path'] and received['create_only'] and received['fsynced'] and received['mode']==info['mode']==info['metadata']['mode']==0o400 and info['metadata']['uid']==info['metadata']['gid']==1000 and info['metadata']['link_count']==1,'received_metadata_'+name)
 dev,ino,size,mtime,ctime=map(int,info['version'].split(':'))
 check(received['identity']==[dev,ino,1000,1000,0o100400,1,size,mtime,ctime],'received_exact_integer_identity_'+name)
for role,filename in (('controller','relay.py'),('sender.py','sender.py'),('receiver.py','receiver.py')):
 observed=c['controller'] if role=='controller' else c['helpers'][role]
 pin=next(v for v in inert['files'] if v['path'].endswith('/'+filename))
 check(observed['identity']==pin['identity'] and observed['sha256']==pin['sha256'] and observed['bytes']==pin['bytes'],'actual_inert_identity_'+filename)
info=json.loads(x['transfer_info_raw']);row=rows['result.public.json']
check(all(info[k]==row[k] for k in ('path','size','sha256','version')) and info['path']==terminal['receipt'],'independent_transfer_fileinfo')
out={'schema':'heptabao.df026.source-carrier.actual-offline-review.v1','status':'passed','checks':checks,'checks_passed':len(checks),'job_id':a['job_id'],'core_sha256':sha(row['text']),'source_before_after_and_destination_identities_exact_integers':True,'all_three_owned_stopped':True,'unknown':False,'original_deadlines_300_90_10_5_5_preserved':True,'read_operations':6,'immutable_pages':7,'files':[{'path':v['path'],'bytes':v['size'],'sha256':v['sha256'],'version':v['version']} for v in infos+[info]],'scope':'actual public source transport only; source import/normal build/QA/product qualification separate'}
pathlib.Path(sys.argv[2]).write_text(json.dumps(out,indent=2,sort_keys=True)+'\n')
print(json.dumps({'status':'passed','checks_passed':len(checks),'core_sha256':out['core_sha256'],'files':out['files']},sort_keys=True))
