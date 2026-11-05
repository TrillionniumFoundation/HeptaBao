import hashlib,json,sys
x=json.loads(sys.argv[1]);ff=json.loads(x['files']);files={v['path'].split('/')[-1]:v for v in ff['files']};c=json.loads(files['result.public.json']['text']);a=json.loads(x['authority']);s=json.loads(x['streams']);t=json.loads(s['stdout']['text']);checks=[]
def ok(name,v):
 assert v,name
 checks.append(name)
ok('authority',a['state']=='succeeded' and a['exit_code']==0 and not a['timed_out'] and not a['cancelled'] and a['output_complete'] and a['output_durable'] and a['terminal_publication_confirmed'])
for k in ('stdout','stderr'):
 z=s[k];ok(k+'_whole',z['offset']==0 and z['eof'] and z['size']==z['next_offset']==len(bytes.fromhex(z['bytes_hex'])) and bytes.fromhex(z['bytes_hex'])==z['text'].encode())
 ok(k+'_authority_bytes',a['log_bytes'][k]['stored']==a['log_bytes'][k]['seen']==z['size'] and not a['log_truncated'][k] and a['log_errors'][k] is None and a['log_synced'][k])
ok('empty_parent_stderr',s['stderr']['text']=='')
ok('terminal',t['status']==c['status']=='transferred' and t['all_owned_stopped'] and t['publication_within_original_deadline'] and t['elapsed_after_publication_seconds']<300)
ok('fixed_source',c['source_commit']==x['commit'] and c['source_tree']==x['tree'] and c['files']==x['expected_files'])
ok('original_budget',c['overall_seconds']==300 and c['ssh_child_seconds']==c['endpoint_seconds']==90 and c['elapsed_seconds']<300)
ok('owned_closed',c['all_owned_stopped'] and c['all_local_owned_stopped'] and c['remote_endpoint_completion_verified'] and not c['remote_cleanup_unknown'] and not c['cleanup_errors'])
ok('three_children',len(c['commands'])==len(c['cleanup'])==3 and len({q['pid'] for q in c['cleanup']})==3 and {q['label'] for q in c['cleanup']}=={'rog-ts-effective-config','receive-desktop','send-rog'})
for q in c['commands']:
 ok(q['label']+'_command',q['exit_code']==0 and q['direct_child_reaped'] and q['remaining']==[] and not q['timed_out'] and q['limit_seconds']==90 and q['elapsed_seconds']<90)
 ok(q['label']+'_raw_record',json.loads(files[q['label']+'.public.json']['text'])==q)
for q in c['cleanup']:ok(q['label']+'_final_empty',q['exit_code']==0 and q['direct_child_reaped'] and q['remaining']==[])
sender=json.loads(files['send-rog.stderr']['text']);receiver=json.loads(files['receive-desktop.stderr']['text'])
ok('raw_endpoints',sender==c['sender'] and receiver==c['receiver'] and files['receive-desktop.stdout']['text']=='')
for e in (sender,receiver):ok(e['role']+'_complete',e['status']=='complete' and e['all_owned_stopped'] and e['within_original_deadline'] and e['request_seconds']==90 and e['source_commit']==x['commit'] and e['source_tree']==x['tree'] and e['git_operations']==0 and not e['server_started'] and not e['compiler_started'])
versions={}
ok('three_endpoint_files',len(sender['files'])==len(receiver['files'])==len(x['expected_files'])==3)
for item,sent,got in zip(x['expected_files'],sender['files'],receiver['files'],strict=True):
 n=item['name'];expected={'bytes':item['bytes'],'sha256':item['sha256']};i=got['identity']
 ok(n+'_binding',sent['name']==got['name']==n and sent['source']==item['path'] and sent['source_version']==item['version'])
 ok(n+'_same_fd_hash',sent['initial_file']==sent['stream']==got['same_fd_readback']==expected and got['bytes']==item['bytes'] and got['sha256']==item['sha256'])
 ok(n+'_source_identity',sent['source_identity_before']==sent['source_identity_after'] and ':'.join(str(sent['source_identity_before'][j]) for j in (0,1,6,7,8))==item['version'])
 ok(n+'_destination',got['path']==x['root']+'/incoming/'+n and got['mode']==item['target_mode'] and got['create_only'] and got['fsynced'] and i[2]==1000 and i[5]==1 and i[4]&0o777==item['target_mode'] and i[6]==item['bytes'])
 versions[n]=':'.join(str(i[j]) for j in (0,1,6,7,8))
ok('raw_receipt_provenance',receiver['normal_release_provenance_verified'] and receiver['raw_receipts_preserved'] and receiver['destination_created_exclusive'] and receiver['destination_fsynced'] and receiver['destination_directory_mode']==320)
ok('source_code_pins',c['controller']['sha256']=='5cb99ccf85533ad91f83f24e86c629395b545ebbf5c967dab36989805dd632da' and c['helpers']['sender.py']['sha256']=='e57040a017a44d9d2a9b4396200325eb8499bf503e9c52be58448fa71fdf5835' and c['helpers']['receiver.py']['sha256']=='dd2209577430e4d9b17918f9688453cb3b68ef725032abb6e3f59b6654a34e31')
ok('old_controller_unchanged',c['original_ha_controller_before']==c['original_ha_controller_after'] and c['original_ha_controller_before']['sha256']=='c70892cb19601fa9769ae3f36810bb123f756f335654f284a4001bf2d69c796e')
ok('trust_unchanged',c['trust_before']==c['trust_after'])
ok('no_product',not c['compiler_started'] and not c['server_started'] and c['git_operations']==0 and not c['runtime_qualification'] and not c['production_changed'])
print(json.dumps({'schema':'heptabao.phaseb3cb.actual-artifact-transfer-review.v1','status':'passed','job_id':a['job_id'],'checks':checks,'source_commit':x['commit'],'source_tree':x['tree'],'all_owned_groups':3,'all_reaped_empty':True,'parent_elapsed_after_publication_seconds':t['elapsed_after_publication_seconds'],'sender_seconds':sender['elapsed_seconds'],'receiver_seconds':receiver['elapsed_seconds'],'received_versions_from_actual_same_fd_identity':versions,'no_independent_postrun_file_info_claim':True,'product_started':False,'source_imported':False},sort_keys=True))
