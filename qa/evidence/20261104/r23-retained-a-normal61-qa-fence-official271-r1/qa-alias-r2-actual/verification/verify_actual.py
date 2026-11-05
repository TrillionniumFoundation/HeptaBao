import hashlib
import json
from pathlib import Path

outer=json.loads(Path(__file__).with_name('alias-r2-actual-input.json').read_text())
request,ack,authority,streams,go=(json.loads(outer[key]) for key in ('request','ack','authority','streams','go'))
checks=[]
def need(name,value):
    assert value,name
    checks.append({'name':name,'passed':True})
def sha(raw):return hashlib.sha256(raw).hexdigest()
need('exact-request-whole',sha(outer['request'].encode())=='7238ba7ba0909a8a881ab85b83b42e0476f8fb2ded7074d5575b5623f9ea2890')
need('root-go-whole',sha(outer['go'].encode())=='068e00522b9699674c34162682e3d5f20688c0536908d02ff456ca35f4026fb6')
need('exact-source-in-argv',len(request['args'][4].encode())==17919 and sha(request['args'][4].encode())==request['args'][5]=='4e72160c838092ff1706fc1b14f826b500edfef2ea68f335d80df5b1148ebf12')
need('exact-python-argv-prefix',request['args'][:4]==['-I','-S','-B','-c'])
job=ack['job'];job_id='1a1ab2db7e2-fc05-4b25'
need('actual-launch-known-not-reused',job['launch_state']=='launched' and ack['reused'] is False and ack['launch']['ok'] is True)
for field in ('host','executable','args','cwd','idempotency_key'):
    need('ack-exact-'+field,job[field]==request[field])
need('same-actual-job',job['id']==authority['job_id']==streams['job_id']==job_id)
need('original-outer45',request['timeout_seconds']==go['timeout_seconds']==45)
need('authority-complete-zero',authority['state']=='succeeded' and authority['exit_code']==0 and authority['output_complete'] is True and authority['output_durable'] is True and authority['terminal_publication_confirmed'] is True)
need('authority-not-timeout-or-cancel',authority['timed_out'] is False and authority['cancelled'] is False)
for label in ('stdout','stderr'):
    row=streams[label];body=bytes.fromhex(row['bytes_hex'])
    need(label+'-lossless-hex-text',body==row['text'].encode())
    need(label+'-complete-eof',row['offset']==0 and row['eof'] is True and row['size']==row['next_offset']==len(body))
    need(label+'-authority-length',authority['log_bytes'][label]['seen']==authority['log_bytes'][label]['stored']==len(body))
    need(label+'-authority-synced',authority['log_synced'][label] is True and authority['log_truncated'][label] is False and authority['log_errors'][label] is None)
need('stderr-empty',streams['stderr']['size']==0)
need('stdout-whole',streams['stdout']['size']==2717 and sha(streams['stdout']['text'].encode())=='3b5d09723d4a4eb14e0c0607a911e86a6ce6f7e6a2d9630073cf5bb670d8ab3e')
core=json.loads(streams['stdout']['text'])
need('observed-status-and-source',core['status']=='observed_fixed_two_aliases' and core['source_sha256']==request['args'][5])
need('no-observation-error',core['error'] is None and core['cancel_signal'] is None)
need('same-later-full9',core['full_identity']==['66306','31633993','1000','1000','33216','2','4616576','1793869496670294192','1793869496695294129'])
need('same-later-version',core['primary_version']=='66306:31633993:4616576:1793869496670294192:1793869496695294129')
base='/home/qian-qi/heptabao-cold-h2-normal-20261105-r1/target-normal-r3/release/'
expected=[base+'heptabao-native-h2-qa',base+'deps/heptabao_native_h2_qa-524c7b86fe50735e']
need('two-exact-alias-paths',[x['path'] for x in core['aliases']]==expected)
need('two-alias-bytes-sha',all(x['bytes']==4616576 and x['sha256']=='1f1c6eccf1ac9652a69572cb270b1d3d99a3402eaabf6d7feed6e4b2c4d55b13' for x in core['aliases']))
need('same-identity-complete-linkset',core['same_full_identity'] is True and core['link_count_fully_accounted_for'] is True and core['expected_link_count']==2)
need('bounded-census',0<core['directory_entries_seen']==1106<=16384 and 0<core['directory_name_bytes']==36135<=1048576 and core['qa_prefix_candidates']==1<=32)
need('body-budget-unchanged',core['body_bytes_read']==core['body_bytes_limit']==9233152)
need('eof-accounting',core['eof_probe_calls']==2 and core['eof_probe_bytes_read']==0 and core['eof_probe_bytes_limit']==2)
need('returned-byte-accounting',core['bytes_read']==core['body_bytes_read']+core['eof_probe_bytes_read'] and core['bytes_read']<=core['total_returned_bytes_limit']==9233154)
need('original15-after-closure',0<core['elapsed_after_closure_ns']==10994143<15000000000 and core['within_original_read_deadline_after_closure'] is True)
need('all-nine-fds-closed-once',core['fds_opened']==core['fds_closed_once']==len(core['fd_closure_rows'])==9 and core['fds_remaining']==core['fd_close_failures']==0)
for number,row in enumerate(core['fd_closure_rows'],1):
    need('fd-once-closed-'+str(number),row['ordinal']==number and row['role']==('ancestor' if number<=7 else 'artifact') and row['close_attempted'] is True and row['closed'] is True and row['close_error'] is row['close_errno'] is None)
need('iterator-once-closed',core['iterator_created'] is core['iterator_close_attempted'] is core['iterator_closed_once'] is True and core['iterator_close_error'] is None)
need('no-resource-unknown',core['all_registered_resources_closed'] is True and core['resource_outcome_unknown'] is core['open_registration_unknown'] is core['iterator_open_unknown'] is False)
need('no-binary-child-network-write',all(core[key]==0 for key in ('binary_executions','child_starts','network_requests','file_writes')))
need('original-failed-run-preserved',core['original_qa_r2_result_remains_failed'] is True)
print(json.dumps({'schema':'heptabao.qa-alias-observer.actual-lossless-verification.v1',
    'status':'passed-existing-evidence-only','checks':checks,'check_count':len(checks),
    'host_requests':0,'main_or_observer_executed':False,
    'conclusion':'Actual later alias set observed; original failed QA R2 is unchanged. No artifact-copy build qualification.'},
    indent=2,sort_keys=True))
