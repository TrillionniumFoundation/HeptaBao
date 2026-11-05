import base64
import hashlib
import json
import stat
from pathlib import Path

ROOT = Path('/workspace/scratch/f86faac821c4')
INPUT = ROOT / 'mac34_inert_actual_input.json'
OUTPUT = ROOT / 'mac34_inert_actual_verification.json'
data = json.loads(INPUT.read_text())
raws = data['raws']
checks = []


def check(name, condition):
    if not condition:
        raise AssertionError(name)
    checks.append(name)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def parsed(path):
    return json.loads(raws[path])


def sdk_text(path):
    sdk = parsed(path)
    check(path + ':not_tool_error', sdk.get('isError') is False)
    texts = [x['text'] for x in sdk['content'] if x.get('type') == 'text']
    check(path + ':one_native_text', len(texts) == 1)
    return texts[0]


def full9(info):
    tokens = info['version'].split(':')
    check(info['path'] + ':canonical_version_tokens', len(tokens) == 5 and all(x.isdecimal() and str(int(x)) == x for x in tokens))
    dev, ino, size, mtime, ctime = map(int, tokens)
    check(info['path'] + ':size_version', size == info['size'])
    m = info['metadata']
    check(info['path'] + ':mode_projection', m['mode'] == info['mode'])
    return [dev, ino, m['uid'], m['gid'], stat.S_IFREG | info['mode'], m['link_count'], size, mtime, ctime]


request = parsed('reference/exact-inert-request.public.json')
go = parsed('reference/root-inert-go.public.json')
check('exact_request_sha', sha(raws['reference/exact-inert-request.public.json'].encode()) == go['exact_request']['sha256'])
check('exact_request_bytes', len(raws['reference/exact-inert-request.public.json'].encode()) == go['exact_request']['bytes'])
check('exact_publisher', request['args'] == ['-I', '-S', '-B', '-c', data['reference_publisher']])
check('exact_carrier', request['stdin'] == data['reference_carrier'])
check('original_outer60', request['timeout_seconds'] == 60)
check('fixed_host', request['host'] == 'mac')
check('inert_go_only', go['prepare_go'] is False and go['live_go'] is False)
intent = parsed('intent/execution.intent.public.json')
check('intent_request_whole', intent['exact_request_json_original'] == raws['reference/exact-inert-request.public.json'])
check('intent_go_whole', intent['root_go_json_original'] == raws['reference/root-inert-go.public.json'])
check('intent_before_submission', intent['process_start_submitted'] is False)
check('handoff_no_inflight', intent['handoff']['runtime_calls_inflight'] == 0 and intent['handoff']['native_futures_inflight'] == 0)
check('two_handoff_closed', all(intent['handoff'][x]['state'] == 'completed/stored_observed/inactive' and intent['handoff'][x]['original_payload_complete'] is True for x in ['sdk12', 'sdk13']))

check('ack_native_exact', sdk_text('actual/start.original.sdk.json') == raws['actual/start.original.native.json'])
ack = parsed('actual/start.original.native.json')
job = ack['job']
JOB = '1a1ac8387b9-fc05-54e4'
check('ack_once_launched', ack['reused'] is False and ack['launch']['ok'] is True and job['launch_state'] == 'launched')
check('ack_job_host', job['id'] == JOB and job['host'] == 'mac')
for key in ['args', 'cwd', 'executable', 'idempotency_key']:
    check('ack_' + key, job[key] == request[key])
check('ack_launch_error_null', job['launch_error'] is None)

records = data['read_records']
check('five_original_reads', [x['name'] for x in records] == ['authority', 'streams', 'wrapper-info', 'receipt-info', 'bodies'])
check('five_unique_operations', len({x['operation_id'] for x in records}) == 5)
for record in records:
    name = record['name']
    prefix = 'reads/' + name + '/'
    rintent = parsed(prefix + 'intent.public.json')
    check(name + ':original_request', rintent['request'] == record['request'])
    check(name + ':read_only', rintent['read_only'] is True and rintent['submitted'] is False)
    check(name + ':host_mac', rintent['request']['operation']['arguments']['host'] == 'mac')
    check(name + ':ack_original', sdk_text(prefix + 'admission.original.sdk.json') == raws[prefix + 'admission.original.native.json'])
    admission = parsed(prefix + 'admission.original.native.json')
    check(name + ':admission_identity', admission['operation_id'] == record['operation_id'] and admission['tool_name'] == record['request']['operation']['tool'])
    check(name + ':status_original', sdk_text(prefix + 'status.original.sdk.json') == raws[prefix + 'status.original.native.json'])
    status = parsed(prefix + 'status.original.native.json')
    check(name + ':native_closed', status['operation_id'] == record['operation_id'] and status['async_state'] == 'completed' and status['result_state'] == 'stored_observed' and status['owned_future_active'] is False and status['payload_available'] is True)
    assembled = bytearray()
    for page_record in record['pages']:
        ppath = prefix + 'page-' + str(page_record['offset']).zfill(7)
        check(ppath + ':native_original', sdk_text(ppath + '.original.sdk.json') == raws[ppath + '.original.native.json'])
        page = parsed(ppath + '.original.native.json')
        chunk = base64.b64decode(page['data_base64'], validate=True)
        check(ppath + ':identity_offset', page['operation_id'] == record['operation_id'] and page['offset'] == len(assembled) and page['next_offset'] == len(assembled) + len(chunk))
        check(ppath + ':immutable_whole_pin', page['immutable_snapshot'] is True and page['result_sha256'] == record['result_sha256'] and page['total_bytes'] == record['total_bytes'])
        assembled.extend(chunk)
        check(ppath + ':eof_cursor', page['eof'] is (len(assembled) == page['total_bytes']))
    payload_raw = raws[prefix + 'immutable-payload.original.json']
    check(name + ':whole_payload_bytes', bytes(assembled) == payload_raw.encode())
    check(name + ':whole_payload_sha', sha(assembled) == record['result_sha256'] and len(assembled) == record['total_bytes'])
    payload = json.loads(payload_raw)
    check(name + ':native_handler_success', payload['resultType'] == 'complete' and payload['isError'] is False)
    check(name + ':native_outcome_exact', payload['content'] == [{'type': 'text', 'text': raws['actual/' + name + '.original.json']}])
    check(name + ':record_complete', record['stage'] == 'COMPLETE')

authority = parsed('actual/authority.original.json')
check('authority_identity', authority['job_id'] == JOB)
check('authority_terminal0', authority['state'] == 'succeeded' and authority['exit_code'] == 0 and authority['timed_out'] is False and authority['cancelled'] is False)
check('authority_full_durable', authority['output_complete'] is True and authority['output_durable'] is True and authority['terminal_publication_confirmed'] is True)
streams = parsed('actual/streams.original.json')
check('streams_job', streams['job_id'] == JOB)
for label in ['stdout', 'stderr']:
    stream = streams[label]
    raw = raws['actual/' + label + '.original.log'].encode()
    check(label + ':whole_text_hex', stream['text'].encode() == raw == bytes.fromhex(stream['bytes_hex']))
    check(label + ':complete_eof', stream['offset'] == 0 and stream['size'] == stream['next_offset'] == len(raw) and stream['eof'] is True)
    check(label + ':authority_exact', authority['log_bytes'][label] == {'seen': len(raw), 'stored': len(raw)} and authority['log_synced'][label] is True and authority['log_truncated'][label] is False and authority['log_errors'][label] is None)
check('854_stdout_empty_stderr', len(raws['actual/stdout.original.log'].encode()) == 854 and raws['actual/stderr.original.log'] == '')

bodies = parsed('actual/bodies.original.json')
check('two_whole_bodies', len(bodies['files']) == 2 and bodies['truncated'] is False)
check('independent_not_atomic', bodies['atomic_snapshot'] is False)
body_by_path = {x['path']: x for x in bodies['files']}
for label, path in [('wrapper-info', 'actual/run_current_mac_full34_r1.py'), ('receipt-info', 'actual/inert-stage.result.public.json')]:
    info = parsed('actual/' + label + '.original.json')
    body = body_by_path[info['path']]
    raw = raws[path].encode()
    check(label + ':whole_exact', raw == body['text'].encode() and len(raw) == body['size'] == info['size'] and sha(raw) == body['sha256'] == info['sha256'])
    check(label + ':independent_version', info['version'] == body['version'] and body['eof'] is True)
    check(label + ':owner_mode_singlelink', info['mode'] == 0o600 and info['metadata']['uid'] == 501 and info['metadata']['gid'] == 20 and info['metadata']['link_count'] == 1)
    full9(info)
wrapper_info = parsed('actual/wrapper-info.original.json')
receipt_info = parsed('actual/receipt-info.original.json')
check('wrapper_original_whole', raws['actual/run_current_mac_full34_r1.py'] == data['reference_wrapper'])
check('wrapper_exact_source_pin', wrapper_info['size'] == 20538 and wrapper_info['sha256'] == '29785927055d2e676c702aa79b97db9a6d274d8d8de0916073c08face41c6c9a')
stdout_obj = json.loads(raws['actual/stdout.original.log'])
receipt = parsed('actual/inert-stage.result.public.json')
check('receipt_equals_stdout_lossless', receipt == stdout_obj)
check('receipt_original_serialization', (json.dumps(stdout_obj, sort_keys=True, indent=2) + '\n') == raws['actual/inert-stage.result.public.json'])
check('prepared_single_wrapper', receipt['status'] == 'prepared' and len(receipt['files']) == 1)
check('fresh_root_control', receipt['root_created'] is True and receipt['control_created'] is True)
check('compile_only', receipt['python_compile_only'] is True)
for flag in ['source_executed', 'git_started', 'compiler_started', 'service_started', 'artifact_transfer_started']:
    check(flag + ':false', receipt[flag] is False)
check('stdin_actual_pin', receipt['stdin_bytes'] == 27485 and receipt['stdin_sha256'] == sha(data['reference_carrier'].encode()))
file = receipt['files'][0]
check('wrapper_publisher_pin', file['path'] == wrapper_info['path'] and file['bytes'] == 20538 and file['sha256'] == wrapper_info['sha256'] and file['mode'] == '0600' and file['publication'] == 'created')
check('wrapper_publisher_full9_lossless', file['identity'] == full9(wrapper_info))
check('wall_time_order', type(receipt['started_ns']) is int and type(receipt['terminal_ns']) is int and 0 <= receipt['terminal_ns'] - receipt['started_ns'] < 60_000_000_000)
prepare_go = json.loads(data['prepare_go'])
check('prepare_request_pin', sha(data['prepare_request'].encode()) == prepare_go['exact_request']['sha256'] and json.loads(data['prepare_request']) == prepare_go['exact_request']['request'])
check('prepare_only_no_live', prepare_go['live_go'] is False and prepare_go['private_fixture_allowed'] is False and prepare_go['product_service_allowed'] is False)

result = {'schema': 'heptabao.mac-current-full34-inert-lossless-closure.v1', 'status': 'PASS_INERT_ONLY_CONDITIONAL_PREPARE_PREREQUISITES', 'checks_passed': len(checks), 'checks': checks, 'source_tree': data['source_tree'], 'job_id': JOB, 'native_read_operations_closed': len(records), 'immutable_pages': sum(len(x['pages']) for x in records), 'stdout_bytes': 854, 'stderr_bytes': 0, 'wrapper_bytes': 20538, 'wrapper_sha256': wrapper_info['sha256'], 'wrapper_full9_decimal_strings': list(map(str, full9(wrapper_info))), 'wrapper_version': wrapper_info['version'], 'receipt_bytes': receipt_info['size'], 'receipt_sha256': receipt_info['sha256'], 'receipt_full9_decimal_strings': list(map(str, full9(receipt_info))), 'receipt_version': receipt_info['version'], 'observed_wall_elapsed_ns': str(receipt['terminal_ns'] - receipt['started_ns']), 'wall_elapsed_is_not_independent_monotonic_timer': True, 'prepare_submitted': False, 'live_submitted': False, 'product_executed': False, 'runtime_calls_inflight': 0, 'native_futures_inflight': 0, 'filesystem_read_batch_atomic': False}
result['checks_passed'] = len(checks)
OUTPUT.write_text(json.dumps(result, indent=2, sort_keys=True) + '\n')
print(json.dumps({'status': result['status'], 'checks_passed': len(checks), 'output_bytes': OUTPUT.stat().st_size, 'output_sha256': sha(OUTPUT.read_bytes()), 'job_id': JOB, 'original_operations': len(records), 'immutable_pages': result['immutable_pages']}, sort_keys=True))
