import ast
import base64
import hashlib
import json
from pathlib import Path

ROOT = Path('/workspace/scratch/f86faac821c4')
INPUT = ROOT / 'mac34_prepare_actual_input.json'
OUTPUT = ROOT / 'mac34_prepare_actual_verification.json'
CANONICAL = ROOT / 'mac34_prepared.actual.canonical.json'
data = json.loads(INPUT.read_text())
raws = data['raws']
checks = []


def check(name, condition):
    if not condition:
        raise AssertionError(name)
    checks.append(name)


def sha(value):
    return hashlib.sha256(value).hexdigest()


def parsed(path):
    return json.loads(raws[path])


def sdk_text(path):
    x = parsed(path)
    check(path + ':isError_false', x.get('isError') is False)
    texts = [c['text'] for c in x['content'] if c.get('type') == 'text']
    check(path + ':one_text', len(texts) == 1)
    return texts[0]


def binding(request):
    check('canonical:empty_env_current_scope', request.get('env', {}) == {})
    fields = {'args': request.get('args', []), 'cpu_quota_percent': request.get('cpu_quota_percent'), 'cwd': request.get('cwd'), 'env': {}, 'executable': request['executable'], 'host': request['host'], 'memory_max_bytes': request.get('memory_max_bytes'), 'nice': request.get('nice'), 'stdin': request.get('stdin'), 'timeout_seconds': request.get('timeout_seconds')}
    return json.dumps(fields, ensure_ascii=False, separators=(',', ':')).encode()


request = parsed('reference/exact-prepare-request.public.json')
go = parsed('reference/conditional-prepare-go.public.json')
check('root_request_exact', request == go['exact_request']['request'])
check('root_request_sha', sha(raws['reference/exact-prepare-request.public.json'].encode()) == go['exact_request']['sha256'])
check('outer90', request['timeout_seconds'] == 90)
check('prepare_only_args', request['args'][0:3] == ['-I', '-S', '-B'] and request['args'][-1] == '--prepare-only' and len(request['args']) == 5)
check('no_live_GO', go['live_go'] is False)
intent = parsed('intent/prepare.execution.intent.public.json')
check('intent_exact_request', intent['exact_request_json_original'] == raws['reference/exact-prepare-request.public.json'])
check('intent_exact_go', intent['root_go_json_original'] == raws['reference/conditional-prepare-go.public.json'])
check('intent_before_start', intent['process_start_submitted'] is False and intent['live_submitted'] is False)
check('inert_closed_prerequisite', intent['actual_inert_packet'] == data['inert_packet'] and data['inert_packet']['lossless_checks'] == 192)
check('ack_sdk_original', sdk_text('actual/prepare-start.original.sdk.json') == raws['actual/prepare-start.original.native.json'])
ack = parsed('actual/prepare-start.original.native.json')
job = ack['job']
JOB = '1a1ac939a61-fc05-5570'
check('ack_identity', job['id'] == JOB and job['host'] == 'mac')
check('ack_once_launched', ack['reused'] is False and ack['launch']['ok'] is True and job['launch_state'] == 'launched')
for field in ['args', 'cwd', 'executable', 'idempotency_key']:
    check('ack:' + field, job[field] == request[field])
canonical = binding(request)
digest = sha(canonical)
check('typed_canonical_bytes', canonical == raws['review/prepare-requestbinding.canonical.json'].encode())
check('typed_digest_actual', digest == job['request_digest'] == 'b35b8731505c9124294eea673a1b62f3df6a414547ac90926f4194b4b778217a')
check('fingerprint_lossless_actual', int(digest[:16], 16) == job['request_fingerprint'] == 12924072201541161252)
positive_request = json.loads(data['inert_request_raw'])
positive_ack = json.loads(data['inert_ack_raw'])
positive_digest = sha(binding(positive_request))
check('second_actual_digest_control', positive_digest == positive_ack['job']['request_digest'])
check('second_actual_fingerprint_control', int(positive_digest[:16], 16) == positive_ack['job']['request_fingerprint'])

check('two_original_read_operations', [x['name'] for x in data['records']] == ['authority', 'streams'])
check('unique_read_ids', len({x['operation_id'] for x in data['records']}) == 2)
for r in data['records']:
    name = r['name']
    prefix = 'reads/' + name + '/'
    ri = parsed(prefix + 'intent.public.json')
    check(name + ':request_exact', ri['request'] == r['request'])
    check(name + ':original_job_only', ri['request']['operation']['arguments']['host'] == 'mac' and ri['request']['operation']['arguments']['job_id'] == JOB)
    check(name + ':admission_original', sdk_text(prefix + 'admission.original.sdk.json') == raws[prefix + 'admission.original.native.json'])
    admission = parsed(prefix + 'admission.original.native.json')
    check(name + ':admission_binding', admission['operation_id'] == r['operation_id'] and admission['tool_name'] == r['request']['operation']['tool'])
    check(name + ':status_original', sdk_text(prefix + 'status.original.sdk.json') == raws[prefix + 'status.original.native.json'])
    status = parsed(prefix + 'status.original.native.json')
    check(name + ':closed', status['operation_id'] == r['operation_id'] and status['async_state'] == 'completed' and status['result_state'] == 'stored_observed' and status['owned_future_active'] is False and status['payload_available'] is True)
    result = bytearray()
    for pr in r['pages']:
        path = prefix + 'page-' + str(pr['offset']).zfill(7)
        check(path + ':native_original', sdk_text(path + '.original.sdk.json') == raws[path + '.original.native.json'])
        page = parsed(path + '.original.native.json')
        chunk = base64.b64decode(page['data_base64'], validate=True)
        check(path + ':cursor', page['offset'] == len(result) and page['next_offset'] == len(result) + len(chunk))
        check(path + ':identity', page['operation_id'] == r['operation_id'] and page['immutable_snapshot'] is True and page['result_sha256'] == r['result_sha256'] and page['total_bytes'] == r['total_bytes'])
        result.extend(chunk)
        check(path + ':eof', page['eof'] is (len(result) == page['total_bytes']))
    payload_raw = raws[prefix + 'immutable-payload.original.json']
    check(name + ':payload_whole_bytes', bytes(result) == payload_raw.encode() and len(result) == r['total_bytes'])
    check(name + ':payload_whole_sha', sha(result) == r['result_sha256'])
    payload = json.loads(payload_raw)
    check(name + ':original_native_success', payload['resultType'] == 'complete' and payload['isError'] is False)
    check(name + ':native_outcome_exact', payload['content'] == [{'type': 'text', 'text': raws['actual/' + name + '.original.json']}])

authority = parsed('actual/authority.original.json')
check('authority_job', authority['job_id'] == JOB)
check('authority_terminal0', authority['state'] == 'succeeded' and authority['exit_code'] == 0 and authority['cancelled'] is False and authority['timed_out'] is False)
check('authority_full_durable', authority['output_complete'] is True and authority['output_durable'] is True and authority['terminal_publication_confirmed'] is True)
streams = parsed('actual/streams.original.json')
check('streams_job', streams['job_id'] == JOB)
for name in ['stdout', 'stderr']:
    stream = streams[name]
    raw = raws['actual/' + name + '.original.log'].encode()
    check(name + ':hex_text_full', bytes.fromhex(stream['bytes_hex']) == raw == stream['text'].encode())
    check(name + ':eof_offsets', stream['offset'] == 0 and stream['next_offset'] == stream['size'] == len(raw) and stream['eof'] is True)
    check(name + ':authority_bytes', authority['log_bytes'][name] == {'seen': len(raw), 'stored': len(raw)})
    check(name + ':authority_no_truncation', authority['log_synced'][name] is True and authority['log_truncated'][name] is False and authority['log_errors'][name] is None)
check('4290_and_empty_streams', len(raws['actual/stdout.original.log'].encode()) == 4290 and raws['actual/stderr.original.log'] == '')
envelope = json.loads(raws['actual/stdout.original.log'])
check('envelope_schema', envelope['schema'] == 'heptabao.current-mac-full34-readonly-prepare-envelope.v1')
check('original_prepare_budget', 0 <= envelope['elapsed_seconds'] < 60)
prepared = envelope['prepared']

# Execute only the selected pure encoder definition from the exact approved source.
module = ast.parse(data['wrapper_source'])
encoder = [n for n in module.body if isinstance(n, ast.FunctionDef) and n.name == 'enc']
check('one_actual_encoder', len(encoder) == 1)
selected = ast.Module(body=encoder, type_ignores=[])
namespace = {'json': json}
exec(compile(selected, '<selected actual enc only>', 'exec'), namespace)
prepared_raw = namespace['enc'](prepared)
check('actual_encoder_exact_json', prepared_raw == (json.dumps(prepared, sort_keys=True, indent=2) + '\n').encode())
check('actual_prepared_sha', sha(prepared_raw) == envelope['prepared_sha256'] == 'ff9ccbc62be817c507ad47e1f2aea7463a2e7b5e636e7ac1c292f4b88e504da3')
check('six_full9_lossless', prepared['fixed_inputs'] == json.loads(data['expected_metadata']))
check('current_commit_tree', prepared['candidate_commit'] == '4e808d0ecb1bcded22870a7ec960dfb2491cf6ec' and prepared['candidate_tree'] == 'eba5e650bd080b8ad41ea52a2bc68867f541d255')
check('exact_driver', prepared['driver_sha256'] == '383176647f0670837f40f3989496c6d1c902f8503dfa006d386b75877436b581')
check('wrapper_pin', prepared['wrapper_sha256'] == sha(data['wrapper_source'].encode()) == '29785927055d2e676c702aa79b97db9a6d274d8d8de0916073c08face41c6c9a')
check('fresh_root_binding', prepared['control_root'] == request['cwd'] and prepared['fresh_work_root'] == request['cwd'] + '/actual-r1')
check('original_caps_cases', (prepared['original_checks'], prepared['original_http_seconds'], prepared['original_migration_seconds'], prepared['original_outer_seconds'], prepared['new_readonly_prepare_seconds']) == (31, 15, 360, 1800, 60))
check('normal61_exact', prepared['normal61_sha256'] == '02422f0070827e4940ae819d117b80ead30b993dba5ec9fe4a1aee21f286c113')
check('native_build_exact', prepared['native_build_sha256'] == '25c1ecc14b5b989d34227cef8d26964fdd0a6682fb3f8be754c2e1c501825f49')
check('normal_release_exact', prepared['normal_release_sha256'] == '2fdafe3670a0a7365245e509343ce1cf23ac28b071351d4f30ea12751d90a571')
check('source_before_exact', prepared['source_before'] == {'commit': prepared['candidate_commit'], 'tree': prepared['candidate_tree'], 'dirty': False, 'binary_sha256': 'c1b005a9f73c3f28681613d6fa3a5703d74e4f30358da4b7d9fa1949eb25ae63'})
for flag in ['private_fixture_created', 'product_started', 'production_changed', 'native_v6_ha_qualified', 'official_cli_phaseb_qualified', 'full_replacement_qualified']:
    check(flag + ':false', prepared[flag] is False)
CANONICAL.write_bytes(prepared_raw)
result = {'schema': 'heptabao.mac-current-full34-prepare-lossless-closure.v1', 'status': 'PASS_READONLY_PREPARE_ONLY', 'checks_passed': len(checks), 'checks': checks, 'job_id': JOB, 'original_native_read_operations': 2, 'immutable_pages': 2, 'stdout_bytes': 4290, 'stderr_bytes': 0, 'prepared_bytes': len(prepared_raw), 'prepared_sha256': sha(prepared_raw), 'request_binding_canonical_bytes': len(canonical), 'request_digest': digest, 'request_fingerprint_decimal': str(job['request_fingerprint']), 'runtime_reference_is_not_deployment_identity_proof': True, 'actual_second_positive_digest': positive_digest, 'source_commit': prepared['candidate_commit'], 'source_tree': prepared['candidate_tree'], 'elapsed_seconds_observed': envelope['elapsed_seconds'], 'original_cases': 31, 'original_http_seconds': 15, 'original_migration_seconds': 360, 'original_runtime_outer_seconds': 1800, 'readonly_prepare_internal_seconds': 60, 'readonly_prepare_outer_seconds': 90, 'live_submitted': False, 'product_started': False, 'native_futures_inflight': 0, 'runtime_calls_inflight': 0, 'original_mac_popen_limitations_unchanged': True}
OUTPUT.write_text(json.dumps(result, sort_keys=True, indent=2) + '\n')
print(json.dumps({'status': result['status'], 'checks_passed': len(checks), 'prepared_bytes': len(prepared_raw), 'prepared_sha256': sha(prepared_raw), 'verification_bytes': OUTPUT.stat().st_size, 'verification_sha256': sha(OUTPUT.read_bytes())}, sort_keys=True))
