import ast
import base64
from decimal import Decimal
import hashlib
import json
from pathlib import Path
import re

ROOT = Path('/workspace/scratch/f86faac821c4/mac34_live_actual_r1')
INPUT = ROOT / 'verification-input.original.json'
OUTPUT = ROOT / 'lossless-closure.public.json'
data = json.loads(INPUT.read_text())
raws = data['raws']
checks = []

def check(name, condition):
    if not condition:
        raise AssertionError(name)
    checks.append(name)

def sha(value):
    return hashlib.sha256(value).hexdigest()

def gitsha(value):
    return hashlib.sha1(b'blob ' + str(len(value)).encode() + b'\0' + value).hexdigest()

def pairs(items):
    d = {}
    for k, v in items:
        if k in d:
            raise AssertionError('duplicate_json_key:' + k)
        d[k] = v
    return d

def parsed(path):
    return json.loads(raws[path], object_pairs_hook=pairs)

def sdk_text(path):
    x = parsed(path)
    check(path + ':isError_false', x.get('isError') is False)
    texts = [c['text'] for c in x['content'] if c.get('type') == 'text']
    check(path + ':one_text', len(texts) == 1)
    return texts[0]

def binding(request):
    check('canonical_empty_env', request.get('env', {}) == {})
    fields = {'args': request.get('args', []), 'cpu_quota_percent': request.get('cpu_quota_percent'), 'cwd': request.get('cwd'), 'env': {}, 'executable': request['executable'], 'host': request['host'], 'memory_max_bytes': request.get('memory_max_bytes'), 'nice': request.get('nice'), 'stdin': request.get('stdin'), 'timeout_seconds': request.get('timeout_seconds')}
    return json.dumps(fields, ensure_ascii=False, separators=(',', ':')).encode()

JOB = '1a1ac9bd07c-fc05-55cf'
COMMIT = '4e808d0ecb1bcded22870a7ec960dfb2491cf6ec'
TREE = 'eba5e650bd080b8ad41ea52a2bc68867f541d255'
SERVER_SHA = 'c1b005a9f73c3f28681613d6fa3a5703d74e4f30358da4b7d9fa1949eb25ae63'
WRAPPER_SHA = '29785927055d2e676c702aa79b97db9a6d274d8d8de0916073c08face41c6c9a'
DRIVER_SHA = '383176647f0670837f40f3989496c6d1c902f8503dfa006d386b75877436b581'
PREPARED_SHA = 'ff9ccbc62be817c507ad47e1f2aea7463a2e7b5e636e7ac1c292f4b88e504da3'
SUMMARY_SHA = '9c3701f34d94934efa31f7308e56a0860756258559476b541c395edd57da29d3'
result_sha = 'cd607cea8a092893a4c311fcf0f17d657a0d9aa6cd90216fca389119426c42d4'

# Every original SDK, native payload and text was independently saved and read whole.
for meta in data['already_archived_files']:
    raw = raws[meta['path']].encode()
    check(meta['path'] + ':whole_bytes_sha_git', len(raw) == meta['bytes'] and sha(raw) == meta['sha256'] and gitsha(raw) == meta['blob'])
check('zero_runtime_future_after_fixed_reads', data['runtime_inflight'] is False and data['active_read'] is None)

request = parsed('reference/exact-live-request.public.json')
go = parsed('reference/root-live-go.public.json')
check('exact_root_request', request == go['exact_request']['request'])
check('exact_root_request_whole', len(raws['reference/exact-live-request.public.json'].encode()) == go['exact_request']['bytes'] == 622 and sha(raws['reference/exact-live-request.public.json'].encode()) == go['exact_request']['sha256'])
check('original_outer1800', request['timeout_seconds'] == 1800)
check('exact_run_args', request['args'][:3] == ['-I', '-S', '-B'] and request['args'][-2:] == ['--run', PREPARED_SHA] and len(request['args']) == 6)
intent = parsed('intent/live.execution.intent.public.json')
check('external_intent_exact_request', intent['exact_request_json_original'] == raws['reference/exact-live-request.public.json'])
check('external_intent_exact_go', intent['root_go_json_original'] == raws['reference/root-live-go.public.json'])
check('ack_original_sdk_native', sdk_text('actual/live-start.original.sdk.json') == raws['actual/live-start.original.native.json'])
ack = parsed('actual/live-start.original.native.json')
job = ack['job']
check('single_ack_identity', job['id'] == JOB and job['host'] == 'mac' and ack['reused'] is False)
check('launched_once', ack['launch']['ok'] is True and job['launch_state'] == 'launched' and job['launch_error'] is None)
for k in ['args', 'cwd', 'executable', 'idempotency_key']:
    check('ack_exact_' + k, job[k] == request[k])
canonical = binding(request)
digest = sha(canonical)
check('typed_request_digest', digest == job['request_digest'] == '8bfc672565bb087cfaafe5e9b5b948d6e8a4585af584d0974bcf2aadff570bdf')
check('lossless_u64_fingerprint', int(digest[:16], 16) == job['request_fingerprint'] == 10087050675721275516)
check('runtime_reference_only', data['runtime_reference_is_not_deployment_identity_proof'] is True)
prepared_raw = raws['reference/prepared.actual.canonical.json'].encode()
prepared = parsed('reference/prepared.actual.canonical.json')
check('actual_prepared_whole', len(prepared_raw) == 4876 and sha(prepared_raw) == PREPARED_SHA)
check('actual_prepared_six_full9_lossless', prepared['fixed_inputs'] == parsed('reference/input-metadata.public.json'))
for role, value in prepared['fixed_inputs'].items():
    info = parsed('reference/actual-' + role + '-file-info.original.json')
    dev, ino, size, mtime, ctime = map(int, info['version'].split(':'))
    md = info['metadata']
    full9 = [dev, ino, md['uid'], md['gid'], 0o100000 | md['mode'], md['link_count'], size, mtime, ctime]
    check('prepared_actual_input_' + role, value['identity'] == full9 and value['bytes'] == info['size'] == size and value['path'] == info['path'] and value['sha256'] == info['sha256'] and value['version'] == info['version'])
check('new_private_work_root_only', prepared['fresh_work_root'] == request['cwd'] + '/actual-r1' == go['fresh_work_root'])
check('actual_controller_unchanged', sha(raws['actual/controller.original.py'].encode()) == prepared['wrapper_sha256'] == WRAPPER_SHA)
check('canonical_driver_whole', len(raws['reference/canonical-full34-driver.py'].encode()) == 49393 and sha(raws['reference/canonical-full34-driver.py'].encode()) == DRIVER_SHA and gitsha(raws['reference/canonical-full34-driver.py'].encode()) == '87db25eab1258c8a2d7f9047e2009b62404b6259')

names = ['authority-01', 'streams', 'core-small', 'summary-info', 'summary-chunk-000000', 'summary-chunk-065536', 'driver-stdout-info', 'driver-stdout-body']
check('eight_original_read_operations', [x['name'] for x in data['records']] == names)
check('eight_distinct_read_ids', len({x['operation_id'] for x in data['records']}) == 8)
check('sixteen_original_pages', sum(len(x['pages']) for x in data['records']) == 16)
for r in data['records']:
    name = r['name']
    prefix = 'reads/' + name + '/'
    ri = parsed(prefix + 'intent.public.json')
    check(name + ':exact_read_intent', ri['request'] == r['request'] and ri['job_ack_blob'] == '6dbe7c089f72e4a18a3d785eaf822a620980a1db')
    check(name + ':fixed_mac_only', r['request']['operation']['arguments']['host'] == 'mac')
    check(name + ':no_native_replay', r['stage'] == 'COMPLETE')
    check(name + ':admission_original', sdk_text(prefix + 'admission.original.sdk.json') == raws[prefix + 'admission.original.native.json'])
    admission = parsed(prefix + 'admission.original.native.json')
    check(name + ':admission_identity', admission['operation_id'] == r['operation_id'] and admission['tool_name'] == r['request']['operation']['tool'])
    check(name + ':status_original', sdk_text(prefix + 'status.original.sdk.json') == raws[prefix + 'status.original.native.json'])
    status = parsed(prefix + 'status.original.native.json')
    check(name + ':closed_inactive', status['operation_id'] == r['operation_id'] and status['async_state'] == 'completed' and status['result_state'] == 'stored_observed' and status['owned_future_active'] is False and status['payload_available'] is True)
    result = bytearray()
    for page_record in r['pages']:
        p = prefix + 'page-' + str(page_record['offset']).zfill(7)
        check(p + ':original_sdk_text', sdk_text(p + '.original.sdk.json') == raws[p + '.original.native.json'])
        page = parsed(p + '.original.native.json')
        chunk = base64.b64decode(page['data_base64'], validate=True)
        check(p + ':offsets', page['offset'] == len(result) and page['next_offset'] == len(result) + len(chunk))
        check(p + ':immutable_identity', page['operation_id'] == r['operation_id'] and page['immutable_snapshot'] is True and page['result_sha256'] == r['result_sha256'] and page['total_bytes'] == r['total_bytes'])
        result.extend(chunk)
        check(p + ':exact_eof', page['eof'] is (len(result) == page['total_bytes']))
    original_payload = raws[prefix + 'immutable-payload.original.json'].encode()
    check(name + ':whole_original_payload', bytes(result) == original_payload and len(result) == r['total_bytes'] and sha(result) == r['result_sha256'])
    payload = json.loads(original_payload, object_pairs_hook=pairs)
    check(name + ':native_complete_success', payload['resultType'] == 'complete' and payload['isError'] is False)
    check(name + ':native_outcome_exact', payload['content'] == [{'type': 'text', 'text': raws['actual/' + name + '.original.json']}])

authority = parsed('actual/authority-01.original.json')
check('authority_job', authority['job_id'] == JOB)
check('authority_zero_full_durable', authority['state'] == 'succeeded' and authority['exit_code'] == 0 and authority['output_complete'] is True and authority['output_durable'] is True and authority['terminal_publication_confirmed'] is True)
check('authority_no_timeout_or_cancel', authority['timed_out'] is False and authority['cancelled'] is False and authority['automatic_retry'] is False)
streams = parsed('actual/streams.original.json')
check('streams_same_original_job', streams['job_id'] == JOB)
for name in ['stdout', 'stderr']:
    stream = streams[name]
    raw = raws['actual/' + name + '.original.log'].encode()
    check(name + ':hex_and_text_whole', bytes.fromhex(stream['bytes_hex']) == raw == stream['text'].encode())
    check(name + ':whole_offsets_eof', stream['offset'] == 0 and stream['next_offset'] == stream['size'] == len(raw) and stream['eof'] is True)
    check(name + ':authority_sizes', authority['log_bytes'][name] == {'seen': len(raw), 'stored': len(raw)})
    check(name + ':no_loss', authority['log_synced'][name] is True and authority['log_truncated'][name] is False and authority['log_errors'][name] is None)
check('original_297_zero', len(raws['actual/stdout.original.log'].encode()) == 297 and raws['actual/stderr.original.log'] == '')
core_map = {'result.public.json': 'actual/result.public.json', 'intent.public.json': 'actual/driver-intent.public.json', 'run.stderr': 'actual/driver.stderr.original.log', 'run_current_mac_full34_r1.py': 'actual/controller.original.py'}
batch = parsed('actual/core-small.original.json')
check('four_complete_public_files_nonatomic', len(batch['files']) == 4 and batch['atomic_snapshot'] is False)
for f in batch['files']:
    k = Path(f['path']).name
    raw = raws[core_map[k]].encode()
    check(k + ':whole_text_bytes_sha', f['text'].encode() == raw and f['size'] == len(raw) and f['sha256'] == sha(raw) and f['eof'] is True)
    check(k + ':version_size', int(f['version'].split(':')[2]) == len(raw))
check('driver_stderr_empty', raws['actual/driver.stderr.original.log'] == '')

summary_info = parsed('actual/summary-info.original.json')
summary_bytes = bytearray()
for name in ['summary-chunk-000000', 'summary-chunk-065536']:
    x = parsed('actual/' + name + '.original.json')
    b = base64.b64decode(x['data_base64'], validate=True)
    check(name + ':version_path_sha', x['version'] == summary_info['version'] and x['path'] == summary_info['path'] and x['chunk_sha256'] == sha(b))
    check(name + ':size_cursor', x['size'] == summary_info['size'] and x['offset'] == len(summary_bytes) and x['next_offset'] == len(summary_bytes) + len(b))
    summary_bytes.extend(b)
    check(name + ':whole_eof', x['eof'] is (len(summary_bytes) == summary_info['size']))
check('summary_complete_whole', bytes(summary_bytes) == raws['actual/summary.public.json'].encode() and len(summary_bytes) == summary_info['size'] == 91727 and sha(summary_bytes) == summary_info['sha256'] == SUMMARY_SHA)
stdout_info = parsed('actual/driver-stdout-info.original.json')
stdout_body = parsed('actual/driver-stdout-body.original.json')
driver_stdout = base64.b64decode(stdout_body['data_base64'], validate=True)
check('driver_stdout_exact_original', driver_stdout == raws['actual/driver.stdout.original.log'].encode() and len(driver_stdout) == stdout_info['size'] == 209 and sha(driver_stdout) == stdout_info['sha256'] == stdout_body['chunk_sha256'])
check('driver_stdout_version_eof', stdout_body['path'] == stdout_info['path'] and stdout_body['version'] == stdout_info['version'] and stdout_body['offset'] == 0 and stdout_body['next_offset'] == 209 and stdout_body['eof'] is True)

envelope = parsed('actual/stdout.original.log')
result = parsed('actual/result.public.json')
summary = parsed('actual/summary.public.json')
check('result_envelope_whole', envelope['bytes'] == len(raws['actual/result.public.json'].encode()) == 1122 and envelope['sha256'] == sha(raws['actual/result.public.json'].encode()) == result_sha)
check('result_summary_reference_whole', result['summary_bytes'] == len(summary_bytes) and result['summary_sha256'] == sha(summary_bytes))
check('result_original31_terminal', result['ok'] is True and result['checks_passed'] == result['checks_total'] == 31 and result['missing_checks'] == [] and result['child_exit_code'] == 0 and result['failure'] is None and result['reported_status'] == 'passed')
check('result47_534_original1800', result['elapsed_seconds'] == 47.534 and 0 < result['elapsed_seconds'] < 1800)
check('unchanged_original_http_migration', result['original_http_seconds'] == 15 and result['original_migration_seconds'] == 360)
check('source_binary_before_after_same', result['source_before'] == result['source_after'] == prepared['source_before'] and result['source_unchanged'] is True)
check('owned_stop_reported', result['owned_processes_stopped'] is True)
driver_intent = parsed('actual/driver-intent.public.json')
check('driver_intent_prepared_source', driver_intent['actual_prepared_sha256'] == PREPARED_SHA and driver_intent['source_before'] == prepared['source_before'])
check('driver_argv_exact', driver_intent['argv'] == [request['executable'], '-I', '-S', '-B', prepared['source'] + '/qa/openbao-acceptance/kv2_271_lossless_native_live.py', '--binary', prepared['retained_server'], '--private-work-root', prepared['fresh_work_root'] + '/private-run', '--migration-lane', 'native-large', '--profile', 'full34'])
check('driver_normal_receipts_bound', driver_intent['default_build_receipt_sha256'] == prepared['native_build_sha256'] and driver_intent['default_build_result_sha256'] == prepared['normal_release_sha256'] and driver_intent['normal_default_build_verified'] is True)

module = ast.parse(raws['reference/canonical-full34-driver.py'])
constants = {n.targets[0].id: n.value for n in module.body if isinstance(n, ast.Assign) and len(n.targets) == 1 and isinstance(n.targets[0], ast.Name)}
original_cases = ast.literal_eval(constants['CHECKS'])
check('31_exact_canonical_names', len(original_cases) == len(set(original_cases)) == 31 and summary['checks'] == [{'case': c, 'passed': True} for c in original_cases])
check('driver15_360', ast.literal_eval(constants['HTTP_SECONDS']) == 15 and ast.literal_eval(constants['MIGRATION_SECONDS']) == 360)
check('summary_current_source', summary['source_commit'] == COMMIT and summary['source_tree'] == TREE and summary['source_dirty'] is False and summary['binary_sha256'] == SERVER_SHA)
check('summary_full34_status', summary['schema'] == 'heptabao.openbao271-kv2-lossless-native-live.v1' and summary['status'] == 'passed' and summary['profile'] == 'full34' and summary['full34_qualified'] is True and summary['missing_checks'] == [])
check('actual17_times2MiB', summary['retained_live_versions'] == 17 and summary['live_payload_bytes'] == 17 * 2 * 1024 * 1024)
check('actual_native_not_fixture', summary['candidate_startup']['storage_profile'] == 'native_v6_file' and summary['candidate_startup']['fixture_options'] is False and summary['native_before_import'] is True)
capacity = summary['capacity_after_import']
check('actual_v6_capacity', capacity['state_storage_format'] == 'heptabao-state-records-v6' and capacity['profile'] == 'bounded-native-record-state-v6-paged' and capacity['state_bytes'] == 35701401 and capacity['native_kv2_logical_payload_bytes'] == 35655894)
check('capacity_no_fullcompat_claim', capacity['full_openbao_compatibility'] is False and capacity['production_qualified'] is False)
official = summary['official_identity']
check('official271_actual_pins', summary['official_version'] == official['version'] == '2.7.1' and official['product'] == 'OpenBao' and official['archive_member_matches_executable'] is True and official['artifact_sha256'] == prepared['fixed_inputs']['oracle_archive']['sha256'] and official['binary_sha256'] == prepared['fixed_inputs']['oracle_binary']['sha256'])
check('official_real_tls_loopback', official['server_mode'] == 'server_not_dev' and official['storage'] == 'pebbledb' and official['tls_verified'] is True and official['endpoint'].startswith('https://127.0.0.1:'))
migrations = summary['migration_invocations']
check('two_migration_invocations', len(migrations) == 2 and [m['operation'] for m in migrations] == ['export', 'import'])
for m in migrations:
    check('migration_' + m['operation'] + '_once_original360', m['lane'] == 'native-large' and m['original_budget_seconds'] == 360 and m['original_popen'] is True and m['original_wait_completed'] is True and m['retried'] is False and m['returncode'] == 0 and m['status'] == 'completed' and m['pid'] == m['pgid'] > 0)
export, imported = [m['receipt'] for m in migrations]
check('migration_actual_bundle', export['bytes'] == 35658766 and export['records'] == 24 and export['sha256'] == imported['source_sha256'] == 'eb60c409df6d00b691ee8797605ef5e827671be1d40c9ea32595e83393997b74' and imported['status'] == 204)

# Read only pure constant and payload/encoder AST definitions; no candidate module execution.
pure_names = {'need', 'payload', 'canonical'}
pure_nodes = [n for n in module.body if isinstance(n, ast.FunctionDef) and n.name in pure_names]
check('three_selected_pure_definitions', len(pure_nodes) == 3)
namespace = {'json': json, 'Decimal': Decimal, 'Failure': RuntimeError}
exec(compile(ast.Module(body=pure_nodes, type_ignores=[]), '<actual pure payload and canonical>', 'exec'), namespace)
expected = {}
for v in range(1, 20):
    raw = b'' if v == 2 else namespace['canonical'](namespace['payload'](v, 17, 2 * 1024 * 1024))
    expected[v] = (len(raw), sha(raw) if v != 2 else None, v != 2)
witnesses = summary['target_storage_witnesses']
stages = ['target_storage_full_history_exact', 'target_storage_cold_history_exact', 'restored_storage_history_exact']
check('three_actual_storage_stages', len(witnesses) == 3 and [w['stage'] for w in witnesses] == stages)
for stage in witnesses:
    vs = stage['versions']
    check(stage['stage'] + ':19_raw_bound', stage['source_raw_bound'] is True and [v['version'] for v in vs] == list(range(1, 20)))
    for w in vs:
        v = w['version']
        check(stage['stage'] + ':v' + str(v) + ':raw_payload_precision', (w['payload_canonical_bytes'], w['payload_canonical_sha256'], w['payload_present']) == expected[v])
        check(stage['stage'] + ':v' + str(v) + ':fixed_identity', w['schema'] == 'heptabao-native-kv2-storage-witness-v1' and w['canonical_profile'] == 'heptabao-lossless-json-v1' and w['mount'] == 'secret' and w['path'] == 'history' and w['destroyed'] is (v == 2) and bool(w['deletion_time']) is (v == 1))
        check(stage['stage'] + ':v' + str(v) + ':actual_root', re.fullmatch(r'[0-9a-f]{64}', w['source_root_sha256']) is not None and type(w['source_publication_generation']) is int and w['source_publication_generation'] >= 0 and w['mount_incarnation'] > 0)
baseline = witnesses[0]['versions']
for stage in witnesses[1:]:
    for old, new in zip(baseline, stage['versions']):
        check(stage['stage'] + ':v' + str(old['version']) + ':same_stored_metadata', all(old[k] == new[k] for k in old if k not in ('source_root_sha256', 'source_publication_generation')))
check('storage_precision_qualification_reported', summary['target_storage_precision_qualified'] is True)
numeric = summary['source_api_numeric_observations']
wire = summary['source_api_wire_observations']
check('19_actual_api_number_and_wire_rows', len(numeric) == len(wire) == 19 and [x['version'] for x in numeric] == list(range(1, 20)))
for n in numeric:
    check('api_projection_distinct_from_raw_v' + str(n['version']), n['wide_integer'] == {'actual_token': '9007199254740992', 'generated_token': '9007199254740993', 'numerically_equal': False} and n['exact_decimal'] == {'actual_token': '0.12345678901234568', 'generated_token': '0.123456789012345678901234567890', 'numerically_equal': False})
snapshot = summary['snapshot']
check('current_snapshot_exact', snapshot == {'archive_bytes': 9018321, 'archive_sha256': 'baffe549dee36624eda867aa62e94f9b47760315aafd8a3805efd213d9417273', 'status': 200})
mutations = summary['mutations']
check('all_mutations_known_waited_once', all(m['outcome'] == 'response_received' and m['owned_leaf_wait_completed'] is True and m['retried'] is False for m in mutations))
check('one_snapshot_restore', len([m for m in mutations if m['endpoint'] == 'target' and m['path'] == 'sys/storage/raft/snapshot' and m['method'] == 'POST' and m['status'] == 200]) == 1)
check('one_post_snapshot_data_write', len([m for m in mutations if m['endpoint'] == 'target' and m['path'] == 'secret/data/history' and m['status'] == 200]) == 1)
check('57_actual_witness_requests', len([m for m in mutations if m['endpoint'] == 'target' and m['path'] == 'sys/internal/storage/kv2-version-witness' and m['status'] == 200]) == 57)
check('two_negative_CAS_and_one_metadata_success', len([m for m in mutations if m['endpoint'] == 'target' and m['path'] in ('secret/data/history', 'secret/metadata/history') and m['status'] == 400]) == 2 and len([m for m in mutations if m['endpoint'] == 'target' and m['path'] == 'secret/metadata/history' and m['status'] == 204]) == 1)
check('cleanup_source_history', summary['source_unchanged_at_cleanup'] is True and summary['target_history_status_at_cleanup'] == 200)
check('driver_stdout_public_summary', json.loads(driver_stdout) == {'status': 'passed', 'profile': 'full34', 'summary': prepared['fresh_work_root'] + '/private-run/summary.json', 'full34_qualified': True})
for flag in ('full_compatibility_claim', 'replacement_authority', 'production_authority', 'v6_ha_qualified'):
    check(flag + ':false', summary[flag] is False)
for flag in ('production_changed', 'production_cutover', 'full_replacement_qualified'):
    check(flag + ':false', result[flag] is False)
check('synthetic_only_tls', summary['synthetic_only'] is True and summary['tls_verified'] is True)

report = {
    'schema': 'heptabao.mac-current-full34-live-lossless-closure.v1',
    'status': 'PASS_MAC_SINGLE_NODE_FULL34_ORIGINAL31',
    'checks_passed': len(checks), 'checks': checks,
    'job_id': JOB, 'host': 'mac', 'source_commit': COMMIT, 'source_tree': TREE,
    'original_read_operations': 8, 'immutable_pages': 16,
    'original_job_stdout_bytes': 297, 'original_job_stderr_bytes': 0,
    'original_driver_stdout_bytes': 209, 'original_driver_stderr_bytes': 0,
    'original_summary_bytes': 91727, 'original_summary_sha256': SUMMARY_SHA,
    'original_result_bytes': 1122, 'original_result_sha256': result_sha,
    'request_digest': digest, 'request_fingerprint_decimal': str(job['request_fingerprint']),
    'request_binding_bytes': len(canonical), 'runtime_reference_is_not_deployment_identity_proof': True,
    'original31_passed': 31, 'original31_total': 31, 'elapsed_seconds_observed': result['elapsed_seconds'],
    'original_limits': {'http_seconds': 15, 'migration_seconds': 360, 'runtime_outer_seconds': 1800, 'native_worker_http_seconds': 5},
    'live_payload_bytes': summary['live_payload_bytes'], 'retained_live_versions': 17,
    'history_versions_per_storage_stage': 19, 'storage_witness_stages': stages, 'storage_witness_count': 57,
    'migration_invocations': 2, 'migration_retries': 0, 'snapshot': snapshot,
    'api_number_projection_and_raw_storage_precision_separate': True,
    'original_mac_popen_limitations_unchanged': True,
    'linux_affine_owner_cleanup_claim': False, 'new_exceptional_cleanup_bound_claim': False,
    'full34_qualified': True, 'single_node_only': True, 'synthetic_only': True,
    'native_v6_ha_qualified': False, 'official_cli_phaseb_qualified': False, 'h2_fixture_qualified': False,
    'x230_qualified': False, 'production_authbus_qualified': False, 'full_openbao271_qualified': False,
    'production_cutover': False, 'production_changed': False, 'full_replacement_qualified': False,
    'runtime_calls_inflight': 0, 'native_futures_inflight': 0,
    'no_private_token_or_credential_files_read': True,
}
OUTPUT.write_text(json.dumps(report, sort_keys=True, indent=2) + '\n')
(ROOT / 'live-requestbinding.canonical.json').write_bytes(canonical)
print(json.dumps({'status': report['status'], 'checks_passed': len(checks), 'verification_bytes': OUTPUT.stat().st_size, 'verification_sha256': sha(OUTPUT.read_bytes()), 'snapshot_bytes': snapshot['archive_bytes'], 'operations': 8, 'pages': 16}, sort_keys=True))
