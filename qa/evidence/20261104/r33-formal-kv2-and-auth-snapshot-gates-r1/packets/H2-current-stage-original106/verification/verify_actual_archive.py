"""Offline H2 stage evidence-chain and closure check; never executes staged code."""
from pathlib import Path
import base64
import hashlib
import json

ROOT = Path('/workspace/scratch/f86faac821c4/ha_h2_stage_actual_r1')
CACHE = Path('/workspace/scratch/f86faac821c4/r32_recovery')
INDEX = json.loads((ROOT / 'archive-input.public.json').read_text())
ROWS = []
RAW = {}

def check(name, value, actual=None):
    ROWS.append({'check': name, 'passed': bool(value), 'actual': actual})
    if not value:
        write_result(False)
        raise AssertionError(name)

def write_result(passed):
    result = {'schema': 'heptabao.H2-stage.actual-offline-verification.v1',
              'passed': passed, 'checks': len(ROWS), 'rows': ROWS,
              'Runtime_calls': 0, 'staged_module_executed': False,
              'product_cases': 0, 'target_file_info_calls': 0, 'target_body_calls': 0,
              'historical_unlocated_status_query_preserved': True}
    (ROOT / 'verification-result.public.json').write_text(json.dumps(result, indent=2) + '\n')

def sha(data):
    return hashlib.sha256(data).hexdigest()

def git_blob(data):
    return hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest()

for path, oid in INDEX['files'].items():
    text = json.loads((CACHE / ('blob-' + oid + '.json')).read_text())['text']
    RAW[path] = text
    check('whole Git blob: ' + path, git_blob(text.encode()) == oid)

def obj(path):
    return json.loads(RAW[path])

def sdk_native(sdk_path, native_path):
    sdk = obj(sdk_path)
    check('SDK non-error: ' + sdk_path, sdk.get('isError') is False)
    blocks = [x for x in sdk['content'] if x['type'] == 'text']
    check('SDK native exact: ' + sdk_path,
          len(blocks) == 1 and blocks[0]['text'] == RAW[native_path])

def request_pin(intent, request_path):
    pin = intent['request']
    data = RAW[request_path].encode()
    check('intent exact request: ' + request_path,
          pin['blob'] == git_blob(data) and pin['bytes'] == len(data)
          and pin['sha256'] == sha(data))

req = obj('execution/request.original.json')
intent = obj('execution/intent.original.json')
ack = obj('execution/ACK.original.native.json')
go = obj('references/ROOT-GO.public.json')
job = ack['job']
job_id = INDEX['job_id']
sdk_native('execution/ACK.original.sdk.json', 'execution/ACK.original.native.json')
check('original exact raw request pin', intent['original_raw_request']['blob'] == INDEX['files']['execution/request.original.json']
      and intent['original_raw_request']['sha256'] == sha(RAW['execution/request.original.json'].encode())
      and intent['original_raw_request']['bytes'] == len(RAW['execution/request.original.json'].encode()))
check('original job identity', job['id'] == job_id and job['host'] == 'desktop')
for field in ('args', 'cwd', 'executable', 'idempotency_key'):
    check('ACK request field: ' + field, job[field] == req[field])
check('original seven argv and exact candidate', len(req['args']) == 7 and req['args'][:4] == ['-I', '-S', '-B', '-c']
      and req['args'][4] == RAW['references/stage-source.py'])
check('source self hash argument', req['args'][5] == '--external-controller-sha256'
      and req['args'][6] == sha(RAW['references/stage-source.py'].encode()) == go['candidate_sha256'])
check('exact stdin source pin', len(req['stdin'].encode()) == 321152
      and sha(req['stdin'].encode()) == go['carrier_sha256'])
check('original supervisor cap', req['timeout_seconds'] == 330 == go['outer_timeout_seconds'])
check('native digest and lossless fingerprint', job['request_digest'] == go['typed_request_sha256']
      and job['request_fingerprint'] == int(go['native_fingerprint']))
check('ACK no replay and launched', ack['reused'] is False and ack['local_record_pending'] is False
      and job['launch_state'] == 'launched' and ack['launch']['ok'] is True)

native_results = {}
for observer in INDEX['observers']:
    name = observer['name']
    base = 'observations/' + name + '/'
    request = obj(base + 'request.original.json')
    request_pin(obj(base + 'intent.original.json'), base + 'request.original.json')
    admission = obj(base + 'admission.original.native.json')
    status = obj(base + 'status.original.native.json')
    sdk_native(base + 'admission.original.sdk.json', base + 'admission.original.native.json')
    sdk_native(base + 'status.original.sdk.json', base + 'status.original.native.json')
    request_pin(obj(base + 'status.intent.original.json'), base + 'status.request.original.json')
    check(name + ' same-ID status request', obj(base + 'status.request.original.json') == {'operation_id': observer['operation_id']})
    check(name + ' same admitted ID/tool', admission['operation_id'] == status['operation_id'] == observer['operation_id']
          and admission['tool_name'] == status['tool_name'] == request['operation']['tool'])
    check(name + ' original job only', request['operation']['arguments']['host'] == 'desktop'
          and request['operation']['arguments']['job_id'] == job_id)
    check(name + ' closed original observer', status['async_state'] == 'completed'
          and status['result_state'] == 'stored_observed' and status['owned_future_active'] is False
          and status['payload_available'] is True)
    collected = bytearray()
    declared = None
    for offset in observer['page_offsets']:
        path = base + 'pages/' + str(offset).zfill(6)
        rq = obj(path + '.request.original.json')
        request_pin(obj(path + '.intent.original.json'), path + '.request.original.json')
        check(path + ' exact original result request', rq == {'operation_id': observer['operation_id'], 'offset': offset, 'limit': 8192})
        sdk_native(path + '.original.sdk.json', path + '.original.native.json')
        page = obj(path + '.original.native.json')
        chunk = base64.b64decode(page['data_base64'], validate=True)
        identity = (page['total_bytes'], page['result_sha256'])
        if declared is None:
            declared = identity
        check(path + ' same immutable payload', identity == declared and page['operation_id'] == observer['operation_id']
              and page['immutable_snapshot'] is True)
        check(path + ' exact cursor and bytes', page['offset'] == offset == len(collected)
              and len(chunk) == min(8192, page['total_bytes'] - offset)
              and page['next_offset'] == offset + len(chunk)
              and page['eof'] is (page['next_offset'] == page['total_bytes']))
        collected.extend(chunk)
    check(name + ' payload EOF and whole', len(collected) == declared[0] and sha(collected) == declared[1]
          and collected == RAW[base + 'payload.original.json'].encode())
    payload = json.loads(collected)
    check(name + ' original payload non-error', payload['resultType'] == 'complete' and payload['isError'] is False)
    text_blocks = [x for x in payload['content'] if x['type'] == 'text']
    check(name + ' original native exact', len(text_blocks) == 1 and text_blocks[0]['text'] == RAW[base + 'native.original.json'])
    native_results[name] = obj(base + 'native.original.json')

authority = native_results['authority0']
check('authoritative original stage terminal', authority['job_id'] == job_id and authority['exit_code'] == 0
      and authority['state'] == 'succeeded' and authority['output_complete'] is True
      and authority['output_durable'] is True and authority['terminal_publication_confirmed'] is True
      and authority['timed_out'] is False and authority['cancelled'] is False)
check('complete durable original log totals', authority['log_bytes'] == {'stdout': {'seen': 23147, 'stored': 23147}, 'stderr': {'seen': 0, 'stored': 0}}
      and authority['log_synced'] == {'stdout': True, 'stderr': True}
      and authority['log_truncated'] == {'stdout': False, 'stderr': False}
      and authority['log_errors'] == {'stdout': None, 'stderr': None})
out = bytearray()
for name in ('streams0', 'streams1'):
    native = native_results[name]
    part = native['stdout']
    raw = bytes.fromhex(part['bytes_hex'])
    check(name + ' exact stdout text/hex/cursor', native['job_id'] == job_id
          and raw == part['text'].encode() and part['offset'] == len(out)
          and part['next_offset'] == len(out) + len(raw) and part['size'] == 23147
          and len(raw) <= 16384)
    out.extend(raw)
    check(name + ' exact stdout EOF', part['eof'] is (len(out) == 23147))
    check(name + ' empty stderr dual EOF', native['stderr'] == {'bytes_hex': '', 'eof': True, 'next_offset': 0, 'offset': 0, 'size': 0, 'text': ''})
check('whole stdout original bytes', out == RAW['actual/stdout.original.json'].encode() and len(out) == 23147)
check('whole stderr empty', RAW['actual/stderr.original.txt'] == '')
result = json.loads(out)
check('post-finally closure conjunct', result['status'] == 'passed' and result['all_stage_fds_closed'] is True
      and result['fd_close_pending'] is False and result['fd_close_errors'] == []
      and result['within_stage_deadline'] is True and 0 <= result['elapsed_after_closure_ms'] < 300000)
check('no product/process/network/prepare/cutover', result['children_spawned'] == 0 and result['network_calls'] == 0
      and all(result[x] is False for x in ('product_started', 'readonly_prepare_started', 'production_changed', 'source_tree_modified', 'runtime_qualification', 'original_existing_assets_replaced')))
check('exact product canonical identity', result['source_commit'] == '4e808d0ecb1bcded22870a7ec960dfb2491cf6ec'
      and result['source_tree'] == 'eba5e650bd080b8ad41ea52a2bc68867f541d255')
check('source custody unchanged', result['source_metadata_unchanged'] is True
      and result['source_full_git_verification_performed_by_stage'] is False
      and result['source_full_git_verification_required_in_readonly_prepare'] is True)
check('fixed staged role counts', len(result['copied']) == 3 and len(result['h2_copied']) == 12
      and len(result['qa_files']) == 5 and len(result['extra_artifacts']) == 2)
for idx, copy_record in enumerate(result['copied'] + list(result['h2_copied'].values())):
    check('same-FD copy/readback ' + str(idx), copy_record['create_only'] is True and copy_record['same_fd_readback'] is True
          and copy_record['source']['sha256'] == copy_record['target']['sha256']
          and copy_record['source']['bytes'] == copy_record['target']['bytes'])
preclose = dict(result)
for key in ('all_stage_fds_closed', 'fd_close_errors', 'elapsed_after_closure_ms', 'within_stage_deadline'):
    del preclose[key]
preclose['fd_close_pending'] = True
expected_receipt = json.dumps(preclose, sort_keys=True, indent=2) + '\n'
check('receipt derived expectation only', expected_receipt == RAW['proposed_reads/metadata/derived-receipt.EXPECTATION-NOT-HOST-READ.json']
      and len(expected_receipt.encode()) == 28615 and sha(expected_receipt.encode()) == 'f2bcc9227a235a40afa11c1703595180a925fbd39abd29d4550872ed3a05ae6a')
check('released without target file observations', obj('LANE-A-RELEASE.public.json')['current_native_futures'] == 0
      and obj('LANE-A-RELEASE.public.json')['target_metadata_observations'] == 0
      and obj('LANE-A-RELEASE.public.json')['target_body_observations'] == 0)
write_result(True)
print(json.dumps({'passed': True, 'checks': len(ROWS), 'returned_observers': 3, 'immutable_pages': 11,
                  'stdout_bytes': len(out), 'stderr_bytes': 0, 'post_finally_closed': True,
                  'elapsed_after_closure_ms': result['elapsed_after_closure_ms'], 'Runtime_calls': 0,
                  'staged_module_executed': False, 'product_cases': 0}))
