"""Offline original-evidence verifier; no Runtime or candidate execution."""
from pathlib import Path
import base64
import hashlib
import json

ROOT = Path('/workspace/scratch/f86faac821c4/ha_h2_target_reads_r2')
CACHE = Path('/workspace/scratch/f86faac821c4/r32_recovery')
index = json.loads((ROOT / 'archive-input.public.json').read_text())
files, state = index['files'], index['state']
rows = []


def check(name, value, actual=None):
    rows.append({'check': name, 'passed': bool(value), 'actual': actual})
    if not value:
        raise AssertionError(name)


def sha(q):
    return hashlib.sha256(q).hexdigest()


def meta(q):
    return {'blob': hashlib.sha1(b'blob ' + str(len(q)).encode() + b'\0' + q).hexdigest(),
            'bytes': len(q), 'sha256': sha(q)}


raw, records = {}, []
for path, blob in files.items():
    local = CACHE / ('blob-' + blob + '.json')
    text = json.loads(local.read_text())['text']
    q = text.encode('utf-8')
    m = meta(q)
    check('whole original: ' + path, m['blob'] == blob)
    raw[path] = q
    records.append({'path': path, **m, 'local_origin': str(local)})


def obj(path):
    return json.loads(raw[path])


def pin(path, p):
    m = meta(raw[path])
    return all(p[k] == m[k] for k in ('blob', 'bytes', 'sha256'))


def sdk_native(prefix):
    sdk = obj(prefix + 'original.sdk.json')
    check(prefix + 'SDK non-error', sdk.get('isError') is False)
    check(prefix + 'single original text', len(sdk['content']) == 1 and
          sdk['content'][0]['type'] == 'text')
    check(prefix + 'native exact bytes', sdk['content'][0]['text'].encode() ==
          raw[prefix + 'original.native.json'])
    return obj(prefix + 'original.native.json')


go = obj('references/root-read-GO.public.json')
cfg = obj('execution-source/conditional-body-config.public.json')
derived = obj('verification/deriver-output.public.json')
release = obj('RELEASE.public.json')
check('exact GO identity', files['references/root-read-GO.public.json'] ==
      '012b76fca8a176e1cc15e3115ad38a69977ef8d9')
check('fixed GO scope', go['metadata_admissions'] == 2 and
      go['conditional_body']['admissions'] == 3 and
      go['conditional_body']['total_bytes'] == 38845 and
      go['native_observation_caps']['operation_result_page_bytes'] == 8192)
check('fixed exact pure deriver', files['execution-source/conditional-body-deriver.py'] ==
      '8e1f37cfa36403a76bfa2e96a83b85d40eef3f15')
check('fixed exact pure config', files['execution-source/conditional-body-config.public.json'] ==
      '69db067f16796f8ad85f8f73b0355c2f14707120')
check('actual pure deriver exit0', obj('verification/deriver-executor.original.json')['exit_code'] == 0)
check('state released, no pending native future', state['released'] is True and
      state['inflight'] is None and state['active_operation'] is None and state['paused'] is True)
check('exact five observations / twenty calls', len(state['observations']) == 5 and len(state['calls']) == 20)
check('no new stage or prepare/live', release['prepare_submitted'] is False and
      release['live_submitted'] is False and release['new_stage_submitted'] is False)

labels = ['receipt-info', 'binding-info', 'receipt-body0', 'receipt-body1', 'binding-body0']
page_counts = [1, 1, 3, 3, 2]
native = {}
ids = []
call_count = 0
page_count = 0
previous = None
release_rows = {x['label']: x for x in release['original_observations']}

for seq, (label, expected_pages) in enumerate(zip(labels, page_counts)):
    base = 'observations/' + label + '/'
    request = obj(base + 'admission/request.original.json')
    expected = go['metadata_exact'][seq] if seq < 2 else derived['requests'][seq - 2]
    check(label + 'exact original admission arguments', request == expected)
    check(label + 'state exact original request', request == state['observations'][label]['request'])
    admission_intent = obj(base + 'admission/intent.public.json')
    check(label + 'admission exact intent', admission_intent['arguments'] == request and
          admission_intent['method'] == 'operation_start' and
          admission_intent['root_GO'] == files['references/root-read-GO.public.json'])
    check(label + 'admission intent whole request pin',
          pin(base + 'admission/request.original.json', admission_intent['request']))
    check(label + 'predecessor whole closure recorded',
          admission_intent['previous_whole_closed'] is None if previous is None else
          admission_intent['previous_whole_closed']['operation_id'] == previous)
    adm = sdk_native(base + 'admission/')
    check(label + 'ACK exact tool and no reused claim', adm['tool_name'] == request['operation']['tool']
          and adm['reused'] is False)
    oid = adm['operation_id']
    ids.append(oid)
    st = sdk_native(base + 'status0/')
    check(label + 'original same-ID closed status', st['operation_id'] == oid and
          st['tool_name'] == adm['tool_name'] and st['async_state'] == 'completed' and
          st['result_state'] == 'stored_observed' and st['owned_future_active'] is False and
          st['payload_available'] is True)
    check(label + 'exact status request', obj(base + 'status0/request.original.json') == {'operation_id': oid})
    phases = ['admission', 'status0']
    page_dirs = sorted({p[len(base + 'pages/'):].split('/')[0] for p in files if p.startswith(base + 'pages/')})
    check(label + 'exact page count', len(page_dirs) == expected_pages)
    data, offset, total, digest = [], 0, None, None
    for page_dir in page_dirs:
        prefix = base + 'pages/' + page_dir + '/'
        req = obj(prefix + 'request.original.json')
        check(label + 'page request ' + page_dir, req == {'operation_id': oid, 'offset': offset, 'limit': 8192})
        p = sdk_native(prefix)
        b = base64.b64decode(p['data_base64'], validate=True)
        check(label + 'page ID offset and cap ' + page_dir, p['operation_id'] == oid and
              p['offset'] == offset and len(b) <= 8192 and p['next_offset'] == offset + len(b))
        check(label + 'immutable native payload ' + page_dir, p['immutable_snapshot'] is True and
              p['payload_kind'] == 'native_result' and p['format'] ==
              'serialized_original_native_sdk_payload_before_operation_metadata_and_transport_normalization')
        if total is None:
            total, digest = p['total_bytes'], p['result_sha256']
        check(label + 'whole hash and EOF ' + page_dir, p['total_bytes'] == total and
              p['result_sha256'] == digest and p['eof'] == (p['next_offset'] == total))
        offset = p['next_offset']
        data.append(b)
        phases.append('pages/' + page_dir)
        page_count += 1
    payload = b''.join(data)
    check(label + 'whole payload complete', offset == total and len(payload) == total and sha(payload) == digest)
    check(label + 'whole payload exact archived bytes', payload == raw[base + 'payload.original.json'])
    pj = json.loads(payload)
    check(label + 'original handler successful', pj['resultType'] == 'complete' and pj['isError'] is False)
    check(label + 'whole native exact payload text', len(pj['content']) == 1 and
          pj['content'][0]['type'] == 'text' and pj['content'][0]['text'].encode() == raw[base + 'native.original.json'])
    native[label] = obj(base + 'native.original.json')
    rr = release_rows[label]
    check(label + 'release same ID and original pin chain', rr['operation_id'] == oid and
          pin(base + 'status0/original.native.json', rr['status']) and
          pin(base + 'payload.original.json', rr['payload']) and
          pin(base + 'native.original.json', rr['native']) and rr['whole_payload_closed'] is True)
    for phase in phases:
        prefix = base + phase + '/'
        req = obj(prefix + 'request.original.json')
        intent = obj(prefix + 'intent.public.json')
        method = 'operation_start' if phase == 'admission' else 'operation_status' if phase == 'status0' else 'operation_result'
        check(label + 'call intent ' + phase, intent['method'] == method and intent['arguments'] == req
              and intent['only_readonly'] is True and intent['stage_replay'] is False and
              intent['prepare_or_live'] is False and intent['one_future_per_lane'] is True)
        check(label + 'call original request pin ' + phase, pin(prefix + 'request.original.json', intent['request']))
        key = label + '.' + (('page' + phase.split('/')[1]) if phase.startswith('pages/') else phase)
        c = state['calls'][key]
        check(label + 'journal returned originals ' + phase, c['method'] == method and c['args'] == req
              and c['submitted'] is True and c['returned'] is True)
        check(label + 'journal SDK/native exact pins ' + phase,
              pin(prefix + 'original.sdk.json', c['sdk']) and pin(prefix + 'original.native.json', c['native']))
        call_count += 1
    previous = oid

check('five unique original native admissions', len(set(ids)) == 5)
check('ten unique immutable result pages and twenty Runtime calls', page_count == 10 and call_count == 20)
check('no Runtime call retries', release['Runtime_repeat_calls'] == 0)

for seq, role in enumerate(('receipt', 'binding')):
    info = native[role + '-info']
    exp = cfg['expected'][seq]
    check(role + 'exact content file_info', (info['path'], info['size'], info['sha256']) ==
          (exp['path'], exp['bytes'], exp['sha256']))
    md = info['metadata']
    check(role + 'exact custody identity', (info['mode'], md['mode'], md['uid'], md['gid'],
          md['link_count'], md['metadata_platform']) == (384, 384, 1000, 1000, 1, 'linux'))
    dev, ino, size, mt, ct = info['version'].split(':')
    nine = {'device': dev, 'inode': ino, 'uid': 1000, 'gid': 1000, 'full_mode': 32768 | 384,
            'links': 1, 'bytes': int(size), 'mtime_ns': mt, 'ctime_ns': ct, 'version': info['version']}
    check(role + 'full9 lossless projection', release['metadata'][role]['full9'] == nine)
    if role == 'binding':
        check('binding exact original stage-writer version', info['version'] == exp['expected_stage_writer_version'])

bodies = {}
for i, label in enumerate(labels[2:]):
    n = native[label]
    req = derived['requests'][i]
    template = cfg['templates'][i]
    copy_req = json.loads(json.dumps(req))
    copy_req['operation']['arguments']['expected_version'] = None
    check(label + 'only expected_version replaced', copy_req == template['request'])
    args = req['operation']['arguments']
    role = template['role']
    info = native[role + '-info']
    data = base64.b64decode(n['data_base64'], validate=True)
    check(label + 'actual path/version/file size', (n['path'], n['version'], n['size']) ==
          (info['path'], info['version'], info['size']))
    check(label + 'fixed original chunk/range/EOF', n['offset'] == args['offset'] and
          len(data) == args['limit'] == template['expected_bytes'] and
          n['next_offset'] == n['offset'] + len(data) and n['eof'] == (n['next_offset'] == n['size']))
    check(label + 'chunk SHA and archived body', sha(data) == n['chunk_sha256'] and
          data == raw['actual/chunks/' + label + '.original.txt'])
    bodies[label] = data

receipt = bodies['receipt-body0'] + bodies['receipt-body1']
binding = bodies['binding-body0']
for role, q in [('receipt', receipt), ('binding', binding)]:
    info = native[role + '-info']
    check(role + 'whole actual from original chunks', q == raw['actual/' + role + '.original.json'])
    check(role + 'whole actual matches independent file_info', len(q) == info['size'] and sha(q) == info['sha256'])
    check(role + 'release actual whole pin', pin('actual/' + role + '.original.json', release['actual_whole'][role]))
check('exact observed body budget', sum(len(v) for v in bodies.values()) == 38845)
check('receipt actual pre-finally projection retained', json.loads(receipt)['fd_close_pending'] is True and
      'all_stage_fds_closed' not in json.loads(receipt))
final = obj('references/original-stage.final.stdout.json')
check('separate original post-finally stage closure remains', final['all_stage_fds_closed'] is True and
      final['fd_close_pending'] is False and final['fd_close_errors'] == [] and final['within_stage_deadline'] is True)

correction = obj('recoveries/derived-mode/correction.public.json')
check('wrong derived mode retained then corrected', correction['old_derived_full_mode'] == 33536 and
      correction['correct_derived_full_mode'] == 33152 and correction['original_native_mode'] == 384 and
      correction['Runtime_calls_for_correction'] == 0)
check('wrong derivation original source retained', pin('recoveries/derived-mode/before-helper.js', correction['before_source']))
check('wrong derivation original journal retained', pin('recoveries/derived-mode/before-journal.public.json', correction['before_state']))
check('corrected derivation original source retained', pin('recoveries/derived-mode/corrected-helper.js', correction['after_source']))
check('three Git errors retained', all(obj('recoveries/Git/' + n)['isError'] is True for n in
      ['original_git_write_error.original.sdk.json', 'git_lookup_404.original.sdk.json',
       'git_write_error_record_failure.original.sdk.json']))
recovery = obj('recoveries/Git/archive-recovery-complete.public.json')
check('same original returned page archived, not re-observed', recovery['Runtime_repeated'] is False and
      recovery['new_Runtime_calls_for_recovery'] == 0 and recovery['old_three_Git_errors_preserved'] is True)
check('recovered original page SDK exact', pin('observations/receipt-body0/pages/016384/original.sdk.json', recovery['original_page_sdk']))
check('recovered original payload exact', pin('observations/receipt-body0/payload.original.json', recovery['original_payload']))
check('release retains historical UNKNOWN and correction', release['older_stage_status_query_UNKNOWN_preserved'] is True and
      release['Git_archive_recovery']['blob'] == files['recoveries/Git/archive-recovery-complete.public.json'] and
      release['full_mode_correction']['blob'] == files['recoveries/derived-mode/correction.public.json'])

summary = {'schema': 'heptabao.H2-target.actual-original-chain-verification.v1', 'passed': True,
           'checks': len(rows), 'whole_input_files': len(records), 'whole_input_bytes': sum(x['bytes'] for x in records),
           'original_observations': 5, 'original_Runtime_calls': call_count, 'unique_pages': page_count,
           'actual_body_bytes': 38845, 'verifier_Runtime_calls': 0, 'candidate_executed': False,
           'prepare_submitted': False, 'live_submitted': False, 'rows': rows}
(ROOT / 'verification-result.public.json').write_text(json.dumps(summary, ensure_ascii=False, indent=2) + '\n')
(ROOT / 'verification-input-index.public.json').write_text(json.dumps({'records': records}, ensure_ascii=False, indent=2) + '\n')
print(json.dumps({k: v for k, v in summary.items() if k != 'rows'}))
