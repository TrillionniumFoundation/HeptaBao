"""Independent offline review of Auth169 original read chains; no source execution."""
from pathlib import Path, PurePosixPath
import base64
import hashlib
import json
import stat

ROOT = Path('/workspace/scratch/f86faac821c4/ha_auth169_peer_r1')
CACHE = Path('/workspace/scratch/f86faac821c4/r32_recovery')
TEXT_CACHE = Path('/workspace/scratch/f86faac821c4/authbus_registration_body4_recovery_r1/blobs')
TREE_SHA = '58c16429b0cd2dd135df7fe50f7582f51413005e'
TREE_SDK_PATH = CACHE / ('tree-' + TREE_SHA + '-sdk.json')
ROWS = []
RAW = {}
INPUTS = []

def result(passed):
    value = {'schema': 'heptabao.Auth169.independent-original-chain-peer.v1',
             'passed': passed, 'checks': len(ROWS), 'rows': ROWS,
             'source_tree': TREE_SHA, 'Runtime_calls': 0,
             'source_modules_executed': False, 'author_checker_executed': False,
             'product_cases': 0, 'source_selected_owner_claim': None,
             'scope': 'Original four read-observer chains, immutable byte reconstruction and finite recovery boundaries only.'}
    (ROOT / 'result.public.json').write_text(json.dumps(value, indent=2) + '\n')

def check(label, value, actual=None):
    ROWS.append({'check': label, 'passed': bool(value), 'actual': actual})
    if not value:
        result(False)
        raise AssertionError(label)

def sha(data):
    return hashlib.sha256(data).hexdigest()

def oid(kind, data):
    return hashlib.sha1(kind.encode() + b' ' + str(len(data)).encode() + b'\0' + data).hexdigest()

tree_sdk = json.loads(json.loads(TREE_SDK_PATH.read_text())['text'])
check('cached tree SDK non-error', tree_sdk.get('isError') is not True)
tree = json.loads(tree_sdk['structuredContent']['content'])
check('exact full recursive tree', tree['sha'] == TREE_SHA and tree.get('truncated') is False)
entries = {row['path']: row for row in tree['tree']}
leaves = [row for row in tree['tree'] if row['type'] == 'blob']
check('fixed 169 leaves / 60 Merkle trees', len(leaves) == 169 and len(tree['tree']) - len(leaves) + 1 == 60)
check('only regular blob/tree entries', all(row['type'] in ('blob', 'tree') and
      row['mode'] == ('100644' if row['type'] == 'blob' else '040000') for row in tree['tree']))
for row in leaves:
    path, expected = row['path'], row['sha']
    cached = TEXT_CACHE / (expected + '.txt')
    if cached.exists():
        data = cached.read_bytes()
        origin = str(cached)
    else:
        cached = CACHE / ('blob-' + expected + '.json')
        data = json.loads(cached.read_text())['text'].encode()
        origin = str(cached)
    check('whole leaf: ' + path, oid('blob', data) == expected and len(data) == row['size'])
    RAW[path] = data
    INPUTS.append({'path': path, 'blob': expected, 'bytes': len(data), 'sha256': sha(data), 'local_origin': origin})
check('whole packet bytes', sum(len(x) for x in RAW.values()) == 1711315)

def verify_tree(path):
    children = [row for row in tree['tree'] if str(PurePosixPath(row['path']).parent) == (path or '.')]
    for row in children:
        if row['type'] == 'tree':
            verify_tree(row['path'])
    children.sort(key=lambda x: PurePosixPath(x['path']).name.encode() + (b'/' if x['type'] == 'tree' else b''))
    raw = b''
    for row in children:
        mode = '40000' if row['type'] == 'tree' else row['mode']
        raw += mode.encode() + b' ' + PurePosixPath(row['path']).name.encode() + b'\0' + bytes.fromhex(row['sha'])
    expected = TREE_SHA if not path else entries[path]['sha']
    check('Merkle tree: ' + (path or '/'), oid('tree', raw) == expected)

verify_tree('')

def obj(path):
    return json.loads(RAW[path])

def pin_matches(pin, path):
    data = RAW[path]
    return pin['blob'] == entries[path]['sha'] and pin['bytes'] == len(data) and pin['sha256'] == sha(data)

manifest = obj('MANIFEST.public.json')
manifest_paths = [x['path'] for x in manifest['files']]
check('manifest exact membership excluding itself', len(manifest_paths) == 168 and len(set(manifest_paths)) == 168
      and set(manifest_paths) == set(RAW) - {'MANIFEST.public.json'})
for item in manifest['files']:
    check('manifest pin: ' + item['path'], pin_matches(item, item['path']))

go = obj('reference/root-go.original.json')
summary = obj('SUMMARY.public.json')
release = obj('RELEASE.public.json')
check('original root GO identity', entries['reference/root-go.original.json']['sha'] == '49fa57d6128f99ff425ea798466514564374d3b4'
      and go['status'] == 'GO_FOUR_FIXED_BODY_OPERATIONS' and len(go['requests']) == 4)
check('separate old/new body accounting', go['accounting']['previous_completed']['bytes'] == 140664
      and go['accounting']['proposed_new']['bytes'] == 213025
      and go['accounting']['cumulative_if_separately_authorized_and_completed']['bytes'] == 353689
      and go['accounting']['old_body_authorization_reused_or_reset'] is False)
check('original caps', go['protocol']['max_native_chunk'] == 65536
      and go['protocol']['immutable_page_limit'] == 8192 and go['protocol']['prior140664_body_bytes_not_reusable'] is True)

def sdk_exact(sdk_path, native_path):
    sdk = obj(sdk_path)
    blocks = [block for block in sdk['content'] if block['type'] == 'text']
    check('SDK non-error: ' + sdk_path, sdk.get('isError') is False)
    check('SDK/native byte exact: ' + sdk_path,
          len(blocks) == 1 and blocks[0]['text'].encode() == RAW[native_path])

metadata = [obj('reference/metadata01.native.original.json'), obj('reference/metadata02.native.original.json')]
for i, meta in enumerate(metadata):
    expected = go['requests'][0 if i == 0 else 1]['expected_whole']
    dev, ino, size, mtime, ctime = map(int, meta['version'].split(':'))
    md = meta['metadata']
    full9 = list(map(str, [dev, ino, md['uid'], md['gid'], stat.S_IFREG | md['mode'], md['link_count'], size, mtime, ctime]))
    check('metadata reference full9: ' + str(i), full9 == expected['full9_decimal']
          and meta['mode'] == md['mode'] == 420 and md['metadata_platform'] == 'darwin')
    check('metadata reference content/version: ' + str(i), meta['path'] == expected['path']
          and meta['size'] == size == expected['bytes'] and meta['version'] == expected['version'] and meta['sha256'] == expected['sha256'])

operation_ids = []
payload_totals = []
page_counts = []
body_chunks = []
previous_binding_path = None
for i in range(1, 5):
    n = str(i).zfill(2)
    base = 'observations/' + n + '/'
    request_path = 'requests/' + n + '.exact.json'
    request = obj(request_path)
    item = go['requests'][i - 1]
    intent = obj(base + 'intent.public.json')
    check(n + ' request exact root value/pin', item['sequence'] == i and request == item['value'] and pin_matches(item['request_pin'], request_path))
    check(n + ' intent exact request/GO', intent['sequence'] == i and intent['exact_request'] == request
          and pin_matches(intent['exact_request_pin'], request_path)
          and pin_matches(intent['go'], 'reference/root-go.original.json'))
    check(n + ' intent retained scope', intent['lane'] == 'A' and intent['start_not_yet_called'] is True
          and intent['only_one_Runtime_call_and_native_future'] is True and intent['immutable_page_limit'] == 8192
          and intent['old_body_bytes_not_reused'] == 140664 and intent['SDK_execution'] is False)
    if previous_binding_path is None:
        check(n + ' first admission metadata predecessor', intent['previous_body_closed_and_whole'] is None
              and intent['prior_metadata_release'] == go['prior_metadata_release'])
    else:
        previous = intent['previous_body_closed_and_whole']
        check(n + ' predecessor is original closed binding', pin_matches(previous, previous_binding_path)
              and previous['operation_id'] == operation_ids[-1])
    admission = obj(base + 'admission/original.native.txt')
    status = obj(base + 'status-0/original.native.txt')
    operation_id = admission['operation_id']
    operation_ids.append(operation_id)
    sdk_exact(base + 'admission/original.sdk.json', base + 'admission/original.native.txt')
    sdk_exact(base + 'status-0/original.sdk.json', base + 'status-0/original.native.txt')
    check(n + ' original admission binary_read', admission['tool_name'] == 'binary_read' and admission['reused'] is False
          and admission['automatic_retry'] is False)
    check(n + ' same-ID original status request', obj(base + 'status-0/request.original.json') == {'operation_id': operation_id})
    check(n + ' original observer closed', status['operation_id'] == operation_id and status['tool_name'] == 'binary_read'
          and status['async_state'] == 'completed' and status['result_state'] == 'stored_observed'
          and status['owned_future_active'] is False and status['payload_available'] is True)
    native_page_paths = sorted(path for path in RAW if path.startswith(base + 'pages/') and path.endswith('/original.native.txt'))
    collected = bytearray()
    common = None
    for native_path in native_page_paths:
        page_base = native_path.rsplit('/', 1)[0] + '/'
        offset = int(page_base.split('/')[-2])
        page_request = obj(page_base + 'request.original.json')
        check(page_base + ' exact result request', page_request == {'operation_id': operation_id, 'offset': offset, 'limit': 8192})
        sdk_exact(page_base + 'original.sdk.json', native_path)
        page = obj(native_path)
        raw = base64.b64decode(page['data_base64'], validate=True)
        identity = (page['total_bytes'], page['result_sha256'])
        if common is None:
            common = identity
        check(page_base + ' original immutable identity', page['operation_id'] == operation_id and page['immutable_snapshot'] is True and identity == common)
        check(page_base + ' exact extent/EOF', page['offset'] == offset == len(collected)
              and len(raw) == min(8192, page['total_bytes'] - offset) and page['next_offset'] == offset + len(raw)
              and page['eof'] is (page['next_offset'] == page['total_bytes']))
        collected.extend(raw)
    check(n + ' whole original payload', bytes(collected) == RAW[base + 'payload.original.json']
          and len(collected) == common[0] and sha(collected) == common[1])
    payload = json.loads(collected)
    blocks = [block for block in payload['content'] if block['type'] == 'text']
    check(n + ' whole original SDK content', payload['resultType'] == 'complete' and payload['isError'] is False
          and len(blocks) == 1 and blocks[0]['text'].encode() == RAW[base + 'native.original.json'])
    native = obj(base + 'native.original.json')
    args = request['operation']['arguments']
    chunk = base64.b64decode(native['data_base64'], validate=True)
    check(n + ' fixed host/tool/range', request['operation']['tool'] == 'binary_read' and args['host'] == 'mac'
          and args['offset'] == [0, 0, 65536, 131072][i - 1] and args['limit'] == [31444, 65536, 65536, 50509][i - 1])
    check(n + ' native original path/version/size', native['path'] == args['path'] == item['expected_whole']['path']
          and native['version'] == args['expected_version'] == item['expected_whole']['version']
          and native['size'] == item['expected_whole']['bytes'])
    check(n + ' native chunk SHA/extent/EOF', native['offset'] == args['offset'] and len(chunk) == args['limit']
          and sha(chunk) == native['chunk_sha256'] and native['next_offset'] == item['expected_next_offset'] == args['offset'] + len(chunk)
          and native['eof'] is item['expected_eof'])
    binding = obj(base + 'binding.public.json')
    body_projection = {key: native[key] for key in ('path', 'version', 'size', 'offset', 'next_offset', 'chunk_sha256', 'eof')}
    body_projection['bytes'] = len(chunk)
    check(n + ' closed binding is lossless projection', binding['sequence'] == i and binding['operation_id'] == operation_id
          and binding['request_blob'] == entries[request_path]['sha']
          and binding['ack_native'] == entries[base + 'admission/original.native.txt']['sha']
          and binding['status_native'] == entries[base + 'status-0/original.native.txt']['sha']
          and binding['completed_stored_inactive'] is True and binding['pages'] == len(native_page_paths)
          and binding['body'] == body_projection and binding['SDK_execution'] is False
          and pin_matches(binding['payload'], base + 'payload.original.json') and pin_matches(binding['native'], base + 'native.original.json'))
    report = summary['original_operations'][i - 1]
    check(n + ' summary original indices', report['sequence'] == i and report['operation_id'] == operation_id
          and report['admission_SDK'] == entries[base + 'admission/original.sdk.json']['sha']
          and report['status_native'] == entries[base + 'status-0/original.native.txt']['sha']
          and report['binding'] == entries[base + 'binding.public.json']['sha'] and report['body'] == body_projection
          and report['unique_pages'] == len(native_page_paths) and report['completed_stored_inactive'] is True
          and pin_matches(report['request'], request_path) and pin_matches(report['payload'], base + 'payload.original.json')
          and pin_matches(report['native'], base + 'native.original.json'))
    released = release['original_operations'][i - 1]
    check(n + ' release exact original observer', released['operation_id'] == operation_id
          and released['original_request'] == entries[request_path]['sha'] and released['binding'] == entries[base + 'binding.public.json']['sha']
          and released['unique_immutable_pages'] == len(native_page_paths) and released['payload_bytes'] == len(collected)
          and released['completed_stored_inactive'] is True and released['full_payload_closed'] is True)
    body_chunks.append(chunk)
    page_counts.append(len(native_page_paths))
    payload_totals.append(len(collected))
    previous_binding_path = base + 'binding.public.json'

check('four distinct original operations / 37 unique pages', len(set(operation_ids)) == 4 and page_counts == [6, 11, 11, 9] and sum(page_counts) == 37)
check('285712 original SDK payload bytes', sum(payload_totals) == 285712)
for source_path, body, expected_meta in [
        ('sources/manifest-registry.original.js', body_chunks[0], metadata[0]),
        ('sources/plugin-registry.original.js', b''.join(body_chunks[1:]), metadata[1])]:
    check('whole source exact native chunks: ' + source_path, body == RAW[source_path]
          and len(body) == expected_meta['size'] and sha(body) == expected_meta['sha256'])
check('new 213025 body bytes without old cap reset', sum(map(len, body_chunks)) == 213025
      and summary['previous_body_bytes'] == release['previous_completed_body_bytes'] == 140664
      and summary['cumulative_body_bytes'] == release['cumulative_body_bytes'] == 353689
      and summary['old_caps_reused_or_reset'] is False)

recovery = obj('recovery/same-ID-prefix-pages.public.json')
check('eight same-ID recovery records separate from unique pages', recovery['operation_id'] == operation_ids[1]
      and recovery['extra_operation_result_calls'] == 8 and recovery['new_native_admissions'] == 0
      and recovery['original_native_admission_repeated'] is False and recovery['native_future_already_closed'] is True
      and recovery['original_pre_reset_prefix_bytes'] == 65536 and recovery['original_unique_payload_total'] == payload_totals[1]
      and [x['offset'] for x in recovery['offsets']] == list(range(0, 65536, 8192)))
for item in recovery['offsets']:
    base = 'observations/02/pages/' + str(item['offset']).zfill(6) + '/'
    check('recovery record bound to same archived page ' + str(item['offset']), item['limit'] == 8192
          and item['request'] == entries[base + 'request.original.json']['sha']
          and item['returned_SDK'] == entries[base + 'original.sdk.json']['sha']
          and item['returned_native'] == entries[base + 'original.native.txt']['sha'])
check('summary recovery count retained, not new admissions', summary['extra_same_ID_cache_recovery_page_calls'] == 8
      and summary['total_operation_result_calls'] == 45 and release['immutable_result_reobservations_for_cache_recovery'] == 8
      and release['unique_native_admissions'] == 4)

reindex = obj('recovery/existing-Git-index-reconstruction.public.json')
check('finite existing-Git reindex report retained', reindex['Runtime_calls'] == 0 and reindex['new_Git_blob_creates'] == 0
      and reindex['failures'] == [] and reindex['payload'] == entries['observations/01/payload.original.json']['sha']
      and reindex['template'] == entries['observations/01/pages/000000/original.sdk.json']['sha'])
for item in reindex['restored']:
    check('existing-Git restored pin exact: ' + item['path'], pin_matches(item, item['path']))
error = obj('archive-errors/page01-offset0-git-whole-read.original.sdk.json')
git_recovery = obj('archive-errors/page01-offset0-git-recovery.public.json')
check('original Git transport error preserved separately', error['isError'] is True
      and 'RemoteProtocolError' in error['content'][0]['text'] and error['structuredContent']['error_code'] == 'UNKNOWN')
check('same Git object recovery, not Runtime page replay', git_recovery['Runtime_page_reread'] is False
      and git_recovery['Runtime_future_closed'] is True and git_recovery['whole_readback_now_exact'] is True
      and pin_matches(git_recovery, 'observations/01/pages/000000/original.sdk.json'))
cache_error = obj('recovery/cache-reset-local-error.public.json')
check('local cache failure retained as local boundary', cache_error['Runtime_called'] is False
      and cache_error['known_native_closed'] is True and cache_error['next_original_page_not_called'] == 65536
      and 'Cannot set properties of undefined' in cache_error['message'])
check('release/scope stays read-only and unqualified', release['Runtime_calls_inflight'] == 0
      and release['known_native_futures_active'] == 0 and release['SDK_executions'] == 0
      and release['private_reads'] == 0 and release['actual_selected_owner'] is None
      and summary['scope']['SDK_execution'] is False and summary['scope']['actual_selected_owner'] is None
      and summary['scope']['production_qualified'] is False)

(ROOT / 'input-index.public.json').write_text(json.dumps({'source_tree': TREE_SHA,
    'source_tree_sdk_local_path': str(TREE_SDK_PATH), 'files': 169, 'bytes': 1711315,
    'merkle_trees': 60, 'records': INPUTS, 'new_Git_fetches': 0, 'Runtime_calls': 0}, indent=2) + '\n')
(ROOT / 'finding-summary.public.json').write_text(json.dumps({'source_tree': TREE_SHA,
    'original_operations': operation_ids, 'unique_page_counts': page_counts, 'original_payload_bytes': sum(payload_totals),
    'new_body_bytes': 213025, 'same_ID_reobservation_records': 8, 'new_native_admissions_in_recovery': 0,
    'boundary': 'The 23 existing-Git reindex records and eight same-ID recovery records are retained with their stated provenance. This offline peer verifies their exact archived values and reconstructed payload; it does not claim an independent wall-clock ordering proof or execute/fetch the sources.',
    'prior_metadata_chains': 'Reference native values/full9 are matched to the original GO. The earlier two metadata SDK chains are not rerun here.',
    'selected_owner': None, 'production_qualified': False, 'Runtime_calls': 0}, indent=2) + '\n')
result(True)
print(json.dumps({'passed': True, 'checks': len(ROWS), 'whole_files': 169, 'bytes': 1711315,
                  'Merkle_trees': 60, 'original_operations': 4, 'unique_pages': 37,
                  'same_ID_recovery_records': 8, 'native_payload_bytes': sum(payload_totals),
                  'body_bytes': sum(map(len, body_chunks)), 'Runtime_calls': 0,
                  'author_checker_executed': False, 'source_modules_executed': False}))
