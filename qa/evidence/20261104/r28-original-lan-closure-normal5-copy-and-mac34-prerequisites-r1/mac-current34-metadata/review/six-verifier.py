import base64
import hashlib
import json
import re
import stat
from pathlib import Path

ROOT = Path('/workspace/scratch/f86faac821c4')
checks = []
def need(value, label):
    assert value, label
    checks.append(label)
def unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate_json_key')
        result[key] = value
    return result
def parse(raw):
    return json.loads(raw, object_pairs_hook=unique)
def digest(raw):
    return hashlib.sha256(raw.encode()).hexdigest()
def blob(raw):
    data = raw.encode()
    return hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest()
def native(raw, label):
    sdk = parse(raw)
    need(sdk.get('isError') is False and len(sdk['content']) == 1 and sdk['content'][0]['type'] == 'text', label + ':sdk_success')
    return sdk['content'][0]['text']

input_raw = (ROOT / 'mac34_six_metadata_input.json').read_text()
need(digest(input_raw) == '34c32fd67dd4931fab950a54d07463167708c0e8a1edba24c163cf23c77c3431', 'exact_verifier_input')
data = parse(input_raw)
review = parse(data['root_review_raw'])
handoff = parse(data['root_handoff_raw'])
need(blob(data['root_review_raw']) == '69c6625843b887e51029846d8ac44249d19b0fa8', 'original_root_review')
need(blob(data['root_handoff_raw']) == '6e6e472415916dfde5a08063dcbaaecba1c4fdb0', 'original_line_handoff')
roles = ['oracle_binary', 'oracle_archive', 'server', 'python', 'git', 'openssl']
need(list(data['rows']) == roles, 'original_six_order')
need(data['openssl_submitted'] is True, 'sixth_separately_authorized_and_submitted')
observations = []
projection = {}
ids = []
for role in roles:
    row = data['rows'][role]
    expected = next(x for x in review['requests'] if x['name'] == role)
    request = parse(row['request_raw'])
    need(blob(row['request_raw']) == expected['blob'] and digest(row['request_raw']) == expected['sha256'], role + ':exact_original_request')
    need(request == {'idempotency_key': expected['key'], 'operation': {'arguments': {'host': 'mac', 'path': expected['path']}, 'tool': 'file_info'}}, role + ':typed_request')
    admission_raw = native(row['admission_sdk_raw'], role + ':admission')
    need(admission_raw == row['admission_native_raw'], role + ':admission_native_exact')
    admission = parse(admission_raw)
    operation_id = admission['operation_id']
    need(re.fullmatch('[0-9a-f]{64}', operation_id) is not None and admission['tool_name'] == 'file_info', role + ':original_operation_id')
    need(admission['idempotency_binding_retained'] is True and admission['reused'] is False, role + ':unique_original_admission')
    ids.append(operation_id)
    status_raw = native(row['status_sdk_raw'], role + ':status')
    need(status_raw == row['status_native_raw'], role + ':status_native_exact')
    status = parse(status_raw)
    need(status['operation_id'] == operation_id and status['async_state'] == 'completed' and status['result_state'] == 'stored_observed' and status['owned_future_active'] is False and status['payload_available'] is True, role + ':native_closed')
    page_raw = native(row['page_sdk_raw'], role + ':page')
    page = parse(page_raw)
    original = base64.b64decode(page['data_base64'], validate=True)
    need(page['operation_id'] == operation_id and page['offset'] == 0 and page['eof'] is True and page['immutable_snapshot'] is True and page['payload_kind'] == 'native_result', role + ':immutable_single_page')
    need(page['next_offset'] == page['total_bytes'] == len(original) <= 16384 and hashlib.sha256(original).hexdigest() == page['result_sha256'], role + ':complete_whole_payload')
    need(original == row['payload_raw'].encode(), role + ':original_sdk_byte_equal')
    payload = parse(row['payload_raw'])
    need(payload['resultType'] == 'complete' and payload['isError'] is False and len(payload['content']) == 1 and payload['content'][0]['type'] == 'text', role + ':original_native_success')
    need(payload['content'][0]['text'] == row['file_info_raw'], role + ':file_info_exact_native_text')
    info = parse(row['file_info_raw'])
    need(set(info) == {'metadata', 'mode', 'path', 'sha256', 'size', 'version'}, role + ':native_info_shape')
    need(info['path'] == expected['path'] and re.fullmatch('[0-9a-f]{64}', info['sha256']) is not None, role + ':fixed_path_and_sha_shape')
    need(expected['expected_sha256'] is None or info['sha256'] == expected['expected_sha256'], role + ':known_whole_sha')
    need(type(info['size']) is int and 0 < info['size'] <= 512 * 1024 * 1024 and (expected['expected_bytes'] is None or info['size'] == expected['expected_bytes']), role + ':size_bound')
    m = info['metadata']
    need(m['metadata_platform'] == 'darwin' and type(m['mode']) is int and info['mode'] == m['mode'] and 0 <= m['mode'] <= 0o7777, role + ':permission_bits')
    need(all(type(m[k]) is int and 0 <= m[k] < 2**32 for k in ('uid', 'gid', 'link_count')) and m['link_count'] >= 1, role + ':native_numeric_fields')
    need(type(info['version']) is str and re.fullmatch('[0-9]+:[0-9]+:[0-9]+:[0-9]+:[0-9]+', info['version']) is not None, role + ':original_version_tokens')
    tokens = info['version'].split(':')
    values = [int(token, 10) for token in tokens]
    need(':'.join(str(value) for value in values) == info['version'] and all(0 <= value < 2**64 for value in values) and values[2] == info['size'], role + ':lossless_version_integer_roundtrip')
    dev, ino, size, mtime, ctime = values
    identity = [dev, ino, m['uid'], m['gid'], stat.S_IFREG | m['mode'], m['link_count'], size, mtime, ctime]
    need(stat.S_IMODE(identity[4]) == info['mode'] and ':'.join(str(identity[i]) for i in (0, 1, 6, 7, 8)) == info['version'], role + ':full9_projection_roundtrip')
    admissible = m['link_count'] == 1
    need(admissible is (role != 'git'), role + ':preserved_single_link_guard_result')
    projection[role] = {'path': info['path'], 'bytes': size, 'sha256': info['sha256'], 'identity': identity, 'version': info['version']}
    observations.append({'role': role, 'operation_id': operation_id, 'native_read_closed': True, 'payload_bytes': len(original), 'payload_sha256': page['result_sha256'], 'file_info_blob': blob(row['file_info_raw']), 'source_single_link_admission_satisfied': admissible})
need(len(set(ids)) == 6, 'six_unique_original_operations')
need(projection['git']['identity'][5] == 78, 'actual_git78_not_single_link')
need(projection['git']['identity'][1] > 2**53 and projection['git']['identity'][1] == 1152921500312571562, 'unsafe_inode_preserved_exact')
result = {'schema': 'heptabao.mac-full34-six-metadata-lossless-verification.v1', 'status': 'SIX_NATIVE_READS_COMPLETE_WITH_KNOWN_GIT_BINDING_REFUSAL', 'checks_passed': len(checks), 'checks': checks, 'observations': observations, 'observed_full9_projection': projection, 'not_a_binding_ready_table': True, 'sixth_openssl_submitted': True, 'candidate_wrapper_changed': False, 'candidate_inert_submitted': False, 'candidate_prepare_submitted': False, 'candidate_live_submitted': False, 'no_claim_all_six_admitted': True, 'runtime_transport_error_count': 0, 'local_validator_regex_correction_preserved_separately': True}
output = json.dumps(result, indent=2, sort_keys=True) + '\n'
(ROOT / 'mac34_six_metadata_verification.json').write_text(output)
print(json.dumps({'checks_passed': len(checks), 'read_count': len(observations), 'single_link_compatible': sum(x['source_single_link_admission_satisfied'] for x in observations), 'git_link_count': projection['git']['identity'][5], 'sixth_submitted': True, 'result_bytes': len(output.encode()), 'result_sha256': digest(output)}))
