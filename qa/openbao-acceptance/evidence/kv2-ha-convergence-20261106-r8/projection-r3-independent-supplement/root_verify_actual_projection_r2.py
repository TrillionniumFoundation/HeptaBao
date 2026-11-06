"""Local independent verification; private inputs stay outside public evidence."""
import hashlib
import json
from pathlib import Path

ROOT = Path('/tmp/heptabao-formal-kv2-projection-20261106-r3')

def pairs(items):
    value = {}
    for key, item in items:
        if key in value:
            raise ValueError('duplicate_json_key')
        value[key] = item
    return value

def decode(raw):
    def reject(_):
        raise ValueError('nonfinite_json_number')
    return json.loads(raw, object_pairs_hook=pairs, parse_constant=reject)

def native(relative):
    wrapper = decode((ROOT / relative).read_bytes())
    assert not wrapper.get('isError')
    return decode(wrapper['content'][0]['text'])

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def version(identity):
    return ':'.join(str(identity[k]) for k in ('dev', 'inode', 'bytes', 'mtime_ns', 'ctime_ns'))

def file_bytes(item):
    raw = item['text'].encode()
    assert item['eof'] and len(raw) == item['size'] and sha(raw) == item['sha256']
    return raw

def match_info(item, info):
    for key in ('path', 'size', 'sha256', 'version'):
        assert item[key] == info[key]
    meta = info['metadata']
    assert info['mode'] == meta['mode'] == 0o600
    assert (meta['uid'], meta['gid'], meta['link_count']) == (501, 20, 1)
    assert meta['xattr_names'] == []

terminal = native('actual-projection-terminal.native.json')
streams = native('actual-projection-streams.native.json')
assert terminal['job_id'] == streams['job_id'] == '1a1b2b773d7-fc05-7f73'
assert terminal['state'] == 'succeeded' and terminal['exit_code'] == 0
assert all(terminal[k] for k in ('output_complete', 'output_durable', 'terminal_publication_confirmed'))
assert not terminal['timed_out'] and not terminal['cancelled']
for name in ('stdout', 'stderr'):
    item = streams[name]
    raw = bytes.fromhex(item['bytes_hex'])
    assert item['offset'] == 0 and item['eof']
    assert len(raw) == item['size'] == item['next_offset'] == terminal['log_bytes'][name]['seen'] == terminal['log_bytes'][name]['stored']
    assert raw.decode() == item['text'] and terminal['log_synced'][name]
    assert not terminal['log_truncated'][name] and terminal['log_errors'][name] is None
assert streams['stderr']['size'] == 0
stdout = bytes.fromhex(streams['stdout']['bytes_hex'])
observed = decode(stdout)
expected_checks = (
    'completed_independent_readback_and_exact_private_closure',
    'same_restored_capture_and_all_database_original_identities',
    'all_present_database_hashes_cold_schema_and_sidecars',
    'every_agent_both_tables_exact_original_row_commitments',
    'same_frozen_protocol_projection_schema_and_complete_denominators',
    'create_only_private_projection_full_readback',
    'original_inputs_roots_and_all_database_bytes_unchanged',
    'all_readonly_connections_files_and_owned_directory_handles_closed',
)
assert observed['checks'] == [{'check': k, 'passed': True} for k in expected_checks]
assert observed['status'] == 'passed' and observed['projection_complete']
assert observed['observed_check_count'] == observed['required_check_count'] == 8
assert observed['primary_failure_code'] is None and observed['cleanup_failure_codes'] == []
assert observed['forbidden_effect_attempt_count'] == observed['new_child_processes_spawned'] == 0
assert observed['cold_connections_opened'] == observed['cold_connections_closed'] == 6
resources = observed['final_resource_custody']
assert resources['fd_birth_count'] == resources['fd_close_attempt_count'] == resources['fd_close_success_count'] == 66
assert resources['sqlite_connection_birth_count'] == resources['sqlite_close_attempt_count'] == resources['sqlite_close_success_count'] == 6
assert resources['all_original_handles_and_stdio_retired'] and not resources['close_errors']
assert resources['unattempted_original_fd_count'] == resources['fd_first_fstat_failure_count'] == 0
assert observed['receipt_publication_handles_closed']
assert observed['new_work_seconds'] == 52 and observed['new_runtime_seconds'] == 60
assert observed['work_and_original_handles_completed_before_52_seconds'] and not observed['deadline_fired'] and not observed['deadline_renewed'] and not observed['interrupted']

public_wrapper = native('root-actual-projection-public-result.native.json')
assert not public_wrapper['truncated'] and len(public_wrapper['files']) == 1
public_file = public_wrapper['files'][0]
public_raw = file_bytes(public_file)
public = decode(public_raw)
match_info(public_file, native('root-output-file-info-0.native.json'))
for key in ('status', 'projection_complete', 'checks', 'counts', 'database_partition', 'primary_failure_code', 'cleanup_failure_codes', 'work_resource_custody', 'private_projection_file_identity'):
    assert public[key] == observed[key]

private_wrapper = native('private-inputs/root-private-output-files.native.json')
assert private_wrapper['atomic_snapshot'] is False and not private_wrapper['truncated']
private_files = {Path(x['path']).name: x for x in private_wrapper['files']}
assert set(private_files) == {'projection.private.json', 'projection-binding.private.json'}
projection_file = private_files['projection.private.json']
binding_file = private_files['projection-binding.private.json']
projection_raw, binding_raw = file_bytes(projection_file), file_bytes(binding_file)
match_info(projection_file, native('private-inputs/root-output-file-info-1.native.json'))
match_info(binding_file, native('private-inputs/root-output-file-info-2.native.json'))
projection, binding = decode(projection_raw), decode(binding_raw)
assert set(projection) == {'schema', 'capture_sha256', 'rows'}
assert projection['schema'] == 'heptabao.current-sqlite-allrows-to-kv2.private.v1'
assert binding['schema'] == 'heptabao.formal-kv2-allrows-projection.private.v1'
assert binding['projection']['path'] == projection_file['path']
assert binding['projection']['pin'] == {'bytes': len(projection_raw), 'sha256': sha(projection_raw)}
assert binding['projection']['identity'] == observed['private_projection_file_identity']
assert projection_file['version'] == version(binding['projection']['identity'])
assert binding['new_history_baseline'] == 1 and not binding['historical_openbao_versions_supplied']
assert binding['source_updated_at_preserved_as_provenance']
inputs = decode((ROOT / 'private-inputs/fixed-inputs.private.json').read_bytes())
assert binding['qualified_readback_private_pin'] == inputs['private_closure']

capture_wrapper = native('private-inputs/root-capture-full-read.native.json')
assert not capture_wrapper['truncated'] and len(capture_wrapper['files']) == 1
capture_file = capture_wrapper['files'][0]
capture_raw = file_bytes(capture_file)
match_info(capture_file, native('private-inputs/root-capture-file-info.native.json'))
capture_pin = binding['capture_pin']
assert capture_file['path'] == capture_pin['path'] == '/Users/qianqi/heptabao-formal-kv2-current-20261106-r1/restores/restore-current-20261106-r1/capture.private.json'
assert len(capture_raw) == capture_pin['identity']['bytes']
assert sha(capture_raw) == capture_pin['sha256'] == projection['capture_sha256']
assert capture_file['version'] == version(capture_pin['identity'])
capture = decode(capture_raw)
assert capture['schema'] == 'heptabao.closed-current-sqlite-capture.v1' and capture['ok'] is True

# Independent local reconstruction from all projection rows. Do not import
# the producer or protocol implementation and do not open a database.
tables = {'auth_profile_store': ('store_key', 'store_json', 'updated_at'), 'auth_profile_state': ('state_key', 'state_json', 'updated_at')}
agents = [d for d in capture['database_rows'] if d['kind'] == 'agent']
assert len(agents) == capture['configured_agent_count'] == 5
assert len(capture['database_rows']) == 9
assert len({a['agent'] for a in agents}) == len(agents)
grouped = [{table: [] for table in tables} for _ in agents]
seen_keys, seen_rows, seen_ids = set(), set(), set()
for row in projection['rows']:
    assert set(row) == {'record_id', 'agent_slot', 'table', 'row_fields', 'kv_mount', 'kv_key'}
    slot, table = row['agent_slot'], row['table']
    assert type(slot) is int and 0 <= slot < len(agents) and table in tables
    fields = row['row_fields']
    assert set(fields) == set(tables[table])
    values = [fields[column] for column in tables[table]]
    assert isinstance(values[0], str) and values[0]
    row_identity = (slot, table, values[0])
    assert row_identity not in seen_rows and row['record_id'] not in seen_ids and row['kv_key'] not in seen_keys
    assert row['kv_mount'] == inputs['business_mount'] and row['record_id'] == row['kv_key']
    seen_rows.add(row_identity); seen_ids.add(row['record_id']); seen_keys.add(row['kv_key'])
    grouped[slot][table].append(values)
expected_record_ids = []
expected_id_by_source = {}
for slot, source in enumerate(agents):
    for table_index, table in enumerate(tables):
        grouped[slot][table].sort(key=lambda values: values[0])
        for ordinal, values in enumerate(grouped[slot][table]):
            record_id = f'a{slot:04d}-t{table_index}-r{ordinal:04d}'
            expected_record_ids.append(record_id)
            source_identity = (slot, table, values[0])
            assert source_identity not in expected_id_by_source
            expected_id_by_source[source_identity] = record_id
    if source.get('present') and not source.get('empty_database_marker'):
        assert len(grouped[slot]['auth_profile_store']) == source['auth_store_rows']
        assert len(grouped[slot]['auth_profile_state']) == source['auth_state_rows']
        raw = json.dumps(grouped[slot], ensure_ascii=False, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()
        assert sha(raw) == source['auth_rows_sha256']
    else:
        assert not any(grouped[slot].values())
assert [row['record_id'] for row in projection['rows']] == expected_record_ids
assert len(expected_id_by_source) == len(projection['rows'])
for row in projection['rows']:
    primary = row['row_fields'][tables[row['table']][0]]
    expected_id = expected_id_by_source[(row['agent_slot'], row['table'], primary)]
    assert row['record_id'] == row['kv_key'] == expected_id
counts = {'agents': len(agents), 'database_families': len(capture['database_rows']), 'business_rows': len(projection['rows']), 'auth_profile_store_rows': sum(len(g['auth_profile_store']) for g in grouped), 'auth_profile_state_rows': sum(len(g['auth_profile_state']) for g in grouped)}
assert counts == observed['counts'] == binding['counts']
assert counts['auth_profile_store_rows'] == 5 and counts['auth_profile_state_rows'] == 4 and counts['business_rows'] == 9
for flag in ('formal_kv2_qualified', 'ha_qualified', 'authbus_qualified', 'historical_openbao_versions_supplied', 'traffic_cutover_performed', 'network_provider_or_j3160_called', 'product_sdk_or_service_executed', 'source_live_database_opened', 'source_live_configuration_opened', 'existing_capture_archive_key_restore_modified', 'old_assets_removed'):
    assert observed[flag] is False

report = {
    'schema': 'heptabao.root-actual-projection-r3-independent-review.v2',
    'job_id': terminal['job_id'], 'terminal_success_complete_durable_confirmed': True,
    'stdout_bytes': len(stdout), 'stdout_sha256': sha(stdout), 'stderr_bytes': 0,
    'public_result_bytes': len(public_raw), 'public_result_sha256': sha(public_raw),
    'actual_checks_passed': 8, 'counts': counts,
    'database_partition': observed['database_partition'],
    'private_projection_bytes': len(projection_raw), 'private_binding_bytes': len(binding_raw),
    'independently_read_original_capture_manifest_bytes': len(capture_raw),
    'all_native_full_bytes_sha_versions_modes_owners_links_match': True,
    'strict_json_duplicate_and_nonfinite_rejection': True,
    'exact_capture_generation_and_original_private_readback_pin_bound': True,
    'independently_recomputed_all_five_agents_both_table_commitments': True,
    'independent_reconstruction_imported_producer_or_protocol': False,
    'independent_reconstruction_opened_database_or_product': False,
    'source_updated_at_null_blob_and_credential_json_string_cells_preserved_by_full_row_commitment': True,
    'all_nine_opaque_record_scopes_unique_and_complete': True,
    'all_nine_row_to_kv_key_mappings_independently_bound': True,
    'original_controller_connections_closed': 6, 'original_controller_fds_closed': 66,
    'controller_forbidden_effect_attempts': 0, 'controller_elapsed_seconds': observed['elapsed_work_observation_seconds'],
    'root_independently_reread_full_six_databases': False,
    'root_read_scope': 'Complete small output, binding and original capture manifest plus independent native metadata; per-file versions match, no atomic multi-file snapshot claim.',
    'private_content_or_fingerprints_published': False,
    'formal_kv2_qualified': False, 'ha_qualified': False, 'authbus_qualified': False,
    'service_initialized_or_api_tested_by_projection': False, 'traffic_cutover_performed': False,
}
(ROOT / 'ROOT_ACTUAL_PROJECTION_REVIEW.r2.public.json').write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')
print(json.dumps(report, sort_keys=True))
