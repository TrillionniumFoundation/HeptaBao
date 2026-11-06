"""Check only the preserved public r2 receipts; no host, source DB or product IO."""
import hashlib
import json
from pathlib import Path
import sys


def need(value, label):
    if not value:
        raise ValueError(label)


def read(root, relative):
    return json.loads((root / relative).read_bytes())


def main(root):
    results = {}
    for role, job, handles, stdout_bytes in (
        ('stage', '1a1b206dab4-fc05-7c17', 2, 5414),
        ('producer', '1a1b20a271e-fc05-7c28', 16, 6633),
    ):
        terminal = read(root, role + '/runtime-terminal.original.json')
        need(terminal['job_id'] == job and terminal['state'] == 'succeeded' and terminal['exit_code'] == 0
             and terminal['timed_out'] is False and terminal['cancelled'] is False
             and terminal['automatic_retry'] is False and terminal['output_complete'] is True
             and terminal['output_durable'] is True and terminal['terminal_publication_confirmed'] is True,
             role + '_authoritative_successful_terminal')
        for stream in ('stdout', 'stderr'):
            raw = (root / role / ('runtime.' + stream + '.original')).read_bytes()
            need(len(raw) == terminal['log_bytes'][stream]['stored'] == terminal['log_bytes'][stream]['seen']
                 and terminal['log_synced'][stream] is True and terminal['log_truncated'][stream] is False
                 and terminal['log_errors'][stream] is None,
                 role + '_complete_' + stream)
        need((root / role / 'runtime.stderr.original').read_bytes() == b'', role + '_empty_stderr')
        need((root / role / 'runtime.stdout.original').stat().st_size == stdout_bytes, role + '_stdout_size')
        result, stdout = read(root, role + '/result.public.json'), read(root, role + '/runtime.stdout.original')
        expected = dict(result, owned_directory_handles_closed=handles, all_owned_directory_handles_retired=True)
        need(stdout == expected and stdout['status'] == 'passed' and stdout['deadline_fired'] is False
             and stdout['interrupted'] is False, role + '_receipt_final_stdout_full_agreement')
        results[role] = result
    stage, producer = results['stage'], results['producer']
    need(stage['staged_inputs'] == len(stage['inputs']) == 21 and stage['staged_public_inputs'] == 20
         and stage['staged_private_inputs'] == 1 and len({f['role'] for f in stage['inputs']}) == 21
         and sum(f['private'] for f in stage['inputs']) == 1
         and all(f['exact_readback'] is True and f['mode'] == 0o600 and f['uid'] == 501 and f['nlink'] == 1
                 for f in stage['inputs']) and stage['original_count'] == 0
         and stage['workflow_executed'] is False and stage['business_source_opened'] is False
         and stage['runtime_seconds'] == 60 and stage['work_seconds'] == 52
         and stage['elapsed_observation_before_receipt_publication_seconds'] < 52,
         'complete_21_input_create_only_stage')
    private_input = next(f for f in stage['inputs'] if f['private'])
    need(private_input['role'] == 'independent_private_pins' and 'sha256' not in private_input,
         'private_envelope_digest_not_published')
    for flag in ('all_clients_and_backups_migrated', 'all_known_writers_fenced', 'authbus_qualified',
                 'automatic_retry', 'business_source_values_or_fingerprints_published',
                 'cross_database_atomic_snapshot_qualified', 'current_credential_validity_qualified',
                 'formal_kv2_qualified', 'full_workspace_product_qualification', 'ha_qualified',
                 'old_assets_removed', 'private_plan_or_config_hashes_published', 'product_or_sdk_executed',
                 'production_service_started', 'provider_or_j3160_called', 'service_or_client_configuration_changed',
                 'source_data_write_invoked', 'source_device_loss_recovery_qualified',
                 'source_freshness_after_capture_qualified', 'source_native_sqlite_sidecar_writes_excluded',
                 'traffic_cutover_performed', 'deadline_renewed', 'resume_after_failed_phase_supported'):
        need(producer[flag] is False, 'producer_preserves_' + flag)
    for flag in ('capture_backup_and_fresh_restore_completed', 'all_bound_inputs_and_artifacts_unchanged',
                 'source_code_unchanged', 'current_two_volume_identities_and_complete_lifecycle_space_verified',
                 'fresh_current_plan_and_independent_native_file_pins_bound',
                 'original_directory_paths_and_handles_preserved', 'original_per_database_transaction_scope_preserved',
                 'original_archive_and_key_parent_identity_dependency_preserved',
                 'read_only_volume_roots_bound_to_original_stage_identity', 'workflow_invoked',
                 'known_product_ci_failures_remain_unresolved_by_this_work'):
        need(producer[flag] is True, 'producer_requires_' + flag)
    need('primary_failure' not in producer and 'cleanup_failures' not in producer
         and producer['runtime_cap_seconds'] == 900 and producer['work_cap_seconds_from_original_entry'] == 840
         and producer['cleanup_and_receipt_reserve_seconds'] == 60
         and producer['admission_cap_within_original_work_seconds'] == 60
         and producer['admission_seconds_from_original_entry'] < 60
         and producer['elapsed_observation_before_receipt_publication_seconds'] < 840
         and producer['owned_directory_handle_count'] == 16 and producer['forbidden_effect_attempt_count'] == 0,
         'original_total_budget_and_no_hidden_failure')
    custody = producer['owned_native_metadata_processes']
    need(custody['original_count'] == len(custody['children']) == 2 and custody['finished'] is True
         and custody['passed_process_custody'] is True and custody['failed'] is False
         and custody['interrupted'] is False, 'exact_two_original_metadata_children')
    for child in custody['children']:
        need(child['exec_admitted'] is True and child['returncode'] == 0 and child['original_wait_count'] == 1
             and child['original_wait_completed'] is True and child['no_live_members_before_reap'] is True
             and child['gap_count'] == 0 and child['pid'] == child['birth']['pid'] == child['birth']['pgid']
             == child['birth']['sid'] and child['birth']['uid'] == 501,
             'each_original_child_exec_and_once_wait')
        for name in ('members_at_leader_exit', 'members_before_original_reap'):
            need(len(child[name]) == 1 and child[name][0]['pid'] == child['pid']
                 and child[name][0]['state'] == 'Z', 'original_group_retired_before_reap')
    workflow = producer['workflow']
    need(workflow['status'] == 'passed' and [r['phase'] for r in workflow['phases']]
         == ['capture', 'backup', 'restore-verify'], 'complete_three_phase_order')
    for row in workflow['phases']:
        need(row['status'] == 'passed' and row['phase_cap_seconds'] == 300
             and row['completion_observed_within_original_phase_and_total_deadlines'] is True
             and type(row['elapsed_seconds']) in (int, float) and 0 <= row['elapsed_seconds'] < 300,
             'each_phase_original_budget')
    counts = workflow['counts']
    need(counts == {'configured_agents': 5, 'captured_database_entries': 9, 'logical_snapshot_bytes': 3278327808,
                    'recovery': {'nonempty_databases': 6, 'auth_stores': 5, 'absent_families': 3,
                                 'all_declared_files': 19, 'plaintext_bytes': 3278398048}}, 'complete_real_generation_counts')
    roots = {row['role']: row['identity'] for row in producer['actual_attempt_roots_at_workflow_closeout']}
    need(set(roots) == {'capture', 'archive', 'key', 'restore'} and len({(r['dev'], r['inode']) for r in roots.values()}) == 4
         and all(r['uid'] == 501 and r['mode'] == 0o700 for r in roots.values())
         and roots['archive']['dev'] != roots['capture']['dev'] and roots['archive']['dev'] != roots['key']['dev'],
         'four_unique_private_closeout_roots_and_distinct_filesystems')
    need(producer['completed_private_closure_file_count'] == 5
         and producer['actual_root_identity_observation_scope'] == 'original_workflow_successful_closeout_not_earlier_inode_history'
         and producer['prior_failed_attempt'] == {'job_id': '1a1b1f76336-fc05-7bc7', 'original_status': 'failed',
             'original_exit_code': 1, 'workflow_invoked': False, 'reclassified_as_success': False},
         'original_failure_and_private_closeout_scope')
    phases = {name: read(root, 'phases/' + filename) for name, filename in (
        ('capture', 'capture-result.public.json'), ('backup', 'backup-result.public.json'),
        ('restore-verify', 'restore-result.public.json'), ('current-source-recovery-workflow', 'workflow-result.public.json'))}
    for phase, value in phases.items():
        need(value['phase'] == phase and value['status'] == 'passed' and value['error'] is None
             and value['credential_values_or_content_fingerprints_published'] is False
             and value['only_declared_captured_generation'] is True,
             'phase_public_receipt_scope')
    need(phases['capture']['counts'] == {'configured_agents': 5, 'database_entries': 9,
         'present_databases': 6, 'logical_snapshot_bytes': 3278327808, 'complete_declared_files': 18},
         'capture_public_count_agreement')
    need(phases['backup']['counts']['declared_files'] == 19
         and phases['backup']['counts']['plaintext_bytes'] == 3278398048
         and phases['backup']['archive_filesystem_distinct_from_source_and_capture'] is True
         and phases['backup']['key_filesystem_distinct_from_archive'] is True
         and phases['backup']['distinct_physical_device_or_power_failure_qualification'] is False,
         'backup_public_count_and_fault_domain_scope')
    need(phases['restore-verify']['counts'] == counts['recovery']
         and phases['restore-verify']['all_chunks_authenticated_before_destination_creation'] is True
         and phases['restore-verify']['full_restored_file_bytes_and_declared_absences_exact'] is True
         and phases['restore-verify']['all_owned_restore_handles_retired'] is True, 'restore_public_count_agreement')
    full = phases['current-source-recovery-workflow']
    need({name: full[name] for name in ('counts', 'phases', 'status')} == workflow
         and full['schema'] == 'heptabao.mac-current-sqlite-recovery-workflow.public.v1'
         and full['total_runtime_cap_seconds'] == 900 and full['controller_work_cap_seconds'] == 840
         and full['cleanup_and_receipt_reserve_seconds'] == 60, 'full_core_receipt_and_outer_projection')
    return {'schema': 'heptabao.successful-current-data-protection-public-reconciliation.v1', 'status': 'passed',
            'stage_job_id': '1a1b206dab4-fc05-7c17', 'producer_job_id': '1a1b20a271e-fc05-7c28',
            'stage_inputs': 21, 'public_inputs': 20, 'private_inputs': 1, 'stage_directory_handles_closed': 2,
            'producer_directory_handles_closed': 16, 'producer_original_metadata_children': 2,
            'three_phases_passed_within_original_budgets': True, 'counts': counts,
            'four_phase_receipts_and_full_stdout_match': True, 'private_ns_integers_preserved': True,
            'data_protection_only': True, 'independent_full_data_readback_performed_by_this_checker': False,
            'formal_kv2_qualified': False, 'product_ci_failures_remain_held': True}


if __name__ == '__main__':
    root = Path(sys.argv[1]) if len(sys.argv) == 2 else Path(__file__).resolve().parent
    print(json.dumps(main(root), sort_keys=True, indent=2))
