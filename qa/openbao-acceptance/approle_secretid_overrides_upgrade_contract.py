"""Admission and completion rules for four real schema45 -> 46 stores."""
import re

# Each option's empty and nonempty presence is the very first candidate write.
PROFILES = {
    'source_empty': ('cidr_list', [], 'random', 'service'),
    'source_bound': ('cidr_list', ['127.0.0.1/32'], 'custom', 'service'),
    'token_empty': ('token_bound_cidrs', [], 'custom', 'batch'),
    'token_bound': ('token_bound_cidrs', ['127.0.0.2/32'], 'random', 'batch'),
}
LIFECYCLE = ('source_bound', 'token_bound')
REQUIRED = frozenset({'processes_stopped', 'complete'}) | frozenset(
    mode+'_'+case for mode in PROFILES for case in (
        'pure_application_unchanged', 'pure_reads_unchanged', 'pure_sid_preserved',
        'pure_restart_application_unchanged', 'pure_restart_reads_unchanged', 'pure_restart_sid_preserved',
        'old_read_control', 'first_mint_status', 'first_shape', 'role_unmodified',
        'downgrade_unseal_status', 'downgrade_health_status', 'downgrade_application_unchanged',
        'final_first_shape', 'final_old_sid_empty', 'secrets_absent')) | frozenset(
    mode+'_'+case for mode in LIFECYCLE for case in (
        'source_denied_status', 'source_after_denied_remaining', 'source_reopened_remaining',
        'source_allowed_shape', 'source_exhausted_status', 'subset_denied_status',
        'subset_after_denied_remaining', 'subset_reopened_remaining', 'subset_allowed_shape',
        'subset_exhausted_status', 'old_sid_current_source_shape',
        'override_initial_one_status', 'override_initial_two_value',
        'override_moved_one_status', 'override_moved_two_value',
        'override_cleared_one_status', 'override_cleared_two_value',
        'legacy_inherited_one_value', 'legacy_inherited_two_status',
        'legacy_cleared_one_value', 'legacy_cleared_two_value', 'legacy_fields_still_empty',
        'override_reopened_one_status', 'override_reopened_two_value',
        'old_bearer_reopened_one_value', 'old_bearer_reopened_two_value'))


def complete(rows):
    if not isinstance(rows, list) or not rows: return False
    names = set()
    for row in rows:
        if not isinstance(row, dict) or set(row)-{'case', 'passed', 'status'}: return False
        name = row.get('case')
        if not isinstance(name, str) or not re.fullmatch('[a-z0-9_]{1,120}', name) or name in names: return False
        names.add(name)
        if row.get('passed') is not True: return False
        if 'status' in row and (type(row['status']) is not int or not 100 <= row['status'] <= 599): return False
    return REQUIRED <= names and rows[-1]['case'] == 'complete'


def old_reader_observed(rows):
    return any(row.get('case') in {mode+'_downgrade_unseal_status' for mode in PROFILES}
               and type(row.get('status')) is int for row in rows)


def old_secret_preserved(current, old):
    # Qualified old45 already reads both absent fields as []; no reconstruction.
    return (isinstance(current, dict) and isinstance(old, dict)
            and old.get('cidr_list') == [] and old.get('token_bound_cidrs') == [] and current == old)


def admit_legacy(receipt, actual_digest, expected_digest, source, binary_hash, expected, lane_complete):
    if not re.fullmatch('[0-9a-f]{40}', source) or not re.fullmatch('[0-9a-f]{64}', binary_hash):
        raise ValueError('legacy_binary_pins_required')
    if not re.fullmatch('[0-9a-f]{64}', expected_digest) or actual_digest != expected_digest:
        raise ValueError('legacy_receipt_digest_mismatch')
    before = receipt.get('candidate_source') or {}; sides = receipt.get('cases') or {}
    phases = receipt.get('completed_scenarios') or {}
    if (receipt.get('schema') != 'heptabao.approle-secret-cidrs-comparison.v1'
        or receipt.get('status') != 'passed' or receipt.get('build_source_commit') != source
        or not re.fullmatch('[0-9a-f]{40}', before.get('source_commit', ''))
        or before.get('binary_sha256') != binary_hash
        or before.get('source_dirty') is not False or receipt.get('candidate_source_after') != before
        or receipt.get('oracle_only') is not False or receipt.get('target_version') != '2.6.2'
        or receipt.get('failures') or set(sides) != {'candidate', 'oracle'} or set(phases) != set(sides)
        or not all(lane_complete(sides[side], phases[side], expected) for side in sides)
        or receipt.get('calibrated_cases_match') != {'candidate': True, 'oracle': True}
        or receipt.get('secrets_absent') != {'candidate': True, 'oracle': True}
        or receipt.get('processes_stopped') is not True
        or any(receipt.get(key) is not True for key in ('source_and_binary_unchanged', 'cases_match',
            'inputs_unchanged', 'oracle_binary_unchanged'))):
        raise ValueError('qualified_schema45_secret_cidrs_receipt_required')
