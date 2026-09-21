"""Pure admission and safety rules for the actual 44 -> 45 process fixture."""
from __future__ import annotations
import os
from pathlib import Path
import re
import stat
from contextlib import contextmanager

FIELD = 'secret_id_bound_cidrs'
MODES = ('empty', 'bound')
KINDS = ('service', 'batch')
REQUIRED = frozenset({'complete', 'processes_stopped'}) | frozenset(
    mode+'_'+case for mode in MODES for case in (
        'pure_application_unchanged', 'pure_reads_unchanged',
        'pure_restart_application_unchanged', 'pure_restart_reads_unchanged',
        'old_read_control', 'first_mutation_status', 'first_shape',
        'downgrade_unseal_status', 'downgrade_health_status',
        'downgrade_application_unchanged', 'secrets_absent')) | frozenset(
    f'{mode}_{kind}_{case}' for mode in MODES for kind in KINDS for case in (
        'old_one_value', 'old_two_value', 'old_renew_status', 'denied_status', 'after_denied_remaining',
        'reopened_remaining', 'allowed_shape', 'exhausted_status',
        'deleted_nil', 'after_clear_shape', 'reopened_denied_status',
        'fault_denied_status', 'fault_unknown_reference', 'fault_manifest_unchanged',
        'fault_fenced_status', 'fault_reopened_remaining',
        'one_denied_status', 'one_exhausted_status', 'unlimited_denied_status',
        'unlimited_remaining', 'unlimited_allowed_shape'))


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


def retained_role(current, old):
    if not isinstance(current, dict) or not isinstance(old, dict) or FIELD in old: return False
    current = dict(current)
    return FIELD in current and current.pop(FIELD) is None and current == old


def old_reader_observed(rows):
    return any(row.get('case') in {mode+'_downgrade_unseal_status' for mode in MODES}
               and type(row.get('status')) is int for row in rows)


def admit_legacy(receipt, actual_digest, expected_digest, source, binary_hash, expected, lane_complete):
    if not re.fullmatch('[0-9a-f]{40}', source) or not re.fullmatch('[0-9a-f]{64}', binary_hash):
        raise ValueError('legacy_binary_pins_required')
    if not re.fullmatch('[0-9a-f]{64}', expected_digest) or actual_digest != expected_digest:
        raise ValueError('legacy_receipt_digest_mismatch')
    before = receipt.get('candidate_source') or {}; sides = receipt.get('cases') or {}
    phases = receipt.get('completed_scenarios') or {}
    if (receipt.get('schema') != 'heptabao.jwt-batch-comparison.v1'
        or receipt.get('status') != 'passed' or receipt.get('build_source_commit') != source
        or not re.fullmatch('[0-9a-f]{40}', before.get('source_commit', ''))
        or before.get('binary_sha256') != binary_hash
        or before.get('source_dirty') is not False or receipt.get('candidate_source_after') != before
        or receipt.get('oracle_only') is not False or receipt.get('target_version') != '2.6.2'
        or receipt.get('failures') or set(sides) != {'candidate', 'oracle'} or set(phases) != set(sides)
        or not all(lane_complete(sides[side], phases[side], expected) for side in sides)
        or receipt.get('calibrated_cases_match') != {'candidate': True, 'oracle': True}
        or receipt.get('secrets_absent') != {'candidate': True, 'oracle': True}
        or receipt.get('processes_stopped') != {'candidate': True, 'oracle': True}
        or any(receipt.get(key) is not True for key in ('source_and_binary_unchanged', 'cases_match',
            'inputs_unchanged', 'oracle_binary_unchanged'))):
        raise ValueError('qualified_schema44_jwt_receipt_required')


@contextmanager
def denied_journal_append(store: Path):
    """Only fixture-owned file mode changes; no serialized application edit."""
    if os.geteuid() == 0: raise ValueError('nonroot_fault_profile_required')
    if not store.is_dir() or store.is_symlink(): raise ValueError('unsafe_store')
    path = store/'journal.hbj'; info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o600:
        raise ValueError('unsafe_journal')
    try:
        path.chmod(0o400, follow_symlinks=False)
        try:
            fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_NOFOLLOW)
        except PermissionError:
            pass
        else:
            os.close(fd)
            raise ValueError('append_fault_not_effective')
        yield
    finally:
        current = path.lstat()
        if (current.st_dev, current.st_ino) != (info.st_dev, info.st_ino) or not stat.S_ISREG(current.st_mode):
            raise ValueError('journal_changed_during_fault')
        path.chmod(0o600, follow_symlinks=False)
