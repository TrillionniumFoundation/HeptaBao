"""Run the unchanged final DR custody test module on one real Mac."""
from __future__ import annotations

import hashlib
import importlib
import json
import os
from pathlib import Path
import signal
import stat
import subprocess
import sys
import time
import unittest

ROOT = Path('/Volumes/T5/hepta-vnext-recovery-20261013/continuation-20261106-authbus-custody18-r1')
SOURCE = Path('/Volumes/T5/hepta-vnext-recovery-20261013/continuation-20261106-kv2-ha-convergence-r1/source-09c14-r1')
COMMIT = '09c14eae7a3b52dee8ce3af3175dad5900ac59ec'
TREE = 'dfb0df97a2c74b1c0154f45342f3debb0ce438ab'
PYTHON_SHA = 'cebfcc4ac431ff7a2179bc6eff7e5c6bdae48b564eeab2d504bef6173a2cfc13'
PINS = [
    ('kv2_dr_process_custody.py', 26131, '669e2cd1d9ee597529c08b88f3fc21c813d4ff7b57f3792381baa44fbdbe7008'),
    ('tests/test_kv2_dr_process_custody.py', 17148, '41d3b0e079b2b17a0ece458f907adf380542cbdf96530213869636e81a447807'),
    ('owned_process.py', 28442, '0ee96c9f43b50ebd57ee8f0ef95f2431c441ec02c1799992588dbf50768745d0'),
]
EXPECTED = [
    'test_cancel_enters_final_cleanup_and_restores_original_signal_handlers',
    'test_darwin_live_esrch_never_uses_a_zombie_anchor_or_grants_retirement',
    'test_darwin_numeric_parser_rejects_session_pointer_and_uses_kernel_sid',
    'test_darwin_observed_signed_nobody_uid_is_numeric_not_a_parse_gap',
    'test_darwin_waitable_zombie_requires_original_waitid_and_exact_retained_ps_identity',
    'test_foreign_reap_loses_authority_and_never_signals_recycled_group',
    'test_gate_identity_failure_never_executes_target_or_signals_a_guessed_group',
    'test_leader_exit_with_live_descendant_is_failure_and_only_owned_group_is_killed',
    'test_legacy_raw_killpg_after_nonzero_communicate_never_signals_retired_id',
    'test_legacy_raw_killpg_live_owned_group_routes_once_and_restores_global_hook',
    'test_legacy_raw_killpg_unknown_group_is_refused_without_touching_foreign_process',
    'test_missing_wnowait_and_external_sigchld_reaper_refuse_before_spawn',
    'test_nested_owner_and_finished_owner_do_not_create_new_originals',
    'test_prior_retirement_receipt_cannot_change_when_later_originals_run',
    'test_real_target_executes_only_in_observed_original_session_and_waits_once',
    'test_retirement_gate_does_not_stop_a_live_target',
    'test_run_check_output_and_owned_process_compatibility_share_originals',
    'test_wait_timeout_keeps_original_anchor_then_declared_stop_retires_it',
]


def digest(data):
    return hashlib.sha256(data).hexdigest()


def read_pinned(path, size, expected):
    assert path.resolve(strict=True) == path, 'source_symlink'
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        before = os.fstat(descriptor)
        assert stat.S_ISREG(before.st_mode) and before.st_uid == 501
        assert before.st_nlink == 1 and before.st_size == size
        assert before.st_mode & 0o022 == 0
        data = b''
        while len(data) <= size:
            part = os.read(descriptor, min(16384, size + 1 - len(data)))
            if not part:
                break
            data += part
        after = os.fstat(descriptor)
        assert (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) == (
            after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns)
        assert len(data) == size and digest(data) == expected
        return data
    finally:
        os.close(descriptor)


def write_new(path, data):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, 'wb') as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())


def write_json(name, value):
    write_new(ROOT / name, (json.dumps(value, indent=2, sort_keys=True) + '\n').encode())


class RecordedResult(unittest.TextTestResult):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.outcomes = []

    def addSuccess(self, test):
        super().addSuccess(test)
        self.outcomes.append({'test': test.id(), 'outcome': 'passed'})

    def addFailure(self, test, err):
        super().addFailure(test, err)
        self.outcomes.append({'test': test.id(), 'outcome': 'failed', 'error_type': err[0].__name__})

    def addError(self, test, err):
        super().addError(test, err)
        self.outcomes.append({'test': test.id(), 'outcome': 'error', 'error_type': err[0].__name__})

    def addSkip(self, test, reason):
        super().addSkip(test, reason)
        self.outcomes.append({'test': test.id(), 'outcome': 'skipped'})


def main():
    started = time.monotonic()
    assert sys.platform == 'darwin' and os.geteuid() == 501
    assert digest(Path(sys.executable).read_bytes()) == PYTHON_SHA
    assert ROOT.parent.resolve(strict=True) == ROOT.parent
    assert ROOT.parent.stat().st_dev == 16777244
    os.umask(0o077)
    ROOT.mkdir(mode=0o700)
    (ROOT / 'inputs').mkdir(mode=0o700)
    (ROOT / 'inputs' / 'tests').mkdir(mode=0o700)
    (ROOT / 'temporary').mkdir(mode=0o700)
    os.environ['TMPDIR'] = str(ROOT / 'temporary')
    os.chdir(ROOT)
    assert (SOURCE / '.git' / 'HEAD').read_text().strip() == COMMIT
    source_files = SOURCE / 'qa' / 'openbao-acceptance'
    inputs = []
    for relative, size, sha in PINS:
        data = read_pinned(source_files / relative, size, sha)
        write_new(ROOT / 'inputs' / relative, data)
        inputs.append({'relative': relative, 'bytes': size, 'sha256': sha})
    names = ['test_kv2_dr_process_custody.ProcessCustodyTests.' + n for n in EXPECTED]
    selection = {
        'schema': 'heptabao.mac-final-custody18-selection.v1', 'host': 'mac',
        'source_commit': COMMIT, 'source_tree': TREE, 'source_directory': str(SOURCE),
        'binding_scope': 'three exact source files copied from detached candidate; local git tree pins verified separately',
        'tests': names, 'expected_count': 18, 'inputs': inputs,
        'outer_seconds': 60, 'original_test_child_timeouts_unchanged': True,
        'cleanup_seconds': 5, 'python_sha256': PYTHON_SHA,
        'production_processes_touched': False, 'product107_or_dr_executed': False,
    }
    write_json('selection.public.json', selection)
    print(json.dumps({'event': 'source-pins-and-complete18-selection-verified',
                      'source_commit': COMMIT, 'expected_count': 18, 'host': 'mac'}), flush=True)
    sys.path.insert(0, str(ROOT / 'inputs' / 'tests'))
    sys.path.insert(1, str(ROOT / 'inputs'))
    module = importlib.import_module('test_kv2_dr_process_custody')
    custody = importlib.import_module('kv2_dr_process_custody')
    methods = unittest.defaultTestLoader.getTestCaseNames(module.ProcessCustodyTests)
    assert methods == EXPECTED, 'actual_test_names_changed'
    originals = {'popen': subprocess.Popen, 'killpg': os.killpg}
    handlers = {sig: signal.getsignal(sig) for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP, signal.SIGCHLD)}
    suite = unittest.defaultTestLoader.loadTestsFromNames(names)
    assert suite.countTestCases() == 18
    result = unittest.TextTestRunner(verbosity=2, resultclass=RecordedResult).run(suite)
    hooks_restored = (subprocess.Popen is originals['popen'] and os.killpg is originals['killpg']
                      and custody._ACTIVE is None
                      and handlers == {sig: signal.getsignal(sig) for sig in handlers})
    no_direct_children = False
    try:
        os.waitid(os.P_ALL, 0, os.WEXITED | os.WNOHANG | os.WNOWAIT)
    except ChildProcessError:
        no_direct_children = True
    source_unchanged = True
    for relative, size, sha in PINS:
        try:
            read_pinned(source_files / relative, size, sha)
            read_pinned(ROOT / 'inputs' / relative, size, sha)
        except Exception:
            source_unchanged = False
    exact_names = sorted(row['test'] for row in result.outcomes) == names
    passed = (result.wasSuccessful() and result.testsRun == 18 and not result.skipped
              and not result.expectedFailures and not result.unexpectedSuccesses
              and exact_names and hooks_restored and no_direct_children and source_unchanged)
    report = {
        'schema': 'heptabao.mac-final-custody18-result.v1', 'status': 'passed' if passed else 'failed',
        'host': 'mac', 'platform': sys.platform, 'source_commit': COMMIT, 'source_tree': TREE,
        'inputs': inputs, 'tests_run': result.testsRun, 'expected_count': 18,
        'passed': sum(r['outcome'] == 'passed' for r in result.outcomes),
        'failed': len(result.failures), 'errors': len(result.errors), 'skipped': len(result.skipped),
        'expected_failures': len(result.expectedFailures), 'unexpected_successes': len(result.unexpectedSuccesses),
        'outcomes': result.outcomes, 'exact_names_matched': exact_names,
        'original_hooks_and_handlers_restored': hooks_restored,
        'no_direct_children_after_tests': no_direct_children,
        'no_additional_cleanup_signal_sent': True,
        'descendant_cleanup_scope': 'existing tests assert their original process-group retirement; no hostile escape containment claim',
        'source_and_copied_inputs_unchanged': source_unchanged,
        'python_sha256': PYTHON_SHA, 'elapsed_seconds': time.monotonic() - started,
        'outer_seconds': 60, 'original_test_child_timeouts_unchanged': True,
        'automatic_retry': False, 'product107_or_dr_executed': False,
        'formal_storage_or_physical_ha_qualified': False, 'production_changed': False,
    }
    write_json('result.public.json', report)
    print(json.dumps(report, sort_keys=True), flush=True)
    return 0 if passed else 1


if __name__ == '__main__':
    raise SystemExit(main())
