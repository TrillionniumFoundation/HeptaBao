#!/usr/bin/env python3
"""Exercise the pinned DR receipt validator with retained actual failures only.

This local check does not run wrapper preparation, a server, or DR. The existing
positive/synthetic validator regressions remain separate evidence.
"""
import time
STARTED = time.monotonic()
import ast
import hashlib
import importlib
import json
import os
from pathlib import Path
import signal
import sys

ROOT = Path(__file__).resolve().parent.parent
OUT = Path(__file__).resolve().parent / 'failed-receipts-guard-r1.public.json'
QA = ROOT / 'HeptaBao-integration/qa/openbao-acceptance'
WRAPPER = Path(__file__).resolve().parent / 'dr25_mac_fixed_wrapper.py'
CURRENT = '09c14eae7a3b52dee8ce3af3175dad5900ac59ec'
MAIN_SHA = '388f763d810e1694ce9fe3d4ce52325318aad8ec4fa4d87ebbcd6cfbe7f1f5a0'
WRAPPER_SHA = '7e4310f29591b40fb6df04d1e322f2fcb727887d82a52d090fcd0262c02c0fe1'
CASES = (
    ('build-test-f301-r1', '31b60348a98aef69c57381637cc59d7c69ba3f6729ba63f89c2b7ff76e5ea155',
     'a5079af9cfdf051b2c926cad6799b22d6bab9f6682b27e74bb7017a37424a57d'),
    ('build-test-868-r1', '8f8ecf43e2fbca843d0c0635b19a774a61f8fb0e17d87c019ade20f8a738a419',
     '4177229337bb7ffc7d1c81b9ea515bd48b0cbd529fd48537815cd40bbfdb53e7'),
)
PINS = {}
FORBIDDEN = []


def pinned(path, expected):
    raw = path.read_bytes()
    assert hashlib.sha256(raw).hexdigest() == expected, 'input_sha_mismatch'
    PINS[path] = expected
    return raw


def audit(event, args):
    if event in {'subprocess.Popen', 'os.system', 'os.fork', 'os.forkpty',
                 'os.exec', 'os.posix_spawn', 'socket.connect', 'socket.bind'}:
        FORBIDDEN.append(event)
        raise RuntimeError('guard_forbids_process_or_network_operation')


def alarm(signum, frame):
    raise TimeoutError('local_guard_five_second_bound')


def main():
    assert not OUT.exists(), 'new_guard_result_required'
    assert signal.getitimer(signal.ITIMER_REAL) == (0.0, 0.0)
    previous = signal.getsignal(signal.SIGALRM)
    assert previous == signal.SIG_DFL
    report = {'schema': 'heptabao.actual-failed-build-receipt-guard.v1',
              'scope': 'local exact validator consumed by the fixed Mac wrapper',
              'full_wrapper_preparation_executed': False, 'dr_executed': False,
              'product_executed': False, 'network_attempted': False,
              'production_authority': False, 'actual_107_pass_claimed': False,
              'expected_rejections': 4, 'checks': [], 'failure': None}
    code = 1
    try:
        signal.signal(signal.SIGALRM, alarm)
        signal.setitimer(signal.ITIMER_REAL, max(.001, 5 - (time.monotonic() - STARTED)))
        sys.dont_write_bytecode = True
        sys.addaudithook(audit)
        main_path = QA / 'kv2_native_fresh_directory_dr_live.py'
        pinned(main_path, MAIN_SHA)
        tree = ast.parse(pinned(WRAPPER, WRAPPER_SHA))
        prepare = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'preparation')
        calls = [n for n in ast.walk(prepare) if isinstance(n, ast.Call)
                 and isinstance(n.func, ast.Attribute) and isinstance(n.func.value, ast.Name)
                 and n.func.value.id == 'dr' and n.func.attr == 'validate_build_receipt']
        assert len(calls) == 1 and isinstance(calls[0].args[1], ast.Name) and calls[0].args[1].id == 'PRODUCT_COMMIT'
        sys.path.insert(0, str(QA))
        dr = importlib.import_module('kv2_native_fresh_directory_dr_live')
        assert Path(dr.__file__).resolve() == main_path.resolve()
        for run, receipt_sha, selection_sha in CASES:
            base = ROOT / 'recovered-evidence/mac-native-convergence-20261106-r1' / run
            receipt = json.loads(pinned(base / 'result.public.json', receipt_sha))
            selection = json.loads(pinned(base / 'test-selection.public.json', selection_sha))
            assert receipt['status'] == 'failed' and receipt['failure'] == 'native-jwt15_exact_test_result_failed'
            server, seed = (receipt['artifacts'][name] for name in ('heptabao-server', 'heptabao-seed'))
            for scope, commit in (('receipt_own_source', receipt['source_commit']), ('current_09c14_source', CURRENT)):
                row = {'run': run, 'receipt_sha256': receipt_sha, 'selection_sha256': selection_sha,
                       'binding_scope': scope, 'expected_commit': commit,
                       'observed_receipt_status': receipt['status'],
                       'observed_qualified_passed_cases': receipt['executed_passed_cases'],
                       'observed_not_qualified_cases': receipt['not_qualified_cases'],
                       'rejected': False, 'failure_label': None}
                report['checks'].append(row)
                try:
                    dr.validate_build_receipt(receipt, commit, server, seed, selection, selection_sha)
                except dr.Failure as error:
                    assert error.args == ('completed_bound_build_receipt_required',), 'different_gate_failed'
                    row.update(rejected=True, failure_label='completed_bound_build_receipt_required')
                else:
                    raise AssertionError('actual_failed_receipt_was_admitted')
        assert len(report['checks']) == 4 and all(row['rejected'] for row in report['checks'])
        assert not FORBIDDEN
        for path, expected in PINS.items():
            assert hashlib.sha256(path.read_bytes()).hexdigest() == expected, 'retained_input_changed'
        assert time.monotonic() - STARTED < 5
        report.update(status='passed', rejected_cases=4, inputs_unchanged=True,
                      forbidden_operations_observed=0, main_sha256=MAIN_SHA,
                      wrapper_sha256=WRAPPER_SHA)
        code = 0
    except BaseException as error:
        report.update(status='failed', failure=type(error).__name__,
                      forbidden_operations_observed=len(FORBIDDEN))
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)
        report['elapsed_seconds'] = round(time.monotonic() - STARTED, 6)
        report['signal_and_timer_restored'] = signal.getsignal(signal.SIGALRM) == previous and signal.getitimer(signal.ITIMER_REAL) == (0.0, 0.0)
        raw = (json.dumps(report, sort_keys=True, indent=2) + '\n').encode()
        fd = os.open(OUT, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_NOFOLLOW', 0), 0o600)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        print(json.dumps({'status': report['status'], 'rejected_cases': report.get('rejected_cases', 0),
                          'result': str(OUT), 'bytes': len(raw),
                          'sha256': hashlib.sha256(raw).hexdigest()}, sort_keys=True))
    return code


if __name__ == '__main__':
    raise SystemExit(main())
