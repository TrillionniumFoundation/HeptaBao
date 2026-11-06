#!/usr/bin/env python3
"""Observe the r2 cold URI audit refusal using two fixed public code files only.

No projection main, private plan, generation closure, SQLite, product, network,
child process, directory creation or file write is performed. Runtime stdout
is the only output. The original controller audit is called unchanged.
"""
import time
ENTRY = time.monotonic()
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import stat
import sys
import types

END, TOTAL_END = ENTRY + 52, ENTRY + 60
PENDING = None
FIRED = False
TIMER_OWNED = False
ROWS = []
CLEANUP = []
ROOT = Path('/Volumes/T5/hepta-vnext-recovery-20261013/continuation-20261106-kv2-ha-convergence-r1')
INPUT = ROOT / 'control/formal-kv2-allrows-projection-inputs-r2'
SOURCES = (
    ('mac_formal_kv2_allrows_projection.py', 44499,
     'e79a8956a14b8c85935ea371a5cbd844d735fbf6ce8c6bb21836d9fda249307c'),
    ('formal_kv2_protocol.py', 91070,
     'f93749dcac3d4f8517c71ff97171aa3cf2083d33f09a16638861e3c4bb012f20'),
)
RESULT = {
    'schema': 'heptabao.projection-r2-cold-uri-audit-code-only.public.v1',
    'status': 'failed', 'expected_refusal_observed': False,
    'work_seconds': 52, 'runtime_seconds': 60, 'automatic_retry': False,
    'original_audit_implementation_changed': False,
    'projection_main_called': False, 'private_plan_or_generation_opened': False,
    'sqlite_connection_opened': False, 'source_or_output_directory_created': False,
    'file_written': False, 'child_process_or_network_or_product_used': False,
    'formal_kv2_qualified': False,
}


class Refused(Exception):
    pass


def need(ok, code):
    if not ok:
        raise Refused(code)


def interrupt(signum, _frame):
    global PENDING, FIRED
    if PENDING is None:
        PENDING = signum
    FIRED = FIRED or signum == signal.SIGALRM
    # Sticky only: never raise between an FD birth and its registry assignment.


def check():
    need(PENDING is None and not FIRED and time.monotonic() < END,
         'original_code_only_deadline')


def identity(st):
    return (st.st_dev, st.st_ino, st.st_uid, st.st_gid, stat.S_IMODE(st.st_mode),
            stat.S_IFMT(st.st_mode), st.st_nlink, st.st_size, st.st_mtime_ns, st.st_ctime_ns)


def read_code(name, size, sha):
    check()
    path = INPUT / name
    need(path.resolve(strict=True) == path, 'canonical_fixed_code_path')
    row = {'fd': None, 'born': False, 'close_attempted': False, 'closed': False,
           'name': name, 'identity': None}
    ROWS.append(row)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    row['fd'] = fd
    row['born'] = True
    before = os.fstat(fd)
    row['identity'] = identity(before)
    need(stat.S_ISREG(before.st_mode) and before.st_uid == 501
         and stat.S_IMODE(before.st_mode) == 0o600 and before.st_nlink == 1
         and before.st_size == size, 'fixed_public_code_identity')
    raw = bytearray()
    while len(raw) <= size:
        check()
        chunk = os.read(fd, min(65536, size + 1 - len(raw)))
        if not chunk:
            break
        raw.extend(chunk)
    need(len(raw) == size and hashlib.sha256(raw).hexdigest() == sha
         and row['identity'] == identity(os.fstat(fd)) == identity(path.lstat()),
         'fixed_public_code_whole_pin')
    return bytes(raw)


def recheck_originals():
    for row, (_, size, sha) in zip(ROWS, SOURCES):
        check()
        need(row['born'] and not row['close_attempted'], 'held_original_code_required')
        os.lseek(row['fd'], 0, os.SEEK_SET)
        raw = bytearray()
        while len(raw) <= size:
            check()
            chunk = os.read(row['fd'], min(65536, size + 1 - len(raw)))
            if not chunk:
                break
            raw.extend(chunk)
        need(len(raw) == size and hashlib.sha256(raw).hexdigest() == sha
             and row['identity'] == identity(os.fstat(row['fd']))
             == identity((INPUT / row['name']).lstat()), 'original_code_unchanged')


def close_originals():
    for row in reversed(ROWS):
        if not row['born'] or row['close_attempted']:
            continue
        row['close_attempted'] = True
        try:
            os.close(row['fd'])
            row['closed'] = True
        except BaseException:
            CLEANUP.append('original_code_close_failed_no_retry')


def main():
    global TIMER_OWNED
    previous = {}
    failure = None
    try:
        need(sys.platform == 'darwin' and os.geteuid() == 501
             and sys.version_info[:3] == (3, 14, 3) and sys.flags.isolated
             and sys.flags.no_site and sys.dont_write_bytecode,
             'fixed_existing_mac_isolated_python')
        need(signal.getitimer(signal.ITIMER_REAL) == (0.0, 0.0)
             and signal.getsignal(signal.SIGALRM) == signal.SIG_DFL,
             'foreign_alarm_refused')
        for signum in (signal.SIGALRM, signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
            previous[signum] = signal.getsignal(signum)
            signal.signal(signum, interrupt)
        TIMER_OWNED = True
        signal.setitimer(signal.ITIMER_REAL, max(0.000001, END - time.monotonic()))
        controller_source, protocol_source = (read_code(*item) for item in SOURCES)
        module = types.ModuleType('heptabao_fixed_projection_code_only_diagnostic')
        module.__file__ = str(INPUT / SOURCES[0][0])
        sys.modules[module.__name__] = module
        exec(compile(controller_source, module.__file__, 'exec', dont_inherit=True), module.__dict__)
        check()
        stdlib = Path(os.__file__).parent.resolve(strict=True)
        RESULT['request_cached_before_conversion'] = 'urllib.request' in sys.modules
        denied = []

        def original_audit_with_fixed_observation(event, args):
            try:
                module.audit(event, args)
            except module.Refused:
                is_request = False
                if event == 'open' and args and type(args[0]) is str:
                    path = Path(args[0])
                    is_request = (path.is_absolute() and path.parent in (stdlib / 'urllib', stdlib / 'urllib/__pycache__')
                        and re.fullmatch(r'request(?:\.cpython-314)?\.(?:py|pyc)', path.name) is not None)
                denied.append({'event_class': 'open' if event == 'open' else 'other_withheld',
                               'stdlib_urllib_request_module_file': is_request})
                raise

        sys.addaudithook(original_audit_with_fixed_observation)
        try:
            Path('/synthetic-only/空 格/%? #/fixture.sqlite').as_uri()
        except module.Refused as error:
            need(str(error) == 'forbidden_projection_effect', 'same_fixed_refusal_required')
            RESULT['expected_refusal_observed'] = True
        need(RESULT['expected_refusal_observed'] and not RESULT['request_cached_before_conversion']
             and denied == [{'event_class': 'open', 'stdlib_urllib_request_module_file': True}]
             and module.DENIALS == 1, 'exact_cold_uri_audit_event_required')
        recheck_originals()
        RESULT.update(denied_observations=denied, original_audit_denial_count=module.DENIALS,
                      original_code_pins_and_identities_unchanged=True,
                      source_pins=[{'name': n, 'bytes': size, 'sha256': sha} for n, size, sha in SOURCES])
        check()
        RESULT['status'] = 'expected_r2_cold_uri_import_refusal_observed'
    except BaseException as error:
        failure = str(error) if isinstance(error, Refused) else 'code_only_diagnostic_unexpected_failure'
    finally:
        close_originals()
        all_closed = all(not r['born'] or r['close_attempted'] and r['closed'] for r in ROWS)
        if TIMER_OWNED:
            try:
                signal.setitimer(signal.ITIMER_REAL, 0)
                TIMER_OWNED = False
            except BaseException:
                CLEANUP.append('owned_timer_disarm_failed')
        for signum, prior in previous.items():
            try:
                signal.signal(signum, prior)
            except BaseException:
                CLEANUP.append('original_handler_restore_failed')
        elapsed = time.monotonic() - ENTRY
        if failure or CLEANUP or not all_closed or PENDING is not None or FIRED or time.monotonic() >= END:
            RESULT['status'] = 'failed'
        RESULT.update(primary_failure_code=failure, cleanup_failure_codes=CLEANUP,
            original_code_fd_births=sum(r['born'] for r in ROWS),
            original_code_close_attempts=sum(r['close_attempted'] for r in ROWS),
            original_code_close_successes=sum(r['closed'] for r in ROWS),
            all_original_code_handles_retired=all_closed, deadline_fired=FIRED,
            interrupted_signal=PENDING, elapsed_observation_seconds=elapsed,
            original_52_second_gate_met=time.monotonic() < END,
            final_runtime_terminal_required=True)
        print(json.dumps(RESULT, sort_keys=True, separators=(',', ':')), flush=True)
    return 0 if RESULT['status'] == 'expected_r2_cold_uri_import_refusal_observed' and time.monotonic() < TOTAL_END else 1


if __name__ == '__main__':
    raise SystemExit(main())
