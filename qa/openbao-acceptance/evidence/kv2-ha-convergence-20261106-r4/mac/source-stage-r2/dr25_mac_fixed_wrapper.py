#!/usr/bin/env python3
"""Fixed synthetic Mac full34+DR25 attempt; a failed107 receipt never admits it.

Prepare is read-only. Run creates only the named fresh private directories. The
same Python process enters the pinned DR controller, retaining its original
process custody. Runtime must also declare its unchanged 1800-second outer cap.
"""
from __future__ import annotations

import time
ENTRY_MONOTONIC = time.monotonic()

import argparse
import contextlib
import hashlib
import importlib
import json
import os
from pathlib import Path
import plistlib
import re
import signal
import stat
import subprocess
import sys
import threading

ROOT = Path('/Volumes/T5/hepta-vnext-recovery-20261013/continuation-20261106-kv2-ha-convergence-r1')
SOURCE = ROOT / 'source-dr25-a2577-r2'
QA_COMMIT = 'a25772377e9bfad91564cf6702a26e861fded16f'
QA_TREE = 'd34d344e261811c406f63de56b3a7227c0e0ddf3'
PRODUCT_COMMIT = '4bde9aee03fcd27c59e13607e529b1cee594b249'
PRODUCT_TREE = 'f08493a23f8ea0637073651231865ea9607b790e'
BUILD = ROOT / 'build-test-4bde9-r1'
SELECTION_SHA = '7da0b1e3efe257b66d31d50af7c1327a4d320c512c1c8f82df30020898c66595'
WORK = ROOT / 'full34-dr25-r2'
OUT = ROOT / 'dr25-execution-4bde9-r2'
BACKUP = Path('/Users/qianqi/heptabao-dr25-backups-20261106-r2')
KEYS = ROOT / 'dr25-key-custody-r2'
ORACLE = Path('/Volumes/T5/hepta-vnext-recovery-20261013/official-openbao-271-macos-20261016')
PYTHON = Path('/opt/homebrew/bin/python3')
PINS = {
    'python': (PYTHON, 'cebfcc4ac431ff7a2179bc6eff7e5c6bdae48b564eeab2d504bef6173a2cfc13', 34640),
    'oracle_binary': (ORACLE / 'bao', '50c3588e64271171cc2147bddeace8ec2b6742f94fd3fe53baa60f6d938cda0c', 177888914),
    'oracle_archive': (ORACLE / 'oracle-official.tar.gz', '15625b5f69aee5bb4578b4e76e856a2141647342b0f8e5969a8875b44e0fbf91', 73965161),
    'main': (SOURCE / 'qa/openbao-acceptance/kv2_native_fresh_directory_dr_live.py', '2271a4ca539e1190b03e95e95d4d1c79414bd852c80ac85e205def2adac74263', 75012),
    'custody': (SOURCE / 'qa/openbao-acceptance/kv2_dr_process_custody.py', '669e2cd1d9ee597529c08b88f3fc21c813d4ff7b57f3792381baa44fbdbe7008', 26131),
    'full34': (SOURCE / 'qa/openbao-acceptance/kv2_271_lossless_native_live.py', '383176647f0670837f40f3989496c6d1c902f8503dfa006d386b75877436b581', 49393),
}
VOLUMES = (('/Volumes/T5', 'FB804D1B-24CB-4D6E-AEA7-A9E180807758', False),
           ('/System/Volumes/Data', '66612ABB-2CE6-4BDE-8B11-8104E60307CC', True))
OUTER_SECONDS, PREPARE_SECONDS, WORK_SECONDS = 1800, 60, 1740
CUSTODY = None


class Failure(RuntimeError):
    pass


class DeadlineExpired(BaseException):
    pass


def need(value, label):
    if not value:
        raise Failure(label)


def encode(value):
    return (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def private_new(path, raw):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        view = memoryview(raw)
        while view:
            count = os.write(fd, view)
            need(count > 0, 'private_short_write')
            view = view[count:]
        os.fsync(fd)
    finally:
        os.close(fd)


class Deadline:
    """One entry time, a fixed prepare boundary, and an unrenewable work end."""
    def __init__(self, started, *, prepare=PREPARE_SECONDS, work=WORK_SECONDS):
        self.started, self.prepare_end, self.work_end = started, started + prepare, started + work
        self.fired = False
        self.phase = 'prepare'
        self.fired_phase = None
        self.previous = None
        self.restored = False

    def _alarm(self, signum, frame):
        self.fired = True  # Independent of any controller result or deferred cleanup.
        self.fired_phase = self.fired_phase or self.phase
        owner = getattr(CUSTODY, '_ACTIVE', None) if CUSTODY else None
        if owner is not None:
            owner._interrupt(signum, frame)  # No signal, process lookup or new worker here.
        else:
            raise DeadlineExpired()

    def __enter__(self):
        need(threading.current_thread() is threading.main_thread(), 'deadline_main_thread')
        need(signal.getitimer(signal.ITIMER_REAL) == (0.0, 0.0), 'foreign_real_timer')
        self.previous = signal.getsignal(signal.SIGALRM)
        need(self.previous == signal.SIG_DFL, 'foreign_alarm_handler')
        signal.signal(signal.SIGALRM, self._alarm)
        try:
            self._arm(self.prepare_end)
        except BaseException:
            signal.signal(signal.SIGALRM, self.previous)
            raise
        return self

    def _arm(self, until):
        need(not self.fired and time.monotonic() < until, 'absolute_deadline_expired')
        signal.setitimer(signal.ITIMER_REAL, max(0.000001, until - time.monotonic()))

    def enter_work(self):
        need(self.phase == 'prepare' and time.monotonic() < self.prepare_end and not self.fired,
             'prepare_original_deadline_expired')
        self.phase = 'work'
        self._arm(self.work_end)  # Absolute job-entry +1740; preparation time is included.

    def eligible(self):
        end = self.prepare_end if self.phase == 'prepare' else self.work_end
        return not self.fired and time.monotonic() < end

    def __exit__(self, *_):
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, self.previous)
        self.restored = True

    def observation(self):
        return {'entry_monotonic': self.started, 'work_end_monotonic': self.work_end,
                'fired': self.fired, 'fired_phase': self.fired_phase,
                'deadline_renewed': False, 'work_seconds_from_entry': WORK_SECONDS,
                'runtime_outer_seconds': OUTER_SECONDS, 'cleanup_reserve_within_outer_seconds': 60}


@contextlib.contextmanager
def private_stdio(root):
    """Capture Python and inherited native fd1/fd2; never hash these outputs publicly."""
    originals, files = {}, []
    try:
        sys.stdout.flush(); sys.stderr.flush()
        for descriptor, name in ((1, 'controller.stdout.private'), (2, 'controller.stderr.private')):
            originals[descriptor] = os.dup(descriptor)
            fd = os.open(root / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            files.append(fd)
            os.dup2(fd, descriptor)
        yield
    finally:
        try:
            sys.stdout.flush(); sys.stderr.flush()
            for fd in files:
                os.fsync(fd)
        finally:
            for descriptor, original in originals.items():
                os.dup2(original, descriptor)
                os.close(original)
            for fd in files:
                os.close(fd)


def file_pin(path, *, expected=None, size=None, private=False):
    # A symlink is allowed only for the explicit Homebrew interpreter alias.
    path = path.resolve(strict=True) if path == PYTHON else path
    before = path.lstat()
    need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1, 'input_regular_single_link')
    if private:
        need(before.st_uid == os.geteuid() and stat.S_IMODE(before.st_mode) == 0o600,
             'private_input_custody')
    need(size is None or before.st_size == size, 'input_byte_count')
    h = hashlib.sha256()
    with open(path, 'rb', opener=lambda p, flags: os.open(p, flags | os.O_NOFOLLOW)) as stream:
        fields = ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns', 'st_mode', 'st_uid', 'st_nlink')
        identity = tuple(getattr(before, name) for name in fields)
        need(tuple(getattr(os.fstat(stream.fileno()), name) for name in fields) == identity, 'input_open_changed')
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            h.update(block)
        need(tuple(getattr(os.fstat(stream.fileno()), name) for name in fields) == identity, 'input_fd_changed')
    need(tuple(getattr(path.lstat(), name) for name in fields) == identity, 'input_name_changed')
    need(expected is None or h.hexdigest() == expected, 'input_sha256')
    return {'path': str(path), 'sha256': h.hexdigest(), 'bytes': before.st_size,
            'device': before.st_dev, 'inode': before.st_ino, 'uid': before.st_uid,
            'mode': stat.S_IMODE(before.st_mode), 'links': before.st_nlink}


def load_modules():
    global CUSTODY
    need(sys.flags.isolated == 1 and sys.flags.no_site == 1 and sys.dont_write_bytecode,
         'isolated_no_site_no_bytecode_interpreter_required')
    for name, (path, expected, size) in PINS.items():
        file_pin(path, expected=expected, size=size)
    need(Path(sys.executable).resolve(strict=True) == PYTHON.resolve(strict=True), 'actual_interpreter')
    sys.path.insert(0, str(SOURCE / 'qa/openbao-acceptance'))
    for name in ('kv2_native_fresh_directory_dr_live', 'kv2_dr_process_custody'):
        need(name not in sys.modules, 'foreign_preloaded_controller')
    dr = importlib.import_module('kv2_native_fresh_directory_dr_live')
    CUSTODY = importlib.import_module('kv2_dr_process_custody')
    need(dr.ROOT == SOURCE and dr.full.HTTP_SECONDS == 15 and dr.full.MIGRATION_SECONDS == 360,
         'unchanged_controller_and_original_budgets')
    return dr


def command(argv, deadline):
    end = deadline.prepare_end if deadline.phase == 'prepare' else deadline.work_end
    remaining = end - time.monotonic()
    need(remaining > 0 and not deadline.fired, 'prepare_original_deadline_expired')
    return subprocess.check_output(argv, stdin=subprocess.DEVNULL, stderr=subprocess.PIPE,
                                   timeout=min(15, remaining), cwd=SOURCE,
                                   env={'PATH': '/usr/bin:/bin:/usr/sbin:/sbin', 'LANG': 'C.UTF-8',
                                        'TZ': 'UTC', 'GIT_CONFIG_NOSYSTEM': '1',
                                        'GIT_CONFIG_GLOBAL': '/dev/null', 'GIT_OPTIONAL_LOCKS': '0'})


def preparation(dr, receipt_sha, deadline, *, out_identity=None):
    need(sys.platform == 'darwin' and os.geteuid() == 501, 'fixed_native_mac_owner')
    root = dr.private_parent(ROOT)
    need(SOURCE.resolve(strict=True) == SOURCE, 'source_path_links')
    if out_identity is None:
        need(not os.path.lexists(OUT), 'new_wrapper_output_required')
    else:
        need(dr.private_parent(OUT) == out_identity, 'wrapper_output_changed')
    for path in (WORK, BACKUP, KEYS):
        need(not os.path.lexists(path), 'fresh_output_paths_required')
    need(dr.disjoint([WORK, OUT, BACKUP, KEYS]), 'disjoint_fresh_paths')
    need(BACKUP.parent.resolve(strict=True) == BACKUP.parent
         and BACKUP.parent.stat().st_uid == os.geteuid()
         and stat.S_IMODE(BACKUP.parent.stat().st_mode) & 0o022 == 0, 'internal_backup_parent')
    need(BACKUP.parent.stat().st_dev != root['device'], 'different_backup_filesystem')
    inputs = {name: file_pin(path, expected=expected, size=size)
              for name, (path, expected, size) in PINS.items()}
    inputs['wrapper'] = file_pin(Path(__file__).resolve())
    files = {'server': BUILD / 'artifacts/heptabao-server', 'seed': BUILD / 'artifacts/heptabao-seed',
             'receipt': BUILD / 'result.public.json', 'selection': BUILD / 'test-selection.public.json',
             'build_log': BUILD / '13-normal-release-build.stdout'}
    inputs.update({name: file_pin(path, private=name in ('receipt', 'selection')) for name, path in files.items()})
    need(inputs['receipt']['sha256'] == receipt_sha and inputs['selection']['sha256'] == SELECTION_SHA,
         'independent_build_and_selection_pins')
    receipt = dr.full.decode(dr.full.private_read(files['receipt'], 8 * 1024 * 1024))
    selection = dr.full.decode(dr.full.private_read(files['selection'], 8 * 1024 * 1024))
    build = dr.validate_build_receipt(receipt, PRODUCT_COMMIT, inputs['server'], inputs['seed'], selection, SELECTION_SHA)
    need(build['source_tree'] == PRODUCT_TREE, 'fixed_product_tree')
    with CUSTODY.activated() as owner:
        def git(*args):
            return command(['/usr/bin/git', '-c', 'core.hooksPath=/dev/null', *args], deadline).decode().strip()
        source = {'commit': git('rev-parse', 'HEAD'), 'tree': git('rev-parse', 'HEAD^{tree}'),
                  'dirty': bool(git('status', '--porcelain', '--untracked-files=all'))}
        need(source == {'commit': QA_COMMIT, 'tree': QA_TREE, 'dirty': False}, 'exact_clean_qa_source')
        need(git('rev-parse', PRODUCT_COMMIT + '^{tree}') == PRODUCT_TREE, 'build_commit_tree')
        need(not git('diff', '--name-only', PRODUCT_COMMIT, 'HEAD', '--', '.', ':!qa', ':!docs'),
             'product_diff_from_bound_build')
        volumes = []
        for mount, uuid, internal in VOLUMES:
            value = plistlib.loads(command(['/usr/sbin/diskutil', 'info', '-plist', mount], deadline))
            need(value.get('MountPoint') == mount and value.get('VolumeUUID') == uuid
                 and value.get('FilesystemType') == 'apfs' and value.get('Internal') is internal
                 and isinstance(value.get('DeviceIdentifier'), str), 'fixed_volume_identity')
            volumes.append({key: value[key] for key in ('MountPoint', 'VolumeUUID', 'FilesystemType', 'Internal', 'DeviceIdentifier')})
        need(Path(VOLUMES[0][0]).stat().st_dev == root['device']
             and Path(VOLUMES[1][0]).stat().st_dev == BACKUP.parent.stat().st_dev, 'mount_to_actual_parent_devices')
        owner.assert_retired()
    custody = owner.receipt()
    need(custody.get('passed_process_custody') is True and custody.get('finished') is True,
         'prepare_originals_retired')
    need(deadline.eligible() and time.monotonic() < deadline.prepare_end, 'prepare_original_deadline_expired')
    binding = {'schema': 'heptabao.mac-dr25-fixed-inputs.v1', 'source': source, 'inputs': inputs,
               'build': build, 'root': root, 'backup_existing_parent': dr.directory_identity(BACKUP.parent),
               'volumes': volumes, 'paths': {key: str(path) for key, path in
                   (('work', WORK), ('out', OUT), ('backup_parent', BACKUP), ('key_parent', KEYS))},
               'http_seconds': 15, 'migration_seconds': 360, 'outer_seconds': OUTER_SECONDS,
               'same_process_entry': True, 'production_authority': False}
    return binding, custody


def driver_argv(receipt_sha):
    return ['--binary', str(BUILD / 'artifacts/heptabao-server'),
            '--seed-binary', str(BUILD / 'artifacts/heptabao-seed'),
            '--build-source-commit', PRODUCT_COMMIT,
            '--build-log', str(BUILD / '13-normal-release-build.stdout'),
            '--build-receipt', str(BUILD / 'result.public.json'), '--build-receipt-sha256', receipt_sha,
            '--private-work-root', str(WORK), '--backup-parent', str(BACKUP), '--key-parent', str(KEYS)]


def qualify_summary(dr, summary, code):
    need(code == 0 and summary.get('status') == 'passed' and summary.get('failure') is None,
         'actual_dr_controller_failed')
    need(dr.complete(summary.get('checks', [])) and summary.get('baseline', {}).get('qualified') is True
         and summary.get('fresh_directory_same_seal_v6_recovery_verified') is True,
         'actual_full31_and_dr25_required')
    original = WORK / 'quarantine/original-closure/summary.json'
    need(summary['baseline'].get('summary') == str(original), 'quarantined_original_summary_required')
    pin = dr.file_pin(original, private=True)
    need(pin['sha256'] == summary['baseline'].get('sha256'), 'bound_original_full34_summary')
    baseline = dr.full.decode(dr.full.private_read(original, 32 * 1024 * 1024))
    need(dr.full34_complete(baseline), 'independently_rechecked_original_full31')
    custody = summary.get('process_custody', {})
    need(custody.get('passed_process_custody') is True and custody.get('finished') is True
         and custody.get('failed') is False and getattr(CUSTODY, '_ACTIVE', None) is None,
         'all_originals_retired_before_wrapper_completion')
    return {'baseline_31_passed': True, 'dr25_passed': True,
            'fresh_directory_same_seal_v6_recovery_verified': True,
            'all_originals_retired': True, 'summary': str(WORK / 'dr25-summary.json')}


def main(argv=None):
    # Starts immediately after importing the monotonic clock, before all other
    # wrapper/controller imports, argument parsing, hashing or preparation.
    started = ENTRY_MONOTONIC
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument('--prepare-only', action='store_true')
    action.add_argument('--run', metavar='PREPARED_SHA256')
    parser.add_argument('--build-receipt-sha256', required=True)
    args = parser.parse_args(argv)
    need(re.fullmatch('[0-9a-f]{64}', args.build_receipt_sha256) is not None, 'receipt_pin_required')
    need(args.run is None or re.fullmatch('[0-9a-f]{64}', args.run) is not None, 'prepared_pin_required')
    os.umask(0o077)
    report = {'schema': 'heptabao.mac-full34-dr25-fixed-execution.v1', 'status': 'failed',
              'production_authority': False, 'formal_kv2_migration_qualified': False,
              'physical_ha_qualified': False, 'authbus_qualified': False, 'full_replacement_qualified': False,
              'http_seconds': 15, 'migration_seconds': 360, 'runtime_outer_seconds': OUTER_SECONDS,
              'automatic_retry': False, 'summary_content_or_private_output_fingerprints_published': False}
    out_identity = None
    timer = Deadline(started)
    try:
        with timer:
            dr = load_modules()
            if args.run:
                dr.private_parent(ROOT)
                need(not os.path.lexists(OUT), 'new_wrapper_output_required')
                OUT.mkdir(mode=0o700)
                out_identity = dr.private_parent(OUT)
                private_new(OUT / 'controller.original.py', Path(__file__).read_bytes())
            binding, prep_custody = preparation(dr, args.build_receipt_sha256, timer, out_identity=out_identity)
            prepared_sha = sha(encode(binding))
            if args.prepare_only:
                need(timer.eligible(), 'prepare_original_deadline_expired')
                report.update(status='prepared', prepared=binding, prepared_sha256=prepared_sha,
                              preparation_process_custody=prep_custody, product_started=False)
            else:
                need(prepared_sha == args.run, 'actual_readonly_preparation_changed')
                timer.enter_work()
                private_new(OUT / 'prepared.public.json', encode({'binding': binding, 'prepared_sha256': prepared_sha,
                                                               'process_custody': prep_custody}))
                BACKUP.mkdir(mode=0o700); KEYS.mkdir(mode=0o700)
                backup, keys = dr.private_parent(BACKUP), dr.private_parent(KEYS)
                need(backup['device'] != dr.directory_identity(ROOT)['device']
                     and dr.disjoint([BACKUP, KEYS]), 'fresh_directory_device_and_key_boundary')
                (OUT / 'tmp').mkdir(mode=0o700)
                environment = {'PATH': '/usr/bin:/bin:/usr/sbin:/sbin', 'LANG': 'C.UTF-8', 'TZ': 'UTC',
                    'TMPDIR': str(OUT / 'tmp'), 'HB_ORACLE_BINARY': str(ORACLE / 'bao'),
                    'HB_ORACLE_ARCHIVE': str(ORACLE / 'oracle-official.tar.gz'),
                    'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': '/dev/null',
                    'GIT_OPTIONAL_LOCKS': '0'}
                os.environ.clear(); os.environ.update(environment)
                private_new(OUT / 'intent.public.json', encode({'argv': driver_argv(args.build_receipt_sha256),
                    'prepared_sha256': prepared_sha, 'backup_parent': backup, 'key_parent': keys,
                    'same_process_entry': True, 'original_outer_seconds': OUTER_SECONDS,
                    'work_deadline_from_entry_seconds': WORK_SECONDS, 'production_authority': False}))
                with private_stdio(OUT):
                    code = dr.main(driver_argv(args.build_receipt_sha256))
                report['controller_exit_code'] = code
                summary = dr.full.decode(dr.full.private_read(WORK / 'dr25-summary.json', 32 * 1024 * 1024))
                checks = summary.get('checks', [])
                report.update(summary=str(WORK / 'dr25-summary.json'),
                              observed_dr25_check_count=len(checks),
                              observed_dr25_pass_count=sum(row.get('passed') is True for row in checks),
                              missing_required_dr25=[name for name in dr.CHECKS
                                  if not any(row.get('case') == name and row.get('passed') is True for row in checks)])
                report.update(qualify_summary(dr, summary, code))
                need(timer.eligible(), 'job_absolute_deadline_failed')
                report['status'] = 'passed'
            # The alarm stays armed through terminal-summary binding and custody checks.
            need(timer.eligible(), 'job_absolute_deadline_failed')
            report['control_work_elapsed_seconds'] = time.monotonic() - started
    except BaseException as error:
        report['status'] = 'failed'
        report['failure'] = (str(error) if isinstance(error, Failure)
                             and re.fullmatch('[a-z0-9_]{1,120}', str(error)) else type(error).__name__)
    finally:
        report.update(deadline=timer.observation(), elapsed_seconds=time.monotonic() - started,
                      signal_and_timer_restored=timer.restored,
                      elapsed_observation_before_receipt_publication=True,
                      durable_completion_authority='separate_runtime_terminal_with_original_1800_second_cap')
        limit = PREPARE_SECONDS if args.prepare_only else WORK_SECONDS
        if timer.fired or time.monotonic() - started >= limit:
            report.update(status='failed', failure='job_absolute_deadline_failed')
        if out_identity is not None:
            private_new(OUT / 'result.public.json', encode(report))
    print(json.dumps(report if args.prepare_only else {key: report.get(key) for key in
        ('status', 'failure', 'controller_exit_code', 'baseline_31_passed', 'dr25_passed', 'elapsed_seconds')}), flush=True)
    return 0 if report['status'] in ('prepared', 'passed') else 1


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except BaseException as error:
        if isinstance(error, SystemExit):
            raise
        print(json.dumps({'status': 'failed', 'failure': type(error).__name__, 'production_authority': False}), flush=True)
        raise SystemExit(1) from None
