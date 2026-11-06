import time
ENTRY_MONOTONIC = time.monotonic()
import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import signal
import stat
import subprocess
import sys

ROOT = Path('/Volumes/T5/hepta-vnext-recovery-20261013/continuation-20261106-kv2-ha-convergence-r1')
STAGE = ROOT / 'control/ci42229582001-test-publication-format-r1'
RUSTFMT = Path('/Users/qianqi/.rustup/toolchains/1.98.0-aarch64-apple-darwin/bin/rustfmt')
RUSTFMT_SHA256 = 'ca9cbe15a4add6baf62d8ce177015c9c48f209ebcf4364416b1953142e8701f8'
RUSTFMT_BYTES = 4453976
PYTHON_SHA256 = 'cebfcc4ac431ff7a2179bc6eff7e5c6bdae48b564eeab2d504bef6173a2cfc13'
WORK_SECONDS = 52
RUNTIME_SECONDS = 60
INPUTS = json.loads('__INPUTS_JSON__')
FORMAT_NAMES = (
    'ha_native_v6_publication.rs',
    'service_native_v6_ha_writer.rs',
    'service_native_v6_ha_published_plan_tests.rs',
)
SUPPORT_NAME = 'ha_native_v6_checkpoint_reselection_probe.rs'
DEADLINE_FIRED = False
OWNER = None


class Refused(Exception):
    pass


class DeadlineExpired(BaseException):
    pass


def need(value, code):
    if not value:
        raise Refused(code)


def deadline(_signum, frame):
    global DEADLINE_FIRED
    DEADLINE_FIRED = True
    if OWNER is not None:
        OWNER._interrupt(signal.SIGALRM, frame)
    else:
        raise DeadlineExpired()


def directory(path):
    info = path.lstat()
    need(stat.S_ISDIR(info.st_mode) and not path.is_symlink(), 'directory_shape')
    need(info.st_uid == os.geteuid() and stat.S_IMODE(info.st_mode) == 0o700,
         'directory_custody')
    return {'dev': info.st_dev, 'inode': info.st_ino, 'uid': info.st_uid,
            'mode': stat.S_IMODE(info.st_mode)}


def file_pin(path):
    before = path.lstat()
    need(stat.S_ISREG(before.st_mode) and not path.is_symlink(), 'regular_file_required')
    need(before.st_uid == os.geteuid() and before.st_nlink == 1, 'file_custody')
    need(stat.S_IMODE(before.st_mode) & 0o022 == 0, 'file_writable_by_others')
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        opened = os.fstat(stream.fileno())
        need((opened.st_dev, opened.st_ino) == (before.st_dev, before.st_ino), 'open_identity')
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(block)
    after = path.lstat()
    fields = ('st_dev', 'st_ino', 'st_uid', 'st_mode', 'st_size', 'st_mtime_ns', 'st_ctime_ns', 'st_nlink')
    need(all(getattr(before, key) == getattr(after, key) for key in fields), 'file_changed_while_read')
    return {'bytes': after.st_size, 'sha256': digest.hexdigest(), 'dev': after.st_dev,
            'inode': after.st_ino, 'uid': after.st_uid, 'mode': stat.S_IMODE(after.st_mode),
            'mtime_ns': after.st_mtime_ns, 'ctime_ns': after.st_ctime_ns, 'links': after.st_nlink}


def create_bytes(path, data):
    with path.open('xb') as stream:
        os.chmod(path, 0o600)
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())


def step(label, argv, seconds, report):
    need(not DEADLINE_FIRED and time.monotonic() - ENTRY_MONOTONIC < WORK_SECONDS,
         'original_work_deadline')
    started = time.monotonic()
    row = {'label': label, 'argv': argv, 'timeout_seconds': seconds}
    report['steps'].append(row)
    stdout_path = STAGE / (label + '.stdout')
    stderr_path = STAGE / (label + '.stderr')
    with stdout_path.open('xb') as stdout, stderr_path.open('xb') as stderr:
        os.chmod(stdout_path, 0o600)
        os.chmod(stderr_path, 0o600)
        process = subprocess.Popen(argv, cwd=STAGE / 'output', stdin=subprocess.DEVNULL,
                                   stdout=stdout, stderr=stderr,
                                   env={'PATH': '/usr/bin:/bin', 'LANG': 'C', 'LC_ALL': 'C'})
        try:
            code = process.wait(timeout=min(seconds, max(0.001, WORK_SECONDS - (time.monotonic() - ENTRY_MONOTONIC))))
            row['returncode'] = code
        finally:
            row['elapsed_seconds'] = time.monotonic() - started
            stdout.flush()
            stderr.flush()
            os.fsync(stdout.fileno())
            os.fsync(stderr.fileno())
    row['stdout'] = file_pin(stdout_path)
    row['stderr'] = file_pin(stderr_path)
    need(row.get('returncode') == 0, 'child_nonzero')


def main():
    global OWNER
    report = {'schema': 'heptabao.ci-publication-test-rustfmt.v1', 'status': 'failed',
              'source_base_commit': '4bde9aee03fcd27c59e13607e529b1cee594b249',
              'source_base_tree': 'f08493a23f8ea0637073651231865ea9607b790e',
              'edition': '2024', 'runtime_seconds': RUNTIME_SECONDS,
              'work_seconds': WORK_SECONDS, 'steps': [], 'product_run': False,
              'build_run': False, 'existing_source_written': False,
              'retry_or_time_extension': False, 'semantic_failure_fixed': False,
              'old_ci_failure_retained': True}
    created = False
    timer_owned = False
    old_alarm = None
    phase = 'timer_admission'
    try:
        need(sys.platform == 'darwin' and sys.version_info[:3] == (3, 14, 3), 'python_platform')
        need(signal.getitimer(signal.ITIMER_REAL) == (0.0, 0.0), 'existing_alarm_timer')
        old_alarm = signal.getsignal(signal.SIGALRM)
        need(old_alarm == signal.SIG_DFL, 'existing_alarm_handler')
        signal.signal(signal.SIGALRM, deadline)
        timer_owned = True
        signal.setitimer(signal.ITIMER_REAL, max(0.001, WORK_SECONDS - (time.monotonic() - ENTRY_MONOTONIC)))
        phase = 'fresh_control_directory'
        need(ROOT.resolve(strict=True) == ROOT, 'root_alias')
        root_before = directory(ROOT)
        parent_before = directory(ROOT / 'control')
        report['root_before'] = root_before
        report['control_parent_before'] = parent_before
        need(not os.path.lexists(STAGE), 'stage_must_be_fresh')
        STAGE.mkdir(mode=0o700)
        created = True
        os.chmod(STAGE, 0o700)
        report['stage_identity'] = directory(STAGE)
        for leaf in ('input', 'output', 'helpers'):
            (STAGE / leaf).mkdir(mode=0o700)
            os.chmod(STAGE / leaf, 0o700)
        phase = 'fixed_input_materialization'
        input_pins = {}
        for name, record in INPUTS.items():
            data = base64.b64decode(record['base64'], validate=True)
            need(len(data) == record['bytes'] and hashlib.sha256(data).hexdigest() == record['sha256'],
                 'fixed_input_bytes')
            target = STAGE / ('helpers' if name.endswith('.py') else 'input') / name
            create_bytes(target, data)
            input_pins[name] = file_pin(target)
            if name.endswith('.rs'):
                create_bytes(STAGE / 'output' / name, data)
        report['input_pins'] = input_pins
        create_bytes(STAGE / 'rustfmt.toml', b'')
        config_pin = file_pin(STAGE / 'rustfmt.toml')
        phase = 'pinned_formatter'
        formatter_before = file_pin(RUSTFMT)
        need(formatter_before['bytes'] == RUSTFMT_BYTES and formatter_before['sha256'] == RUSTFMT_SHA256,
             'formatter_pin')
        report['formatter_before'] = formatter_before
        interpreter = Path(sys.executable).resolve(strict=True)
        interpreter_before = file_pin(interpreter)
        need(interpreter_before['sha256'] == PYTHON_SHA256, 'interpreter_pin')
        report['interpreter_before'] = interpreter_before
        phase = 'custody_import'
        sys.path.insert(0, str(STAGE / 'helpers'))
        spec = importlib.util.spec_from_file_location('ci422_formatter_custody', STAGE / 'helpers/kv2_dr_process_custody.py')
        need(spec is not None and spec.loader is not None, 'custody_spec')
        custody = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = custody
        spec.loader.exec_module(custody)
        with custody.activated() as owner:
            OWNER = owner
            try:
                phase = 'rustfmt_version'
                step('01-rustfmt-version', [str(RUSTFMT), '--version'], 5, report)
                arguments = [str(RUSTFMT), '--edition', '2024', '--config-path', str(STAGE / 'rustfmt.toml')]
                targets = [str(STAGE / 'output' / name) for name in FORMAT_NAMES]
                phase = 'rustfmt_files'
                step('02-rustfmt-format', arguments + targets, 15, report)
                phase = 'rustfmt_check'
                step('03-rustfmt-check', arguments + ['--check'] + targets, 15, report)
                report['output_pins'] = {name: file_pin(STAGE / 'output' / name)
                                         for name in (*FORMAT_NAMES, SUPPORT_NAME)}
                support_output = report['output_pins'][SUPPORT_NAME]
                need(support_output['bytes'] == INPUTS[SUPPORT_NAME]['bytes']
                     and support_output['sha256'] == INPUTS[SUPPORT_NAME]['sha256'],
                     'unmodified_external_module')
                phase = 'final_input_preservation'
                after_pins = {name: file_pin(STAGE / ('helpers' if name.endswith('.py') else 'input') / name)
                              for name in INPUTS}
                need(after_pins == input_pins, 'input_identity_or_bytes_changed')
                need(file_pin(RUSTFMT) == formatter_before, 'formatter_changed')
                need(file_pin(interpreter) == interpreter_before, 'interpreter_changed')
                need(file_pin(STAGE / 'rustfmt.toml') == config_pin, 'configuration_changed')
                need(directory(ROOT) == root_before, 'root_changed')
                need(directory(ROOT / 'control') == parent_before, 'control_parent_changed')
                need(directory(STAGE) == report['stage_identity'], 'stage_changed')
                report['inputs_and_tool_unchanged'] = True
                owner.assert_retired()
            finally:
                report['process_custody'] = owner.finish()
        need(report['process_custody'].get('passed_process_custody') is True, 'process_custody')
        need(not DEADLINE_FIRED and time.monotonic() - ENTRY_MONOTONIC < WORK_SECONDS,
             'original_work_deadline')
        report['status'] = 'passed'
    except BaseException as error:
        report['failure'] = {'phase': phase, 'exception_type': type(error).__name__}
        if type(error) is Refused:
            report['failure']['fixed_code'] = error.args[0]
    finally:
        if OWNER is not None:
            report['process_custody'] = OWNER.finish()
            if report['process_custody'].get('passed_process_custody') is not True:
                report['status'] = 'failed'
        if created:
            report['retained_step_streams'] = {}
            for row in report['steps']:
                for suffix in ('.stdout', '.stderr'):
                    leaf = row['label'] + suffix
                    path = STAGE / leaf
                    if os.path.lexists(path):
                        try:
                            report['retained_step_streams'][leaf] = file_pin(path)
                        except BaseException as error:
                            report['retained_step_streams'][leaf] = {'pin_error_type': type(error).__name__}
                            report['status'] = 'failed'
        report['deadline_fired'] = DEADLINE_FIRED
        report['work_elapsed_seconds'] = time.monotonic() - ENTRY_MONOTONIC
        if DEADLINE_FIRED or report['work_elapsed_seconds'] >= WORK_SECONDS:
            report['status'] = 'failed'
        if timer_owned:
            signal.setitimer(signal.ITIMER_REAL, 0)
            signal.signal(signal.SIGALRM, old_alarm)
        if OWNER is not None:
            report['process_custody'] = OWNER.receipt()
            if report['process_custody'].get('passed_process_custody') is not True:
                report['status'] = 'failed'
        report['receipt_reserve_seconds'] = RUNTIME_SECONDS - WORK_SECONDS
        report['runtime_terminal_remains_authoritative'] = True
        if created:
            create_bytes(STAGE / 'result.public.json',
                         (json.dumps(report, indent=2, sort_keys=True) + '\n').encode())
        print(json.dumps({'status': report['status'], 'stage': str(STAGE),
                          'deadline_fired': DEADLINE_FIRED, 'product_run': False,
                          'build_run': False, 'failure': report.get('failure')}, sort_keys=True))
    return 0 if report['status'] == 'passed' else 1


if __name__ == '__main__':
    raise SystemExit(main())
