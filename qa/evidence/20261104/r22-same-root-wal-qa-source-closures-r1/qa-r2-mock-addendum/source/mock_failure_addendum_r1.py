#!/usr/bin/env python3
"""Separate injected-failure addendum. Frozen builder/reference/mock18 unchanged.

Only AST-selected target definitions and in-memory OS/Popen doubles execute.
No target main, host API, real child, network, service, or Cargo is invoked.
"""
from __future__ import annotations
import ast
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import types


HERE = Path(__file__).parent
spec = importlib.util.spec_from_file_location('frozen_mock18_definitions', HERE / 'mock_components.py')
base = importlib.util.module_from_spec(spec)
spec.loader.exec_module(base)
BaseModel = base.Model
INSTANCES = []


class FailureModel(BaseModel):
    def __init__(self, config):
        super().__init__(config)
        self.closed = []
        self.stream_opened = []
        INSTANCES.append(self)

    def popen(self, argv, **options):
        child = super().popen(argv, **options)
        original_wait = child.wait

        def wait(timeout):
            if self.config.get('wait_exception'):
                if self.last_terminal is None or timeout <= 0:
                    raise AssertionError('wait must follow a real modeled WNOWAIT event')
                self.wait_count += 1
                if self.config['wait_exception'] == 'timeout':
                    raise subprocess.TimeoutExpired(argv, timeout)
                raise OSError('synthetic wait exception')
            return original_wait(timeout)
        child.wait = wait
        return child

    def stop(self, child, captured=None):
        if self.config.get('stop_exception'):
            self.stop_count += 1
            raise OSError('synthetic cleanup exception')
        return super().stop(child, captured)

    def open(self, path, flags, mode):
        if str(path).endswith(('.stdout', '.stderr')):
            if flags != os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW:
                raise AssertionError('stream creation flags changed')
            if str(path).endswith('.stderr') and self.config.get('stderr_open_exception'):
                raise OSError('synthetic second stream open exception')
            fd = self.next_fd
            self.next_fd += 1
            self.fd_values[fd] = b''
            self.stream_opened.append((fd, str(path)))
            return fd
        return super().open(path, flags, mode)

    def close(self, fd):
        super().close(fd)
        self.closed.append(fd)


def setup_owner(builder_code, reference_code, config):
    model = FailureModel(config)

    class Refused(RuntimeError):
        pass

    class Base:
        def interrupted(self, signum, frame):
            if self.creating_child:
                if self.pending_signal is None:
                    self.pending_signal = signum
                return
            raise Refused('owner_signal_' + str(signum))

    def unexpected(*args, **kwargs):
        raise AssertionError('unexpected post-failure log/group operation')

    cli = types.SimpleNamespace(Owner=Base, Refused=Refused, stop_owned=model.stop,
                                stop_provisional=model.stop, group_members=unexpected)
    fake_os = types.SimpleNamespace(open=model.open, read=model.read, close=model.close,
        getpid=lambda: 7, getuid=lambda: 1000, fsencode=os.fsencode, waitid=model.waitid,
        P_PID=os.P_PID, WEXITED=os.WEXITED, WNOHANG=os.WNOHANG, WNOWAIT=os.WNOWAIT,
        CLD_EXITED=os.CLD_EXITED, CLD_KILLED=os.CLD_KILLED, CLD_DUMPED=os.CLD_DUMPED,
        O_RDONLY=os.O_RDONLY, O_NOFOLLOW=os.O_NOFOLLOW, O_WRONLY=os.O_WRONLY,
        O_CREAT=os.O_CREAT, O_EXCL=os.O_EXCL, fsync=unexpected)
    fake_signal = types.SimpleNamespace(SIGCHLD=signal.SIGCHLD, SIG_DFL=signal.SIG_DFL,
        NSIG=signal.NSIG, getsignal=lambda signum: signal.SIG_DFL)
    fake_subprocess = types.SimpleNamespace(Popen=model.popen, DEVNULL=subprocess.DEVNULL,
                                           TimeoutExpired=subprocess.TimeoutExpired)
    ns = {'__name__': 'selected_failure_addendum', 'Path': Path, 'hashlib': hashlib,
          'os': fake_os, 'signal': fake_signal, 'subprocess': fake_subprocess,
          'time': types.SimpleNamespace(monotonic_ns=lambda: model.now, sleep=model.sleep),
          'ROOT': Path('/qa-mock-root'), 'TOOL_ROOT': Path('/qa-mock-tools'),
          'OPEN_FDS': set(), 'FD_CLOSE_FAILED': False}
    exec(builder_code, ns)
    ns['require'] = ns['need']
    exec(reference_code, ns)
    owner = ns['qa_command_owner_class'](types.SimpleNamespace(owner_class=ns['owner_class']), cli)(ns['ROOT'])
    model.owner = owner
    ns.update(owner=owner, cli=cli)
    return model, owner, ns


def actual_command_case(name, config, builder, builder_code, reference_code):
    model, owner, ns = setup_owner(builder_code, reference_code, config)
    calls = []
    command_node = [n for n in ast.walk(ast.parse(builder)) if isinstance(n, ast.FunctionDef) and n.name == 'command']
    if len(command_node) != 1:
        raise AssertionError('exact one actual nested command')
    ns.update(project=ns['ROOT'] / 'project', until=model.now + 5_000_000,
              environment={}, result={'command_intents': [], 'commands': []}, MAX_LOG=8192,
              write_json=lambda path, value: calls.append((str(path), value)))
    unit = ast.Module(body=[command_node[0]], type_ignores=[])
    exec(compile(ast.fix_missing_locations(unit), 'exact_nested_builder_command.py', 'exec'), ns)
    error = None
    try:
        ns['command']('injected-failure', ['/usr/bin/git', '--version'], 15)
    except BaseException as caught:
        error = type(caught).__name__
    if error != 'OSError':
        raise AssertionError(name + ': actual injected failure did not propagate')
    if len(ns['result']['command_intents']) != 1 or ns['result']['commands'] or len(calls) != 1:
        raise AssertionError(name + ': incomplete intent falsely produced completed record')
    expected_streams = 1 if config.get('stderr_open_exception') else 2
    if len(model.stream_opened) != expected_streams or model.fd_values or ns['OPEN_FDS'] or ns['FD_CLOSE_FAILED']:
        raise AssertionError(name + ': opened stream/proc descriptors not all closed')
    stream_fds = [fd for fd, _ in model.stream_opened]
    if [fd for fd in model.closed if fd in stream_fds] != list(reversed(stream_fds)):
        raise AssertionError(name + ': stream finally order/once changed')
    first = owner.cleanup()
    second = owner.cleanup()
    if model.stop_count != len(model.created):
        raise AssertionError(name + ': cleanup granted a repeated budget')
    if config.get('stop_exception'):
        if not second or any(row.get('owned_stopped') or row.get('stop_terminal_captured') or row.get('direct_child_reaped') for row in second):
            raise AssertionError(name + ': unknown cleanup became success')
        if not all(row.get('prior_cleanup_result_retained') for row in second):
            raise AssertionError(name + ': first unknown result not retained')
    return {'case': name, 'passed': True, 'actual_nested_command_ast_selected': True,
            'error_type': error, 'intents': 1, 'completed_command_records': 0,
            'modeled_popen_count': len(model.created), 'modeled_wait_count': model.wait_count,
            'cleanup_calls': model.stop_count, 'cleanup_collections': 2,
            'streams_closed_once': expected_streams, 'all_modeled_fds_closed': True,
            'cleanup_unknown': bool(second and not all(row.get('owned_stopped') for row in second))}


def main():
    builder = (HERE / 'builder_r2.py').read_text()
    reference = (HERE / 'owner_reference_original.py').read_text()
    old_mock = (HERE / 'mock_components.py').read_text()
    if hashlib.sha256(builder.encode()).hexdigest() != 'c961a54dfc35332be035bb16fc1ae697199e35da496b0c9ea52c35dc3f8455d8':
        raise AssertionError('frozen R2 identity')
    names = {'BindingError', 'open_fd', 'close_fd', 'need', 'remaining', 'sha', 'qa_command_owner_class'}
    builder_code = base.selected(builder, names, 'exact_builder_selected.py')
    reference_code = base.selected(reference, {'owner_class'}, 'exact_owner_selected.py')
    base.Model = FailureModel
    rows = []
    for name, config, expected in (
        ('popen_wait_raises_not_terminal_success', {'wait_exception': 'oserror'}, 'OSError'),
        ('cleanup_raises_after_known_wait_remains_unknown', {'stop_exception': True}, None),
        ('wait_and_cleanup_raises_both_remain_unknown', {'wait_exception': 'oserror', 'stop_exception': True}, 'OSError'),
    ):
        row = base.run_case(name, config, builder_code, reference_code, expected_error=expected)
        model = INSTANCES[-1]
        if model.wait_count != 1 or model.stop_count != 1:
            raise AssertionError(name + ': wait or cleanup repeated')
        if config.get('stop_exception'):
            retained = model.owner.cleanup_records[0]
            if retained.get('owned_stopped') or retained.get('stop_terminal_captured') or not retained.get('prior_cleanup_result_retained') or retained.get('error_type') != 'OSError':
                raise AssertionError(name + ': unknown cleanup erased')
            row['cleanup_unknown_preserved'] = True
        rows.append(row)
    # Change only the old harness's injected stdout fd, never target source.
    node = next(n for n in ast.parse(old_mock).body if isinstance(n, ast.FunctionDef) and n.name == 'run_case')
    changed = 0
    for call in ast.walk(node):
        if isinstance(call, ast.Call) and isinstance(call.func, ast.Attribute) and call.func.attr == 'start_child':
            for kw in call.keywords:
                if kw.arg == 'stdout':
                    kw.value = ast.Constant(999)
                    changed += 1
    if changed != 1:
        raise AssertionError('one harness stdout injection')
    namespace = dict(vars(base))
    exec(compile(ast.fix_missing_locations(ast.Module(body=[node], type_ignores=[])), 'one_fd_harness_injection.py', 'exec'), namespace)
    row = namespace['run_case']('unregistered_stdout_refused_before_popen', {}, builder_code, reference_code, expected_error='BindingError')
    if row['popen_count'] != 0:
        raise AssertionError('unregistered output descriptor dispatched')
    rows.append(row)
    for name, config in (
        ('actual_command_wait_error_closes_two_streams', {'wait_exception': 'oserror'}),
        ('actual_command_second_open_error_closes_first', {'stderr_open_exception': True}),
        ('actual_command_timeout_and_stop_error_no_new_cleanup_budget', {'wait_exception': 'timeout', 'stop_exception': True}),
    ):
        rows.append(actual_command_case(name, config, builder, builder_code, reference_code))
    print(json.dumps({'schema': 'heptabao.qa-custody-r2-mock-failure-addendum.v1',
        'builder_sha256': hashlib.sha256(builder.encode()).hexdigest(),
        'owner_reference_sha256': hashlib.sha256(reference.encode()).hexdigest(),
        'original_mock18_source_sha256': hashlib.sha256(old_mock.encode()).hexdigest(),
        'passed': len(rows), 'results': rows, 'actual_children': 0, 'network_requests': 0,
        'target_main_executed': False, 'frozen_source_changed': False,
        'limits': ['Independent seven-case addendum; original mock18 is unchanged.',
                   'In-memory failure injection does not prove every real kernel failure mode.',
                   'Successful real Linux custody scope is a separate three-case receipt.',
                   'No Cargo, TLS, product or production qualification.']}, indent=2, sort_keys=True))


if __name__ == '__main__':
    main()
