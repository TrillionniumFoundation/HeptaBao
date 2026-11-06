#!/usr/bin/env python3
"""Repair only the stopped candidate's initial Python role binding.

52 seconds of work from this entry, 60 seconds native cap. No bootstrap,
init, secret content read, restart, permission change or old-asset cleanup.
The private dispatch envelope contains original native metadata, not keys.
"""
from __future__ import annotations
import time
ENTRY = time.monotonic()
import hashlib
import importlib
import json
import os
from pathlib import Path
import signal
import stat
import sys
import types

ROOT = Path('/Volumes/T5/hepta-vnext-recovery-20261013/continuation-20261106-kv2-ha-convergence-r1')
INPUTS = ROOT / 'control/formal-kv2-manager-init-inputs-r1'
SERVICE = Path('/Volumes/T5/hepta-vnext-recovery-20261013/heptabao-production-20261104-r1/formal-kv2-current-20261106-r1')
AUTHORITY = Path('/Users/qianqi/heptabao-formal-kv2-current-20261106-r1/service-authority-current-20261106-r1')
OUTPUT = ROOT / 'control/formal-kv2-stopped-base-launcher-binding-repair-r1'
READONLY = ROOT / 'control/formal-kv2-failed-manager-readonly-r2'
VENV = ROOT / 'control/formal-kv2-python-env-50-0-2-r3/venv'
PRIVATE_INPUT = None  # Inject only the exact private native metadata envelope.
HELPER_SOURCE = None  # Inject the separately reviewed exact public helper.
HELPER_PIN = {'bytes': 7540, 'sha256': 'b21dba79cc64af09b429214204ec49238ccdacd9757bf058265f36ebe19784bd'}
SOURCE_PINS = {
    'launch_guard.py': {'bytes': 18573, 'sha256': '2884f17e6629e7f5bebcce067e100e8402c73bc3f709e13cd411a32bf52f88b3'},
    'manager_runtime.py': {'bytes': 25233, 'sha256': 'c5bacfd931d63561ee204fe7f4e0b886378c87ca9db2632327783c709eddf91f'},
    'kv2_dr_process_custody.py': {'bytes': 26131, 'sha256': '669e2cd1d9ee597529c08b88f3fc21c813d4ff7b57f3792381baa44fbdbe7008'},
    'owned_process.py': {'bytes': 28442, 'sha256': '0ee96c9f43b50ebd57ee8f0ef95f2431c441ec02c1799992588dbf50768745d0'},
}


def bootstrap_read(path, pin):
    if path.resolve(strict=True) != path:
        raise ValueError('source_symlink')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        info = os.fstat(fd)
        identity = lambda s: (s.st_dev, s.st_ino, s.st_uid, s.st_gid, s.st_mode,
                              s.st_nlink, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
        if not (stat.S_ISREG(info.st_mode) and info.st_uid == 501 and info.st_gid == 20
                and stat.S_IMODE(info.st_mode) == 0o600 and info.st_nlink == 1
                and 0 < info.st_size == pin['bytes'] <= 65536):
            raise ValueError('fixed_source_identity')
        raw = bytearray()
        while len(raw) <= pin['bytes']:
            block = os.read(fd, min(16384, pin['bytes'] + 1 - len(raw)))
            if not block:
                break
            raw.extend(block)
        if (len(raw) != pin['bytes'] or hashlib.sha256(raw).hexdigest() != pin['sha256']
                or identity(info) != identity(os.fstat(fd)) or identity(info) != identity(path.lstat())):
            raise ValueError('fixed_source_changed')
        return bytes(raw)
    finally:
        os.close(fd)


def fullpin(item):
    return {k: item[k] for k in ('path', 'bytes', 'sha256')} | {
        'identity': {k: item['identity'][k] for k in runtime.guard.FILE_KEYS}}


def original_terminal(value, job_id, returncode):
    need = runtime.need
    need(value['job_id'] == job_id and value['exit_code'] == returncode
         and value['state'] == ('succeeded' if returncode == 0 else 'failed')
         and value['timed_out'] is False and value['cancelled'] is False
         and all(value[k] is True for k in ('output_complete', 'output_durable', 'terminal_publication_confirmed'))
         and value['log_truncated'] == {'stdout': False, 'stderr': False}
         and value['log_errors'] == {'stdout': None, 'stderr': None}, 'original_complete_durable_terminal')


def original_retirement():
    need = runtime.need
    records = PRIVATE_INPUT['retirement_originals']
    need(set(records) == {'bootout', 'after_absence'}, 'two_original_retirement_records')
    for role, expected_argv, code, actual_job_id in (
        ('bootout', ['bootout', 'gui/501/org.heptabao.kv2'], 0, '1a1b28ed7a1-fc05-7e9f'),
        ('after_absence', ['print', 'gui/501/org.heptabao.kv2'], 113, '1a1b28fb493-fc05-7ea2'),
    ):
        row = records[role]
        start = runtime.parsed(row['start_original_text'])
        terminal = runtime.parsed(row['terminal_original_text'])
        job = start['job']
        need(start['launch']['ok'] is True and job['id'] == actual_job_id and job['host'] == 'mac'
             and job['executable'] == '/bin/launchctl' and job['args'] == expected_argv
             and job['env_keys'] == [] and job['launch_state'] == 'launched'
             and job['launch_error'] is None, 'original_exact_label_retirement_job')
        original_terminal(terminal, job['id'], code)
        streams = runtime.parsed(row['streams_original_text'])
        need(streams['job_id'] == actual_job_id, 'original_retirement_stream_job')
        out, err = bytes.fromhex(streams['stdout']['bytes_hex']), bytes.fromhex(streams['stderr']['bytes_hex'])
        for stream, raw in (('stdout', out), ('stderr', err)):
            observed = streams[stream]
            need(observed['offset'] == 0 and observed['next_offset'] == observed['size'] == len(raw)
                 and observed['eof'] is True and observed['text'] == raw.decode('utf-8', 'strict')
                 and terminal['log_bytes'][stream] == {'seen': len(raw), 'stored': len(raw)},
                 'complete_original_retirement_output')
        if role == 'bootout':
            need(out == err == b'', 'exact_bootout_zero_empty_streams')
        else:
            need(runtime.exact_absence(code, out, err, 'gui/501', 'org.heptabao.kv2'),
                 'actual_retired_label_original_absence')
    need(records['bootout']['terminal_original_text'] != records['after_absence']['terminal_original_text'],
         'distinct_original_bootout_and_absence_jobs')


def execute(io, owner, public, private):
    need = runtime.need
    need(sys.platform == 'darwin' and os.geteuid() == 501 and os.getegid() == 20
         and sys.version_info[:3] == (3, 14, 3) and sys.flags.isolated == 1
         and sys.dont_write_bytecode and Path(sys.executable) == VENV / 'bin/python3',
         'qualified_isolated_controller')
    need(PRIVATE_INPUT['schema'] == 'heptabao.stopped-candidate-python-binding-repair-input.private.v1', 'exact_input_schema')
    original_retirement()
    public['original_exact_label_bootout_and_absence_bound'] = True
    r2_terminal = runtime.parsed(PRIVATE_INPUT['readonly_terminal_original_text'])
    original_terminal(r2_terminal, '1a1b28aaaf3-fc05-7e83', 0)
    final_raw = PRIVATE_INPUT['readonly_final_stdout_original'].encode()
    need(len(final_raw) == 3176 and hashlib.sha256(final_raw).hexdigest()
         == '3ea06d9688ddb9f3f867c27f6f60679d0ee0782aa6de1e2349df275713ca74de',
         'original_readonly_r2_complete_final_stdout')
    final = runtime.parsed(final_raw)
    need(final['status'] == 'completed_readonly_observation' and final['all_owned_fds_closed'] is True
         and final['owned_file_handles_opened'] == final['owned_file_handles_closed'] == 35
         and final['primary_failure_code'] is None and final['cleanup_failure_codes'] == []
         and final['guard_python_path_matches_actual_base_launcher'] is False
         and final['unresolved_configuration_conflicts'] ==
             ['guard_python_binding_uses_controller_venv_instead_of_plist_base_launcher']
         and final['initialization_material_absent_count'] == 5, 'actual_readonly_configuration_conflict')
    io.hold(INPUTS)
    for name, pin in SOURCE_PINS.items():
        path = INPUTS / name
        io.read_file(dict(pin, path=str(path), identity=runtime.file_identity(path.lstat())), maximum=65536, materialize=False)
    result_path = READONLY / 'result.public.json'
    result = runtime.parsed(io.read_file({
        'path': str(result_path), 'bytes': 3002,
        'sha256': 'd32cf16fbd29ccf160fe5b796ef9be29dee2404491969d9e2f997b292fdcf516',
        'identity': runtime.file_identity(result_path.lstat())}, maximum=65536))
    closure_pin = fullpin(PRIVATE_INPUT['readonly_private_native_pin'])
    need(closure_pin['path'] == str(READONLY / 'manager-init.private.json')
         and closure_pin['identity'] == result['private_closure_identity'] == final['private_closure_identity'],
         'original_readonly_private_closure_full_identity')
    closure = runtime.parsed(io.read_file(closure_pin, maximum=131072))
    failed = runtime.parsed(io.read_file(fullpin(closure['original_failure_private_pin']), maximum=131072))
    prep = runtime.parsed(io.read_file(fullpin(closure['original_preparation_private_pin']), maximum=131072))
    need(failed['public_before_closeout']['initialization_attempted'] is False, 'original_candidate_never_initialized')
    for role, fixed in (('service', SERVICE), ('key', AUTHORITY)):
        io.hold(fixed, failed['roots'][role])
    for role, fixed in (('t5', '/Volumes/T5'), ('internal', '/System/Volumes/Data')):
        need(failed['volume_pins'][role]['path'] == fixed, 'two_original_volume_roots')
        io.hold(fixed, failed['volume_pins'][role], private=False)
    manager = io.hold(SERVICE / 'manager', prep['directories']['service_manager'])
    data = io.hold(SERVICE / 'data', prep['initial_empty_data_binding']['identity'])
    need(os.listdir(data['fd']) == [], 'original_data_empty_before_repair')
    missing = []
    for role, name in (('root', 'root.token'), ('bootstrap', 'recovery.nonce'),
                       ('share-1', 'unseal.share'), ('pending-share-2', 'unseal.share'),
                       ('pending-share-3', 'unseal.share')):
        row = io.hold(AUTHORITY / role, prep['directories']['authority_' + role])
        io.absent(row, name)
        missing.append((row, name))
    old_pin = fullpin(closure['current_launch_binding'])
    initial_pin = fullpin(closure['original_initial_binding'])
    old_raw = io.read_file(old_pin, maximum=131072)
    need(old_raw == io.read_file(initial_pin, maximum=131072), 'old_binding_retains_initial_archive')
    initial = runtime.parsed(old_raw)
    actual_base = fullpin(closure['actual_base_launcher'])
    need(actual_base == result['actual_base_launcher_public_pin'] == final['actual_base_launcher_public_pin'],
         'original_actual_base_launcher_full_pin')
    repair.replacement(initial, actual_base)
    for role in ('python', 'guard', 'server', 'config', 'ca_certificate', 'server_certificate'):
        io.read_file(fullpin(initial['files'][role]), maximum=128 * 1024 * 1024,
                     private=role != 'python', materialize=False)
    key = fullpin(initial['files']['server_private_key'])
    need(runtime.file_identity(Path(key['path']).lstat()) == key['identity'], 'original_tls_key_metadata_only')
    installed = fullpin(closure['original_installed_plist'])
    io.read_file(installed, maximum=65536, materialize=False)
    io.read_file(actual_base, maximum=1048576, private=False, materialize=False)
    need(Path('/opt/homebrew/bin/python3').resolve(strict=True) == Path(actual_base['path']), 'same_public_launcher_target')
    output = io.mkdir(io.hold(ROOT / 'control'), OUTPUT.name)
    private['_output'] = output
    leaf = io.read_file(fullpin(initial['files']['server_certificate']), maximum=65536)
    wire = runtime.ManagedWire(io, output, owner, initial['files']['ca_certificate']['path'], leaf,
                               SERVICE, Path(installed['path']))
    private['_wire'] = wire
    rc, out, err = wire.command('fresh_exact_label_absence_before_binding_repair',
                               ['/bin/launchctl', 'print', 'gui/501/org.heptabao.kv2'])
    need(runtime.exact_absence(rc, out, err, 'gui/501', 'org.heptabao.kv2'), 'fresh_stopped_candidate_absence')
    observation = {'domain': 'gui/501', 'label': 'org.heptabao.kv2',
                   'argv': ['/bin/launchctl', 'print', 'gui/501/org.heptabao.kv2'],
                   'returncode': rc, 'stdout_bytes': len(out), 'stderr': err.decode('utf-8', 'strict')}
    private['repair'] = {}
    repair.publish(io, manager, old_pin, initial_pin, actual_base, observation, private['repair'])
    for row, name in missing:
        io.absent(row, name)
    need(os.listdir(data['fd']) == [] and runtime.file_identity(Path(key['path']).lstat()) == key['identity'],
         'original_empty_data_and_key_after_binding_repair')
    io.recheck()
    public.update(status='binding_repaired_candidate_remains_stopped', binding_repair_confirmed=True,
                  only_files_python_changed=True, retained_initial_archive_unchanged=True,
                  original_guard_plist_config_data_unchanged=True, original_empty_data=True,
                  initialization_material_absent_count=5, actual_base_launcher_public_pin=actual_base,
                  original_controller_venv_runtime_still_bound=True)


def main():
    global runtime, repair
    for name, pin in SOURCE_PINS.items():
        bootstrap_read(INPUTS / name, pin)
    if (type(HELPER_SOURCE) is not str or len(HELPER_SOURCE.encode()) != HELPER_PIN['bytes']
            or hashlib.sha256(HELPER_SOURCE.encode()).hexdigest() != HELPER_PIN['sha256']):
        raise ValueError('exact_repair_helper_source')
    sys.path.insert(0, str(INPUTS))
    runtime = importlib.import_module('manager_runtime')
    custody = importlib.import_module('kv2_dr_process_custody')
    repair = types.ModuleType('fixed_manager_python_binding_repair')
    exec(compile(HELPER_SOURCE, '<fixed-manager-python-binding-repair>', 'exec'), repair.__dict__)
    clock = runtime.Clock(ENTRY, custody)
    clock.end, clock.total_end = ENTRY + 52, ENTRY + 60
    io = runtime.PrivateIO(clock)
    public = {'schema': 'heptabao.stopped-candidate-python-binding-repair.public.v1', 'status': 'failed',
              'work_seconds': 52, 'runtime_seconds': 60, 'deadline_renewed': False,
              'binding_repair_confirmed': False, 'primary_failure_code': None, 'cleanup_failure_codes': [],
              'http_requests_sent': 0, 'service_restart_performed': False, 'initialization_performed': False,
              'os_privacy_permission_changed': False, 'os_privacy_permission_hold_resolved': False,
              'formal_kv2_qualified': False, 'ha_qualified': False, 'authbus_qualified': False,
              'old_asset_cleanup_performed': False, 'original_failed_attempt_reclassified': False,
              'private_key_nonce_root_share_content_read': False, 'provider_or_j3160_called': False,
              'durable_completion_authority': 'public_record_plus_final_stdout_plus_separate_original_native_terminal'}
    private = {'schema': 'heptabao.stopped-candidate-python-binding-repair.private.v1'}
    try:
        with custody.activated() as owner:
            clock.start()
            try:
                execute(io, owner, public, private)
                clock.check()
            except BaseException as error:
                public['primary_failure_code'] = str(error) if isinstance(error, runtime.Refused) else 'binding_repair_operation_failed'
                if not public['primary_failure_code'].replace('_', '').isalnum():
                    public['primary_failure_code'] = 'binding_repair_operation_failed'
            finally:
                clock.cleaning = True
                with clock.critical():
                    owner.finish()
                    private['command_custody'] = owner.receipt()
                    public['command_custody'] = runtime.safe_custody(private['command_custody'])
                    if owner.failed:
                        public['cleanup_failure_codes'].append('original_command_custody_failed')
                    try:
                        io.recheck()
                    except BaseException:
                        public['cleanup_failure_codes'].append('original_identity_postflight_failed')
                    wire = private.pop('_wire', None)
                    if wire is not None:
                        private['commands'] = wire.commands
                        public['cleanup_failure_codes'].extend(wire.command_cleanup_errors)
                    public['publication_attempted'] = private.get('repair', {}).get('publication_attempted', False)
                    public['publication_outcome_unknown'] = private.get('repair', {}).get('publication_outcome_unknown', False)
                    if public['primary_failure_code'] or public['cleanup_failure_codes'] or clock.pending is not None:
                        public['status'] = 'failed'
                    output = private.pop('_output', None)
                    private['public_before_closeout'] = dict(public)
                    if output is not None:
                        try:
                            pin = io.put(output, 'manager-init.private.json', runtime.encoded(private),
                                         remember=False, closeout_evidence=True)
                            public['private_closure_identity'] = pin['identity']
                            public['private_closure_content_hash_published'] = False
                            io.put(output, 'result.public.json', runtime.encoded(public),
                                   remember=False, closeout_evidence=True)
                        except BaseException:
                            public['cleanup_failure_codes'].append('repair_evidence_publication_failed')
                    public['cleanup_failure_codes'].extend(io.close())
                    try:
                        clock.finish()
                    except BaseException:
                        public['cleanup_failure_codes'].append('signal_handler_retirement_failed')
    except BaseException:
        if public['primary_failure_code'] is None:
            public['primary_failure_code'] = 'repair_entry_or_custody_failed'
    finally:
        clock.cleaning = True
        with clock.critical():
            public['cleanup_failure_codes'].extend(io.close())
            try:
                clock.finish()
            except BaseException:
                public['cleanup_failure_codes'].append('signal_handler_retirement_failed')
    public['owned_file_handles_opened'] = io.open_count
    public['owned_file_handles_closed'] = io.close_count
    public['remaining_original_fds'] = len(io.handles)
    public['interrupted_signal'] = clock.pending
    public['elapsed_seconds'] = time.monotonic() - ENTRY
    if (public['primary_failure_code'] or public['cleanup_failure_codes'] or clock.pending is not None
            or io.open_count != io.close_count or io.handles or public['elapsed_seconds'] >= 52):
        public['status'] = 'failed'
    print(runtime.encoded(public).decode(), end='', flush=True)
    return 0 if public['status'] == 'binding_repaired_candidate_remains_stopped' else 1


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except SystemExit:
        raise
    except BaseException:
        print('{"schema":"heptabao.stopped-binding-repair-bootstrap-failure.v1","status":"failed"}', flush=True)
        raise SystemExit(1)
