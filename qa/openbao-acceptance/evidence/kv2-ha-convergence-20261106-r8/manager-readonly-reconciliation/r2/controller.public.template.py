#!/usr/bin/env python3
"""One read-only observation of the first failed, never-initialized candidate.

Only a new evidence directory is created. No manager utility, child, HTTP
mutation, private-key read, initialization or restart is performed. The
private native pin is injected only into the private dispatch envelope.
"""
from __future__ import annotations
import time
ENTRY = time.monotonic()
import hashlib
import importlib
import json
import os
from pathlib import Path
import plistlib
import signal
import stat
import sys

ROOT = Path('/Volumes/T5/hepta-vnext-recovery-20261013/continuation-20261106-kv2-ha-convergence-r1')
INPUTS = ROOT / 'control/formal-kv2-manager-init-inputs-r1'
OUTPUT = ROOT / 'control/formal-kv2-failed-manager-readonly-r2'
SERVICE = Path('/Volumes/T5/hepta-vnext-recovery-20261013/heptabao-production-20261104-r1/formal-kv2-current-20261106-r1')
AUTHORITY = Path('/Users/qianqi/heptabao-formal-kv2-current-20261106-r1/service-authority-current-20261106-r1')
VENV = ROOT / 'control/formal-kv2-python-env-50-0-2-r3/venv'
FAILED_JOB = '1a1b27bfa3f-fc05-7e3a'
FAILURE_PIN = None  # Private native identity/content binding, never public.
FAILED_PUBLIC = {'bytes': 5687, 'sha256': '15f2676d4aae1d9db9c88fe19f2adc57be6fa871f82c602e9df6328c31ec6fad'}
SOURCE_PINS = {
    'launch_guard.py': {'bytes': 18573, 'sha256': '2884f17e6629e7f5bebcce067e100e8402c73bc3f709e13cd411a32bf52f88b3'},
    'manager_runtime.py': {'bytes': 25233, 'sha256': 'c5bacfd931d63561ee204fe7f4e0b886378c87ca9db2632327783c709eddf91f'},
}


def bootstrap_read(path, pin):
    if path.resolve(strict=True) != path:
        raise ValueError('source_symlink')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        identity = lambda s: (s.st_dev, s.st_ino, s.st_uid, s.st_gid, s.st_mode,
                              s.st_nlink, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
        if not (stat.S_ISREG(before.st_mode) and before.st_uid == 501 and before.st_gid == 20
                and stat.S_IMODE(before.st_mode) == 0o600 and before.st_nlink == 1
                and before.st_size == pin['bytes'] and pin['bytes'] <= 65536):
            raise ValueError('source_identity')
        raw = bytearray()
        while len(raw) <= pin['bytes']:
            block = os.read(fd, min(16384, pin['bytes'] + 1 - len(raw)))
            if not block:
                break
            raw.extend(block)
        if (len(raw) != pin['bytes'] or hashlib.sha256(raw).hexdigest() != pin['sha256']
                or identity(before) != identity(os.fstat(fd)) or identity(before) != identity(path.lstat())):
            raise ValueError('source_changed')
        return bytes(raw)
    finally:
        os.close(fd)


def normalize(item):
    return {k: item[k] for k in ('path', 'bytes', 'sha256')} | {
        'identity': {k: item['identity'][k] for k in runtime.guard.FILE_KEYS}}


def observe(io, public, private):
    need = runtime.need
    need(sys.platform == 'darwin' and os.geteuid() == 501 and os.getegid() == 20
         and sys.version_info[:3] == (3, 14, 3) and sys.flags.isolated == 1
         and sys.dont_write_bytecode and Path(sys.executable) == VENV / 'bin/python3',
         'fixed_isolated_darwin_python')
    input_dir = io.hold(INPUTS)
    for name, pin in SOURCE_PINS.items():
        io.read_file(dict(pin, path=str(INPUTS / name), identity=runtime.file_identity((INPUTS / name).lstat())),
                     maximum=65536, materialize=False)
    public_path = ROOT / 'control/formal-kv2-manager-init-execution-r1/result.public.json'
    original_public = runtime.parsed(io.read_file(dict(FAILED_PUBLIC, path=str(public_path),
                        identity=runtime.file_identity(public_path.lstat())), maximum=65536))
    need(original_public.get('status') == 'failed'
         and original_public.get('primary_failure_code') == 'fixed_endpoint_readiness_deadline'
         and original_public.get('initialization_attempted') is False
         and original_public.get('bootstrap_command_completed_zero') is True,
         'original_failed_attempt_boundary')
    need(FAILURE_PIN['path'] == str(AUTHORITY / 'preparation/manager-init.private.json')
         and FAILURE_PIN['identity'] == original_public['private_closure_identity'],
         'native_failed_private_closure_identity')
    failed_raw = io.read_file(FAILURE_PIN, maximum=131072)
    failed = runtime.parsed(failed_raw)
    need(failed['public_before_closeout']['initialization_attempted'] is False
         and failed['data_directory_transitions'] == []
         and failed['negative_tls_observations'] == []
         and len(failed['commands']) == 4 and len(failed['http_observations']) == 140,
         'retained_original_attempt_was_before_init')
    need(all(row['method'] == 'GET' and row['path'] == 'sys/init'
             and row['mutation'] is False and row['request_attempted'] is False
             and row['response_complete'] is False for row in failed['http_observations']),
         'original_connections_sent_no_http')
    prep = runtime.parsed(io.read_file(normalize(failed['preparation_private']), maximum=131072))
    envelope = runtime.parsed(io.read_file(normalize(failed['private_input']), maximum=131072))
    service = io.hold(SERVICE, failed['roots']['service'])
    authority = io.hold(AUTHORITY, failed['roots']['key'])
    for role, path in (('t5', '/Volumes/T5'), ('internal', '/System/Volumes/Data')):
        need(failed['volume_pins'][role]['path'] == path, 'fixed_two_volume_paths')
        io.hold(path, failed['volume_pins'][role], private=False)
    io.hold('/Users/qianqi/Library/LaunchAgents', envelope['launch_agents_parent'])
    archive_raw = io.read_file(normalize(failed['initial_launch_binding']), maximum=131072)
    binding = runtime.parsed(archive_raw)
    need(binding['state'] == 'initial_empty' and binding['seal_file'] is None
         and binding['data_pin'] == prep['initial_empty_data_binding']['identity'],
         'original_initial_binding_only')
    current_raw, current_pin = io.current_file(SERVICE / 'manager/launch-binding.private.json', maximum=131072)
    need(current_raw == archive_raw, 'current_binding_content_matches_retained_initial_archive')
    private['current_launch_binding'] = current_pin
    private['current_binding_inode_is_only_a_new_observation'] = True
    files = binding['files']
    for role in ('guard', 'server', 'config', 'ca_certificate', 'server_certificate', 'python'):
        io.read_file(normalize(files[role]), maximum=128 * 1024 * 1024,
                     private=role != 'python', materialize=False)
    # No key open/read or hash: its exact original metadata is checked twice.
    key = normalize(files['server_private_key'])
    need(runtime.file_identity(Path(key['path']).lstat()) == key['identity'], 'original_tls_key_metadata')
    config = runtime.parsed(io.read_file(normalize(files['config']), maximum=65536))
    need(config == binding['normal_config'], 'normal_config_exact_initial_binding')
    installed_raw = io.read_file(normalize(failed['installed_plist']), maximum=65536)
    draft_raw = io.read_file(normalize(prep['files']['uninstalled_plist']), maximum=65536)
    need(installed_raw == draft_raw and plistlib.loads(installed_raw) == plistlib.loads(draft_raw),
         'installed_plist_exact_prepared_bytes_and_structure')
    plist = plistlib.loads(installed_raw)
    need(plist['Label'] == 'org.heptabao.kv2'
         and plist['ProgramArguments'] == ['/opt/homebrew/bin/python3', '-I', '-B',
                   str(SERVICE / 'manager/launch_guard.py'), '--binding',
                   str(SERVICE / 'manager/launch-binding.private.json')]
         and plist['WorkingDirectory'] == str(SERVICE)
         and plist['StandardOutPath'] == str(SERVICE / 'logs/stdout.log')
         and plist['StandardErrorPath'] == str(SERVICE / 'logs/stderr.log'),
         'installed_plist_exact_normal_launcher')
    # Controller/venv and launchd base interpreter are distinct roles.
    # Verify the base launcher's public bytes without concealing a mismatch.
    launcher_path = Path(plist['ProgramArguments'][0]).resolve(strict=True)
    launcher_identity = runtime.file_identity(launcher_path.lstat())
    need(launcher_identity['file_type'] == stat.S_IFREG
         and launcher_identity['uid'] in (0, 501) and launcher_identity['nlink'] == 1
         and launcher_identity['mode'] & 0o022 == 0 and launcher_identity['mode'] & 0o111 != 0,
         'actual_base_launcher_regular_executable')
    launcher_pin = {'path': str(launcher_path), 'identity': launcher_identity,
                    'bytes': 34640,
                    'sha256': 'cebfcc4ac431ff7a2179bc6eff7e5c6bdae48b564eeab2d504bef6173a2cfc13'}
    io.read_file(launcher_pin, maximum=1048576, private=False, materialize=False)
    private['actual_base_launcher'] = launcher_pin
    private['original_controller_venv_python'] = files['python']
    public['actual_base_launcher_public_pin'] = launcher_pin
    public['guard_python_path_matches_actual_base_launcher'] = (
        launcher_path == Path(files['python']['path']))
    public['unresolved_configuration_conflicts'] = ([] if
        public['guard_python_path_matches_actual_base_launcher'] else
        ['guard_python_binding_uses_controller_venv_instead_of_plist_base_launcher'])
    # Completing this read-only observation does not resolve the separately
    # retained exact-path mismatch or authorize a launch/initialization.
    data = io.hold(SERVICE / 'data', binding['data_pin'])
    need(os.listdir(data['fd']) == [], 'original_data_still_empty')
    missing = []
    for role, name in (('root', 'root.token'), ('bootstrap', 'recovery.nonce'),
                        ('share-1', 'unseal.share'), ('pending-share-2', 'unseal.share'),
                        ('pending-share-3', 'unseal.share')):
        parent = io.hold(AUTHORITY / role, prep['directories']['authority_' + role])
        io.absent(parent, name)
        missing.append((parent, name))
    private['original_failure_private_pin'] = FAILURE_PIN
    private['original_preparation_private_pin'] = failed['preparation_private']
    private['original_initial_binding'] = failed['initial_launch_binding']
    private['original_installed_plist'] = failed['installed_plist']
    public.update(original_failed_attempt_bound=True, original_initial_binding_archive_unchanged=True,
                  current_binding_bytes_equal_initial_archive=True,
                  current_binding_original_inode_history_claimed=False,
                  installed_plist_exact_prepared_bytes=True, launcher_program_exact=True,
                  normal_binary_guard_config_cert_pins_unchanged=True,
                  private_tls_key_original_metadata_unchanged=True,
                  private_tls_key_content_read=False, original_empty_data_identity_unchanged=True,
                  initialization_material_absent_count=len(missing))
    output = io.mkdir(io.hold(ROOT / 'control'), OUTPUT.name)
    private['_output'] = output
    leaf = io.read_file(normalize(files['server_certificate']), maximum=65536)
    wire = runtime.ManagedWire(io, output, None, files['ca_certificate']['path'], leaf,
                               SERVICE, Path(failed['installed_plist']['path']))
    private['_wire'] = wire
    for route in ('sys/init', 'sys/seal-status'):
        status, _, row = wire.http('GET', route, readiness=True)
        safe = {'method': 'GET', 'path': route, 'http_status': status,
                'request_attempted': row['request_attempted'],
                'response_complete': row['response_complete'],
                'connection_refused_before_http': status is None}
        if row['response_complete']:
            body = row.get('body')
            need(isinstance(body, dict), 'readonly_endpoint_response_object')
            # Only boolean and numeric status fields are ever public.
            safe['status_fields'] = {k: body[k] for k in
                ('initialized', 'sealed', 't', 'n', 'progress', 'recovery_seal', 'migration')
                if k in body and type(body[k]) in (bool, int)}
            safe['tls_exact_leaf_verified'] = row['tls']['peer_leaf_sha256'] == wire.leaf_sha256
        public['endpoint_observations'].append(safe)
    for parent, name in missing:
        io.absent(parent, name)
    need(os.listdir(data['fd']) == []
         and runtime.file_identity(Path(key['path']).lstat()) == key['identity'],
         'post_observation_empty_data_and_key_metadata')
    io.recheck()
    public['observations_complete'] = True


def main():
    global runtime
    for name, pin in SOURCE_PINS.items():
        bootstrap_read(INPUTS / name, pin)
    sys.path.insert(0, str(INPUTS))
    runtime = importlib.import_module('manager_runtime')
    runtime.need(Path(runtime.__file__).resolve() == INPUTS / 'manager_runtime.py'
                 and Path(runtime.guard.__file__).resolve() == INPUTS / 'launch_guard.py', 'fixed_import_origin')
    clock = runtime.Clock(ENTRY)
    clock.end, clock.total_end = ENTRY + 52, ENTRY + 60
    io = runtime.PrivateIO(clock)
    public = {'schema': 'heptabao.failed-manager-readonly-reconciliation.public.v1',
              'original_failed_job_id': FAILED_JOB, 'status': 'failed', 'work_seconds': 52,
              'runtime_seconds': 60, 'deadline_renewed': False, 'observations_complete': False,
              'primary_failure_code': None, 'cleanup_failure_codes': [], 'endpoint_observations': [],
              'child_processes_created': 0, 'manager_queries_performed_here': 0,
              'launchd_log_queries_performed_here': 0, 'service_mutation_performed': False,
              'initialization_request_sent': False, 'unseal_or_ack_sent': False,
              'root_nonce_or_share_content_opened': False, 'business_source_opened': False,
              'provider_or_j3160_called': False, 'original_failed_attempt_reclassified': False,
              'formal_kv2_qualified': False, 'ha_qualified': False, 'authbus_qualified': False,
              'durable_completion_authority': 'public_record_plus_final_stdout_plus_separate_native_terminal'}
    private = {'schema': 'heptabao.failed-manager-readonly-reconciliation.private.v1'}
    try:
        clock.start()
        observe(io, public, private)
        clock.check()
        public['status'] = 'completed_readonly_observation'
    except BaseException as error:
        public['primary_failure_code'] = str(error) if isinstance(error, runtime.Refused) else 'readonly_observation_failed'
        if not public['primary_failure_code'].replace('_', '').isalnum():
            public['primary_failure_code'] = 'readonly_observation_failed'
    finally:
        clock.cleaning = True
        output = private.pop('_output', None)
        wire = private.pop('_wire', None)
        if wire is not None:
            private['http_observations'] = wire.http_rows
            public['http_connections_created'] = wire.http_connections_created
            public['http_connections_closed'] = wire.http_connections_closed
        with clock.critical():
            try:
                io.recheck()
            except BaseException:
                public['cleanup_failure_codes'].append('original_input_postflight_failed')
            try:
                if output is not None:
                    private['public_before_closeout'] = dict(public)
                    pin = io.put(output, 'manager-init.private.json', runtime.encoded(private),
                                 remember=False, closeout_evidence=True)
                    public['private_closure_identity'] = pin['identity']
                    public['private_closure_content_hash_published'] = False
                    io.put(output, 'result.public.json', runtime.encoded(public),
                           remember=False, closeout_evidence=True)
            except BaseException:
                public['cleanup_failure_codes'].append('readonly_evidence_publication_failed')
            public['cleanup_failure_codes'].extend(io.close())
            try:
                clock.finish()
            except BaseException:
                public['cleanup_failure_codes'].append('signal_handler_retirement_failed')
        public['owned_file_handles_opened'] = io.open_count
        public['owned_file_handles_closed'] = io.close_count
        public['all_owned_fds_closed'] = not io.handles and io.open_count == io.close_count
        public['interrupted_signal'] = clock.pending
        public['elapsed_seconds'] = time.monotonic() - ENTRY
        if (clock.pending is not None or public['elapsed_seconds'] >= 52 or public['primary_failure_code']
                or public['cleanup_failure_codes'] or not public['all_owned_fds_closed']):
            public['status'] = 'failed'
        print(runtime.encoded(public).decode(), end='', flush=True)
    return 0 if public['status'] == 'completed_readonly_observation' else 1


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except SystemExit:
        raise
    except BaseException:
        print('{"schema":"heptabao.failed-manager-readonly-bootstrap-failure.v1","status":"failed"}', flush=True)
        raise SystemExit(1)
