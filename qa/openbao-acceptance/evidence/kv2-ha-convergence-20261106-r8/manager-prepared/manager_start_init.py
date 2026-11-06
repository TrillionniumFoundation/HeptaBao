#!/usr/bin/env python3
"""Start one normal launchd-owned KV2 service and deliver an unacked 2/3 init.

This is a distinct 110/120-second step. It performs no unseal, ack, mount,
activation, business import, provider call, cutover, or cleanup of old assets.
Only an exact successful layout/TLS generation is admitted. An uncertain
bootstrap or init is retained for a separate read-only reconciliation; it is
never retried here. A successful service remains managed and sealed.
"""
from __future__ import annotations

import time
ENTRY = time.monotonic()
import argparse
import base64
import hashlib
import importlib
import json
import os
from pathlib import Path
import platform
import signal
import stat
import sys

ROOT = Path('/Volumes/T5/hepta-vnext-recovery-20261013/continuation-20261106-kv2-ha-convergence-r1')
SERVICE = Path('/Volumes/T5/hepta-vnext-recovery-20261013/heptabao-production-20261104-r1/formal-kv2-current-20261106-r1')
AUTHORITY = Path('/Users/qianqi/heptabao-formal-kv2-current-20261106-r1/service-authority-current-20261106-r1')
LAUNCH_AGENTS = Path('/Users/qianqi/Library/LaunchAgents')
INPUTS = ROOT / 'control/formal-kv2-manager-init-inputs-r1'
OUTPUT = ROOT / 'control/formal-kv2-manager-init-execution-r1'
VENV = ROOT / 'control/formal-kv2-python-env-50-0-2-r3/venv'
DOMAIN, LABEL = 'gui/501', 'org.heptabao.kv2'
PRODUCT_COMMIT = '4bde9aee03fcd27c59e13607e529b1cee594b249'
PRODUCT_TREE = 'f08493a23f8ea0637073651231865ea9607b790e'
PREPARATION_JOB = '1a1b2643b65-fc05-7dde'
FILE_FIELDS = {'dev', 'inode', 'uid', 'gid', 'mode', 'nlink', 'bytes', 'mtime_ns', 'ctime_ns', 'file_type'}
MODULES = ('launch_guard.py', 'manager_runtime.py', 'manager_launch_binding.py',
           'init_delivery.py', 'kv2_dr_process_custody.py', 'owned_process.py')


def bootstrap_read(path, pin):
    """Read fixed public code before importing it. No mutation occurs here."""
    if (path.resolve(strict=True) != path or set(pin) != {'bytes', 'sha256'} or
            type(pin['bytes']) is not int or not 0 < pin['bytes'] <= 2 * 1024 * 1024):
        raise ValueError('bootstrap_input_shape')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        if not (stat.S_ISREG(before.st_mode) and before.st_uid == 501 and before.st_gid == 20
                and stat.S_IMODE(before.st_mode) == 0o600 and before.st_nlink == 1
                and before.st_size == pin['bytes']):
            raise ValueError('bootstrap_input_identity')
        raw = bytearray()
        while len(raw) <= pin['bytes']:
            part = os.read(fd, min(65536, pin['bytes'] + 1 - len(raw)))
            if not part:
                break
            raw.extend(part)
        def identity(s):
            return (s.st_dev, s.st_ino, s.st_uid, s.st_gid, s.st_mode, s.st_nlink,
                    s.st_size, s.st_mtime_ns, s.st_ctime_ns)
        if (identity(before) != identity(os.fstat(fd)) or identity(before) != identity(path.lstat())
                or len(raw) != pin['bytes'] or hashlib.sha256(raw).hexdigest() != pin['sha256']):
            raise ValueError('bootstrap_input_changed')
        return bytes(raw)
    finally:
        os.close(fd)


def normalize_pin(pin):
    return {k: pin[k] for k in ('path', 'bytes', 'sha256')} | {
        'identity': {k: pin['identity'][k] for k in FILE_FIELDS}}


def terminal_ok(value, job, need):
    need(value.get('job_id') == job and value.get('state') == 'succeeded'
         and type(value.get('exit_code')) is int and value['exit_code'] == 0,
         'actual_preparation_terminal_zero')
    need(all(value.get(k) is True for k in ('output_complete', 'output_durable', 'terminal_publication_confirmed'))
         and value.get('timed_out') is False and value.get('cancelled') is False,
         'complete_durable_preparation_terminal')
    need(value.get('log_truncated') == {'stdout': False, 'stderr': False}
         and value.get('log_errors') == {'stdout': None, 'stderr': None}, 'complete_preparation_streams')


def execute(io, runtime, binding_module, delivery_module, owner, inputs, public, private):
    need = runtime.need
    public['phase'] = 'exact_preparation_admission'
    need(platform.system() == 'Darwin' and platform.machine() == 'arm64'
         and os.geteuid() == 501 and os.getegid() == 20, 'fixed_darwin_operator')
    need(sys.version_info[:3] == (3, 14, 3) and sys.flags.isolated == 1 and sys.dont_write_bytecode
         and Path(sys.executable) == VENV / 'bin/python3' and Path(sys.prefix) == VENV,
         'qualified_isolated_interpreter')
    need(inputs['schema'] == 'heptabao.normal-kv2-manager-init-inputs.v1'
         and inputs['normal_product'] == {'commit': PRODUCT_COMMIT, 'tree': PRODUCT_TREE}
         and inputs['preparation_job_id'] == PREPARATION_JOB
         and inputs['budgets'] == {'work': 110, 'runtime': 120, 'cleanup_reserve': 10, 'http': 15, 'utility': 5},
         'fixed_manager_init_input_scope')
    need(inputs['product_ci_hold'] == {'run_id': 42229582001, 'resolved': False}, 'existing_product_ci_hold_preserved')
    input_dir = io.hold(INPUTS)
    for name, pin in inputs['source_files'].items():
        need(name in MODULES or name == 'manager_start_init.py', 'only_fixed_bootstrap_modules')
        path = INPUTS / name
        item = {**pin, 'path': str(path), 'identity': runtime.file_identity(path.lstat())}
        io.read_file(item, maximum=2 * 1024 * 1024, materialize=False)
    need(set(inputs['source_files']) == set(MODULES) | {'manager_start_init.py'}, 'complete_bootstrap_source_denominator')
    public_files = {}
    for name, pin in inputs['public_prerequisites'].items():
        need(name in ('preparation-result.public.json', 'preparation-runtime-terminal.original.json',
                      'preparation-runtime.stdout.original'), 'only_exact_preparation_originals')
        path = INPUTS / name
        raw = io.read_file({**pin, 'path': str(path), 'identity': runtime.file_identity(path.lstat())},
                           maximum=262144)
        public_files[name] = runtime.parsed(raw)
    need(set(public_files) == {'preparation-result.public.json', 'preparation-runtime-terminal.original.json',
                              'preparation-runtime.stdout.original'}, 'three_complete_preparation_originals')
    terminal_ok(public_files['preparation-runtime-terminal.original.json'], PREPARATION_JOB, need)
    result, final = public_files['preparation-result.public.json'], public_files['preparation-runtime.stdout.original']
    need(result.get('schema') == 'heptabao.normal-kv2-layout-tls.public.v1'
         and result.get('preparation_complete') is True and result.get('status') == 'prepared_not_started'
         and result.get('normal_product_commit') == PRODUCT_COMMIT
         and result.get('normal_product_tree') == PRODUCT_TREE, 'qualified_prepared_generation')
    need(final.get('status') == result['status'] and final.get('preparation_complete') is True
         and final.get('primary_failure_code') is None and final.get('cleanup_failure_codes') == []
         and final.get('deadline_fired') is False and final.get('interrupted_signal') is None
         and final.get('owned_directory_handles') == final.get('owned_directory_handles_closed') == 23
         and final.get('owned_file_handles_opened') == final.get('owned_file_handles_closed') == 35
         and final.get('child_processes_created') == 0
         and final.get('private_record_identity') == result.get('private_record_identity'),
         'actual_preparation_final_closeout')
    for record in (result, final):
        need(all(record.get(k) is False for k in ('service_started', 'root_token_or_unseal_share_created',
                   'initialization_nonce_created', 'formal_kv2_qualified', 'current_product_ci_hold_resolved')),
             'preparation_does_not_claim_future_qualification')
    envelope_path = INPUTS / 'preparation.native-envelope.private.json'
    first = runtime.file_identity(envelope_path.lstat())
    need(first == inputs['private_input_identity'], 'original_private_envelope_identity')
    envelope_raw, envelope_pin = io.current_file(envelope_path, maximum=262144)
    need(envelope_pin['identity'] == first, 'private_envelope_stable_read')
    envelope = runtime.parsed(envelope_raw)
    need(type(envelope) is dict and set(envelope) == {'schema', 'preparation_private', 'launch_agents_parent', 'volume_pins'}
         and envelope['schema'] == 'heptabao.normal-kv2-manager-init-native-input.private.v1', 'private_envelope_shape')
    prep_pin = normalize_pin(envelope['preparation_private'])
    need(prep_pin['path'] == str(AUTHORITY / 'preparation/layout-tls.private.json')
         and prep_pin['identity'] == result['private_record_identity'], 'independent_native_preparation_private_binding')
    prep = runtime.parsed(io.read_file(prep_pin, maximum=131072))
    need(prep.get('schema') == 'heptabao.normal-kv2-layout-tls.private.v1'
         and prep.get('status') == 'prepared_not_started'
         and prep.get('source_bindings', {}).get('commit') == PRODUCT_COMMIT
         and prep.get('source_bindings', {}).get('tree') == PRODUCT_TREE,
         'actual_private_preparation_generation')
    need(prep['layout']['service_root'] == str(SERVICE) and prep['layout']['key_root'] == str(AUTHORITY)
         and prep['layout']['manager_domain'] == DOMAIN and prep['layout']['manager_label'] == LABEL,
         'exact_prepared_service_layout')
    service = io.hold(SERVICE, prep['roots']['service'])
    authority = io.hold(AUTHORITY, prep['roots']['key'])
    parents = {}
    for role, suffix in {'manager': 'manager', 'data': 'data', 'tls_public': 'tls', 'runtime': 'runtime'}.items():
        parents[role] = io.hold(SERVICE / suffix, prep['directories']['service_' + suffix])
    for role in ('root', 'bootstrap', 'share-1', 'pending-share-2', 'pending-share-3', 'preparation', 'manager-admissions'):
        parents[role] = io.hold(AUTHORITY / role, prep['directories']['authority_' + role])
    launch_agents = io.hold(LAUNCH_AGENTS, envelope['launch_agents_parent'])
    for role, fixed in (('t5', '/Volumes/T5'), ('internal', '/System/Volumes/Data')):
        need(envelope['volume_pins'][role]['path'] == fixed, 'fixed_volume_root')
        io.hold(fixed, envelope['volume_pins'][role], private=False)
    need(service['pin']['dev'] == envelope['volume_pins']['t5']['dev']
         and authority['pin']['dev'] == envelope['volume_pins']['internal']['dev']
         and service['pin']['dev'] != authority['pin']['dev'], 'actual_distinct_key_and_data_filesystems')
    need(os.listdir(parents['data']['fd']) == [] and parents['data']['pin'] == prep['initial_empty_data_binding']['identity'],
         'same_original_empty_preinitialization_data')
    io.read_file(normalize_pin(prep['source_bindings']['python']), maximum=128 * 1024 * 1024,
                 private=False, materialize=False)
    io.read_file(normalize_pin(prep['source_bindings']['venv']), maximum=4096, materialize=False)
    for role in ('server', 'seed', 'server_config', 'uninstalled_plist', 'ca_certificate', 'server_certificate'):
        io.read_file(normalize_pin(prep['files'][role]), maximum=128 * 1024 * 1024, materialize=False)
    # Metadata/held FD only: the existing private TLS key is not re-read or
    # hashed by this bootstrap controller. The exact server uses it for TLS.
    io.read_file(normalize_pin(prep['files']['server_private_key']), maximum=16384,
                 materialize=False, verify_bytes=False)
    reserved = {'root': 'root.token', 'bootstrap': 'recovery.nonce', 'share-1': 'unseal.share',
                'pending-share-2': 'unseal.share', 'pending-share-3': 'unseal.share'}
    for role, name in reserved.items():
        io.absent(parents[role], name)
    io.absent(parents['preparation'], 'manager-init.private.json')
    io.absent(launch_agents, LABEL + '.plist')
    io.absent(parents['manager'], 'launch_guard.py')
    io.absent(parents['manager'], 'launch-binding.private.json')
    control_parent = io.hold(ROOT / 'control')
    output = io.mkdir(control_parent, OUTPUT.name)
    private['_output_parent'] = output
    private['_private_parent'] = parents['preparation']
    private.update(preparation_private=prep_pin, private_input=envelope_pin, volume_pins=envelope['volume_pins'],
                   roots=prep['roots'], prepared_layout=prep['layout'])
    leaf = io.read_file(normalize_pin(prep['files']['server_certificate']), maximum=65536)
    wire = runtime.ManagedWire(io, output, owner, prep['files']['ca_certificate']['path'], leaf,
                               SERVICE, LAUNCH_AGENTS / (LABEL + '.plist'))
    private['_wire'] = wire
    public['phase'] = 'current_exact_label_absence'
    for domain in ('gui/501', 'user/501', 'system'):
        rc, out, err = wire.command('current_exact_label_absence', ['/bin/launchctl', 'print', domain + '/' + LABEL])
        need(runtime.exact_absence(rc, out, err, domain, LABEL), 'candidate_label_not_explicitly_absent')
    public['exact_label_absence_queries'] = 3
    public['phase'] = 'private_initial_launch_binding_and_plist'
    guard_source = INPUTS / 'launch_guard.py'
    guard_raw = io.read_file({**inputs['source_files']['launch_guard.py'], 'path': str(guard_source),
                             'identity': runtime.file_identity(guard_source.lstat())}, maximum=65536)
    guard_pin = io.put(parents['manager'], 'launch_guard.py', guard_raw)
    initial = binding_module.build_initial_binding(prep, guard_pin, envelope['volume_pins'])
    initial_raw = runtime.encoded(initial)
    initial_archive = io.put(parents['manager'], 'launch-binding.initial-empty.original.private.json', initial_raw)
    current_binding = io.put(parents['manager'], 'launch-binding.private.json', initial_raw)
    plist_raw = io.read_file(normalize_pin(prep['files']['uninstalled_plist']), maximum=65536)
    installed_plist = io.put(launch_agents, LABEL + '.plist', plist_raw)
    private.update(initial_launch_binding=initial_archive, installed_plist=installed_plist)
    public['new_private_plist_installed'] = True
    public['phase'] = 'single_launchd_bootstrap'
    public['bootstrap_attempted'] = True
    public['bootstrap_outcome_unknown'] = True
    wire.command('launchctl_bootstrap_original_plist', ['/bin/launchctl', 'bootstrap', DOMAIN, installed_plist['path']], 0)
    public['bootstrap_command_completed_zero'] = True
    public['phase'] = 'sealed_uninitialized_owned_endpoint'
    readiness_end = min(io.clock.end, time.monotonic() + 15)
    while True:
        status, raw, row = wire.http('GET', 'sys/init', readiness=True)
        if status is not None:
            break
        need(time.monotonic() < readiness_end, 'fixed_endpoint_readiness_deadline')
        time.sleep(min(0.1, max(0, readiness_end - time.monotonic())))
    need(status == 200 and runtime.parsed(raw) == {'initialized': False}, 'actual_uninitialized_server_required')
    before = wire.running(server_pin=normalize_pin(prep['files']['server']), plist_pin=installed_plist,
                          data_pin=parents['data']['pin'])
    private['manager_before_init'] = before
    public['bootstrap_outcome_unknown'] = False
    public['owned_managed_server_observed'] = True
    public['phase'] = 'negative_tls_before_initialization'
    wire.negative_tls()
    public['negative_tls_observations'] = wire.negative_tls_rows
    public['phase'] = 'durable_nonce_then_single_init'
    nonce = base64.b64encode(os.urandom(32))
    nonce_pin = io.put(parents['bootstrap'], 'recovery.nonce', nonce)
    need(len(nonce) == 44, 'canonical_recovery_nonce_length')
    private['nonce'] = nonce_pin
    io.put(parents['bootstrap'], 'init-request-intent.private.json', runtime.encoded({
        'schema': 'heptabao.single-init-intent.private.v1', 'nonce_file': nonce_pin,
        'manager': before, 'shares': 3, 'threshold': 2, 'single_attempt': True,
        'automatic_recovery_replay': False, 'request_response_values_saved_here': False}))
    public['initialization_attempted'] = True
    public['initialization_outcome_unknown'] = True
    status, response, init_row = wire.http('POST', 'sys/init', {
        'secret_shares': 3, 'secret_threshold': 2, 'recovery_nonce': nonce.decode('ascii')}, mutation=True)
    need(status == 200, 'single_init_did_not_return_200')
    delivery = delivery_module.decode_exact_three_share_response(response)
    del response
    initialized_data = io.initialized_directory_transition(parents['data'], actual_init_status=status,
                                                           actual_response_validated=True)
    private['data_directory_transition'] = io.transitions[-1]
    seal_raw, seal_pin = io.current_file(SERVICE / 'data/seal.json', maximum=16384)
    seal = runtime.parsed(seal_raw)
    need(seal.get('schema') == 1 and seal.get('generation') == 1 and seal.get('share_format') == 'shamir-v1'
         and seal.get('secret_shares') == 3 and seal.get('secret_threshold') == 2,
         'actual_initialized_seal_two_of_three')
    del seal_raw, seal
    public['phase'] = 'separate_private_delivery_and_rebind'
    root_pin = io.put(parents['root'], 'root.token', delivery.root_token)
    shares = {}
    for role, value in zip(('share-1', 'pending-share-2', 'pending-share-3'), delivery.shares_base64):
        shares[role] = io.put(parents[role], 'unseal.share', value)
    del delivery, nonce
    private.update(root_token=root_pin, shares=shares, seal_file=seal_pin)
    public['root_token_separately_saved'] = True
    public['separately_saved_share_count'] = 3
    updated = binding_module.build_initialized_binding(initial, initialized_data['pin'], seal_pin)
    updated_pin = io.publish_initialized_binding(parents['manager'], current_binding, updated)
    private['initialized_launch_binding'] = updated_pin
    public['initialized_launch_binding_published'] = True
    status, raw, seal_row = wire.http('GET', 'sys/seal-status')
    actual_seal = runtime.parsed(raw)
    need(status == 200 and actual_seal.get('type') == 'shamir' and actual_seal.get('initialized') is True
         and actual_seal.get('sealed') is True and actual_seal.get('t') == 2 and actual_seal.get('n') == 3
         and actual_seal.get('progress') == 0 and actual_seal.get('seal_generation') == 1,
         'actual_sealed_two_of_three_after_init')
    after = wire.running(server_pin=normalize_pin(prep['files']['server']), plist_pin=installed_plist,
                         data_pin=initialized_data['pin'])
    need(all(after[k] == before[k] for k in ('pid', 'ppid', 'uid', 'gid', 'pgid', 'session',
                                           'executable_identity', 'plist_file_identity', 'process_birth_observation')),
         'same_live_manager_received_initialization')
    private['manager_after_init'] = after
    private['commands'] = wire.commands
    private['http_observations'] = wire.http_rows
    public.update(initialization_outcome_unknown=False, initialized_and_sealed=True,
                  actual_shares=3, actual_threshold=2, service_left_registered_and_running=True,
                  server_pid=after['pid'], server_uid=after['uid'], server_pgid=after['pgid'],
                  server_session=after['session'], actual_tls_leaf_sha256=wire.leaf_sha256,
                  phase='initialized_sealed_awaiting_off_host_custody', status='initialized_sealed_held',
                  bootstrap_complete=True)
    io.recheck()
    io.check()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--inputs-sha256', required=True)
    parser.add_argument('--code-sha256', required=True)
    args = parser.parse_args()
    public = {'schema': 'heptabao.normal-kv2-manager-init.public.v1', 'status': 'failed', 'phase': 'input_loading',
              'bootstrap_complete': False, 'primary_failure_code': None, 'cleanup_failure_codes': [],
              'runtime_seconds': 120, 'work_seconds': 110, 'cleanup_reserve_seconds': 10,
              'automatic_retry': False, 'deadline_renewed': False, 'bootstrap_attempted': False,
              'initialization_attempted': False, 'initialization_outcome_unknown': False,
              'bootstrap_outcome_unknown': False, 'service_left_registered_and_running': False,
              'unseal_performed': False, 'init_ack_performed': False, 'off_host_share_custody_verified': False,
              'preactivation_seed_exported': False, 'native_v6_activated': False, 'kv_mount_created': False,
              'business_source_opened': False, 'business_kv_imported': False, 'provider_or_j3160_called': False,
              'authbus_credential_created': False, 'formal_kv2_qualified': False, 'ha_qualified': False,
              'authbus_qualified': False, 'current_product_ci_hold_resolved': False,
              'traffic_cutover_performed': False, 'old_asset_removed': False,
              'long_server_waitpid_performed_by_controller': False,
              'combined_plaintext_init_response_persisted': False,
              'python_secret_memory_zeroization_claimed': False,
              'durable_completion_authority': 'original_runtime_terminal_and_final_stdout_with_120_second_cap'}
    private = {'schema': 'heptabao.normal-kv2-manager-init.private.v1'}
    runtime = clock = io = custody = owner = None
    old_umask = os.umask(0o077)
    try:
        path = INPUTS / 'fixed-inputs.public.json'
        raw = bootstrap_read(path, {'bytes': path.lstat().st_size, 'sha256': args.inputs_sha256})
        inputs = json.loads(raw)
        if set(inputs) != {'schema', 'source_files', 'public_prerequisites', 'private_input_identity',
                           'normal_product', 'preparation_job_id', 'budgets', 'product_ci_hold'}:
            raise ValueError('exact_fixed_input_fields')
        if inputs['source_files']['manager_start_init.py']['sha256'] != args.code_sha256:
            raise ValueError('exact_entry_source_hash')
        for name in ('manager_start_init.py', *MODULES):
            bootstrap_read(INPUTS / name, inputs['source_files'][name])
        if Path(__file__).resolve(strict=True) != INPUTS / 'manager_start_init.py':
            raise ValueError('fixed_manager_entry_location')
        sys.path.insert(0, str(INPUTS))
        runtime = importlib.import_module('manager_runtime')
        custody = importlib.import_module('kv2_dr_process_custody')
        binding_module = importlib.import_module('manager_launch_binding')
        delivery_module = importlib.import_module('init_delivery')
        clock, io = runtime.Clock(ENTRY, custody), None
        io = runtime.PrivateIO(clock)
        with custody.activated() as owner:
            clock.start()
            try:
                execute(io, runtime, binding_module, delivery_module, owner, inputs, public, private)
            except BaseException as error:
                public['status'] = 'failed'
                public['bootstrap_complete'] = False
                if isinstance(error, (runtime.Refused, delivery_module.RejectedInitDelivery)):
                    value = str(error)
                    public['primary_failure_code'] = value if value.replace('_', '').isalnum() else 'fixed_operation_refused'
                else:
                    public['primary_failure_code'] = 'unexpected_' + type(error).__name__
            finally:
                clock.cleaning = True
                with clock.critical():
                    owner.finish()
                    private['command_custody'] = owner.receipt()
                    public['command_custody'] = runtime.safe_custody(private['command_custody'])
                    if owner.failed:
                        public['cleanup_failure_codes'].append('owned_short_command_custody_failed')
                    try:
                        io.recheck()
                    except BaseException:
                        public['cleanup_failure_codes'].append('final_original_identity_check_failed')
                    if clock.pending is not None or time.monotonic() >= clock.end:
                        public['cleanup_failure_codes'].append('original_work_deadline_or_signal_not_clear')
                    if public['primary_failure_code'] is not None or public['cleanup_failure_codes']:
                        public['status'], public['bootstrap_complete'] = 'failed', False
                    wire = private.pop('_wire', None)
                    if wire is not None:
                        private.update(commands=wire.commands, http_observations=wire.http_rows,
                                       negative_tls_observations=wire.negative_tls_rows)
                        public['http_connections_created'] = wire.http_connections_created
                        public['http_connections_closed'] = wire.http_connections_closed
                        public['cleanup_failure_codes'].extend(wire.command_cleanup_errors)
                        if wire.http_connections_created != wire.http_connections_closed:
                            public['cleanup_failure_codes'].append('http_connection_retirement_incomplete')
                    output, private_parent = private.pop('_output_parent', None), private.pop('_private_parent', None)
                    private['public_before_closeout'] = dict(public)
                    private['data_directory_transitions'] = io.transitions
                    if private_parent is not None:
                        try:
                            pin = io.put(private_parent, 'manager-init.private.json', runtime.encoded(private),
                                         closeout_evidence=True)
                            public['private_closure_identity'] = pin['identity']
                            public['private_closure_content_hash_published'] = False
                        except BaseException:
                            public['cleanup_failure_codes'].append('private_receipt_publication_failed')
                            public['status'], public['bootstrap_complete'] = 'failed', False
                    if output is not None:
                        try:
                            io.put(output, 'result.public.json', runtime.encoded(public), closeout_evidence=True)
                        except BaseException:
                            public['cleanup_failure_codes'].append('public_receipt_publication_failed')
                            public['status'], public['bootstrap_complete'] = 'failed', False
                    public['cleanup_failure_codes'].extend(io.close())
                    public['original_fd_count'] = io.open_count
                    public['original_fds_closed'] = io.close_count
                    public['remaining_original_fds'] = len(io.handles)
                    if io.open_count != io.close_count or io.handles:
                        public['cleanup_failure_codes'].append('original_fd_retirement_incomplete')
                    clock.finish()
    except BaseException as error:
        if public['primary_failure_code'] is None:
            public['primary_failure_code'] = 'entry_' + type(error).__name__
        public['status'], public['bootstrap_complete'] = 'failed', False
    finally:
        if io is not None:
            if clock is not None:
                clock.cleaning = True
            public['cleanup_failure_codes'].extend(io.close())
        if clock is not None:
            with clock.critical():
                clock.finish()
            public['interrupted_signal'] = clock.pending
        os.umask(old_umask)
    public['elapsed_final_observation_seconds'] = time.monotonic() - ENTRY
    if clock is not None and (clock.pending is not None or time.monotonic() >= clock.end):
        public['cleanup_failure_codes'].append('final_original_work_deadline_or_signal_not_clear')
    if public['primary_failure_code'] is not None or public['cleanup_failure_codes'] or time.monotonic() >= ENTRY + 120:
        public['status'], public['bootstrap_complete'] = 'failed', False
    print(json.dumps(public, sort_keys=True, allow_nan=False), flush=True)
    return 0 if public['status'] == 'initialized_sealed_held' else 1


if __name__ == '__main__':
    raise SystemExit(main())
