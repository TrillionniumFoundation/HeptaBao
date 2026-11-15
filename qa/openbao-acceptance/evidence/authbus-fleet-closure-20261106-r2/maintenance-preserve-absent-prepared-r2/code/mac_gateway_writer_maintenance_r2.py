#!/usr/bin/env python3
"""Concrete once-only actuator for the already registered Mac gateway.

Prepared source; no import-time I/O or automatic execution. The original outer
controller supplies qualified Commands/libproc/parser implementations, one
same-parent current observation, real selector/consumer fences and private
create-only fsynced storage. No JSON receipt can stand in for those fences.
Unknown provider, CAS, launchctl or namespace effects never restore a writer.
"""
from __future__ import annotations

import copy
import ctypes
import errno
import hashlib
import json
import os
from pathlib import Path
import plistlib
import re
import stat
import time

import mac_gateway_parameter_wrapper_fallback_r1 as fallback
from mac_maintenance_wrapper_inputs_r1 import MaintenanceWrapperInputs
from mac_current_gateway_observation_r2 import scoped_environments

ROOT = Path('/Users/qianqi/heptabao-authbus-writer-maintenance-20261106-r1')
DOMAIN = 'gui/501'
LABEL = 'ai.openclaw.gateway'
TARGET = DOMAIN + '/' + LABEL
PLIST = Path('/Users/qianqi/Library/LaunchAgents/ai.openclaw.gateway.plist')
CONFIG = Path('/Users/qianqi/.openclaw/openclaw.json')
NODE = '/opt/homebrew/Cellar/node/25.9.0_1/bin/node'
FALLBACK_CONFIG = ROOT / 'local-sdk-fallback.private.json'
FALLBACK_ENVIRONMENT = ROOT / 'local-sdk-fallback.environment.private'
PENDING_PLIST_NAME = 'ai.openclaw.gateway.heptabao-maintenance-20261106-r1.pending'
FIELDS = ('st_dev', 'st_ino', 'st_uid', 'st_gid', 'st_mode', 'st_nlink',
          'st_size', 'st_mtime_ns', 'st_ctime_ns')
SERVICE_GRAPH = ('bootout', 'publish-safe-plist', 'bootstrap-safe-local')


class MaintenanceRefused(RuntimeError):
    pass


def need(value, code):
    if not value:
        raise MaintenanceRefused(code)


def full(value):
    return tuple(getattr(value, key) for key in FIELDS)


def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n').encode()


def safe_command(row):
    # Original stdout/stderr, full-domain output hashes and argv remain private.
    allowed = ('label', 'pid', 'exitCode', 'outcomeUnknown', 'completeBeforeDeadline',
               'streamsClosed', 'errorType', 'errorCode', 'stdoutBytes', 'stderrBytes',
               'elapsedSeconds', 'cleanup')
    return {key: copy.deepcopy(row[key]) for key in allowed if key in row}


class GatewayWriterMaintenance:
    def __init__(self, *, commands, reader, bsd_info, parse_print, parse_disabled,
                 missing_service, until, source_fence, private_write,
                 selector_fence, consumer_fence, clock=time.monotonic):
        need(clock() < until <= clock() + 600, 'maintenance_original_outer_budget')
        for function in (parse_print, parse_disabled, missing_service, source_fence,
                         private_write, selector_fence, consumer_fence):
            need(callable(function), 'maintenance_complete_actual_bindings')
        self.commands, self.reader, self.bsd_info = commands, reader, bsd_info
        self.parse_print, self.parse_disabled, self.missing_service = parse_print, parse_disabled, missing_service
        self.until, self.clock, self.source_fence = until, clock, source_fence
        self.private_write, self.selector_fence, self.consumer_fence = private_write, selector_fence, consumer_fence
        self.actions, self.command_rows, self.descriptors = {}, [], []
        self.directories, self.fallback_files = {}, {}
        self.binding = self.plist_bytes = self.config_bytes = self.safe = None
        self.wrapper_inputs = None
        self.original_disabled = self.original_parent = None
        self.original_rows, self.original_relations = {}, {}
        self.owned_refresh_child = None
        self.retired_refresh_children = []
        self.new_process = None
        self.parking = None
        self.safe_files_attempted = False
        self.phase, self.unknown, self.closed = 'new', False, False
        self.report = {'schema': 'heptabao.registered-gateway-maintenance.public.r2',
            'ok': False, 'phase': self.phase, 'actions': self.actions, 'commands': self.command_rows,
            'automaticRetry': False, 'automaticCompensation': False,
            'configuredFlagsUsedAsRunningWriterProof': False,
            'allProductionConsumersCovered': False,
            'postRefreshGenerationRequiredBeforeRestore': True,
            'postQuiescenceFreshCaptureRequired': True, 'oldKeeperUsedAsLatest': False,
            'sourceSidecarsInitializedByMaintenance': False,
            'providerOrCasUnknownRestorationAllowed': False,
            'oldCredentialRollbackAllowed': False, 'productionTrafficSwitched': False,
            'credentialValuesOrDigestsPublished': False, 'privateConfigurationDigestsPublished': False,
            'privateArgumentsOrEnvironmentPublished': False,
            'conditionalRenameIsAtomicCompareAndSwapClaimed': False,
            'originalOverrideAbsencePreserved': False, 'disabledOverrideMutations': 0}

    def within(self, cap=600):
        need(not self.closed and self.clock() < self.until, 'maintenance_original_deadline')
        return min(cap, self.until - self.clock())

    def _write(self, name, value):
        need(isinstance(name, str) and re.fullmatch(r'[a-z0-9.-]{1,140}', name),
             'maintenance_fixed_private_artifact_name')
        raw = value if isinstance(value, bytes) else encoded(value)
        need(len(raw) <= 2 * 1048576, 'maintenance_bounded_private_artifact')
        try:
            self.private_write(name, raw)
        except BaseException:
            self.unknown = True
            raise

    def _directory(self, path):
        if path in self.directories:
            self._verify_directories()
            return self.directories[path]
        if path == path.parent:
            fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        else:
            parent = self._directory(path.parent)
            fd = os.open(path.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent['fd'])
        row = {'fd': fd, 'path': path, 'closeAttempts': 0, 'closed': False}
        self.descriptors.append(row)
        info = os.fstat(fd)
        row['identity'] = full(info)
        need(stat.S_ISDIR(info.st_mode) and info.st_uid in (0, 501)
             and not stat.S_IMODE(info.st_mode) & 0o022,
             'maintenance_complete_nonalias_parent_custody')
        need(full(info) == full(path.lstat()), 'maintenance_same_original_named_parent')
        if path in (ROOT, PLIST.parent):
            need(info.st_uid == 501 and info.st_gid == 20,
                 'maintenance_same_owned_writable_directory')
        if path == ROOT:
            need(stat.S_IMODE(info.st_mode) == 0o700, 'maintenance_private_staged_root_0700')
        self.directories[path] = row
        self._verify_directories()
        return row

    def _verify_directories(self):
        self.within()
        for path, row in self.directories.items():
            # These two explicitly owned publication directories change from
            # our create/rename operations. All other original ancestors keep
            # the full nine fields. Source file identities are never rebased.
            width = 5 if path in (ROOT, PLIST.parent) else 9
            need(not row['closeAttempts']
                 and full(os.fstat(row['fd']))[:width] == row['identity'][:width]
                 == full(path.lstat())[:width], 'maintenance_original_directory_chain_stable')

    def _create_fallback_file(self, path, raw):
        need(path in (FALLBACK_CONFIG, FALLBACK_ENVIRONMENT) and path not in self.fallback_files,
             'maintenance_fixed_fallback_file_once')
        parent = self._directory(ROOT)
        fd = os.open(path.name, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                     0o600, dir_fd=parent['fd'])
        row = {'fd': fd, 'closeAttempts': 0, 'closed': False}
        self.descriptors.append(row)
        try:
            self._write_complete_private(fd, raw)
            info = os.fstat(fd)
            need(stat.S_ISREG(info.st_mode) and info.st_uid == 501 and info.st_gid == 20
                 and info.st_nlink == 1 and stat.S_IMODE(info.st_mode) == 0o600
                 and info.st_size == len(raw)
                 and full(info) == full(os.stat(path.name, dir_fd=parent['fd'], follow_symlinks=False)),
                 'maintenance_private_fallback_complete_named_generation')
            os.fsync(parent['fd'])
            self.fallback_files[path] = {'identity': full(info), 'raw': raw}
            self._verify_directories()
        finally:
            self._close_descriptor(row)

    def _write_complete_private(self, descriptor, raw):
        need(isinstance(raw, bytes) and 0 < len(raw) <= 1048576,
             'maintenance_bounded_private_publication_bytes')
        view = memoryview(raw)
        while view:
            self.within()
            count = os.write(descriptor, view)
            need(count > 0, 'maintenance_private_publication_write_progress')
            view = view[count:]
        os.fsync(descriptor)
        need(os.pread(descriptor, len(raw) + 1, 0) == raw,
             'maintenance_private_publication_exact_whole_readback')

    def _verify_fallback_files(self):
        need(set(self.fallback_files) == {FALLBACK_CONFIG, FALLBACK_ENVIRONMENT},
             'maintenance_both_private_fallback_files_published')
        parent = self._directory(ROOT)
        for path, expected in self.fallback_files.items():
            fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent['fd'])
            row = {'fd': fd, 'closeAttempts': 0, 'closed': False}
            self.descriptors.append(row)
            try:
                need(full(os.fstat(fd)) == expected['identity']
                     == full(os.stat(path.name, dir_fd=parent['fd'], follow_symlinks=False))
                     and os.pread(fd, len(expected['raw']) + 1, 0) == expected['raw']
                     and full(os.fstat(fd)) == expected['identity']
                     == full(os.stat(path.name, dir_fd=parent['fd'], follow_symlinks=False)),
                     'maintenance_safe_environment_and_configuration_unchanged')
            finally:
                self._close_descriptor(row)
        self._verify_directories()
        self.wrapper_inputs.verify()

    def _command(self, name, argv, *, allow_stopped=False):
        self.within()
        need(len(self.command_rows) < (3 * 96 + 64) * 3, 'maintenance_finite_original_helpers')
        need(not self.unknown or allow_stopped, 'maintenance_no_new_helper_after_unknown')
        self.source_fence()
        ordinal = len(self.command_rows)
        try:
            row, stdout, stderr = self.commands.run(name, argv,
                until=min(self.until, self.clock() + 8), maximum=262144)
        except BaseException:
            self.unknown = True
            raise
        self.command_rows.append(safe_command(row))
        self._write('command-%03d.record.private.json' % ordinal, row)
        self._write('command-%03d.stdout.private' % ordinal, stdout)
        self._write('command-%03d.stderr.private' % ordinal, stderr)
        if row.get('outcomeUnknown') is not False or row.get('completeBeforeDeadline') is not True:
            self.unknown = True
            raise MaintenanceRefused('maintenance_original_helper_unknown')
        need(type(row.get('exitCode')) is int and isinstance(stdout, bytes) and isinstance(stderr, bytes),
             'maintenance_original_typed_helper_result')
        self.within()
        return row, stdout, stderr

    def disabled(self):
        row, stdout, stderr = self._command('maintenance-disabled', ['/bin/launchctl', 'print-disabled', DOMAIN])
        need(row['exitCode'] == 0 and not stderr, 'maintenance_complete_original_disabled_projection')
        value = self.parse_disabled(stdout)
        need(value is None or type(value) is bool, 'maintenance_typed_selected_disabled_value')
        return value

    def query(self):
        row, stdout, stderr = self._command('maintenance-label', ['/bin/launchctl', 'print', TARGET])
        if self.missing_service(row['exitCode'], stdout, stderr, LABEL):
            return None
        need(row['exitCode'] == 0 and not stderr, 'maintenance_complete_registered_label_projection')
        result = self.parse_print(stdout, TARGET)
        result['observedEnvironmentScope'] = scoped_environments(stdout)
        return result

    def _related_rows(self):
        row, stdout, stderr = self._command('maintenance-related', ['/bin/ps', '-axo', 'pid=,ppid=,pgid=,uid=,stat='])
        need(row['exitCode'] == 0 and not stderr, 'maintenance_complete_related_process_rows')
        identities = set(self.original_rows)
        groups = {item['pgid'] for item in self.original_rows.values()}
        related = []
        for line in stdout.decode('ascii', 'strict').splitlines():
            fields = line.split()
            need(len(fields) == 5 and all(field.isdecimal() for field in fields[:3])
                 and (fields[3].isdecimal() or fields[3] == '-2'), 'maintenance_typed_process_metadata')
            pid, parent, group, uid = map(int, fields[:4])
            if pid in identities or parent in identities or group in groups:
                related.append({'pid': pid, 'ppid': parent, 'pgid': group, 'uid': uid, 'state': fields[4]})
        return related

    def _pid_absent(self, pid):
        info = self.bsd_info()
        ctypes.set_errno(0)
        count = self.reader.lib.proc_pidinfo(pid, 3, 0, ctypes.byref(info), ctypes.sizeof(info))
        return count == 0 and ctypes.get_errno() == errno.ESRCH

    def _read_plist(self, expected=None, raw_expected=None):
        need(self.original_parent is not None, 'maintenance_original_launchagents_parent_held')
        self._verify_directories()
        parent = self.original_parent
        need(full(os.fstat(parent['fd']))[:5] == parent['identity'][:5]
             and full(PLIST.parent.lstat())[:5] == parent['identity'][:5],
             'maintenance_same_original_launchagents_parent')
        descriptor = os.open(PLIST.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent['fd'])
        row = {'fd': descriptor, 'closeAttempts': 0, 'closed': False}
        self.descriptors.append(row)
        try:
            before = os.fstat(descriptor)
            need(stat.S_ISREG(before.st_mode) and before.st_uid == 501 and before.st_gid == 20
                 and before.st_nlink == 1 and not stat.S_IMODE(before.st_mode) & 0o022
                 and 0 < before.st_size <= 262144, 'maintenance_original_private_plist_custody')
            if expected is not None:
                need(full(before) == tuple(int(x) for x in expected), 'maintenance_exact_expected_plist_generation')
            chunks, total = [], 0
            while total <= before.st_size:
                self.within()
                block = os.read(descriptor, min(65536, before.st_size + 1 - total))
                if not block:
                    break
                chunks.append(block)
                total += len(block)
            raw = b''.join(chunks)
            need(total == before.st_size and full(os.fstat(descriptor)) == full(before)
                 == full(os.stat(PLIST.name, dir_fd=parent['fd'], follow_symlinks=False)),
                 'maintenance_stable_complete_named_plist')
            if raw_expected is not None:
                need(raw == raw_expected, 'maintenance_same_original_plist_bytes')
            return raw, full(before)
        finally:
            self._close_descriptor(row)

    def _close_descriptor(self, row):
        need(row['closeAttempts'] == 0, 'maintenance_descriptor_close_once')
        row['closeAttempts'] += 1
        try:
            os.close(row['fd'])
            row['closed'] = True
        except BaseException:
            row['unknown'] = True
            raise

    def bind_original(self, binding, config_bytes, plist_bytes, wrapper_inputs):
        need(self.phase == 'new' and not self.unknown, 'maintenance_original_observation_once')
        self.phase = 'binding-original'
        self.source_fence()
        need(isinstance(binding, dict)
             and binding.get('schema') == 'heptabao.current-gateway-private-restore-inputs.r1'
             and binding.get('observationSchema') == 'heptabao.current-gateway-observation.private.r2'
             and binding.get('target') == TARGET and binding.get('plistPath') == str(PLIST)
             and binding.get('configPath') == str(CONFIG)
             and binding.get('configSource') == 'same_parent_original_inventory_capture',
             'maintenance_exact_same_parent_original_observation')
        self.binding = copy.deepcopy(binding)
        self.config_bytes, self.plist_bytes = config_bytes, plist_bytes
        need(isinstance(wrapper_inputs, MaintenanceWrapperInputs)
             and not wrapper_inputs.closed and not wrapper_inputs.failed
             and wrapper_inputs.maintenance_handoff is True
             and wrapper_inputs.maintenance_until == self.until
             and wrapper_inputs.source_binding.get('sameParentRetainedDescriptors') is True,
             'maintenance_actual_same_parent_parameter_sources')
        wrapper_inputs.verify()
        # Publication must not change a directory whose full9 is itself an
        # original wrapper/environment source binding. Refuse this before any
        # gateway action instead of weakening that original source fence.
        need(ROOT not in wrapper_inputs.parents and PLIST.parent not in wrapper_inputs.parents,
             'maintenance_publication_does_not_mutate_original_wrapper_parent')
        self.wrapper_inputs = wrapper_inputs
        self.safe = fallback.make_parameter_wrapper_fallback(config_bytes, plist_bytes, binding,
            wrapper_inputs.files[0]['raw'], wrapper_inputs.files[1]['raw'], wrapper_inputs.source_binding)
        rows = [binding.get('process'), *binding.get('descendants', [])]
        need(1 <= len(rows) <= 128 and all(isinstance(row, dict) for row in rows),
             'maintenance_finite_original_family')
        self.original_rows = {row['pid']: copy.deepcopy(row) for row in rows}
        need(len(self.original_rows) == len(rows), 'maintenance_unique_original_family_pids')
        self.original_relations = {int(key): list(value) for key, value in binding['relations'].items()}
        need(set(self.original_relations) == set(self.original_rows), 'maintenance_original_child_sets_complete')
        root = rows[0]
        need(root['executable'] == NODE and root['uid'] == 501 and root['ppid'] == 1,
             'maintenance_original_registered_node_identity')
        self.original_parent = self._directory(PLIST.parent)
        self._directory(ROOT)
        self._read_plist(binding['plistFull9'], plist_bytes)
        # These two original executable fences must use the same parent's
        # private selector inputs / finite actual consumer observations.
        self.selector_fence('before-maintenance', self.safe)
        self.consumer_fence('before-maintenance', self.original_rows, None)
        self.same_original_running('bound-original')
        self.original_disabled = self.disabled()
        original_plist = plistlib.loads(plist_bytes)
        need(self.original_disabled is None and original_plist.get('Disabled', False) is False
             and original_plist.get('KeepAlive') is True
             and original_plist.get('AbandonProcessGroup', False) is False,
             'maintenance_observed_keepalive_true_original_override_absent')
        self._write('original-disabled.private.json', {'override': self.original_disabled})
        self._write('original-restore-inputs.private.json', binding)
        self._write('original-config.private.json', config_bytes)
        self._write('original-gateway.plist.private', plist_bytes)
        self._write('original-wrapper.private', wrapper_inputs.files[0]['raw'])
        self._write('original-wrapper-environment.private', wrapper_inputs.files[1]['raw'])
        self._write('original-wrapper-source-binding.private.json', wrapper_inputs.source_binding)
        self.phase = 'original-bound'
        self.report['originalEffectiveDisabledFalse'] = True
        return self

    def same_original_running(self, stage, ordinal=None):
        need(not self.unknown and self.phase in ('binding-original', 'original-bound'),
             'maintenance_original_running_phase')
        self.within()
        expected = self.binding['loadedSecond']
        current = self.query()
        need(current is not None and all(current.get(key) == expected.get(key) for key in
             ('path', 'program', 'pid', 'runs', 'state', 'arguments', 'observedEnvironmentScope')),
             'maintenance_same_original_loaded_registration')
        for pid, process in self.original_rows.items():
            need(self.reader.read(pid) == process
                 and sorted(self.reader.children(pid)) == sorted(self.original_relations[pid]),
                 'maintenance_same_entire_original_family')
        related = self._related_rows()
        need({row['pid'] for row in related} == set(self.original_rows)
             and all(row['uid'] == 501 and all(row[key] == self.original_rows[row['pid']][key]
                 for key in ('pid', 'ppid', 'pgid', 'uid')) for row in related),
             'maintenance_no_other_original_group_or_direct_child')
        self._read_plist(self.binding['plistFull9'], self.plist_bytes)
        self.wrapper_inputs.verify()
        need(self.owned_refresh_child is None, 'maintenance_no_refresh_child_while_original_gateway_running')
        self.consumer_fence(stage, self.original_rows, None)
        return True

    def _intent(self, operation, extra=None):
        original_restore = operation == 'bootstrap-original-before-provider'
        need(not self.unknown and (operation in SERVICE_GRAPH or original_restore)
             and operation not in self.actions, 'maintenance_original_service_effect_once')
        if original_restore:
            need(tuple(self.actions) == ('bootout',)
                 and self.actions['bootout']['outcome'] == 'COMPLETE'
                 and self.phase == 'restoring-original-before-provider',
                 'maintenance_original_restore_is_separate_pre_provider_branch')
        else:
            need(len(self.actions) < len(SERVICE_GRAPH) and SERVICE_GRAPH[len(self.actions)] == operation,
                 'maintenance_fixed_post_commit_service_effect_graph')
        self.source_fence();self.within()
        row = {'attempted': True, 'intentDurable': False, 'outcome': 'UNKNOWN'}
        self.actions[operation] = row
        try:
            self._write('intent-%s.private.json' % operation,
                        {'operation': operation, 'target': TARGET, 'detail': extra})
            row['intentDurable'] = True
        except BaseException:
            self.unknown = True
            raise
        return row

    def _complete(self, operation, result):
        row = self.actions[operation]
        self._write('complete-%s.private.json' % operation, result)
        row['outcome'] = 'COMPLETE'

    def prepare_safe_private_files(self):
        need(self.phase == 'original-bound' and not self.safe_files_attempted and not self.unknown,
             'maintenance_safe_private_files_prepared_before_first_service_action')
        self.safe_files_attempted = True
        try:
            self.same_original_running('before-private-fallback-preparation')
            self.selector_fence('before-private-fallback-preparation', self.safe)
            self._create_fallback_file(FALLBACK_CONFIG, self.safe['configBytes'])
            self._create_fallback_file(FALLBACK_ENVIRONMENT, self.safe['environmentBytes'])
            self._verify_fallback_files()
            self._write('safe-private-fallback-prepared.private.json',
                {'authbusExplicitlyDisabled': True, 'autoloadEntryPublished': False,
                 'configurationFull9': self.fallback_files[FALLBACK_CONFIG]['identity'],
                 'environmentFull9': self.fallback_files[FALLBACK_ENVIRONMENT]['identity']})
            self.report['safeFallbackPrivateFilesPreparedWithoutAutoload'] = True
        except BaseException:
            self.unknown = True
            raise

    def bootout(self):
        need(self.phase == 'original-bound' and self.disabled() is None
             and self.parking is not None and self.parking.phase == 'bound'
             and self.parking.relays.phase == 'retired',
             'maintenance_original_bootout_after_four_known_relay_retirements')
        self.parking.verify();self.parking.relays.verify_retired()
        self._verify_fallback_files()
        self.same_original_running('before-bootout')
        self._intent('bootout')
        try:
            row, _, stderr = self._command('maintenance-bootout', ['/bin/launchctl', 'bootout', TARGET])
            need(row['exitCode'] == 0 and not stderr, 'maintenance_original_bootout_known_zero')
            self._complete('bootout', {'exitCode': 0, 'disabledOverrideMutation': False})
            self.phase = 'quiescing'
            deadline = min(self.until, self.clock() + 15)
            while True:
                gone = self.query() is None and all(self._pid_absent(pid) for pid in self.original_rows)
                if gone and not self._related_rows():break
                need(self.clock() < deadline, 'maintenance_original_family_retirement_budget')
                time.sleep(min(0.1, deadline - self.clock()))
            self.phase = 'quiesced'
            for number in range(2):
                self.verify_quiesced('after-bootout')
                if number == 0:time.sleep(min(0.15, self.within()))
            self.report.update(originalRegisteredFamilyRetiredTwice=True,
                               originalOverrideAbsencePreserved=True)
        except BaseException:
            self.unknown = True
            raise

    def verify_quiesced(self, stage):
        need(not self.unknown and self.phase in ('quiesced', 'parked-for-refresh', 'refreshing',
             'committed', 'safe-plist-published'), 'maintenance_quiesced_original_phase')
        self.within();self.source_fence()
        need(self.disabled() is None and self.query() is None
             and all(self._pid_absent(pid) for pid in self.original_rows)
             and not self._related_rows(), 'maintenance_preserved_override_absence_and_original_family_absent')
        if self.owned_refresh_child is not None:
            original = self.owned_refresh_child
            need(self.reader.read(original['pid']) == original and not self.reader.children(original['pid']),
                 'maintenance_same_original_refresh_child_before_consumer_check')
        self.consumer_fence(stage, self.original_rows, copy.deepcopy(self.owned_refresh_child))
        need(self.parking is not None, 'maintenance_concrete_original_five_plist_owner')
        self.parking.verify()
        if self.phase != 'quiesced':self.parking.verify_parked()
        self._verify_fallback_files()
        return True

    def bind_owned_refresh_child(self, original, custody):
        """Allow one parent-owned original Node handle in the main DB scan.

        This grants no additional consumer, provider request or service action.
        The consumer fence must still enforce its fixed main-file scope and
        inspect all other admitted writers. The original process remains bound
        by complete libproc identity, not just a copied PID.
        """
        need(self.owned_refresh_child is None and not self.unknown
             and self.phase in ('parked-for-refresh', 'refreshing')
             and isinstance(original, dict) and isinstance(custody, dict),
             'maintenance_single_original_refresh_child_binding')
        self.within()
        pid = original.get('pid')
        ps = custody.get('ps', {})
        need(type(pid) is int and pid > 1 and original.get('ppid') == os.getpid()
             and original.get('pgid') == pid and original.get('uid') == 501
             and original.get('executable') == NODE
             and all(ps.get(key) == original[key] for key in ('pid', 'ppid', 'pgid', 'uid'))
             and custody.get('sid_observed_while_live') == pid
             and self.reader.read(pid) == original and not self.reader.children(pid),
             'maintenance_original_retained_child_custody_and_full_birth')
        self.owned_refresh_child = copy.deepcopy(original)

    def retire_owned_refresh_child(self, original, cleanup):
        """Retire only the original handle after its one retained wait.

        Cleanup may finish after the business deadline; this removes no once
        ledger and permits no new work or gateway restoration by itself.
        """
        need(self.owned_refresh_child == original and isinstance(cleanup, dict)
             and cleanup.get('ok') is True and cleanup.get('directChildReaped') is True
             and cleanup.get('allGroupRowsEmptyAfterReap') is True
             and cleanup.get('ownedLiveGroupEmptyBeforeReap') is True
             and cleanup.get('pid') == original['pid'] and cleanup.get('pgid') == original['pgid']
             and cleanup.get('postReapSignalSent') is False,
             'maintenance_original_refresh_child_retained_wait_and_group_closure')
        self.retired_refresh_children.append(copy.deepcopy(original))
        self.owned_refresh_child = None

    def accept_known_original_park(self, parking):
        from mac_fixed_launchagent_park_r1 import FixedLaunchAgentParking
        need(type(parking) is FixedLaunchAgentParking and parking is self.parking
             and parking.gateway is self and parking.until == self.until
             and parking.phase == 'parked' and parking.parked == list(range(5))
             and not parking.unknown and not parking.blocked and self.phase == 'quiesced',
             'maintenance_actual_five_original_inodes_known_parked')
        parking.verify_parked()
        self.phase = 'parked-for-refresh'
        self.report['fiveOriginalAutoloadEntriesParkedBeforeProvider'] = True

    def publish_safe_plist(self, *, sequence):
        from mac_refresh_capture_sequence_r2 import FreshOwnerRefreshSequence
        need(type(sequence) is FreshOwnerRefreshSequence and sequence.maintenance is self
             and sequence.until == self.until and sequence.report['ok'] is True
             and self.phase == 'committed' and self.parking is not None,
             'maintenance_actual_three_committed_before_safe_autoload')
        self.verify_quiesced('before-safe-autoload-publication')
        sequence.verify_current_epoch('before-safe-plist-intent')
        self._intent('publish-safe-plist')
        try:
            self.parking.publish_safe_gateway(sequence=sequence)
        except BaseException:
            self.unknown = True
            raise

    def accept_known_safe_autoload(self, parking):
        from mac_fixed_launchagent_park_r1 import FixedLaunchAgentParking
        need(type(parking) is FixedLaunchAgentParking and parking is self.parking
             and parking.phase == 'safe-published' and parking.safe_file is not None
             and not parking.unknown and not parking.blocked and self.phase == 'committed'
             and self.actions.get('publish-safe-plist', {}).get('outcome') == 'UNKNOWN',
             'maintenance_original_known_safe_publication_handoff')
        parking.verify_parked()
        self.safe_plist_identity = parking.safe_file['expected']
        self._read_plist(self.safe_plist_identity, self.safe['plistBytes'])
        self._verify_fallback_files()
        self.selector_fence('after-safe-plist', self.safe)
        self._complete('publish-safe-plist', {'newFull9': self.safe_plist_identity,
            'authbusExplicitlyDisabled': True, 'originalOverrideAbsent': True,
            'threeCommittedEpochRequiredBeforePublication': True})
        self.phase = 'safe-plist-published'
        self.verify_quiesced('after-safe-plist')
        self.report['persistentOriginalLabelPlistNowUsesSafeLocalConfig'] = True

    def restore_safe_local(self, *, current_epoch_fence, current_baseline_fence, retired_source_resources):
        need(not self.unknown and self.phase == 'safe-plist-published'
             and callable(current_epoch_fence) and callable(current_baseline_fence),
             'maintenance_known_current_post_refresh_epoch_required')
        need(retired_source_resources.get('allOwnedResourcesClosedOnce') is True,
             'maintenance_original_source_handles_closed_before_restore')
        current_epoch_fence();current_baseline_fence()
        self.selector_fence('before-safe-restore', self.safe)
        self.verify_quiesced('before-safe-restore')
        need(self.owned_refresh_child is None, 'maintenance_no_owned_refresh_child_before_restore')
        self._read_plist(self.safe_plist_identity, self.safe['plistBytes'])
        self._verify_fallback_files()
        self._intent('bootstrap-safe-local')
        try:
            row, _, stderr = self._command('maintenance-bootstrap-safe',
                ['/bin/launchctl', 'bootstrap', DOMAIN, str(PLIST)])
            need(row['exitCode'] == 0 and not stderr, 'maintenance_bootstrap_safe_local_known_zero')
            self._complete('bootstrap-safe-local', {'exitCode': 0})
            self.phase = 'safe-local-bootstrap-complete'
            need(self.disabled() is None, 'maintenance_original_override_absence_preserved_after_bootstrap')
            self.report.update(safeLocalBootstrapKnown=True, restoredEffectiveDisabledFalse=True,
                originalOverrideAbsencePreserved=True, gatewayRuntimeQualified=False,
                productionRollbackQualified=False)
            # The outer still must observe actual new birth/config/memory,
            # real cold consumption and the post-refresh full-state baseline.
        except BaseException:
            self.unknown = True
            raise

    def restore_original_before_any_provider(self, parent):
        from mac_owned_refresh_parent_r2 import OwnedRefreshParent
        need(type(parent) is OwnedRefreshParent and parent.maintenance is self
             and parent.until == self.until and not self.unknown
             and self.phase == 'parked-for-refresh' and self.parking is not None
             and self.parking.phase == 'restored' and self.owned_refresh_child is None,
             'maintenance_original_restore_only_before_any_provider_attempt')
        parent.assert_no_provider_dispatch()
        self.parking.verify();self.wrapper_inputs.verify()
        need(self.disabled() is None and self.query() is None
             and all(self._pid_absent(pid) for pid in self.original_rows) and not self._related_rows(),
             'maintenance_original_restore_no_original_registration_or_family')
        restored = self.parking.files[4]
        need(restored['location'] == 'restored' and restored['raw'] == self.plist_bytes,
             'maintenance_same_original_parked_inode_and_bytes_restored')
        self._read_plist(restored['expected'], self.plist_bytes)
        self.consumer_fence('before-pre-provider-original-bootstrap', self.original_rows, None)
        parent.assert_no_provider_dispatch()
        self.phase = 'restoring-original-before-provider'
        self._intent('bootstrap-original-before-provider')
        try:
            row, _, stderr = self._command('maintenance-bootstrap-original-before-provider',
                ['/bin/launchctl', 'bootstrap', DOMAIN, str(PLIST)])
            need(row['exitCode'] == 0 and not stderr, 'maintenance_original_restore_bootstrap_known_zero')
            self._complete('bootstrap-original-before-provider', {'exitCode': 0,
                'providerAttemptCount': 0, 'originalOverrideAbsent': True})
            deadline = min(self.until, self.clock() + 15)
            while True:
                current = self.query()
                if current is not None and current.get('state') == 'running' and type(current.get('pid')) is int:
                    break
                need(self.clock() < deadline, 'maintenance_original_restore_cold_start_budget')
                time.sleep(min(.1, max(0, deadline - self.clock())))
            prior = self.binding['loadedSecond']
            need(all(current.get(key) == prior.get(key) for key in
                 ('path', 'program', 'arguments', 'observedEnvironmentScope')),
                 'maintenance_original_restored_exact_registration_configuration')
            pid = current['pid'];new = self.reader.read(pid)
            need(pid not in self.original_rows and new['uid'] == 501 and new['ppid'] == 1
                 and new['executable'] == NODE and not self.reader.children(pid),
                 'maintenance_original_restored_new_node_birth_without_unclassified_children')
            for number in range(2):
                parent.assert_no_provider_dispatch();self.parking.verify();self.wrapper_inputs.verify()
                need(self.disabled() is None and self.query() == current
                     and self.reader.read(pid) == new and not self.reader.children(pid),
                     'maintenance_original_restored_same_new_birth_twice')
                if number == 0:time.sleep(min(.15, self.within()))
            self._write('original-gateway-restored-before-provider.private.json',
                {'registration': current, 'process': new, 'originalOverrideAbsent': True,
                 'sameOriginalPlistInodeAndBytes': True, 'sourceCredentialRollbackExecuted': False})
            self.new_process = new
            self.phase = 'original-restored-before-provider'
            self.report.update(originalRegistrationRestoredBeforeAnyProviderAttempt=True,
                originalOverrideAbsencePreserved=True, gatewayRuntimeQualified=False,
                productionRollbackQualified=False)
        except BaseException:
            self.unknown = True
            raise

    def close(self):
        if self.closed:
            return self.report
        errors = []
        for row in reversed(self.descriptors):
            if not row['closeAttempts']:
                try:
                    self._close_descriptor(row)
                except BaseException as error:
                    errors.append(type(error).__name__)
        self.closed = True
        self.report.update(phase=self.phase, unknown=self.unknown,
            originalRefreshChildrenRetired=len(self.retired_refresh_children),
            originalRefreshChildRetirementKnown=self.owned_refresh_child is None,
            originalDescriptorsOpened=len(self.descriptors), closeErrorTypes=errors,
            allOriginalDescriptorsClosedOnce=all(row['closed'] and row['closeAttempts'] == 1 for row in self.descriptors),
            registeredGatewayMayRemainStopped=self.phase not in ('new', 'binding-original', 'original-bound', 'safe-local-bootstrap-complete', 'original-restored-before-provider'),
            fullRollbackOrProductionCutoverQualified=False)
        if errors or not self.report['allOriginalDescriptorsClosedOnce'] or self.owned_refresh_child is not None:
            self.report['ok'] = False
        return self.report

