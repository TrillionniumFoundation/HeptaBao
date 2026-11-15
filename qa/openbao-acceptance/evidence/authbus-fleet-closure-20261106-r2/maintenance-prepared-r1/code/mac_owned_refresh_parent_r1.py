#!/usr/bin/env python3
"""Prepared original-parent driver; no import-time I/O or provider call.

Only the fixed Node worker may be started. Actual gateway/process/source checks
answer its inherited anonymous pipes; a status receipt never grants authority.
Each original owner slot is consumed before launch and cannot be retried here.
"""
from __future__ import annotations

import base64
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import select
import stat
import subprocess
import time

ROOT = Path('/Users/qianqi/heptabao-authbus-writer-maintenance-20261106-r1')
LEDGER = Path('/Users/qianqi/heptabao-authbus-refresh-once-ledger-20261106')
LIVE = Path('/Users/qianqi/.openclaw')
NODE = '/opt/homebrew/Cellar/node/25.9.0_1/bin/node'
WORKER = ROOT / 'code/mac_refresh_production_worker_r1.mjs'
OWNER = LIVE / 'agents/main/agent'
STAGES = frozenset(('before-lock', 'under-lock', 'after-current-owner-read', 'intent-durable',
    'provider-preparation', 'before-dispatch-record', 'final-native-send', 'after-provider-return',
    'before-original-owner-cas', 'after-own-commit', 'before-read', 'after-read',
    'before-write-open', 'before-begin', 'after-commit', 'after-readback', 'worker-before-retirement'))
FIELDS = ('st_dev', 'st_ino', 'st_uid', 'st_gid', 'st_mode', 'st_nlink',
          'st_size', 'st_mtime_ns', 'st_ctime_ns')
MAX_MESSAGE = 4096


class ParentRefused(RuntimeError):
    pass


def need(value, code):
    if not value:
        raise ParentRefused(code)


def full(value):
    return tuple(getattr(value, key) for key in FIELDS)


def encoded(value):
    return (json.dumps(value, ensure_ascii=False, separators=(',', ':'), allow_nan=False) + '\n').encode()


def strict_json(raw, maximum):
    need(isinstance(raw, bytes) and 0 < len(raw) <= maximum, 'parent_bounded_original_json')
    def unique(pairs):
        value = {}
        for key, item in pairs:
            need(key not in value, 'parent_duplicate_original_json_key')
            value[key] = item
        return value
    def invalid(_):
        raise ParentRefused('parent_nonfinite_original_json')
    try:
        return json.loads(raw.decode('utf-8', 'strict'), object_pairs_hook=unique, parse_constant=invalid)
    except ParentRefused:
        raise
    except BaseException as error:
        raise ParentRefused('parent_original_json_parse') from error


def parse_request(raw, *, nonce, ordinal, sequence):
    value = strict_json(raw, MAX_MESSAGE)
    need(type(value) is dict and set(value) == {'schema', 'nonce', 'sequence', 'ordinal', 'stage'}
         and value['schema'] == 'heptabao.refresh-writer-check.private.r1'
         and value['nonce'] == nonce and type(value['sequence']) is int and value['sequence'] == sequence
         and type(value['ordinal']) is int and value['ordinal'] == ordinal
         and value['stage'] in STAGES and sequence < 96,
         'parent_exact_original_worker_request')
    expected = {'schema': value['schema'], 'nonce': nonce, 'sequence': sequence,
                'ordinal': ordinal, 'stage': value['stage']}
    need(raw == encoded(expected), 'parent_canonical_complete_request')
    return expected


def response(request, allowed):
    need(type(allowed) is bool, 'parent_typed_actual_authorization')
    return encoded({**request, 'allowed': allowed})


def capsule_scope(raw, ordinal):
    value = strict_json(raw, 1048576)
    need(type(value) is dict, 'parent_private_capsule_object')
    entries = value.get('ownerEntries')
    need(value.get('schema') == 'heptabao.actual-sdk-selected-owner-credentials.private.r1'
         and value.get('host') == 'mac' and type(ordinal) is int and 0 <= ordinal < 3
         and isinstance(entries, list) and len(entries) == 3,
         'parent_original_selected_main_three_capsule')
    identifiers, refreshes = [], []
    for entry in entries:
        credential = entry.get('credential') if type(entry) is dict else None
        need(type(entry) is dict and entry.get('ownerAgentDir') == str(OWNER)
             and entry.get('actualProvider') == 'openai'
             and isinstance(entry.get('profileId'), str) and 0 < len(entry['profileId']) <= 240
             and type(credential) is dict and credential.get('provider') == 'openai'
             and credential.get('type') == 'oauth' and isinstance(credential.get('refresh'), str)
             and 0 < len(credential['refresh']) <= 131072,
             'parent_exact_selected_owner_object')
        identifiers.append(entry['profileId'])
        refreshes.append(credential['refresh'])
    need(len(set(identifiers)) == len(set(refreshes)) == 3,
         'parent_duplicate_refresh_object_or_owner_refused')
    return tuple(identifiers)


def original_success(value, ordinal):
    need(type(value) is dict and value.get('schema') == 'heptabao.actual-main3-refresh-worker.public.r1'
         and value.get('ok') is True and type(value.get('ordinal')) is int and value['ordinal'] == ordinal
         and value.get('sourceLoaderClosuresKnown') is True and value.get('outputHooksRestored') is True
         and value.get('writerChannel', {}).get('allOriginalPipesClosedOnce') is True
         and value.get('generation', {}).get('allOwnedDescriptorsClosedOnce') is True
         and value.get('ledger', {}).get('allOwnedDescriptorsClosedOnce') is True,
         'parent_complete_original_worker_success_and_closures')
    once = value.get('once', {})
    need(once.get('ok') is True and once.get('localOwnerCommitKnown') is True
         and once.get('knownTerminalPrivateRecord') is True and once.get('outcomeUnknown') is False
         and all(type(once.get(key)) is int and once[key] == 1 for key in
                 ('providerDispatches', 'completeResponsesCaptured', 'normalizedResponsesDurable', 'rawCasInvocations'))
         and once.get('providerExchangeAccepted') is True
         and all(once.get('providerReceipt', {}).get(key) is True for key in
                 ('originalFunctionSettled', 'transportClosureKnown', 'contextClosed'))
         and once.get('rawBeforeReceipt', {}).get('allReturnedConnectionsClosedOnce') is True
         and once.get('rawCasReceipt', {}).get('allReturnedConnectionsClosedOnce') is True
         and once.get('rawCasReceipt', {}).get('independentPostCommitReadback') is True
         and all(once.get('mutexReceipt', {}).get(key) is True for key in
                 ('released', 'originalHandleClosed', 'parentDescriptorsClosed', 'guardianClosed')),
         'parent_one_complete_provider_original_cas_and_mutex')
    return once


class OwnedRefreshParent:
    def __init__(self, *, maintenance, reader, custody, signals, until, source_fence,
                 read_private, write_private, write_closure, clock=time.monotonic):
        need(clock() < until <= clock() + 600 and until == maintenance.until,
             'parent_same_original_maintenance_deadline')
        for function in (source_fence, read_private, write_private, write_closure,
                         custody.require_waitid, custody.capture_child,
                         custody.exit_observation, custody.observed_returncode, custody.stop_once_unreaped,
                         maintenance.bind_owned_refresh_child, maintenance.retire_owned_refresh_child):
            need(callable(function), 'parent_actual_original_bindings')
        self.maintenance, self.reader, self.custody, self.signals = maintenance, reader, custody, signals
        self.until, self.source_fence, self.read_private, self.write_private, self.clock = (
            until, source_fence, read_private, write_private, clock)
        self.write_closure = write_closure
        self.attempts, self.committed, self.profile_ids = [], [], None
        self.blocked = self.closed = False
        self.report = {'schema': 'heptabao.owned-refresh-parent.public.r1', 'ok': False,
            'originalMaintenanceMaximumSeconds': 600, 'originalOwnerMaximumSeconds': 120,
            'credentialValuesOrDigestsPublished': False, 'privateRequestNoncesPublished': False,
            'sourceReadFromOldKeeper': False, 'writerAuthorityFromReceiptFile': False,
            'automaticProviderOrChildRetry': False, 'automaticGatewayRestore': False,
            'originalWorkerCount': 0, 'knownCommittedOwnerCount': 0, 'children': []}

    def _within(self, until):
        need(not self.closed and self.signals.pending is None and self.clock() < min(until, self.until),
             'parent_original_deadline_or_signal')

    def _write(self, name, value):
        raw = value if isinstance(value, bytes) else encoded(value)
        need(re.fullmatch(r'owner-0[123]\.[a-z0-9.-]{1,130}', name) and len(raw) <= 2 * 1048576,
             'parent_fixed_bounded_private_artifact')
        self.write_private(name, raw)

    def _ledger_commit(self, ordinal, once):
        base = LEDGER / ('owner-0%d' % (ordinal + 1))
        def read(name):
            return strict_json(self.read_private(base / name, 1048577), 1048577)
        scope = strict_json(self.read_private(LEDGER / 'scope.private.json', 1048577), 1048577)
        need(scope.get('schema') == 'heptabao.main3-once-private-scope.r1'
             and scope.get('provider') == 'openai' and scope.get('stateRoot') == str(LIVE)
             and scope.get('ownerDir') == str(OWNER) and tuple(scope.get('profileIds', ())) == self.profile_ids,
             'parent_same_fixed_private_scope')
        intent, dispatch, metadata, normalized, outcome = (read(name) for name in
            ('intent.private.json', 'dispatch-unknown.private.json', 'provider-response.private.json',
             'normalized-credential.private.json', 'outcome.private.json'))
        body = self.read_private(base / 'provider-response.private.bin', 1048576)
        need(intent.get('schema') == 'heptabao.refresh-once-intent-private.r1'
             and intent.get('ordinal') == ordinal and type(intent.get('ordinal')) is int
             and intent.get('profileId') == self.profile_ids[ordinal] and intent.get('ownerDir') == str(OWNER)
             and intent.get('provider') == 'openai' and isinstance(intent.get('attemptId'), str)
             and re.fullmatch(r'[a-f0-9-]{36}', intent['attemptId'])
             and dispatch.get('schema') == 'heptabao.provider-dispatch-private.r1'
             and dispatch.get('state') == 'UNKNOWN' and dispatch.get('attemptId') == intent['attemptId'],
             'parent_original_private_intent_and_dispatch')
        digest = hashlib.sha256(body).hexdigest()  # private only, never projected
        need(metadata.get('schema') == 'heptabao.provider-response-private.r1'
             and type(metadata.get('status')) is int and 200 <= metadata['status'] < 300
             and metadata['status'] == once.get('providerResponseStatus')
             and metadata.get('bodyBytes') == len(body) and metadata.get('bodySha256') == digest
             and normalized.get('schema') == 'heptabao.normalized-response-private.r1'
             and normalized.get('responseBodySha256') == digest
             and normalized.get('beforeFingerprint') == intent.get('beforeFingerprint')
             and outcome.get('schema') == 'heptabao.refresh-once-terminal-private.r1'
             and outcome.get('state') == 'COMMITTED' and outcome.get('originalOwnerCasKnown') is True
             and outcome.get('providerStatus') == metadata['status'],
             'parent_durable_original_complete_response_and_commit')
        return {'ordinal': ordinal, 'attemptId': intent['attemptId'], 'outcome': outcome,
                'normalizedCredential': normalized['credential'], 'privateResponseSha256': digest}

    def run_one(self, *, ordinal, capsule_bytes, capsule_identity, fresh_capture_fence):
        """Caller has just completed its original fresh capture under this parent.

        The supplied fence performs named full9/private-byte checks now, not a
        historical receipt check. The child independently re-reads the complete
        live owner before-image under the original SDK mutex before dispatch.
        """
        need(not self.blocked and type(ordinal) is int and ordinal == len(self.attempts) < 3
             and len(self.committed) == ordinal and callable(fresh_capture_fence),
             'parent_next_original_ordinal_only_after_prior_known_closure')
        phase_until = min(self.until, self.clock() + 120)
        self._within(phase_until)
        need(isinstance(capsule_identity, (tuple, list)) and len(capsule_identity) == 9
             and all(type(x) in (str, int) and str(x).isdigit() for x in capsule_identity),
             'parent_private_capsule_full9_shape')
        ids = capsule_scope(capsule_bytes, ordinal)
        need(self.profile_ids is None or self.profile_ids == ids, 'parent_same_private_three_owner_order')
        self.profile_ids = ids
        fresh_capture_fence()
        self.source_fence()
        self.maintenance.verify_quiesced('before-original-refresh-child')
        self.custody.require_waitid()
        self._within(phase_until)
        row = {'ordinal': ordinal, 'child': None, 'custody': None, 'libproc': None,
               'stopAttempted': False, 'fds': [], 'requests': [], 'complete': False,
               'stdoutEof': False, 'stderrEof': False, 'requestEof': False,
               'started': self.clock(), 'deadline': phase_until}
        self.attempts.append(row)  # a failing durable intent still consumes this original slot
        result = {'ordinal': ordinal, 'ok': False, 'childDispatched': False, 'writerRequests': 0,
                  'writerAuthorizations': 0, 'writerRefusals': 0, 'nextOrdinalAdmitted': False}
        self.report['children'].append(result)
        output, errors, incoming, pending_response = bytearray(), bytearray(), bytearray(), bytearray()
        p, refused, sequence, private_input = None, False, 0, b''

        def own(fd, name, stream=None):
            owned = {'fd': fd, 'name': name, 'stream': stream, 'closed': False, 'closeAttempts': 0}
            row['fds'].append(owned)
            return owned

        def close(owned):
            need(owned['closeAttempts'] == 0, 'parent_original_pipe_close_once')
            owned['closeAttempts'] += 1
            try:
                owned['stream'].close() if owned['stream'] is not None else os.close(owned['fd'])
                owned['closed'] = True
            except BaseException:
                owned['unknown'] = True
                raise

        try:
            self._write('owner-0%d.launch-intent.private.json' % (ordinal + 1),
                {'schema': 'heptabao.original-refresh-child-intent.private.r1', 'ordinal': ordinal,
                 'parentPid': os.getpid(), 'executable': NODE, 'worker': str(WORKER),
                 'originalPhaseDeadlineMonotonic': phase_until})
            nonce = secrets.token_hex(32)
            with self.signals.critical():
                request_r, request_w = os.pipe()
                request_read, request_write = own(request_r, 'request-read'), own(request_w, 'request-write-child')
                response_r, response_w = os.pipe()
                response_read, response_write = own(response_r, 'response-read-child'), own(response_w, 'response-write')
            channels = {}
            for name, descriptor in (('request', request_w), ('response', response_r)):
                info = os.fstat(descriptor)
                need(stat.S_ISFIFO(info.st_mode) and info.st_uid == 501,
                     'parent_original_owned_anonymous_pipe')
                channels[name] = {'descriptor': descriptor, 'identity': [str(x) for x in full(info)[:5]]}
            environment = {'PATH': '/usr/bin:/bin:/usr/sbin:/sbin', 'LANG': 'C', 'LC_ALL': 'C',
                'HOME': '/Users/qianqi', 'OPENCLAW_STATE_DIR': str(LIVE), 'TMPDIR': str(ROOT / 'output/tmp')}
            self.source_fence()
            with self.signals.critical():
                self._within(phase_until)
                p = subprocess.Popen([NODE, str(WORKER)], cwd=str(ROOT), env=environment,
                    stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                    close_fds=True, pass_fds=(request_w, response_r), start_new_session=True)
                row['child'] = p
                result['childDispatched'] = True
                self.report['originalWorkerCount'] += 1
                stdin, stdout, stderr = (own(stream.fileno(), name, stream) for name, stream in
                    (('stdin', p.stdin), ('stdout', p.stdout), ('stderr', p.stderr)))
                close(request_write)
                close(response_read)
            row['custody'] = self.custody.capture_child(p, until=phase_until)
            identity = self.reader.read(p.pid)
            need(identity['pid'] == p.pid and identity['ppid'] == os.getpid()
                 and identity['pgid'] == p.pid and identity['uid'] == 501 and identity['executable'] == NODE
                 and not self.reader.children(p.pid), 'parent_original_fixed_node_birth_before_private_input')
            row['libproc'] = identity
            self.maintenance.bind_owned_refresh_child(identity, row['custody'])
            row['maintenanceChildBound'] = True
            fresh_capture_fence()
            self.maintenance.verify_quiesced('before-original-private-input')
            self._within(phase_until)
            remaining_ms = int((phase_until - self.clock()) * 1000)
            need(0 < remaining_ms <= 120000, 'parent_remaining_original_worker_budget')
            private_input = encoded({'schema': 'heptabao.main3-refresh-original-worker.private.r1',
                'ordinal': ordinal, 'remainingMilliseconds': remaining_ms, 'parentPid': os.getpid(),
                'parentNonce': nonce, 'channels': channels,
                'capsulePath': str(ROOT / 'captures' / ('owner-0%d' % (ordinal + 1)) /
                                   'output/selected-owner-credentials.private.json'),
                'capsuleIdentity': [str(x) for x in capsule_identity],
                'capsuleBytesBase64': base64.b64encode(capsule_bytes).decode('ascii')})
            self._write('owner-0%d.original-input.private.json' % (ordinal + 1), private_input)
            for fd in (request_r, response_w, stdin['fd'], stdout['fd'], stderr['fd']):
                os.set_blocking(fd, False)
            read_fds = {request_r: 'request', stdout['fd']: 'stdout', stderr['fd']: 'stderr'}
            sent, event = 0, None
            while read_fds or event is None or pending_response:
                self._within(phase_until)
                writes = ([stdin['fd']] if sent < len(private_input) else []) + (
                    [response_w] if pending_response else [])
                ready, writable, _ = select.select(list(read_fds), writes, [],
                                                  min(0.025, phase_until - self.clock()))
                for fd in writable:
                    if fd == stdin['fd']:
                        count = os.write(fd, private_input[sent:sent + 65536])
                        need(count > 0, 'parent_original_stdin_progress')
                        sent += count
                        if sent == len(private_input):
                            close(stdin)
                    else:
                        self._within(phase_until)
                        count = os.write(fd, pending_response)
                        need(count > 0, 'parent_original_authorization_progress')
                        del pending_response[:count]
                for fd in ready:
                    kind = read_fds[fd]
                    data = os.read(fd, 65536 if kind != 'request' else MAX_MESSAGE + 1)
                    if not data:
                        del read_fds[fd]
                        row[{'request': 'requestEof', 'stdout': 'stdoutEof', 'stderr': 'stderrEof'}[kind]] = True
                        if kind == 'request':
                            need(not incoming, 'parent_no_partial_request_at_original_eof')
                        continue
                    if kind in ('stdout', 'stderr'):
                        target = output if kind == 'stdout' else errors
                        target.extend(data)
                        need(len(target) <= (1048576 if kind == 'stdout' else 262144),
                             'parent_original_output_bound')
                        continue
                    incoming.extend(data)
                    need(len(incoming) <= MAX_MESSAGE, 'parent_original_request_bound')
                    if b'\n' not in incoming:
                        continue
                    need(incoming[-1] == 10 and incoming.count(b'\n') == 1 and not pending_response,
                         'parent_one_complete_outstanding_worker_request')
                    request = parse_request(bytes(incoming), nonce=nonce, ordinal=ordinal, sequence=sequence)
                    incoming.clear()
                    sequence += 1
                    result['writerRequests'] += 1
                    allowed = False
                    try:
                        need(not refused, 'parent_prior_writer_check_refused')
                        self.source_fence()
                        need(self.reader.read(p.pid) == row['libproc'] and not self.reader.children(p.pid),
                             'parent_same_original_node_during_authorization')
                        self.maintenance.verify_quiesced(request['stage'])
                        self._within(phase_until)
                        allowed = True
                    except BaseException:
                        refused = True
                        self.blocked = True
                    audit = {**request, 'allowed': allowed}
                    self._write('owner-0%d.writer-%03d.private.json' % (ordinal + 1, request['sequence']), audit)
                    pending_response.extend(response(request, allowed))
                    row['requests'].append(audit)
                    result['writerAuthorizations' if allowed else 'writerRefusals'] += 1
                event = self.custody.exit_observation(p)
            self._within(phase_until)
            need(sent == len(private_input) and row['stdoutEof'] and row['stderrEof'] and row['requestEof'],
                 'parent_all_original_input_and_streams_complete')
            row['observedExit'] = event
            result['originalObservedExitCode'] = self.custody.observed_returncode(event)
            row['complete'] = True
        except BaseException as error:
            self.blocked = True
            result['errorType'] = type(error).__name__
            result['errorCode'] = str(error) if isinstance(error, ParentRefused) else 'parent_original_execution_refused'
        finally:
            self._retire_original(row, result, p, close, output, errors)
        return self._accept_original(row, result, p, output, errors)

    def _retire_original(self, row, result, child, close, output, errors):
        ordinal = row['ordinal']
        with self.signals.critical():
            if child is not None:
                need(not row['stopAttempted'], 'parent_original_child_stop_not_replayed')
                row['stopAttempted'] = True
                try:
                    row['cleanup'] = self.custody.stop_once_unreaped(child, row['custody'])
                except BaseException:
                    row['cleanup'] = {'ok': False, 'directChildReaped': child.returncode is not None,
                                      'allGroupRowsEmptyAfterReap': False, 'outcomeUnknown': True}
            for item in reversed(row['fds']):
                if not item['closeAttempts']:
                    try:
                        close(item)
                    except BaseException:
                        self.blocked = True
            result.update(originalPipeCount=len(row['fds']),
                allOriginalPipesClosedOnce=all(item['closed'] and item['closeAttempts'] == 1 for item in row['fds']),
                originalChildClosureKnown=child is not None and row.get('cleanup', {}).get('ok') is True
                    and row['cleanup'].get('directChildReaped') is True
                    and row['cleanup'].get('allGroupRowsEmptyAfterReap') is True,
                completeBeforeOriginalDeadline=row['complete'], stdoutBytes=len(output), stderrBytes=len(errors),
                elapsedSeconds=self.clock() - row['started'])
            if row.get('maintenanceChildBound'):
                if result['originalChildClosureKnown']:
                    try:
                        self.maintenance.retire_owned_refresh_child(row['libproc'], row['cleanup'])
                        result['originalChildRemovedFromTemporaryConsumerAllowance'] = True
                    except BaseException:
                        self.blocked = True
                        result['originalChildAllowanceRetirementUnknown'] = True
                else:
                    self.blocked = True
                    result['originalChildAllowanceRetirementUnknown'] = True
            try:
                self.write_closure('owner-0%d.original.stdout.private' % (ordinal + 1), bytes(output))
                self.write_closure('owner-0%d.original.stderr.private' % (ordinal + 1), bytes(errors))
                self.write_closure('owner-0%d.original-custody.private.json' % (ordinal + 1), encoded({
                    'custody': row['custody'], 'libproc': row['libproc'],
                    'cleanup': row.get('cleanup'), 'result': result}))
            except BaseException:
                self.blocked = True
                result['privatePublicationUnknown'] = True

    def _accept_original(self, row, result, child, output, errors):
        ordinal = row['ordinal']
        try:
            need(not self.blocked and row['complete'] and result['originalChildClosureKnown']
                 and result['allOriginalPipesClosedOnce'] and child.returncode == 0
                 and result['originalObservedExitCode'] == 0 and not errors,
                 'parent_original_worker_and_resources_closed_known_zero')
            once = original_success(strict_json(bytes(output), 1048576), ordinal)
            committed = self._ledger_commit(ordinal, once)
            self._write('owner-0%d.parent-accepted-commit.private.json' % (ordinal + 1), committed)
            self.committed.append(committed)
            result.update(ok=True, originalCompleteResponseAndCommitReadback=True,
                          providerDispatches=1, sourceCasInvocations=1)
            self.report['knownCommittedOwnerCount'] = len(self.committed)
            self._within(self.until)
            self.maintenance.verify_quiesced('after-original-worker-closed')
            self.source_fence()
            return copy.deepcopy(result)
        except BaseException:
            self.blocked = True
            result['ok'] = False
            result['nextOrdinalAdmitted'] = False
            self.maintenance.unknown = True
            raise

    def all_committed(self, *, current_epoch_fence):
        need(not self.blocked and len(self.attempts) == len(self.committed) == 3
             and all(row['ok'] for row in self.report['children']) and callable(current_epoch_fence),
             'parent_all_three_original_committed_and_closed')
        self._within(self.until)
        self.source_fence()
        self.maintenance.verify_quiesced('all-original-owners-closed')
        current_epoch_fence(tuple(self.committed))
        self.maintenance.phase = 'committed'
        self.report.update(ok=True, allThreeOriginalCommitRecordsReadBack=True,
                           currentPostRefreshEpochObserved=True, providerApplicationLivenessProven=False,
                           productionRollbackQualified=False, productionTrafficSwitched=False)
        return copy.deepcopy(self.report)

    def close(self):
        self.closed = True
        self.report['noAutomaticServiceActionOnClose'] = True
        self.report['unknownOrFailedEffectBlocksRestore'] = self.blocked
        return copy.deepcopy(self.report)
