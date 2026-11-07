#!/usr/bin/env python3
"""Same-parent capture of the two files named by the current gateway wrapper.

The caller first observes the exact registered launchd argv. This module opens
only argv[1] and argv[2], retains their non-alias descriptor chains, and joins
them to the same parent's completed gateway/config observation. All paths,
environment values and whole-file digests stay private. No database is opened.
"""
from __future__ import annotations

import copy
import hashlib
import json
import os
from pathlib import Path
import stat
import time

import mac_gateway_parameter_wrapper_fallback_r1 as fallback

FIELDS = ('st_dev', 'st_ino', 'st_uid', 'st_gid', 'st_mode', 'st_nlink',
          'st_size', 'st_mtime_ns', 'st_ctime_ns')


class WrapperInputsRefused(RuntimeError):
    pass


def need(value, code):
    if not value:
        raise WrapperInputsRefused(code)


def full(value):
    return tuple(getattr(value, key) for key in FIELDS)


class CurrentParameterWrapperInputs:
    def __init__(self, *, until, source_fence, private_write, clock=time.monotonic):
        need(clock() < until <= clock() + 45 and callable(source_fence) and callable(private_write),
             'wrapper_inputs_original_parent_45_second_scope')
        self.until, self.clock = until, clock
        self.source_fence, self.private_write = source_fence, private_write
        self.rows, self.parents, self.files = [], {}, []
        self.arguments = self.source_binding = self.prepared = None
        self.closed, self.failed, self.prepare_attempted = False, False, False
        self.report = {'schema': 'heptabao.current-parameter-wrapper-inputs.public.r1',
            'ok': False, 'registeredSourceFileCount': 0, 'sqlConnections': 0,
            'childCount': 0, 'networkCalls': 0, 'providerCalls': 0, 'serviceActions': 0,
            'productionWrites': 0, 'sourceNamesValuesOrDigestsPublished': False,
            'sameParentOriginalConfigAndGatewayRequired': True,
            'productionFallbackQualified': False, 'runningPluginMemoryQualified': False}

    def _within(self):
        need(not self.closed and not self.failed and self.clock() < self.until,
             'wrapper_inputs_original_deadline_or_failed_context')

    def _track(self, fd, path, kind):
        row = {'fd': fd, 'path': Path(path), 'kind': kind, 'closeAttempts': 0, 'closed': False}
        self.rows.append(row)
        row['identity'] = full(os.fstat(fd))
        return row

    def _parent(self, path):
        if path in self.parents:
            row = self.parents[path]
            self._verify_row(row)
            return row
        if path == path.parent:
            fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        else:
            ancestor = self._parent(path.parent)
            fd = os.open(path.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=ancestor['fd'])
        row = self._track(fd, path, 'directory')
        info = os.fstat(fd)
        need(stat.S_ISDIR(info.st_mode) and info.st_uid in (0, 501)
             and not stat.S_IMODE(info.st_mode) & 0o022, 'wrapper_inputs_held_parent_custody')
        self.parents[path] = row
        self._verify_row(row)
        return row

    def _verify_row(self, row):
        need(not row['closeAttempts'] and full(os.fstat(row['fd'])) == row['identity']
             == full(row['path'].lstat()), 'wrapper_inputs_whole9_named_and_held_generation')

    def _bytes(self, row):
        self._within()
        self._verify_row(row)
        size = row['identity'][6]
        result, offset = [], 0
        while offset <= size:
            self._within()
            block = os.pread(row['fd'], min(16384, size + 1 - offset), offset)
            if not block:
                break
            result.append(block)
            offset += len(block)
        need(offset == size, 'wrapper_inputs_complete_original_file')
        self._verify_row(row)
        return b''.join(result)

    def _open_file(self, path, kind):
        self._within()
        parent = self._parent(path.parent)
        row = self._track(os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                                  dir_fd=parent['fd']), path, kind)
        info = os.fstat(row['fd'])
        need(stat.S_ISREG(info.st_mode) and info.st_uid == 501 and info.st_gid == 20
             and info.st_nlink == 1 and not stat.S_IMODE(info.st_mode) & 0o022
             and 0 < info.st_size <= 65536, 'wrapper_inputs_existing_private_original_source')
        if kind == 'environment':
            need(stat.S_IMODE(info.st_mode) == 0o600, 'wrapper_inputs_private_environment_mode')
        self.files.append(row)
        row['raw'] = self._bytes(row)
        return row

    def open(self, arguments):
        need(self.arguments is None and not self.rows, 'wrapper_inputs_open_once')
        self._within()
        need(isinstance(arguments, list) and len(arguments) == 8
             and all(isinstance(item, str) for item in arguments)
             and arguments[0] == '/bin/sh'
             and fallback.normalized_home_path(arguments[1]) and arguments[1].endswith('.sh')
             and fallback.normalized_home_path(arguments[2]) and arguments[1] != arguments[2]
             and arguments[3:] == ['/opt/homebrew/opt/node/bin/node',
                '/opt/homebrew/lib/node_modules/openclaw/dist/index.js', 'gateway', '--port', '18789'],
             'wrapper_inputs_exact_observed_registered_argument_shape')
        self.arguments = copy.deepcopy(arguments)
        try:
            self.source_fence()
            wrapper = self._open_file(Path(arguments[1]), 'wrapper')
            environment = self._open_file(Path(arguments[2]), 'environment')
            self.report['wrapperShape'] = fallback.parameter_wrapper_shape(wrapper['raw'])
            values, exports = fallback.literal_environment(environment['raw'])
            self.report['literalEnvironmentAssignmentCount'] = len(values)
            self.report['literalExportedAssignmentCount'] = sum(exports.values())
            self.source_binding = {
                'schema': 'heptabao.current-parameter-wrapper.private.r1',
                'arguments': self.arguments,
                'wrapperPath': str(wrapper['path']), 'wrapperFull9': wrapper['identity'],
                'wrapperSha256': hashlib.sha256(wrapper['raw']).hexdigest(),
                'environmentPath': str(environment['path']), 'environmentFull9': environment['identity'],
                'environmentSha256': hashlib.sha256(environment['raw']).hexdigest(),
                'sameParentRetainedDescriptors': True,
            }
            self.verify()
            self.report['registeredSourceFileCount'] = 2
            return self
        except BaseException:
            self.failed = True
            self.close()
            raise

    def verify(self):
        self._within()
        need(self.arguments is not None and len(self.files) == 2, 'wrapper_inputs_original_two_files_bound')
        for row in self.parents.values():
            self._verify_row(row)
        for row in self.files:
            need(self._bytes(row) == row['raw'], 'wrapper_inputs_original_whole_bytes_unchanged')
        self.source_fence()
        return True

    def prepare(self, gateway_binding, config_bytes, plist_bytes):
        need(not self.prepare_attempted, 'wrapper_inputs_prepare_once')
        self.prepare_attempted = True
        self.verify()
        need(gateway_binding.get('arguments') == self.arguments
             and gateway_binding.get('loadedFirst', {}).get('arguments') == self.arguments
             and gateway_binding.get('loadedSecond', {}).get('arguments') == self.arguments,
             'wrapper_inputs_same_parent_two_current_gateway_observations')
        prepared = fallback.make_parameter_wrapper_fallback(config_bytes, plist_bytes, gateway_binding,
                        self.files[0]['raw'], self.files[1]['raw'], self.source_binding)
        self.verify()
        # Only same-parent private review outputs are published here. Never
        # write the fixed production fallback path or the current LaunchAgent.
        for name, raw in (
            ('gateway-wrapper.original.private', self.files[0]['raw']),
            ('gateway-wrapper-environment.original.private', self.files[1]['raw']),
            ('gateway-parameter-fallback.review.config.private.json', prepared['configBytes']),
            ('gateway-parameter-fallback.review.plist.private', prepared['plistBytes']),
            ('gateway-parameter-fallback.review.environment.private', prepared['environmentBytes']),
            ('gateway-wrapper-source-binding.private.json',
             (json.dumps(self.source_binding, sort_keys=True, separators=(',', ':')) + '\n').encode()),
        ):
            self._within()
            self.private_write(name, raw)
        self.verify()
        self.prepared = prepared
        self.report.update(ok=True, sourceFull9AndBytesStable=True,
                           privateSameParentSourceBindingDurable=True,
                           parameterFallbackReviewPrepared=True, fallback=prepared['public'])
        return prepared, copy.deepcopy(self.source_binding), self.report

    def close(self):
        if self.closed:
            return self.report
        errors = []
        for row in reversed(self.rows):
            if not row['closeAttempts']:
                row['closeAttempts'] += 1
                try:
                    os.close(row['fd'])
                    row['closed'] = True
                except BaseException as error:
                    errors.append(type(error).__name__)
        self.closed = True
        self.report.update(descriptorsOpened=len(self.rows), closeErrorTypes=errors,
            allOriginalDescriptorsClosedOnce=all(row['closed'] and row['closeAttempts'] == 1 for row in self.rows))
        if not self.report['allOriginalDescriptorsClosedOnce']:
            self.report['ok'] = False
        return self.report

