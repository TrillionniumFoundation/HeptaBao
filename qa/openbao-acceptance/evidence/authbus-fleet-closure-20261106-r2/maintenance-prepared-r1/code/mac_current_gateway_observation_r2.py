#!/usr/bin/env python3
"""Read-only binding of the one registered Mac gateway in a shared parent.

The parent supplies the previously qualified Commands, ProcessReader and
parse_print implementations and a private create-only output writer. Its one
inventory child supplies the original configuration bytes/full9; this module
does not open a credential database, registry, configuration file or gateway
RPC. Two launchctl-print commands bracket the same parent inventory phase.
Their original stdout/argv/environment and output digests stay private.

This observes launchd registration and process identity, not JavaScript heap
state. A prepared fallback is never a service action or a runtime proof.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import plistlib
import re
import stat
import time

import mac_gateway_local_fallback_r1 as fallback

HOME = Path('/Users/qianqi')
LIVE = HOME / '.openclaw'
CONFIG = LIVE / 'openclaw.json'
LABEL = 'ai.openclaw.gateway'
TARGET = 'gui/501/' + LABEL
PLIST = HOME / 'Library/LaunchAgents' / (LABEL + '.plist')
NODE = '/opt/homebrew/Cellar/node/25.9.0_1/bin/node'
FIELDS = ('st_dev', 'st_ino', 'st_uid', 'st_gid', 'st_mode', 'st_nlink',
          'st_size', 'st_mtime_ns', 'st_ctime_ns')
# These 18 keys come from the actual pre-bootstrap selection signature. The
# additional keys cover the actual shell fallback and Node preload branches.
SELECTION_KEYS = (
    'ANDROID_DATA', 'HOME', 'HOMEDRIVE', 'HOMEPATH', 'OPENCLAW_AGENT_DIR',
    'OPENCLAW_CONFIG_PATH', 'OPENCLAW_HOME', 'OPENCLAW_INCLUDE_ROOTS',
    'OPENCLAW_NIX_MODE', 'OPENCLAW_OAUTH_DIR', 'OPENCLAW_PACKAGE_DIR',
    'OPENCLAW_PROFILE', 'OPENCLAW_STATE_DIR', 'OPENCLAW_TEST_FAST',
    'OPENCLAW_WORKSPACE_DIR', 'PI_CODING_AGENT_DIR', 'PREFIX', 'USERPROFILE',
)
EXTRA_ENV_KEYS = ('OPENCLAW_LOAD_SHELL_ENV', 'OPENCLAW_DEFER_SHELL_ENV_FALLBACK',
                  'OPENCLAW_SHELL_ENV_TIMEOUT_MS', 'SHELL', 'NODE_OPTIONS',
                  'NODE_PATH', 'OPENCLAW_AUTH_STORE_READONLY',
                  'OPENCLAW_SERVICE_MARKER')
ENV_KEYS = frozenset(SELECTION_KEYS + EXTRA_ENV_KEYS)


class ObservationRefused(RuntimeError):
    pass


def need(value, code):
    if not value:
        raise ObservationRefused(code)


def identity(value):
    return tuple(int(getattr(value, key)) for key in FIELDS)


def normalize_full9(value):
    need(isinstance(value, (list, tuple)) and len(value) == 9
         and all(type(item) is int or isinstance(item, str)
                 and re.fullmatch(r'[0-9]{1,24}', item) for item in value),
         'gateway_exact_private_full9_shape')
    result = tuple(int(item) for item in value)
    need(all(0 <= item < 10 ** 24 for item in result),
         'gateway_nonnegative_bounded_private_full9')
    return result


def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'),
                       allow_nan=False) + '\n').encode()


def scoped_environments(raw):
    """Keep selected values privately, preserving each launchd environment layer.

    The qualified whole-record parser runs separately. In an environment block
    a value can contain braces, so only a complete closing line ends the block;
    braces inside a value are not treated as nesting. Duplicate selected keys
    in one layer and duplicate environment blocks are refused.
    """
    need(isinstance(raw, bytes) and len(raw) <= 262144,
         'gateway_bounded_environment_record')
    lines = raw.decode('utf-8', 'strict').splitlines()
    need(lines and lines[0].strip() == TARGET + ' = {',
         'gateway_environment_exact_target')
    result, depth, block = {}, 1, None
    known = ('environment', 'default environment', 'inherited environment')
    for line in lines[1:]:
        text = line.strip()
        if block is not None:
            if text == '}':
                block = None
                depth -= 1
                continue
            need(' => ' in text, 'gateway_complete_environment_mapping')
            key, value = text.split(' => ', 1)
            need(re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]{0,255}', key) is not None
                 and '\x00' not in value and len(value.encode()) <= 16384,
                 'gateway_bounded_typed_environment_mapping')
            if key in ENV_KEYS:
                need(key not in result[block], 'gateway_unique_selected_environment_key')
                result[block][key] = value
            continue
        if depth == 1 and any(text == name + ' = {' for name in known):
            block = text[:-4]
            need(block not in result, 'gateway_unique_environment_layer')
            result[block] = {}
            depth += 1
            continue
        depth += text.count('{') - text.count('}')
        need(depth >= 0, 'gateway_balanced_environment_record')
    need(depth == 0 and block is None, 'gateway_complete_environment_record')
    return result


def environment_projection(layers, plist_env):
    values = {key: [layer[key] for layer in layers.values() if key in layer]
              for key in ENV_KEYS}
    expected = {'HOME': str(HOME), 'OPENCLAW_HOME': str(HOME),
                'OPENCLAW_STATE_DIR': str(LIVE), 'OPENCLAW_CONFIG_PATH': str(CONFIG)}
    return {
        'selectedLaunchdEnvironmentLayerCount': len(layers),
        'selectedLaunchdEnvironmentKeyCount': sum(bool(items) for items in values.values()),
        'selectionLayerConflicts': sum(len(set(values[key])) > 1 for key in SELECTION_KEYS),
        'registeredHomeStateConfigValuesConsistent': all(
            all(value == target for value in values[key])
            and (key not in plist_env or plist_env[key] == target)
            for key, target in expected.items()),
        'configurationPathExplicitInLoadedScope': bool(values['OPENCLAW_CONFIG_PATH']),
        'configurationPathExplicitInPlist': 'OPENCLAW_CONFIG_PATH' in plist_env,
        'loadedProfileSelectorPresent': bool(values['OPENCLAW_PROFILE']),
        'loadedNodePreloadPresent': any(values[key] for key in ('NODE_OPTIONS', 'NODE_PATH')),
        'launchdEnvironmentIsJavaScriptMemoryProof': False,
    }


class FixedPlist:
    """Hold the exact fixed non-symlink chain, with full9 checked before close."""
    def __init__(self, remaining):
        self.remaining = remaining
        self.rows = []
        self.raw = None
        self.closed = False
        self.close_errors = []

    def open(self):
        need(not self.rows and self.raw is None and not self.closed,
             'gateway_plist_open_once')
        parent_fd = None
        current = Path('/')
        for number, name in enumerate(('/', *PLIST.parts[1:])):
            self.remaining()
            if number:
                current /= name
            leaf = current == PLIST
            named = os.lstat('/') if not number else os.stat(
                name, dir_fd=parent_fd, follow_symlinks=False)
            need((stat.S_ISREG(named.st_mode) if leaf else stat.S_ISDIR(named.st_mode))
                 and named.st_uid == (501 if current.is_relative_to(HOME) else 0)
                 and not stat.S_IMODE(named.st_mode) & 0o022,
                 'gateway_fixed_plist_chain_custody')
            if leaf:
                need(named.st_gid == 20 and named.st_nlink == 1
                     and 0 < named.st_size <= 262144,
                     'gateway_bounded_single_plist')
            flags = os.O_RDONLY | os.O_NOFOLLOW | (os.O_NONBLOCK if leaf else os.O_DIRECTORY)
            fd = os.open(name, flags, **({} if parent_fd is None else {'dir_fd': parent_fd}))
            row = {'fd': fd, 'path': current, 'expected': identity(named),
                   'closeAttempts': 0, 'closed': False}
            self.rows.append(row)
            need(identity(os.fstat(fd)) == row['expected'], 'gateway_named_held_plist_chain')
            parent_fd = fd
        leaf = self.rows[-1]
        raw = bytearray()
        maximum = leaf['expected'][6]
        while len(raw) <= maximum:
            self.remaining()
            part = os.read(leaf['fd'], min(65536, maximum + 1 - len(raw)))
            if not part:
                break
            raw.extend(part)
        need(len(raw) == maximum, 'gateway_complete_plist_bytes')
        self.raw = bytes(raw)
        self.verify()
        return self.raw, leaf['expected']

    def verify(self):
        need(self.rows and not self.closed, 'gateway_plist_still_held')
        for row in self.rows:
            self.remaining()
            need(row['expected'] == identity(os.fstat(row['fd']))
                 == identity(row['path'].lstat()), 'gateway_fixed_plist_full9_unchanged')
        leaf = self.rows[-1]
        self.remaining()
        actual = os.pread(leaf['fd'], leaf['expected'][6] + 1, 0)
        need(actual == self.raw, 'gateway_held_plist_bytes_unchanged')

    def close(self):
        if self.closed:
            return
        for row in reversed(self.rows):
            if row['closeAttempts']:
                continue
            row['closeAttempts'] = 1
            try:
                os.close(row['fd'])
                row['closed'] = True
            except BaseException as error:
                self.close_errors.append(type(error).__name__)
        self.closed = True

    def public(self):
        return {'ownedDescriptorCount': len(self.rows),
                'allOwnedDescriptorsClosedOnce': self.closed and all(
                    row['closeAttempts'] == 1 and row['closed'] for row in self.rows),
                'closeErrorCount': len(self.close_errors)}


class CurrentGatewayObservation:
    """Executable begin/bind/finish observer; supplied dependencies are trusted code.

    runtime_fence must recheck the pinned public helper/native sources. The
    source_verify callable must verify this inventory capture's full9, including
    its declared absences, and raise on change. Its source is pinned by the
    parent. private_write(name, bytes) must create 0600 files once and fsync them.
    This class never accepts a precomputed boolean receipt as that verifier.
    """
    def __init__(self, *, commands, reader, parse_print, until, runtime_fence,
                 private_write):
        now = time.monotonic()
        need(os.getuid() == 501 and now < until <= now + 45,
             'gateway_original_parent_observation_deadline')
        need(callable(parse_print) and callable(runtime_fence) and callable(private_write),
             'gateway_source_bound_callable_dependencies')
        self.commands, self.reader, self.parse_print = commands, reader, parse_print
        self.until, self.runtime_fence, self.private_write = until, runtime_fence, private_write
        self.plist = FixedPlist(self.remaining)
        self.phase = 'new'
        self.public_commands = []
        self.private_queries = []
        self.query_sequence_blocked = False
        self.source_verify = None
        self.configuration = None
        self.report = {'schema': 'heptabao.current-gateway-observation.public.r2',
                       'ok': False, 'target': TARGET, 'providerCalls': 0,
                       'credentialDatabasesOpened': 0, 'gatewayRpcCalls': 0,
                       'serviceMutations': 0, 'runningPluginMemoryFlagsProven': False,
                       'runtimeEnvironmentAfterJavaScriptMutationsProven': False,
                       'fullConsumerCoverageProven': False,
                       'quiescencePerformed': False, 'productionRestoreQualified': False,
                       'rawArgumentsEnvironmentConfigurationOrDigestsPublished': False,
                       'commands': self.public_commands}

    def remaining(self):
        left = self.until - time.monotonic()
        need(left > 0, 'gateway_original_parent_observation_deadline')
        return left

    def query(self, ordinal):
        self.remaining()
        need(not self.query_sequence_blocked and ordinal == len(self.private_queries)
             and ordinal in (0, 1),
             'gateway_two_readonly_queries_once')
        self.runtime_fence()
        # Record an attempted slot before dispatch; an unknown original command
        # is never reissued from this observer.
        self.private_queries.append({'ordinal': ordinal, 'dispatched': True})
        self.query_sequence_blocked = True
        row, out, err = self.commands.run(
            'current-gateway-print-' + str(ordinal), ['/bin/launchctl', 'print', TARGET],
            until=min(self.until, time.monotonic() + 8), maximum=262144)
        self.private_queries[ordinal]['original'] = row
        public = {key: value for key, value in row.items()
                  if key not in ('stdoutSha256', 'stderrSha256')}
        public['originalOutputAndDigestsPrivate'] = True
        self.public_commands.append(public)
        self.private_write('gateway-print-%d.record.private.json' % ordinal, encoded(row))
        self.private_write('gateway-print-%d.stdout.private' % ordinal, out)
        self.private_write('gateway-print-%d.stderr.private' % ordinal, err)
        need(row.get('outcomeUnknown') is False and row.get('completeBeforeDeadline') is True
             and type(row.get('exitCode')) is int and row['exitCode'] == 0 and not err,
             'gateway_original_print_known_zero_complete_closed')
        self.remaining()
        parsed = self.parse_print(out, TARGET)
        parsed['observedEnvironmentScope'] = scoped_environments(out)
        self.query_sequence_blocked = False
        return parsed

    def family(self, pid):
        root = self.reader.read(pid)
        need(root['uid'] == 501 and root['ppid'] == 1 and root['executable'] == NODE,
             'gateway_actual_registered_node_birth')
        rows, relations = {pid: root}, {}
        queue = [(pid, 0)]
        while queue:
            self.remaining()
            parent, depth = queue.pop(0)
            children = sorted(self.reader.children(parent))
            need(len(children) == len(set(children)) and len(rows) + len(children) <= 128,
                 'gateway_finite_distinct_descendant_scope')
            relations[parent] = children
            for child in children:
                need(child not in rows and depth < 8, 'gateway_acyclic_bounded_process_family')
                row = self.reader.read(child)
                need(row['ppid'] == parent and row['uid'] == 501,
                     'gateway_same_user_actual_descendant')
                rows[child] = row
                queue.append((child, depth + 1))
        self.verify_family(rows, relations)
        return rows, relations

    def verify_family(self, rows, relations):
        for pid, expected in rows.items():
            self.remaining()
            need(self.reader.read(pid) == expected, 'gateway_entire_family_birth_unchanged')
            need(sorted(self.reader.children(pid)) == relations[pid],
                 'gateway_entire_family_child_set_unchanged')

    def begin(self):
        need(self.phase == 'new', 'gateway_begin_once')
        self.phase = 'begin-attempted'
        self.runtime_fence()
        raw, ident = self.plist.open()
        value = plistlib.loads(raw)
        need(isinstance(value, dict) and value.get('Label') == LABEL,
             'gateway_fixed_plist_label')
        args = value.get('ProgramArguments')
        need(isinstance(args, list) and 1 <= len(args) <= 32
             and all(isinstance(arg, str) and len(arg.encode()) <= 16384 for arg in args),
             'gateway_bounded_private_original_argv')
        env = value.get('EnvironmentVariables', {})
        need(isinstance(env, dict) and len(env) <= 256
             and all(isinstance(key, str) and isinstance(item, str)
                     and len(key) <= 256 and len(item.encode()) <= 16384
                     for key, item in env.items()), 'gateway_bounded_private_plist_environment')
        first = self.query(0)
        need(first.get('path') == str(PLIST) and first.get('state') == 'running'
             and type(first.get('pid')) is int
             and first.get('arguments') == args
             and first.get('program') == value.get('Program', args[0]),
             'gateway_current_loaded_plist_arguments_exact')
        self.rows, self.relations = self.family(first['pid'])
        self.original_plist, self.plist_identity = value, ident
        self.args, self.env, self.first = args, env, first
        self.phase = 'begun'

    def bind_configuration(self, raw_bytes, full9, source_verify):
        need(self.phase == 'begun' and self.configuration is None
             and callable(source_verify), 'gateway_one_current_inventory_binding')
        self.remaining()
        ident = normalize_full9(full9)
        need(isinstance(raw_bytes, bytes) and 0 < len(raw_bytes) <= 1048576
             and ident[2] == 501 and ident[3] == 20 and ident[5] == 1
             and stat.S_ISREG(ident[4]) and stat.S_IMODE(ident[4]) == 0o600
             and ident[6] == len(raw_bytes), 'gateway_original_current_config_bytes_custody')
        value = fallback.strict_json(raw_bytes)
        source_verify()
        self.configuration = (raw_bytes, ident, value)
        self.source_verify = source_verify
        self.phase = 'configuration-bound'

    def finish(self):
        need(self.phase == 'configuration-bound', 'gateway_finish_once_after_original_capture')
        self.phase = 'finish-attempted'
        self.source_verify()
        self.plist.verify()
        self.verify_family(self.rows, self.relations)
        second = self.query(1)
        need(all(second.get(key) == self.first.get(key) for key in
                 ('path', 'program', 'pid', 'runs', 'state', 'arguments',
                  'observedEnvironmentScope')), 'gateway_two_same_loaded_registration_observations')
        self.verify_family(self.rows, self.relations)
        self.plist.verify()
        self.source_verify()
        self.runtime_fence()
        self.remaining()
        raw, full9, value = self.configuration
        process = self.rows[self.first['pid']]
        private = {
            # Compatible with the separately qualified pure fallback converter.
            'schema': 'heptabao.current-gateway-private-restore-inputs.r1',
            'observationSchema': 'heptabao.current-gateway-observation.private.r2',
            'target': TARGET, 'process': process,
            'children': [self.rows[pid] for pid in self.relations[process['pid']]],
            'descendants': [row for pid, row in self.rows.items() if pid != process['pid']],
            'relations': self.relations, 'ancestors': [],
            'loadedFirst': self.first, 'loadedSecond': second,
            'plistPath': str(PLIST), 'plistFull9': self.plist_identity,
            'plistSha256': hashlib.sha256(self.plist.raw).hexdigest(),
            'configPath': str(CONFIG), 'configFull9': full9,
            'configSha256': hashlib.sha256(raw).hexdigest(),
            'environment': self.env, 'arguments': self.args,
            'configSource': 'same_parent_original_inventory_capture',
            'observationsAreDiscreteNotAContinuousLock': True,
        }
        prepared = None
        try:
            prepared = fallback.make_fallback(raw, self.plist.raw, private)
        except fallback.Refused as error:
            self.report['fallbackPreparationRefusal'] = str(error)
        self.private_write('gateway-original.plist.private', self.plist.raw)
        self.private_write('gateway-restore-inputs.private.json', encoded(private))
        if prepared is not None:
            # Only the caller's private *observation* directory receives these
            # review artifacts. Never write FALLBACK_CONFIG or the live plist.
            self.private_write('gateway-fallback.review.config.private.json', prepared['configBytes'])
            self.private_write('gateway-fallback.review.plist.private', prepared['plistBytes'])
        self.report.update(
            ok=True, originalLaunchctlPrintCount=2, loadedArgumentsEqualCurrentPlist=True,
            actualGatewayProcess=process, observedDescendantCount=len(self.rows) - 1,
            allObservedFamilyIdentitiesAndChildSetsStable=True,
            currentConfigurationFromSameParentInventory=True,
            configurationAndPlistFull9AndBytesStable=True,
            observationsAreDiscreteNotAContinuousLock=True,
            originalPlistKeepAliveConfigured=bool(self.original_plist.get('KeepAlive')),
            privateRestoreInputsDurable=True, fallbackReviewArtifactsPrepared=prepared is not None,
            fallbackReviewIsDeployment=False,
            productionFallbackSelectorQualified=False,
            environment=environment_projection(self.first['observedEnvironmentScope'], self.env),
        )
        self.phase = 'finished'
        return private, self.report

    def close(self):
        self.plist.close()
        self.report['querySequenceBlockedAfterFailure'] = self.query_sequence_blocked
        self.report['descriptors'] = self.plist.public()
        if not self.report['descriptors']['allOwnedDescriptorsClosedOnce']:
            self.report['ok'] = False
        return self.report
