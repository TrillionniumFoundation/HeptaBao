#!/usr/bin/env python3
"""Fresh read of the three already SDK-authorized main-owned credentials.

The old capsule supplies only the ordered, previously authorized profile IDs.
Every returned credential comes from a new invocation of the qualified auth18
reader. This observation does not rerun SDK selection, prove a provider token
valid, or exclude a running process's cached authentication. It grants no
service, refresh, or CAS authority. The caller must apply the reviewed kernel
read-only source/no-network policy before invoking this module.
"""
from __future__ import annotations

import copy
import hashlib
import json
import os
from pathlib import Path
import stat
import time

from main3_source_authority import SDK_SOURCE_PINS, SOURCE_SELECTION_AUTHORITY, validate_authority

HOME = Path('/Users/qianqi')
LIVE = HOME / '.openclaw'
MAIN = LIVE / 'agents/main/agent/openclaw-agent.sqlite'
OWNER = MAIN.parent
SDK = Path('/opt/homebrew/lib/node_modules/openclaw')
QUAL = HOME / 'heptabao-authbus-auth-wal-qualification-20261106-r2/qa'
SCOPE = HOME / 'heptabao-authbus-main3-sdk-inline-capsule-20261106-r4/output/selected-owner-credentials.private.json'
CONFIG = LIVE / 'openclaw.json'
SOURCE_PINS = {
    'authbus_current_auth_wal.py': 'ad443869e259da06de2be71131e5d1854680477d1cf77248e05a3c1704160f8c',
    'mac_registry_readonly_wal_r1.py': '60d5e5874c281af2e19fee55bc4b2242627f69b500f1af1d6b5b22e16120bfed',
    'mac_guarded_current_capture_r3.py': '606b5df58909ebedc035ebbff6a4aa5e754d19c6a7e0f5e4e88c9ddfc57c2693',
}
FIELDS = ('st_dev', 'st_ino', 'st_uid', 'st_gid', 'st_mode', 'st_nlink',
          'st_size', 'st_mtime_ns', 'st_ctime_ns')
UID, GID, SYSTEM_UID = 501, 20, 0


class CurrentOwnersRefused(RuntimeError):
    pass


class CurrentOwnersCaptureFailure(CurrentOwnersRefused):
    def __init__(self, closure, original):
        super().__init__('current_three_original_read_refused')
        self.closure = public_closure(closure)
        self.original = original



CLOSURE_BOOLEANS = ('allOwnedDescriptorsClosed', 'allHeldDescriptorsClosed',
    'allReturnedConnectionsClosed', 'allExplicitCursorsClosed',
    'allPublicCodeDescriptorsClosed', 'emptyWalHeldFdRouteInvoked')
CLOSURE_COUNTS = ('connectionAttemptCount', 'returnedConnectionCount', 'cursorCount', 'queryCount')


def public_closure(value):
    """One identical closed allowlist for success and failure receipts.

    Bottom-layer error text and all unlisted keys remain private. A malformed
    receipt cannot be represented as known resource closure.
    """
    qualified = (type(value) is dict
        and all(type(value.get(key)) is bool for key in CLOSURE_BOOLEANS)
        and all(type(value.get(key)) is int and 0 <= value[key] <= 2147483647 for key in CLOSURE_COUNTS)
        and type(value.get('closeErrors')) is list and len(value['closeErrors']) <= 1024)
    if not qualified:
        return {**{key: False for key in CLOSURE_BOOLEANS},
            **{key: None for key in CLOSURE_COUNTS}, 'closeErrors': ['closure_shape_unavailable'],
            'closeErrorCount': None, 'closureShapeQualified': False}
    return {**{key: value[key] for key in CLOSURE_BOOLEANS},
        **{key: value[key] for key in CLOSURE_COUNTS},
        'closeErrors': [] if not value['closeErrors'] else ['original_resource_close_failed'],
        'closeErrorCount': len(value['closeErrors']), 'closureShapeQualified': True}


def need(value, code):
    if not value:
        raise CurrentOwnersRefused(code)


def full(value):
    return tuple(str(getattr(value, key)) for key in FIELDS)


def strict(raw):
    need(type(raw) is bytes and 0 < len(raw) <= 1048576, 'current_three_bounded_private_json')
    def pairs(items):
        result = {}
        for key, value in items:
            need(key not in result, 'current_three_duplicate_private_json_key')
            result[key] = value
        return result
    def invalid(_):
        raise CurrentOwnersRefused('current_three_nonfinite_private_json')
    try:
        result = json.loads(raw.decode('utf-8', 'strict'), object_pairs_hook=pairs, parse_constant=invalid)
    except (ValueError, UnicodeError, RecursionError):
        raise CurrentOwnersRefused('current_three_invalid_private_json') from None
    need(type(result) is dict, 'current_three_private_json_object')
    return result


def authorized_scope(raw, configuration_raw):
    """Extract identifiers, never historical credential values."""
    doc = strict(raw)
    validate_authority(doc, need)
    need(doc.get('schema') == 'heptabao.actual-sdk-selected-owner-credentials.private.r1'
         and doc.get('host') == 'mac' and type(doc.get('ownerEntries')) is list
         and len(doc['ownerEntries']) == 3, 'current_three_original_sdk_authorization_scope')
    identifiers = []
    for entry in doc['ownerEntries']:
        need(type(entry) is dict and entry.get('ownerAgentDir') == str(OWNER)
             and entry.get('actualProvider') == 'openai' and type(entry.get('profileId')) is str
             and 0 < len(entry['profileId']) <= 240
             and all(32 <= ord(char) != 127 for char in entry['profileId']),
             'current_three_exact_original_main_owner_ids')
        identifiers.append(entry['profileId'])
    need(len(set(identifiers)) == 3, 'current_three_unique_original_owner_ids')
    need(type(configuration_raw) is bytes and 0 < len(configuration_raw) <= 1048576
         and hashlib.sha256(configuration_raw).hexdigest() == doc.get('configurationSha256'),
         'current_three_same_configuration_for_authorized_scope')
    # Deliberately discard all historical values and generations. Neither is
    # a substitute for the current primary-row observation below.
    return tuple(identifiers)


def current_entries(value, identifiers):
    need(type(value) is dict and value.get('storeRowPresent') is True
         and value.get('registeredMissingCount') == 0 and type(value.get('profiles')) is dict
         and set(value['profiles']) == set(identifiers), 'current_three_all_exact_current_owner_values')
    entries = []
    for identifier in identifiers:
        credential = value['profiles'][identifier]
        need(type(credential) is dict and credential.get('provider') == 'openai'
             and credential.get('type') == 'oauth' and type(credential.get('refresh')) is str
             and 0 < len(credential['refresh'].encode('utf-8')) <= 131072,
             'current_three_current_oauth_refresh_required')
        entries.append({'profileId': identifier, 'ownerAgentDir': str(OWNER),
                        'actualProvider': 'openai', 'credential': copy.deepcopy(credential)})
    need(len({entry['credential']['refresh'] for entry in entries}) == 3,
         'current_three_shared_refresh_objects_refused')
    return entries


def verify_current_namespace(output, *, until):
    need(time.monotonic() < until and type(output) is dict
         and output.get('schema') == 'heptabao.current-selected-main3.private.r1',
         'current_three_original_generation_document')
    generation = output.get('sourceGeneration', {})
    present, absent = generation.get('sourceIdentities'), generation.get('sourceAbsences')
    parents = output.get('sourceParentGenerations')
    need(type(present) is dict and type(absent) is list and len(absent) == len(set(absent))
         and set(present).isdisjoint(absent)
         and set(present) | set(absent) == {str(MAIN) + suffix for suffix in ('', '-wal', '-shm', '-journal')}
         and str(MAIN) in present and str(MAIN) + '-journal' in absent
         and type(parents) is dict and set(parents) == set(map(str, MAIN.parents)),
         'current_three_exact_primary_and_parent_namespace')
    for name, expected in (*present.items(), *parents.items()):
        need(type(expected) is list and len(expected) == 9
             and all(type(item) is str and item.isdecimal() and len(item) <= 30 for item in expected)
             and full(Path(name).lstat()) == tuple(expected), 'current_three_closed_generation_exact')
    for name in absent:
        try:
            Path(name).lstat()
        except FileNotFoundError:
            continue
        raise CurrentOwnersRefused('current_three_closed_sidecar_absence_changed')
    need(time.monotonic() < until, 'current_three_generation_deadline_after_observation')
    return True


class ScopeInputs:
    """Exactly the old authorization capsule and current config, held fully."""
    def __init__(self, *, until, source_fence, clock=time.monotonic):
        need(clock() < until <= clock() + 45 and os.geteuid() == UID and callable(source_fence),
             'current_three_finite_scope_input_deadline')
        self.until, self.clock, self.source_fence = until, clock, source_fence
        self.rows, self.directories, self.files = [], {}, {}
        self.closed = self.failed = False

    def within(self):
        need(not self.closed and not self.failed and self.clock() < self.until,
             'current_three_scope_original_lifetime')

    def track(self, fd):
        row = {'fd': fd, 'closeAttempts': 0, 'closed': False}
        self.rows.append(row)
        return row

    def directory(self, path):
        self.within()
        need(path in set(SCOPE.parents) | set(CONFIG.parents), 'current_three_only_exact_scope_ancestors')
        if path in self.directories:
            return self.directories[path]
        parent = None if path == Path('/') else self.directory(path.parent)
        named = path.lstat() if parent is None else os.stat(path.name, dir_fd=parent['fd'], follow_symlinks=False)
        wanted = SYSTEM_UID if path in (Path('/'), Path('/Users')) else UID
        need(stat.S_ISDIR(named.st_mode) and named.st_uid == wanted
             and not stat.S_IMODE(named.st_mode) & 0o022, 'current_three_owned_nonalias_scope_directory')
        row = self.track(os.open(str(path) if parent is None else path.name,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
            **({} if parent is None else {'dir_fd': parent['fd']})))
        need(full(named) == full(os.fstat(row['fd'])), 'current_three_original_scope_directory_fd')
        row.update(path=path, parent=parent, expected=full(named))
        self.directories[path] = row
        return row

    def read(self, path):
        self.within(); self.source_fence()
        need(path in (SCOPE, CONFIG) and path not in self.files, 'current_three_two_fixed_private_inputs_once')
        parent = self.directory(path.parent)
        named = os.stat(path.name, dir_fd=parent['fd'], follow_symlinks=False)
        need(stat.S_ISREG(named.st_mode) and named.st_uid == UID and named.st_gid == GID
             and stat.S_IMODE(named.st_mode) == 0o600 and named.st_nlink == 1
             and 0 < named.st_size <= 1048576, 'current_three_private_scope_file_custody')
        row = self.track(os.open(path.name, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC,
                                 dir_fd=parent['fd']))
        row.update(path=path, parent=parent, expected=full(named))
        need(full(os.fstat(row['fd'])) == row['expected'], 'current_three_named_scope_original_inode')
        self.files[path] = row
        row['raw'] = self.whole(row)
        self.verify()
        return row['raw']

    def whole(self, row):
        expected, parts, count = int(row['expected'][6]), [], 0
        while count <= expected:
            self.within()
            block = os.pread(row['fd'], min(65536, expected + 1 - count), count)
            if not block:
                break
            parts.append(block); count += len(block)
        need(count == expected, 'current_three_complete_bounded_scope_read')
        return b''.join(parts)

    def verify(self):
        self.within()
        for row in (*self.directories.values(), *self.files.values()):
            named = row['path'].lstat() if row['parent'] is None else os.stat(
                row['path'].name, dir_fd=row['parent']['fd'], follow_symlinks=False)
            need(not row['closeAttempts'] and full(named) == full(os.fstat(row['fd'])) == row['expected'],
                 'current_three_scope_full_nine_unchanged')
        for row in self.files.values():
            if 'raw' in row:
                need(self.whole(row) == row['raw'], 'current_three_complete_scope_bytes_unchanged')
        self.within()

    def close(self):
        if not self.closed:
            for row in reversed(self.rows):
                if row['closeAttempts']:
                    continue
                row['closeAttempts'] = 1
                try:
                    os.close(row['fd']); row['closed'] = True
                except BaseException:
                    self.failed = True
            self.closed = True
        return {'allOriginalDescriptorsClosedOnce': all(row['closed'] and row['closeAttempts'] == 1 for row in self.rows),
                'originalDescriptorCount': len(self.rows), 'closeErrorObserved': self.failed}

    def closed_fence(self):
        need(self.closed and not self.failed and self.clock() < self.until,
             'current_three_closed_scope_deadline')
        for row in (*self.directories.values(), *self.files.values()):
            need(full(row['path'].lstat()) == row['expected'], 'current_three_closed_scope_names_exact')
        self.source_fence()
        return True


def read_current(*, auth, scope, until, critical, cancelled, source_fence):
    """One SQL transaction, no caller-supplied profiles or refresh values."""
    need(type(scope) is ScopeInputs and not scope.closed and until <= scope.until
         and time.monotonic() < until <= time.monotonic() + 45,
         'current_three_original_scope_and_read_deadline')
    need(Path(auth.__file__) == QUAL / 'authbus_current_auth_wal.py'
         and Path(auth.readonly_auth_query.__code__.co_filename) == QUAL / 'authbus_current_auth_wal.py'
         and Path(auth.wal.__file__) == QUAL / 'mac_registry_readonly_wal_r1.py'
         and Path(auth.base.__file__) == QUAL / 'mac_guarded_current_capture_r3.py',
         'current_three_actual_qualified_module_locations')
    scope_raw, config_raw = scope.read(SCOPE), scope.read(CONFIG)
    identifiers = authorized_scope(scope_raw, config_raw)
    requested = auth.validate_profiles('main', identifiers, identifiers)
    inputs, output, error = None, None, None
    try:
        source_fence(); scope.verify()
        inputs = auth.AuthInputs(until=until, critical=critical, cancelled=cancelled)
        before = {name: inputs.code_pin(SDK / name) for name in SDK_SOURCE_PINS}
        need(all(before[name]['sha256'] == expected for name, expected in SDK_SOURCE_PINS.items()),
             'current_three_same_installed_selection_code_pins')
        bundle = auth.auth_wal_database(inputs, 'main')
        value = auth.readonly_auth_query(inputs, bundle, requested)
        entries = current_entries(value, identifiers)
        inputs.verify(); auth.verify_auth_bundle(inputs, bundle, until=until)
        generation = {'agent': 'main', 'sourceIdentities': {
            name: list(row['expected']) for name, row in inputs.files.items()},
            'sourceAbsences': list(inputs.absent)}
        parent_generations = {name: list(auth.wal._full_parent(row)) for name, row in inputs.parents.items()}
        after = {name: inputs.code_pin(SDK / name) for name in SDK_SOURCE_PINS}
        need(before == after, 'current_three_current_selection_code_unchanged')
        scope.verify(); source_fence()
        output = {'schema': 'heptabao.current-selected-main3.private.r1', 'ownerEntries': entries,
            'sourceGeneration': generation, 'sourceParentGenerations': parent_generations,
            'configurationIdentity': list(scope.files[CONFIG]['expected']),
            'configurationSha256': hashlib.sha256(config_raw).hexdigest(),
            'historicalCapsuleUsedOnlyForAuthorizedIds': True,
            'sourceSelectionAuthority': copy.deepcopy(SOURCE_SELECTION_AUTHORITY),
            'actualSdkSelectionRerun': False, 'providerValidityProven': False}
    except BaseException as caught:
        error = caught
    finally:
        if inputs is not None:
            try:
                inputs.close()
            except BaseException as caught:
                if error is None:
                    error = caught
    closure = inputs.public() if inputs is not None else None
    if error is not None:
        raise CurrentOwnersCaptureFailure(closure, error) from None
    need(closure is not None and closure['allOwnedDescriptorsClosed']
         and closure['allHeldDescriptorsClosed'] and closure['allReturnedConnectionsClosed']
         and closure['allExplicitCursorsClosed'] and closure['allPublicCodeDescriptorsClosed']
         and not closure['closeErrors'], 'current_three_original_sql_and_fd_closure_known')
    verify_current_namespace(output, until=until)
    scope.verify(); source_fence()
    need(not cancelled() and time.monotonic() < until, 'current_three_original_deadline_after_closure')
    projected = public_closure(closure)
    need(projected['closureShapeQualified'], 'current_three_typed_success_closure_projection')
    return output, projected
