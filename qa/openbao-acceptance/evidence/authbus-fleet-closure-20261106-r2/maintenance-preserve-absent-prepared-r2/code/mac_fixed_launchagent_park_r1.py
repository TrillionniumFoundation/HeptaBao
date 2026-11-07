#!/usr/bin/env python3
"""Park exactly five already bound LaunchAgents without changing overrides.

Prepared actuator. No import-time I/O. The original maintenance parent creates
one private directory before capturing source ancestors, then hands the actual
gateway/relay controller instances to bind(). Only their five original plists
may move. Other LaunchAgents entries retain full metadata. Each original inode
survives link(1 -> 2), directory sync, unlink(2 -> 1), directory sync. Every
effect has a consumed, fsynced intent and a separate fsynced completion.

The before/after checks do not make conditional unlink an atomic compare-delete.
An unknown effect never triggers another link, unlink, service or compensation.
Old autoload entries cannot be restored after a provider attempt. The only
post-COMMITTED publication is the explicitly AuthBus-disabled gateway plist.
"""
from __future__ import annotations

import copy
import json
import os
from pathlib import Path
import plistlib
import re
import stat
import time

ROOT = Path('/Users/qianqi/heptabao-authbus-writer-maintenance-20261106-r1')
HOME = Path('/Users/qianqi')
LA = HOME / 'Library/LaunchAgents'
PARK = ROOT / 'parked-launchagents'
SAFE = ROOT / 'safe-gateway.plist.pending'
UID, GID = 501, 20
LABELS = tuple('ai.openclaw.authbus-relay.' + name for name in
               ('proxy', 'bridge', 'egressguard', 'front')) + ('ai.openclaw.gateway',)
NAMES = tuple(label + '.plist' for label in LABELS)
PARK_NAMES = tuple('original-%02d.plist.private' % (n + 1) for n in range(5))
FIELDS = ('st_dev', 'st_ino', 'st_uid', 'st_gid', 'st_mode', 'st_nlink',
          'st_size', 'st_mtime_ns', 'st_ctime_ns')


class ParkRefused(RuntimeError):
    pass


def need(value, code):
    if not value:
        raise ParkRefused(code)


def full(value):
    return tuple(getattr(value, key) for key in FIELDS)


def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n').encode()


class FixedLaunchAgentParking:
    def __init__(self, *, until, source_fence, private_write, clock=time.monotonic):
        need(os.getuid() == UID and clock() < until <= clock() + 600
             and callable(source_fence) and callable(private_write), 'park_original_parent_and_budget')
        self.until, self.clock = until, clock
        self.source_fence, self.private_write = source_fence, private_write
        self.rows, self.parents, self.files, self.actions = [], {}, [], []
        self.gateway = self.relays = None
        self.la_expected = self.park_expected = None
        self.la_entries, self.park_entries = {}, {}
        self.parked, self.restored = [], []
        self.phase = 'new'
        self.unknown = self.blocked = self.closed = False
        self.safe_file = None
        self.report = {'schema': 'heptabao.fixed-five-launchagent-parking.public.r1',
            'ok': False, 'phase': 'new', 'fixedPlistCount': 5, 'actions': self.actions,
            'disabledOverrideMutations': 0, 'applicationSignals': 0,
            'automaticRetry': False, 'automaticCompensation': False,
            'conditionalUnlinkAtomicCompareDeleteClaimed': False,
            'oldAutoloadRestoreAfterProviderAttemptAllowed': False,
            'oldCredentialOrOnceLedgerRollbackAllowed': False,
            'productionRollbackQualified': False,
            'privatePathsValuesArgumentsOrDigestsPublished': False}

    def within(self):
        need(not self.closed and not self.blocked and not self.unknown and self.clock() < self.until,
             'park_known_original_lifetime')

    def _write(self, name, value):
        need(re.fullmatch(r'[a-z0-9.-]{1,140}', name) is not None, 'park_fixed_private_record_name')
        raw = value if type(value) is bytes else encoded(value)
        need(len(raw) <= 2 * 1048576, 'park_bounded_private_record')
        try:
            self.private_write(name, raw)
        except BaseException:
            self.unknown = True
            raise

    def _track(self, descriptor, path):
        row = {'fd': descriptor, 'path': path, 'closeAttempts': 0, 'closed': False}
        self.rows.append(row)
        row['expected'] = full(os.fstat(descriptor))
        return row

    def _directory(self, path):
        self.within()
        if path in self.parents:
            return self.parents[path]
        if path == path.parent:
            descriptor = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        else:
            parent = self._directory(path.parent)
            descriptor = os.open(path.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                                 dir_fd=parent['fd'])
        row = self._track(descriptor, path)
        info = os.fstat(descriptor)
        need(stat.S_ISDIR(info.st_mode) and info.st_uid in (0, UID)
             and not stat.S_IMODE(info.st_mode) & 0o022
             and row['expected'] == full(path.lstat()), 'park_original_nonalias_directory_chain')
        if path in (ROOT, PARK):
            need(info.st_uid == UID and info.st_gid == GID and stat.S_IMODE(info.st_mode) == 0o700,
                 'park_private_directory_exact_custody')
        if path == LA:
            need(info.st_uid == UID and info.st_gid == GID, 'park_original_launchagents_owner')
        self.parents[path] = row
        return row

    def _ancestors(self):
        self.within()
        for path, row in self.parents.items():
            # ROOT receives only this owner's private staging. LA and PARK are
            # additionally checked against exact full9 + complete entry maps.
            width = 5 if path in (ROOT, LA, PARK) else 9
            need(row['closeAttempts'] == 0 and full(os.fstat(row['fd']))[:width]
                 == row['expected'][:width] == full(path.lstat())[:width],
                 'park_original_held_named_ancestor')

    def _snapshot(self, path):
        self.within()
        parent = self.parents[path]
        before = full(os.fstat(parent['fd']))
        need(before == full(path.lstat()), 'park_snapshot_named_held_directory')
        names = sorted(os.listdir(parent['fd']))
        need(len(names) <= 1024 and all(type(name) is str and 0 < len(name.encode()) <= 255
             and name not in ('.', '..') and '/' not in name and '\0' not in name for name in names),
             'park_bounded_directory_metadata_only')
        entries = {}
        for name in names:
            self.within()
            entries[name] = full(os.stat(name, dir_fd=parent['fd'], follow_symlinks=False))
        need(sorted(os.listdir(parent['fd'])) == names and before == full(os.fstat(parent['fd']))
             == full(path.lstat()), 'park_complete_unchanged_directory_snapshot')
        return before, entries

    def _intent(self, operation, ordinal=None, detail=None):
        self.within()
        self.source_fence()
        need(type(operation) is str and re.fullmatch(r'[a-z-]{1,48}', operation)
             and (ordinal is None or type(ordinal) is int and 0 <= ordinal < 5)
             and len(self.actions) < 48
             and not any(row['operation'] == operation and row['ordinal'] == ordinal for row in self.actions),
             'park_finite_effect_once')
        row = {'operation': operation, 'ordinal': ordinal, 'intentDurable': False,
               'syscallAttempted': False, 'outcome': 'UNKNOWN'}
        self.actions.append(row)  # consumed before the durable intent
        self._write('park-%02d-intent.private.json' % (len(self.actions) - 1),
                    {'operation': operation, 'ordinal': ordinal, 'detail': detail})
        row['intentDurable'] = True
        return row

    def _complete(self, row, detail):
        self._write('park-%02d-complete.private.json' % self.actions.index(row), detail)
        row['outcome'] = 'COMPLETE'

    def prepare_directory(self):
        """Before source capture, create exactly one private parking directory."""
        need(self.phase == 'new' and not self.actions, 'park_prepare_once_before_source_capture')
        try:
            parent = self._directory(ROOT)
            self._ancestors()
            row = self._intent('create-park-directory')
            row['syscallAttempted'] = True
            os.mkdir(PARK.name, 0o700, dir_fd=parent['fd'])  # EEXIST is a refusal
            park = self._directory(PARK)
            need(os.fstat(park['fd']).st_dev == os.fstat(parent['fd']).st_dev
                 and os.listdir(park['fd']) == [], 'park_new_empty_same_filesystem_directory')
            self._ancestors()
            self._complete(row, {'newPrivateDirectoryFull9': park['expected']})
            row = self._intent('sync-park-parent')
            row['syscallAttempted'] = True
            os.fsync(parent['fd'])
            self._ancestors()
            self._complete(row, {'sameOriginalParentSynchronized': True})
            self.park_expected, self.park_entries = self._snapshot(PARK)
            self.phase = 'prepared'
            return self
        except BaseException:
            self.unknown = self.blocked = True
            raise

    def bind(self, *, gateway, relays):
        from mac_gateway_writer_maintenance_r2 import GatewayWriterMaintenance
        from mac_registered_relay_retirement_r2 import RegisteredRelayRetirement
        need(self.phase == 'prepared' and type(gateway) is GatewayWriterMaintenance
             and type(relays) is RegisteredRelayRetirement
             and gateway.phase == 'original-bound' and relays.phase == 'bound'
             and gateway.commands is relays.commands and gateway.reader is relays.reader
             and gateway.until == relays.until == self.until
             and not gateway.unknown and not relays.unknown and not relays.blocked
             and gateway.parking is None and relays.parking is None,
             'park_actual_same_parent_original_controllers')
        self.within()
        gateway.same_original_running('before-fixed-five-park-bind')
        relays._sources()
        for slot in range(4):
            relays._same_running(slot)
        try:
            self.gateway, self.relays = gateway, relays
            parent = self._directory(LA)
            need(os.fstat(parent['fd']).st_dev == os.fstat(self.parents[PARK]['fd']).st_dev
                 and full(os.fstat(gateway.original_parent['fd'])) == full(os.fstat(parent['fd'])),
                 'park_exact_original_directory_same_filesystem')
            self.la_expected, self.la_entries = self._snapshot(LA)
            need(set(NAMES) <= set(self.la_entries) and self.park_entries == {},
                 'park_exact_five_existing_names_and_empty_destination')
            for ordinal, name in enumerate(NAMES):
                if ordinal < 4:
                    binding = relays.inputs.packet['registrations'][ordinal]
                    need(binding['label'] == LABELS[ordinal] and binding['originalDisabledOverride'] is None
                         and binding['plist'].get('KeepAlive') is True
                         and binding['originalPlistDisabled'] is False,
                         'park_observed_relay_keepalive_absent_override')
                    raw, expected = relays.inputs.plists[ordinal].raw, tuple(binding['plistFull9'])
                else:
                    need(gateway.original_disabled is None and plistlib.loads(gateway.plist_bytes).get('KeepAlive') is True,
                         'park_observed_gateway_keepalive_absent_override')
                    raw, expected = gateway.plist_bytes, tuple(gateway.binding['plistFull9'])
                descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                                     dir_fd=parent['fd'])
                row = self._track(descriptor, LA / name)
                info = os.fstat(descriptor)
                need(stat.S_ISREG(info.st_mode) and info.st_uid == UID and info.st_gid == GID
                     and info.st_nlink == 1 and not stat.S_IMODE(info.st_mode) & 0o022
                     and 0 < info.st_size <= 262144 and row['expected'] == expected == self.la_entries[name]
                     and type(raw) is bytes and os.pread(descriptor, len(raw) + 1, 0) == raw
                     and row['expected'] == full(os.fstat(descriptor)), 'park_whole_original_inode_binding')
                row.update(ordinal=ordinal, raw=raw, location='original', originalFull9=expected)
                self.files.append(row)
            self._verify_maps()
            self._write('fixed-five-original-parking-inputs.private.json',
                {'originalParentPid': os.getpid(), 'launchAgentsFull9': self.la_expected,
                 'allOriginalLaunchAgentsMetadata': self.la_entries, 'parkFull9': self.park_expected,
                 'selectedOriginals': [{'ordinal': row['ordinal'], 'full9': row['originalFull9'],
                                       'originalName': NAMES[row['ordinal']], 'parkName': PARK_NAMES[row['ordinal']]}
                                      for row in self.files]})
            self.phase = 'bound'
            gateway.parking = relays.parking = self
            self.verify()
            return self
        except BaseException:
            self.blocked = True
            raise

    def _verify_maps(self, *, file_override=None, la_entries=None, park_entries=None,
                     changed_directory=None):
        self._ancestors()
        la_full, la_actual = self._snapshot(LA)
        park_full, park_actual = self._snapshot(PARK)
        need(la_actual == (self.la_entries if la_entries is None else la_entries)
             and park_actual == (self.park_entries if park_entries is None else park_entries),
             'park_only_exact_selected_directory_entry_changes')
        for path, observed, expected in ((LA, la_full, self.la_expected), (PARK, park_full, self.park_expected)):
            width = 5 if path == changed_directory else 9
            need(observed[:width] == expected[:width], 'park_only_known_directory_generation_change')
        for row in self.files:
            expected = file_override[1] if file_override is not None and file_override[0] == row['ordinal'] else row['expected']
            need(row['closeAttempts'] == 0 and full(os.fstat(row['fd'])) == expected
                 and os.pread(row['fd'], len(row['raw']) + 1, 0) == row['raw']
                 and full(os.fstat(row['fd'])) == expected, 'park_all_original_held_inodes_and_whole_bytes')
        self._ancestors()
        return la_full, park_full

    def verify(self):
        try:
            return self._verify_current()
        except BaseException:
            # A rejected source observation blocks this original graph even
            # when no namespace syscall was dispatched. Restoring a name later
            # does not turn that failed observation into a fresh authority.
            self.blocked = True
            raise

    def _verify_current(self):
        need(self.phase in ('bound', 'parking', 'parked', 'restoring', 'restored', 'safe-publishing', 'safe-published'),
             'park_current_original_source_phase')
        self.within()
        self.source_fence()
        self._verify_maps()
        # Original input objects retain their descriptors, but their selected
        # leaf/link metadata and LA directory are now verified by this owner.
        # No other source ancestor, executable or wrapper is rebased.
        for plist in self.relays.inputs.plists:
            for row in plist.rows:
                if row['path'] == LA or row['path'].parent == LA:
                    continue
                need(row['closeAttempts'] == 0 and full(os.fstat(row['fd'])) == tuple(row['expected'])
                     == full(row['path'].lstat()), 'park_nonselected_original_source_ancestor_exact')
        for binding in self.relays.inputs.packet['registrations']:
            self.relays.inputs._binary_metadata(binding['originalExecutable'])
        self.gateway._verify_directories()
        self.gateway.wrapper_inputs.verify()
        return True

    def _transition(self, ordinal, *, operation, source, source_name, destination, destination_name, linking):
        self.verify()
        item = self.files[ordinal]
        before = item['expected']
        row = self._intent(operation, ordinal, {'beforeFull9': before})
        try:
            row['syscallAttempted'] = True
            if linking:
                os.link(source_name, destination_name, src_dir_fd=self.parents[source]['fd'],
                        dst_dir_fd=self.parents[destination]['fd'], follow_symlinks=False)
            else:
                os.unlink(source_name, dir_fd=self.parents[source]['fd'])
            after = full(os.fstat(item['fd']))
            need(after[:5] == before[:5] and after[5] == (2 if linking else 1)
                 and before[5] == (1 if linking else 2) and after[6:8] == before[6:8],
                 'park_original_inode_only_recorded_link_count_and_ctime_transition')
            la_next, park_next = copy.deepcopy(self.la_entries), copy.deepcopy(self.park_entries)
            maps = {LA: la_next, PARK: park_next}
            if linking:
                need(destination_name not in maps[destination], 'park_exclusive_destination_absent')
                maps[source][source_name] = after
                maps[destination][destination_name] = after
                changed = destination
            else:
                need(source_name in maps[source] and destination_name in maps[destination],
                     'park_known_two_names_before_single_unlink')
                del maps[source][source_name]
                maps[destination][destination_name] = after
                changed = source
            la_full, park_full = self._verify_maps(file_override=(ordinal, after), la_entries=la_next,
                                                  park_entries=park_next, changed_directory=changed)
            self._complete(row, {'beforeFull9': before, 'afterFull9': after,
                'launchAgentsFull9': la_full, 'parkFull9': park_full,
                'onlyOriginalInodeNlinkAndCtimeChanged': True})
            item['expected'] = after
            self.la_entries, self.park_entries = la_next, park_next
            self.la_expected, self.park_expected = la_full, park_full
        except BaseException:
            self.unknown = self.blocked = True
            raise

    def _sync(self, operation, ordinal, path):
        self.verify()
        row = self._intent(operation, ordinal)
        try:
            row['syscallAttempted'] = True
            os.fsync(self.parents[path]['fd'])
            self.verify()
            self._complete(row, {'sameOriginalDirectoryFsyncCompleted': True})
        except BaseException:
            self.unknown = self.blocked = True
            raise

    def park_next(self):
        need(self.phase in ('bound', 'parking') and len(self.parked) < 5,
             'park_next_fixed_original_ordinal')
        ordinal = len(self.parked)
        self.gateway.verify_quiesced('before-fixed-autoload-park')
        self.relays.verify_retired()
        self.phase = 'parking'
        self._transition(ordinal, operation='park-link', source=LA, source_name=NAMES[ordinal],
            destination=PARK, destination_name=PARK_NAMES[ordinal], linking=True)
        self._sync('park-link-directory-sync', ordinal, PARK)
        self._transition(ordinal, operation='park-unlink-autoload', source=LA, source_name=NAMES[ordinal],
            destination=PARK, destination_name=PARK_NAMES[ordinal], linking=False)
        self._sync('park-autoload-directory-sync', ordinal, LA)
        self.files[ordinal]['location'] = 'parked'
        self.parked.append(ordinal)
        self._write('park-%02d-original-fully-parked.private.json' % ordinal,
                    {'ordinal': ordinal, 'full9': self.files[ordinal]['expected'], 'autoloadAbsent': True})
        if len(self.parked) == 5:
            self.phase = 'parked'
            self.gateway.accept_known_original_park(self)
            self.relays.verify_retired()
            self.gateway.verify_quiesced('after-all-five-autoload-absent')
            self.report.update(ok=True, fiveOriginalAutoloadNamesAbsent=True,
                fiveOriginalInodesPreservedPrivately=True, disabledOverrideAbsencePreserved=True)
        return ordinal

    def verify_parked(self):
        need(self.phase in ('parked', 'safe-publishing', 'safe-published') and self.parked == list(range(5))
             and not self.restored and all(row['location'] == 'parked' for row in self.files),
             'park_all_five_originals_remain_parked')
        self.verify()
        need(all(NAMES[n] not in self.la_entries for n in range(4))
             and (NAMES[4] not in self.la_entries if self.phase == 'parked' else self.safe_file is not None),
             'park_no_old_autoload_name_restored')
        if self.safe_file is not None:
            self._verify_safe()
        return True

    def restore_originals_before_any_provider(self, parent):
        """Explicit pre-provider recovery only; never an exception handler."""
        from mac_owned_refresh_parent_r2 import OwnedRefreshParent
        need(type(parent) is OwnedRefreshParent and parent.maintenance is self.gateway
             and parent.until == self.until and self.phase == 'parked' and not self.restored,
             'park_same_original_parent_before_provider_restore')
        parent.assert_no_provider_dispatch()
        self.gateway.verify_quiesced('before-pre-provider-original-restore')
        self.relays.verify_retired()
        self.phase = 'restoring'
        for ordinal in range(5):
            parent.assert_no_provider_dispatch()
            self._transition(ordinal, operation='restore-link', source=PARK, source_name=PARK_NAMES[ordinal],
                destination=LA, destination_name=NAMES[ordinal], linking=True)
            self._sync('restore-autoload-directory-sync', ordinal, LA)
            self._transition(ordinal, operation='restore-unlink-park', source=PARK, source_name=PARK_NAMES[ordinal],
                destination=LA, destination_name=NAMES[ordinal], linking=False)
            self._sync('restore-park-directory-sync', ordinal, PARK)
            self.files[ordinal]['location'] = 'restored'
            self.restored.append(ordinal)
        parent.assert_no_provider_dispatch()
        self.phase = 'restored'
        self.verify()
        self.report.update(originalAutoloadRestoredBeforeAnyProviderAttempt=True,
            restoredOriginalInodesAndWholeBytes=True, originalCtimeClaimedRestored=False,
            serviceRestartedByParking=False)

    def _verify_safe(self):
        need(self.safe_file is not None, 'park_actual_safe_publication_required')
        row = self.safe_file
        need(row['closeAttempts'] == 0 and full(os.fstat(row['fd'])) == row['expected']
             and os.pread(row['fd'], len(row['raw']) + 1, 0) == row['raw']
             and full(os.fstat(row['fd'])) == row['expected'], 'park_safe_actual_inode_whole_bytes')
        links = 0
        if row['privateNamed']:
            need(full(os.stat(SAFE.name, dir_fd=self.parents[ROOT]['fd'], follow_symlinks=False)) == row['expected'],
                 'park_safe_current_private_name_same_inode')
            links += 1
        else:
            try:
                os.stat(SAFE.name, dir_fd=self.parents[ROOT]['fd'], follow_symlinks=False)
            except FileNotFoundError:
                pass
            else:
                raise ParkRefused('park_safe_private_name_remains_absent')
        if row['autoloadNamed']:
            need(self.la_entries[NAMES[4]] == row['expected'], 'park_safe_current_autoload_same_inode')
            links += 1
        else:
            need(NAMES[4] not in self.la_entries, 'park_safe_not_yet_published_autoload_absent')
        need(row['expected'][5] == links and links in (1, 2), 'park_safe_exact_known_name_count')

    def publish_safe_gateway(self, *, sequence):
        from mac_refresh_capture_sequence_r2 import FreshOwnerRefreshSequence
        need(type(sequence) is FreshOwnerRefreshSequence and sequence.maintenance is self.gateway
             and sequence.until == self.until and sequence.current_epoch is not None
             and sequence.report['ok'] is True and self.gateway.phase == 'committed'
             and self.phase == 'parked' and self.safe_file is None,
             'park_actual_original_three_committed_epoch_before_safe_publication')
        sequence.verify_current_epoch('before-safe-autoload-publication')
        self.verify_parked()
        self.gateway.verify_quiesced('before-safe-autoload-publication')
        self.gateway._verify_fallback_files()
        self.gateway.selector_fence('before-safe-autoload-publication', self.gateway.safe)
        row = self._intent('create-safe-private-plist')
        try:
            row['syscallAttempted'] = True
            descriptor = os.open(SAFE.name, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                                 0o600, dir_fd=self.parents[ROOT]['fd'])
            item = self._track(descriptor, SAFE)
            raw = self.gateway.safe['plistBytes']
            need(type(raw) is bytes and 0 < len(raw) <= 262144, 'park_bounded_safe_plist_bytes')
            before = os.fstat(descriptor)
            need(stat.S_ISREG(before.st_mode) and before.st_uid == UID and before.st_gid == GID
                 and before.st_nlink == 1 and stat.S_IMODE(before.st_mode) == 0o600,
                 'park_new_safe_plist_custody')
            view = memoryview(raw)
            while view:
                self.within()
                count = os.write(descriptor, view)
                need(count > 0, 'park_safe_private_write_progress')
                view = view[count:]
            os.fsync(descriptor)
            item.update(expected=full(os.fstat(descriptor)), raw=raw, privateNamed=True, autoloadNamed=False)
            need(item['expected'][:6] == full(before)[:6] and item['expected'][6] == len(raw)
                 and os.pread(descriptor, len(raw) + 1, 0) == raw
                 and full(os.fstat(descriptor)) == item['expected']
                 == full(os.stat(SAFE.name, dir_fd=self.parents[ROOT]['fd'], follow_symlinks=False)),
                 'park_safe_private_full9_whole_readback')
            self.verify()
            self._complete(row, {'newSafePrivateFull9': item['expected']})
            self.safe_file = item
            self.phase = 'safe-publishing'
            for operation, action in (
                ('sync-safe-private-parent', lambda: os.fsync(self.parents[ROOT]['fd'])),
                ('link-safe-autoload', lambda: os.link(SAFE.name, NAMES[4],
                    src_dir_fd=self.parents[ROOT]['fd'], dst_dir_fd=self.parents[LA]['fd'], follow_symlinks=False)),
                ('sync-safe-autoload-parent', lambda: os.fsync(self.parents[LA]['fd'])),
                ('unlink-safe-private-name', lambda: os.unlink(SAFE.name, dir_fd=self.parents[ROOT]['fd'])),
                ('sync-unlinked-safe-private-parent', lambda: os.fsync(self.parents[ROOT]['fd']))):
                sequence.verify_current_epoch('before-' + operation)
                self.verify()
                prior = item['expected']
                effect = self._intent(operation)
                effect['syscallAttempted'] = True
                action()
                current = full(os.fstat(descriptor))
                expected_links = 2 if operation in ('link-safe-autoload', 'sync-safe-autoload-parent') else 1
                need(current[:5] == prior[:5] and current[5] == expected_links
                     and current[6:8] == prior[6:8] and os.pread(descriptor, len(raw) + 1, 0) == raw
                     and full(os.fstat(descriptor)) == current, 'park_safe_only_expected_link_transition')
                la_full, entries = self._snapshot(LA)
                if operation == 'link-safe-autoload':
                    need(NAMES[4] not in self.la_entries and set(entries) == set(self.la_entries) | {NAMES[4]}
                         and all(entries[name] == value for name, value in self.la_entries.items())
                         and entries[NAMES[4]] == current and la_full[:5] == self.la_expected[:5],
                         'park_only_new_safe_gateway_entry_published')
                else:
                    expected_entries = dict(self.la_entries)
                    if NAMES[4] in expected_entries:
                        expected_entries[NAMES[4]] = current
                    need(entries == expected_entries and la_full == self.la_expected,
                         'park_other_autoload_names_and_directory_unchanged')
                if operation not in ('unlink-safe-private-name', 'sync-unlinked-safe-private-parent'):
                    need(full(os.stat(SAFE.name, dir_fd=self.parents[ROOT]['fd'], follow_symlinks=False)) == current,
                         'park_same_named_safe_private_link')
                else:
                    try:
                        os.stat(SAFE.name, dir_fd=self.parents[ROOT]['fd'], follow_symlinks=False)
                    except FileNotFoundError:
                        pass
                    else:
                        raise ParkRefused('park_safe_private_name_expected_absence')
                self._complete(effect, {'safeFull9': current, 'launchAgentsFull9': la_full})
                item['expected'], self.la_entries, self.la_expected = current, entries, la_full
                if operation == 'link-safe-autoload':
                    item['autoloadNamed'] = True
                if operation == 'unlink-safe-private-name':
                    item['privateNamed'] = False
            self.phase = 'safe-published'
            self.verify_parked()
            sequence.verify_current_epoch('after-safe-autoload-publication')
            self.gateway.accept_known_safe_autoload(self)
            self.report.update(safeGatewayPublishedOnlyAfterThreeCommitted=True,
                fourOldRelayAutoloadNamesRemainAbsent=True, originalDisabledOverridesUntouched=True)
        except BaseException:
            self.unknown = self.blocked = True
            raise

    def close(self):
        if self.closed:
            return self.report
        errors = []
        for row in reversed(self.rows):
            if row['closeAttempts']:
                continue
            row['closeAttempts'] = 1
            try:
                os.close(row['fd'])
                row['closed'] = True
            except BaseException as error:
                errors.append(type(error).__name__)
        self.closed = True
        self.report.update(phase=self.phase, unknown=self.unknown, operationGraphBlocked=self.blocked,
            parkedCount=len(self.parked), restoredCount=len(self.restored), originalDescriptorsOpened=len(self.rows),
            closeErrorTypes=errors, allOriginalDescriptorsClosedOnce=all(
                row['closed'] and row['closeAttempts'] == 1 for row in self.rows),
            partialNamesPreservedForOriginalReconciliation=bool(self.actions) and (self.unknown or self.blocked),
            automaticNamespaceCleanupAttempted=False)
        if self.unknown or self.blocked or errors:
            self.report['ok'] = False
        return copy.deepcopy(self.report)
