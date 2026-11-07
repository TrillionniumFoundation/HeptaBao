#!/usr/bin/env python3
"""Concrete same-parent fresh-clone -> original refresh-child sequence.

No import-time I/O, service action, provider call or credential discovery.
The original outer supplies the actual stopped-writer actuator and its current
consumer fence. This module never converts a JSON receipt into writer authority.
Each owner consumes one fixed capture path and the original provider slot.
"""
from __future__ import annotations

import copy
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
import time
import types

from mac_gateway_writer_maintenance_r2 import GatewayWriterMaintenance
from mac_maintenance_private_files_r1 import MaintenancePrivateFiles
from mac_owned_refresh_parent_r2 import OwnedRefreshParent, strict_json
from mac_refresh_capture_authority_r1 import OWNER_CAPTURES
from mac_post_commit_epoch_r2 import PostCommitEpoch

ROOT = Path('/Users/qianqi/heptabao-authbus-writer-maintenance-20261106-r1')
LEDGER = Path('/Users/qianqi/heptabao-authbus-refresh-once-ledger-20261106')
LIVE = Path('/Users/qianqi/.openclaw')
PYTHON = '/opt/homebrew/Cellar/python@3.14/3.14.3_1/Frameworks/Python.framework/Versions/3.14/bin/python3.14'
AGENTS = ('main', 'trnm', 'hepta-ui', 'hepta', 'hepta-backend')
MAX_DATABASE = 4 * 1024 ** 3
FIXED_OTHER_ALLOWANCE = 1024 ** 3


class SequenceRefused(RuntimeError):
    pass


def need(value, code):
    if not value:
        raise SequenceRefused(code)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False)


def capacity_requirements(packet):
    """Fresh original inventory only; byte arithmetic does not admit a writer.

    Available bytes already exclude existing originals, snapshots and
    quarantine. Include all additional three double-five captures, two full-six
    post-COMMITTED baseline outputs, one full-six restore staging, a conservative
    three-registry observation allowance, and a fixed private-record/sidecar
    margin. Neither this calculation nor statvfs reserves space.
    """
    need(type(packet) is dict
         and packet.get('schema') == 'heptabao.current-production-source-inventory.private.r1'
         and packet.get('unopenedAdditionalRegisteredPaths') == [],
         'sequence_original_finite_six_database_inventory')
    entries = packet.get('databases')
    need(type(entries) is list and len(entries) == 6
         and all(type(row) is dict and type(row.get('slot')) is int and row['slot'] == i
                 for i, row in enumerate(entries)), 'sequence_six_original_ordered_slots')
    estimated = []
    source_bytes = 0
    for slot, entry in enumerate(entries):
        base = LIVE / ('state/openclaw.sqlite' if slot == 5 else
                       'agents/%s/agent/openclaw-agent.sqlite' % AGENTS[slot])
        if slot < 5:
            need(entry.get('agentId') == AGENTS[slot], 'sequence_exact_five_registered_agent_slots')
        else:
            need(entry.get('kind') == 'shared-state', 'sequence_exact_registry_slot')
        generation = entry.get('generation', {})
        present, absent = generation.get('sourceIdentities'), generation.get('sourceAbsences')
        need(type(present) is dict and type(absent) is list and len(absent) == len(set(absent))
             and set(present).isdisjoint(absent)
             and set(present) | set(absent) == {str(base) + s for s in ('', '-wal', '-shm', '-journal')}
             and str(base) in present and str(base) + '-journal' in absent,
             'sequence_fixed_whole_source_namespace_capacity')
        physical = 0
        for value in present.values():
            need(type(value) is list and len(value) == 9
                 and all(type(v) is str and v.isdecimal() and len(v) <= 30 for v in value),
                 'sequence_typed_private_namespace_for_capacity')
            physical += int(value[6])
        pragmas = entry.get('inventory', {}).get('pragmas', {})
        pages, page_size = pragmas.get('page_count'), pragmas.get('page_size')
        need(type(pages) is int and pages > 0 and type(page_size) is int
             and page_size in (512, 1024, 2048, 4096, 8192, 16384, 32768, 65536)
             and 0 < pages * page_size <= MAX_DATABASE,
             'sequence_actual_logical_source_capacity_bound')
        logical = pages * page_size
        need(0 < int(present[str(base)][6]) <= MAX_DATABASE
             and physical <= 2 * MAX_DATABASE, 'sequence_actual_physical_source_capacity_bound')
        estimated.append(max(logical, physical))
        source_bytes += physical
    five = sum(estimated[:5])
    six = sum(estimated)
    components = {
        'threeOwnersTwoWholeFiveDatabaseCopiesBytes': 6 * five,
        'postThreeCommittedTwoWholeSixBaselineCopiesBytes': 2 * six,
        'oneWholeSixRestoreStagingBytes': six,
        'threeRegistryObservationAllowancesBytes': 3 * estimated[5],
        'fixedAdditionalPrivateRecordsAndSidecarsBytes': FIXED_OTHER_ALLOWANCE,
    }
    return {'schema': 'heptabao.maintenance-disk-capacity-plan.public.r1',
            'fixedDatabaseCount': 6, 'actualObservedSourceAndSidecarBytes': source_bytes,
            'components': components, 'requiredAdditionalBytes': sum(components.values()),
            'existingFilesOrQuarantineCountedAsFree': False,
            'observationIsSpaceReservation': False, 'productionCapacityAdmitted': False}


class FreshOwnerRefreshSequence:
    def __init__(self, *, maintenance, refresh_parent, private_files, commands,
                 journal, read_public, source_fence, until, clock=time.monotonic):
        need(isinstance(maintenance, GatewayWriterMaintenance)
             and isinstance(refresh_parent, OwnedRefreshParent)
             and isinstance(private_files, MaintenancePrivateFiles)
             and refresh_parent.maintenance is maintenance
             and refresh_parent.until == maintenance.until == private_files.until == until,
             'sequence_same_original_concrete_parent_instances')
        need(clock() < until <= clock() + 600 and callable(read_public)
             and callable(source_fence) and callable(journal.append),
             'sequence_same_original_parent_deadline_and_public_source_reader')
        self.maintenance, self.refresh_parent, self.private_files = maintenance, refresh_parent, private_files
        self.commands, self.journal, self.read_public = commands, journal, read_public
        self.source_fence, self.until, self.clock = source_fence, until, clock
        self.attempted, self.accepted, self.loaded = [], [], []
        self.failed, self.closed, self.preflight_completed = False, False, False
        self.last_capsule_bytes = self.last_capsule_identity = self.current_epoch = None
        self.report = {'schema': 'heptabao.main3-same-parent-fresh-clone-refresh.public.r2',
            'ok': False, 'captureMaximumSeconds': 45, 'ownerMaximumSeconds': 120,
            'sameParentMaximumSeconds': 600, 'captureAttempts': [],
            'privateCredentialValuesPathsOrDigestsPublished': False,
            'olderCloneReusedForLaterOwner': False, 'oldKeeperUsedAsLatest': False,
            'captureIsProductionConsumption': False, 'automaticRetry': False,
            'automaticServiceRestore': False, 'productionCutoverQualified': False,
            'postThreeCommittedFullBaselineStillRequired': True}

    def remaining(self):
        left = self.until - self.clock()
        need(not self.closed and not self.failed and left > 0, 'sequence_original_deadline_or_failed_context')
        return left

    def _read_source(self, ordinal, name, expected):
        self.remaining()
        info = OWNER_CAPTURES[ordinal]
        filename = ROOT / 'code' / ('owner-0%d' % (ordinal + 1)) / name
        need(str(filename.parent) == info['stageRoot'], 'sequence_exact_owner_source_directory')
        raw = self.read_public(filename, 131072)
        need(type(raw) is bytes and len(raw) == expected['bytes'] and sha(raw) == expected['sha256'],
             'sequence_original_whole_public_source_pin')
        return raw

    def _module(self, ordinal, name, expected, key):
        need(key not in sys.modules, 'sequence_source_module_not_preloaded_or_replayed')
        raw = self._read_source(ordinal, name, expected)
        module = types.ModuleType(key)
        module.__file__ = str(ROOT / 'code' / ('owner-0%d' % (ordinal + 1)) / name)
        sys.modules[key] = module
        self.loaded.append((key, module))
        try:
            exec(compile(raw, module.__file__, 'exec'), module.__dict__)
        except BaseException:
            # Keep the consumed import name in this original context. A failed
            # module load is not replaced and retried from another source.
            self.failed = True
            raise
        return module

    def preflight(self, *, inventory, inventory_fence):
        need(not self.preflight_completed and not self.attempted
             and self.maintenance.phase == 'original-bound' and callable(inventory_fence),
             'sequence_preflight_once_before_any_service_intent')
        self.remaining()
        inventory_fence()
        self.source_fence()
        need(type(OWNER_CAPTURES) is list and len(OWNER_CAPTURES) == 3,
             'sequence_exact_prepared_three_owner_capture_sources')
        for ordinal, entry in enumerate(OWNER_CAPTURES):
            need(entry.get('ordinal') == ordinal and type(entry.get('ordinal')) is int
                 and entry['captureRoot'] == str(ROOT / 'captures' / ('owner-0%d' % (ordinal + 1))),
                 'sequence_original_fixed_capture_scope')
            for name, expected in entry['sourcePins'].items():
                self._read_source(ordinal, name, expected)
            for name, key in (('main3_inline_capture.py', 'inlineAdapterPin'),
                              ('main3_source_fence.py', 'sourceFencePin')):
                self._read_source(ordinal, name, entry[key])
            for name in (Path(entry['captureRoot']),
                         ROOT / 'output' / ('owner-0%d.inline-capture-authority.public.json' % (ordinal + 1)),
                         ROOT / 'output' / ('owner-0%d.inline-capture-result.public.json' % (ordinal + 1)),
                         ROOT / 'output' / ('owner-0%d.capsule-admission-binding.private.json' % (ordinal + 1))):
                try:
                    name.lstat()
                except FileNotFoundError:
                    continue
                raise SequenceRefused('sequence_original_capture_paths_already_consumed')
        ledger = self.private_files.directory(LEDGER)
        need(os.listdir(ledger['fd']) == [], 'sequence_fixed_once_ledger_empty_before_first_original_attempt')
        disk = capacity_requirements(inventory)
        available = os.statvfs(ROOT)
        free_bytes = available.f_bavail * available.f_frsize
        need(type(free_bytes) is int and free_bytes >= disk['requiredAdditionalBytes'],
             'sequence_whole_maintenance_additional_capacity_before_stop')
        # Preserve fixed, held roots on the same device required by WholeStore.
        root = self.private_files.directory(ROOT)
        live = LIVE.lstat()
        need(stat.S_ISDIR(live.st_mode) and not stat.S_ISLNK(live.st_mode)
             and live.st_uid == 501 and stat.S_IMODE(live.st_mode) == 0o700
             and os.fstat(root['fd']).st_dev == live.st_dev,
             'sequence_private_whole_clone_same_source_device')
        self.private_files.verify_parents()
        inventory_fence()
        self.source_fence()
        self.maintenance.same_original_running('whole-maintenance-preflight')
        disk.update(currentAvailableBytes=free_bytes, productionCapacityAdmitted=True)
        self.report['diskCapacity'] = disk
        self.preflight_completed = True
        return copy.deepcopy(disk)

    def _prior_committed_values(self, document, ordinal):
        entries = document['ownerEntries']
        for previous in range(ordinal):
            original = self.refresh_parent.committed[previous]
            need(entries[previous]['profileId'] == self.refresh_parent.profile_ids[previous]
                 and canonical(entries[previous]['credential']) == canonical(original['normalizedCredential']),
                 'sequence_new_fresh_source_contains_each_prior_original_committed_credential')

    def run_one(self, ordinal):
        need(self.preflight_completed and type(ordinal) is int
             and ordinal == len(self.attempted) == len(self.accepted) < 3
             and len(self.refresh_parent.committed) == ordinal
             and self.maintenance.phase in ('parked-for-refresh', 'refreshing')
             and not self.refresh_parent.blocked, 'sequence_next_original_owner_only')
        self.remaining()
        self.source_fence()
        entry = OWNER_CAPTURES[ordinal]
        row = {'ordinal': ordinal, 'captureAdmitted': False, 'refreshParentInvoked': False,
               'knownCommitted': False, 'captureSourceHandlesClosed': False}
        self.report['captureAttempts'].append(row)
        self.attempted.append(ordinal)
        fence = None
        try:
            inline = self._module(ordinal, 'main3_inline_capture.py', entry['inlineAdapterPin'],
                                  'mac_maintenance_capture_owner_0%d_inline' % (ordinal + 1))
            fence_module = self._module(ordinal, 'main3_source_fence.py', entry['sourceFencePin'],
                                        'mac_maintenance_capture_owner_0%d_fence' % (ordinal + 1))
            capture_plan = {'pythonRuntime': {'path': PYTHON}, 'sourcePins': entry['sourcePins']}
            original = inline.run_capture(self.commands, capture_plan, self.journal,
                self.until, self.remaining, self.read_public, self.maintenance.verify_quiesced)
            row['captureOriginal'] = original
            self.remaining()
            fence = fence_module.CapsuleFence(min(self.until, self.clock() + 120), admit_mode='qualify')
            fence.observe('preflight')
            capsule_path = Path(entry['captureRoot']) / 'output/selected-owner-credentials.private.json'
            private = self.private_files.read(capsule_path, 1048576, expected=fence.capsule_identity)
            document = strict_json(private, 1048576)
            need(document == fence.doc, 'sequence_same_original_private_capsule_bytes')
            self._prior_committed_values(document, ordinal)
            row['captureAdmitted'] = True

            def fresh_fence():
                self.remaining()
                self.source_fence()
                fence.observe('before-phase')
                need(self.private_files.read(capsule_path, 1048576, expected=fence.capsule_identity) == private,
                     'sequence_original_capsule_never_rebound_between_children')
                self._prior_committed_values(document, ordinal)
                return True

            row['refreshParentInvoked'] = True
            result = self.refresh_parent.run_one(ordinal=ordinal, capsule_bytes=private,
                capsule_identity=fence.capsule_identity, fresh_capture_fence=fresh_fence)
            need(result.get('ok') is True and len(self.refresh_parent.committed) == ordinal + 1,
                 'sequence_original_refresh_parent_accepted_known_commit')
            self.accepted.append(ordinal)
            self.last_capsule_bytes, self.last_capsule_identity = private, fence.capsule_identity
            row['knownCommitted'] = True
            row['refreshOriginal'] = result
            self.source_fence()
        except BaseException:
            self.failed = True
            self.refresh_parent.blocked = True
            row['sequenceStoppedWithoutAutomaticRetryOrRestore'] = True
            raise
        finally:
            if fence is not None:
                row['captureFence'] = fence.public()
                row['captureSourceHandlesClosed'] = fence.opened == fence.closed
                if not row['captureSourceHandlesClosed']:
                    self.failed = True
                    self.refresh_parent.blocked = True
        need(not self.failed and row['captureSourceHandlesClosed'],
             'sequence_original_capture_and_refresh_complete_before_next_owner')
        return copy.deepcopy(row)

    def all_committed(self, *, auth, critical, cancelled):
        need(self.accepted == [0, 1, 2] and self.attempted == [0, 1, 2]
             and all(row['captureSourceHandlesClosed'] for row in self.report['captureAttempts'])
             and self.current_epoch is None and callable(critical) and callable(cancelled),
             'sequence_all_three_original_contexts_closed')
        self.remaining()
        self.current_epoch = PostCommitEpoch(parent=self.refresh_parent, private_files=self.private_files,
            auth=auth, read_public=self.read_public, source_fence=self.source_fence,
            capsule_bytes=self.last_capsule_bytes, capsule_identity=self.last_capsule_identity,
            critical=critical, cancelled=cancelled, clock=self.clock)
        result = self.refresh_parent.all_committed(current_epoch_fence=self.current_epoch.capture)
        self.report.update(ok=True, allThreeOriginalKnownCommitted=True,
                           currentPostRefreshEpochRechecked=True, refreshParent=result,
                           postCommitEpoch=copy.deepcopy(self.current_epoch.report))
        return copy.deepcopy(self.report)

    def verify_current_epoch(self, label):
        self.remaining()
        need(self.report['ok'] is True and self.current_epoch is not None,
             'sequence_original_post_commit_epoch_required_before_baseline')
        return self.current_epoch.verify(label)

    def close(self):
        self.closed = True
        if self.current_epoch is not None:
            self.report['postCommitEpoch'] = self.current_epoch.close()
        self.report.update(originalCaptureSlotsConsumed=len(self.attempted),
            originalOwnersKnownCommitted=len(self.accepted), failed=self.failed,
            sourceModulesRetainedWithoutReload=len(self.loaded),
            automaticServiceRestore=False, productionRollbackQualified=False)
        return copy.deepcopy(self.report)
