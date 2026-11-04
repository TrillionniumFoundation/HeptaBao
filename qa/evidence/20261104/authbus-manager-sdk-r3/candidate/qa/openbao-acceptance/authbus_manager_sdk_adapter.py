#!/usr/bin/env python3
"""Join the exact proven system supervisor with the original SDK fixture.

This only prepares one fresh runtime QA unit. The frozen supervisor, nonroot
entry, root unit-file helper, and read-only owned-process observer are copied
without changes. The original owner state and SDK databases stay in this same
owned fixture; no production gateway or external OAuth provider is used.
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import time
from types import SimpleNamespace

import owned_process

SUPERVISOR_SHA = '15ea12db58325c4edf8878f31b8a0a1e7efc00595fb9feaac7147fb65b2a9302'
OBSERVER_SHA = '35aef07cd212a759efb4ac38eed55ab45d0db37f52ec487397b05bef208a35ff'
HELPER_SHA = 'b2fcca5d9e7432ab20063e4b25608e2717fef6cbeff786dbb0dc4e1d7c514958'
ENTRY_SHA = '16204429b78d370e58aa1332aa17ae1a295eae94e59bceb08c9144d7e991891b'
CORE_SHA = 'eaf83832144e7ecf1f369ec91007b0d8b4dc55f59342f3ce27ca64a4aea6f76d'
SNAPSHOT_SHA = '383176647f0670837f40f3989496c6d1c902f8503dfa006d386b75877436b581'


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def load(path, pin, name):
    path = Path(path)
    if path.is_symlink() or sha(path) != pin:
        raise RuntimeError('exact_manager_qa_module_pin')
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class ManagerFixture:
    def __init__(self, args, root, confidential):
        here = Path(__file__).resolve().parent
        supervisor = load(here / 'authbus_coordinator_installed_supervisor_live.py',
                          SUPERVISOR_SHA, 'manager_sdk_exact_supervisor')
        supervisor.owned_process = owned_process

        class Probe(supervisor.Run):
            def journal_rows(self, unit, label, *, timeout=supervisor.MANAGER_SECONDS):
                invocation = unit['last']['InvocationID']
                supervisor.need(re.fullmatch(r'[a-f0-9]{32}', invocation) is not None,
                                'actual_manager_invocation_id')
                result = self.execute(label + '.' + str(self.phase_no),
                    ['/usr/bin/sudo', '-n', '/usr/bin/journalctl', '--no-pager',
                     '--unit', unit['name'], '--output=cat', '_SYSTEMD_INVOCATION_ID=' + invocation],
                    timeout=min(timeout, supervisor.MANAGER_SECONDS))
                rows = []
                for line in result.stdout.decode().splitlines():
                    try:
                        value = json.loads(line)
                    except ValueError:
                        continue
                    if isinstance(value, dict) and value.get('schema') == self.entry.SCHEMA + '.installed-result':
                        rows.append(value)
                return invocation, rows

            def failure_journal(self, unit, label, status):
                if label != 'revoked_writer_cold_start':
                    return super().failure_journal(unit, label, status)
                invocation, rows = self.journal_rows(unit, label + '.journal')
                # The unchanged transport conservatively calls non-CAS HTTP400
                # on a dispatched authentication POST an unknown outcome. Keep
                # that exact behavior and the no-retry exit status in evidence.
                self.check(label + '.actual_revoked_login_entry_error', status == 3 and len(rows) == 1
                    and rows[0].get('ok') is False
                    and rows[0].get('error') == 'mutation_outcome_unknown'
                    and rows[0].get('unknown_outcome') is True
                    and rows[0].get('operator_reconciliation_required') is False
                    and rows[0].get('service_recovery_required') is False
                    and rows[0].get('immutable_profile_write_may_have_dispatched') is False
                    and rows[0].get('event_manifest_write_may_have_dispatched') is False)
                self.report.setdefault('managerFailureReceipts', []).append(
                    {'invocationId': invocation, 'case': label, **rows[0]})

        self.module = supervisor
        self.args = args
        self.root = Path(root)
        self.run = Probe(SimpleNamespace(work_dir=self.root, service_manager='system'))
        self.run.secrets = confidential
        self.unit = None
        self.report = self.run.report
        self.report.update(schema='heptabao.authbus-manager-sdk-combination.v1',
            sameFixture=True, sdkProducerFollowerTested=False, actualManagerRestartTested=False,
            managerPendingRecoveryTested=False, managerRevokedColdStartTested=False,
            originalSupervisorSha256=SUPERVISOR_SHA, originalRuntimeObserverSha256=OBSERVER_SHA,
            originalUnitFileHelperSha256=HELPER_SHA, adapterSha256=sha(__file__))

    def prepare(self, config, original_binding, instance):
        m, run = self.module, self.run
        m.need(sha(self.args.system_plan) == self.args.system_plan_sha256, 'same_fixture_system_plan_pin')
        plan = json.loads(self.args.system_plan.read_bytes())
        m.need(plan['schema'] == 'heptabao.installed-supervisor-system-plan.v1'
               and plan['workDir'] == str(self.root) and len(plan['units']) == 1
               and re.fullmatch(r'[a-f0-9]{12}', plan['runId']) is not None
               and plan['entrySha256'] == ENTRY_SHA and plan['coreSha256'] == CORE_SHA
               and plan['helperSha256'] == HELPER_SHA and plan['runtimeObserverSha256'] == OBSERVER_SHA,
               'same_fixture_exact_system_plan')
        run.system_plan = plan
        run.run_id = plan['runId']
        run.root_helper_source = self.args.system_unit_helper.read_bytes()
        run.root_observer_source = self.args.runtime_observer.read_bytes()
        m.need(hashlib.sha256(run.root_helper_source).hexdigest() == HELPER_SHA
               and hashlib.sha256(run.root_observer_source).hexdigest() == OBSERVER_SHA,
               'same_fixture_exact_privileged_helpers')
        for name in ('code', 'logs', 'phases', 'grants'):
            (self.root / name).mkdir(mode=0o700)
        run.entry_path = self.root / 'code/authbus_coordinator_installed.py'
        m.private(run.entry_path, self.args.installed_entry_source.read_bytes())
        m.private(self.root / 'code/authbus_coordinator.py', self.args.central_source.read_bytes())
        run.entry = m.load(run.entry_path, ENTRY_SHA, 'manager_sdk_bound_entry')
        run.central = run.entry.load_core(CORE_SHA)
        m.need(plan['actor'] == run.entry.current_service_identity(), 'same_fixture_nonroot_actor')
        m.need(config['state_dir'] == str(self.root / 'owner-state-a'), 'original_observer_state_contract')
        config = {**config, 'service_scope': {'manager': 'system', **plan['actor']}}
        snapshot = m.load(Path(__file__).resolve().parent / 'kv2_271_lossless_native_live.py',
                          SNAPSHOT_SHA, 'manager_sdk_bounded_snapshot_endpoint')
        run.endpoint = snapshot.Endpoint(instance.address, instance.root / 'ca.crt',
                                         instance.token, run, 'same-fixture-manager')
        run.manager('actual_same_fixture_manager_preflight', ['show', '--property=Version'])
        self.unit = run.install_unit(self.root / 'installation-a', config, 'same_fixture_install')
        binding = self.unit['binding']
        before = original_binding.value
        run.check('same_original_owner_directory_and_locks', all(
            binding.value[k] == before[k] for k in
            ('state_directory', 'operation_lock', 'service_lock', 'owner_anchor')))
        run.check('same_original_backend_and_credentials',
            binding.value['address'] == before['address']
            and binding.value['server_certificate_sha256'] == before['server_certificate_sha256']
            and binding.value['credentials'] == before['credentials']
            and binding.config['owner_id'] == original_binding.config['owner_id']
            and binding.config['source_hosts'] == original_binding.config['source_hosts'])
        self.report['installation'] = {'unitName': self.unit['name'],
            'unitSha256': self.unit['sha256'], 'unitPath': str(self.unit['runtime']),
            'bindingSha256': binding.expected, 'ownerState': str(binding.state),
            'originalApiBindingSha256': original_binding.expected,
            'systemPlanSha256': self.args.system_plan_sha256,
            'sameOriginalOwnerAndLocks': True, 'sameOriginalBackendAndCredentials': True}

    def authorize(self, value, label):
        path = self.root / 'grants' / (label + '.private.json')
        self.module.private(path, value)
        result = self.run.cli(self.unit, label, 'authorize', grant=path)
        self.run.check(label + '.exact_authorization_id',
                       result.get('authorized') is True and result['authorization_id'] == value['authorizationId'])
        return result

    def start(self, label):
        self.run.start_unit(self.unit, label)

    def stop(self, label):
        self.run.stop_unit(self.unit, label)

    def cycle_receipt(self, label, predicate):
        deadline = time.monotonic() + self.module.READINESS_SECONDS
        while time.monotonic() < deadline:
            left = deadline - time.monotonic()
            invocation, rows = self.run.journal_rows(self.unit, label, timeout=left)
            self.module.need(time.monotonic() < deadline, 'original_manager_receipt_deadline')
            self.module.need(not any(row.get('ok') is False for row in rows), 'actual_manager_cycle_error')
            matching = [row for row in rows if row.get('ok') is True and predicate(row)]
            if matching:
                row = matching[-1]
                self.run.check(label + '.exact_bound_journal_receipt',
                    row.get('production_configuration') is True
                    and row.get('installation_sha256') == self.unit['binding'].expected)
                self.report.setdefault('managerCycleReceipts', []).append(
                    {'case': label, 'invocationId': invocation, **row})
                return row
            time.sleep(.1)
        raise self.module.Failure('original_manager_receipt_deadline')

    def wait_published(self, digest, label):
        return self.run.wait_manifest(self.unit, digest, label)

    def restart(self, label):
        run, unit, m = self.run, self.unit, self.module
        before = run.show(unit, label + '.before')
        run.check(label + '.owned_active_before', before['ActiveState'] == 'active'
                  and int(before['MainPID']) == unit['pid'])
        old_pid, old_start = unit['pid'], unit['startTime']
        run.manager(label + '.actual_restart', ['restart', unit['name']])
        deadline = time.monotonic() + m.READINESS_SECONDS
        while time.monotonic() < deadline:
            state = run.show(unit, label + '.state' + str(run.phase_no),
                             timeout=max(.01, deadline - time.monotonic()))
            if state['ActiveState'] == 'active' and int(state['MainPID']) > 1:
                run.runtime_fence(unit, state, deadline=deadline)
                break
            time.sleep(.1)
        else:
            raise m.Failure('actual_manager_restart_original_deadline')
        old_stat = Path('/proc') / str(old_pid) / 'stat'
        old_identity_absent = not old_stat.exists() or old_stat.read_text().rsplit(')', 1)[1].split()[19] != old_start
        run.check(label + '.new_manager_invocation_and_original_pid_gone',
                  state['InvocationID'] != before['InvocationID']
                  and (unit['pid'], unit['startTime']) != (old_pid, old_start) and old_identity_absent)
        self.report['actualManagerRestartTested'] = True
        self.report['managerRestart'] = {'oldPid': old_pid, 'newPid': unit['pid'],
            'oldInvocationId': before['InvocationID'], 'newInvocationId': state['InvocationID'],
            'oldIdentityAbsent': old_identity_absent, 'exactOriginalUnitAndBinding': True}

    def fault_after_commit(self, label):
        self.run.fault(self.unit, label, 'event-crash')
        path = self.root / 'logs' / (label + '.tokens.private.json')
        return json.loads(path.read_bytes())['tokens']

    def wait_recovered(self, original_head):
        pending = self.unit['binding'].state / 'pending.private.json'
        deadline = time.monotonic() + self.module.READINESS_SECONDS
        while time.monotonic() < deadline and pending.exists():
            time.sleep(.1)
        self.run.check('actual_manager_cleared_same_fixture_pending', not pending.exists())
        self.run.check('actual_manager_same_fixture_manifest_not_replayed', self.run.head() == original_head)
        self.cycle_receipt('same_fixture_pending_recovery', lambda row: row.get('recovered_pending') is True)
        self.report['managerPendingRecoveryTested'] = True

    def assert_active(self, label):
        expected_invocation = self.unit['last']['InvocationID']
        fields = self.run.show(self.unit, label)
        self.run.check(label + '.same_owned_process', fields['ActiveState'] == 'active'
            and int(fields['MainPID']) == self.unit['pid']
            and fields['InvocationID'] == expected_invocation)

    def revoked_cold_start(self):
        before = self.run.head()
        self.run.start_unit(self.unit, 'revoked_writer_cold_start', failure=3)
        self.run.check('revoked_manager_no_remote_manifest_write', self.run.head() == before)
        self.run.check('revoked_manager_no_pending_write_journal',
            not (self.unit['binding'].state / 'pending.private.json').exists()
            and not (self.unit['binding'].state / 'operator-pending.private.json').exists())
        self.report['managerRevokedColdStartTested'] = True

    def cleanup(self):
        self.run.cleanup()
        self.report['ok'] = bool(self.report.get('sdkProducerFollowerTested')
            and self.report.get('actualManagerRestartTested')
            and self.report.get('managerPendingRecoveryTested')
            and self.report.get('managerRevokedColdStartTested')
            and self.report.get('ownedCleanupComplete')
            and all(row['passed'] for row in self.report['checks']))
        self.report['realSystemManagerTested'] = self.report['ok']
        return self.report
