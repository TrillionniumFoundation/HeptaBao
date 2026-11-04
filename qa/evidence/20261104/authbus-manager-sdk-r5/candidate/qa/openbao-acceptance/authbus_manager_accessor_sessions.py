#!/usr/bin/env python3
"""Observe and revoke only exact token-issuance intervals in an owned fixture.

Accessors and token lookup bodies stay private. Each daemon start/restart must
add exactly one accessor, and each operator inspect/authorize interval exactly
two, with the exact writer AppRole policy and issuer metadata. A mismatch stops
before any revocation. No bearer, process memory or process environment is read.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import time

WRITER = 'authbus-central-writer'


def digest(value):
    raw = value.encode() if isinstance(value, str) else json.dumps(value, sort_keys=True).encode()
    return hashlib.sha256(raw).hexdigest()


class AccessorSessions:
    def __init__(self, fixture):
        self.fixture, self.run, self.module = fixture, fixture.run, fixture.module
        self.sessions = []
        self.report = {'schema': 'heptabao.owned-manager-accessor-session-proof.v1', 'ok': False,
            'bearersRead': False, 'processMemoryRead': False, 'processEnvironmentRead': False,
            'captures': [], 'revocations': [], 'inventories': [],
            'daemonAccessorsRevoked': False, 'operatorAccessorsRevoked': False,
            'activeDaemonDeniedWithOldBearer': False, 'coldRevocationsPersisted': False,
            'onlyFixtureRootRemains': False,
            'namespaceScope': 'owned_root_endpoint_without_namespace_header',
            'namespaceProjectionEvidenceSha256': '8bdcde8af3c1c469a35344d5f278f7c0e0ed0dcd7bbf25a2ffadb968cd8d0b9a'}
        fixture.report['accessorSessionQualification'] = self.report

    def check(self, name, condition, **metadata):
        self.run.check('accessor_sessions.' + name, condition, **metadata)

    def snapshot(self, label):
        status, value = self.run.endpoint.call('LIST', 'auth/token/accessors')
        keys = value.get('data', {}).get('keys') if isinstance(value, dict) else None
        self.check(label + '.bounded_inventory', status == 200 and isinstance(keys, list)
            and 1 <= len(keys) <= 256 and len(keys) == len(set(keys))
            and all(isinstance(key, str) and 8 <= len(key) <= 4096 for key in keys))
        for key in keys:
            if key not in self.run.secrets:
                self.run.secrets.append(key)
        self.report['inventories'].append({'case': label, 'count': len(keys),
            'sortedAccessorSetSha256': digest(sorted(keys))})
        return set(keys)

    def lookup(self, accessor, label, expected=200):
        status, value = self.run.endpoint.call('POST', 'auth/token/lookup-accessor', {'accessor': accessor})
        self.check(label + '.lookup_status', status == expected, expected=expected, actual=status)
        if expected == 200:
            info = value.get('data', {})
            self.check(label + '.accessor_and_no_bearer', isinstance(info, dict)
                and info.get('accessor') == accessor and info.get('id') in (None, ''))
            return info
        self.check(label + '.invalid_accessor_response', isinstance(value, dict)
            and isinstance(value.get('errors'), list)
            and value['errors'] == ['1 error occurred:\n\t* invalid accessor\n\n'])
        return None

    def writer_metadata(self, info, label):
        policies = info.get('policies')
        metadata = info.get('meta')
        # The exact normal binary projects the public OpenBao lookup contract:
        # namespace is omitted. Scope comes from this owned root-only endpoint,
        # which never sends a namespace header; do not accept an arbitrary value.
        predicates = {
            'exact_writer_policies': isinstance(policies, list) and WRITER in policies
                and set(policies) <= {WRITER, 'default'} and len(policies) == len(set(policies)),
            'exact_writer_role': isinstance(metadata, dict) and metadata.get('role_name') == WRITER,
            'service_token': info.get('type') == 'service',
            'renewable': info.get('renewable') is True,
            'live_ttl': isinstance(info.get('ttl'), int) and info['ttl'] > 30,
            'exact_native_namespace_projection': 'namespace' not in info,
        }
        self.check(label + '.exact_writer_app_role', all(predicates.values()),
                   predicates=predicates,
                   ttl=info.get('ttl') if isinstance(info.get('ttl'), int) else None)

    def capture(self, before, label, kind, expected):
        self.module.need(kind in ('daemon', 'operator') and expected == (1 if kind == 'daemon' else 2),
                         'exact_issuance_interval_shape')
        after = self.snapshot(label + '.after')
        delta = after - before
        self.check(label + '.exact_issuance_difference', before <= after and len(delta) == expected
            and not any(item['accessor'] in delta for item in self.sessions),
            expected=expected, observed=len(delta))
        invocation = self.fixture.unit['last']['InvocationID'] if kind == 'daemon' else None
        for ordinal, accessor in enumerate(sorted(delta)):
            info = self.lookup(accessor, label + '.' + str(ordinal))
            self.writer_metadata(info, label + '.' + str(ordinal))
            row = {'kind': kind, 'case': label, 'accessorSha256': digest(accessor),
                'invocationId': invocation, 'policies': sorted(info['policies']),
                'roleName': info['meta']['role_name'], 'ttlAtCapture': info['ttl'],
                'exactDifferenceCardinality': expected}
            self.sessions.append({'accessor': accessor, **row})
            self.report['captures'].append(row)

    def wait_new_cycle(self, label, predicate):
        # Polling a running owner keeps the original 75-second worker deadline;
        # the service's unchanged poll interval is 15 seconds.
        _, prior = self.run.journal_rows(self.fixture.unit, label + '.baseline')
        observed_count = len(prior)
        deadline = time.monotonic() + self.module.PROCESS_SECONDS
        while time.monotonic() < deadline:
            invocation, rows = self.run.journal_rows(self.fixture.unit, label + '.observe',
                timeout=max(.01, deadline - time.monotonic()))
            self.module.need(time.monotonic() < deadline, 'original_worker_cycle_observation_deadline')
            self.module.need(not any(row.get('ok') is False for row in rows), 'manager_cycle_before_revocation_error')
            matching = [row for row in rows[observed_count:] if row.get('ok') is True and predicate(row)]
            if matching:
                row = matching[-1]
                self.check(label + '.new_exact_bound_cycle',
                    row.get('installation_sha256') == self.fixture.unit['binding'].expected
                    and row.get('production_configuration') is True)
                self.fixture.report.setdefault('managerCycleReceipts', []).append(
                    {'case': label, 'invocationId': invocation, **row})
                return row
            time.sleep(min(1.0, max(0, deadline - time.monotonic())))
        raise self.module.Failure('original_worker_cycle_observation_deadline')

    def revoke_all_and_observe_live_denial(self):
        kinds = [item['kind'] for item in self.sessions]
        self.check('exact_managed_session_cohort', kinds.count('daemon') == 4 and kinds.count('operator') == 4
            and len({item['accessor'] for item in self.sessions}) == 8)
        # SDK stores have completed generation D. Wait for a new actual no-op
        # owner cycle to consume their final reports before revoking its bearer.
        self.wait_new_cycle('quiescent_after_sdk_convergence',
                            lambda row: row.get('committed') == 0)
        state = self.fixture.unit['binding'].state
        self.check('no_pending_before_revocation', not (state / 'pending.private.json').exists()
            and not (state / 'operator-pending.private.json').exists())
        before_head = self.run.head()
        before_unit = self.run.show(self.fixture.unit, 'accessor_sessions.active_before_revoke')
        self.check('actual_daemon_active_before_revoke', before_unit['ActiveState'] == 'active'
            and int(before_unit['MainPID']) == self.fixture.unit['pid'])
        # Validate the complete cohort before dispatching the first revoke.
        for index, item in enumerate(self.sessions):
            info = self.lookup(item['accessor'], 'revoke_preflight_' + str(index))
            self.writer_metadata(info, 'revoke_preflight_' + str(index))
        for index, item in enumerate(self.sessions):
            status, _ = self.run.endpoint.call('POST', 'auth/token/revoke-accessor',
                                               {'accessor': item['accessor']})
            self.check('revoke_' + str(index) + '.actual_request', status == 204, status=status)
            self.lookup(item['accessor'], 'revoke_' + str(index) + '.after', expected=400)
            self.report['revocations'].append({'kind': item['kind'], 'case': item['case'],
                'accessorSha256': item['accessorSha256'], 'revokeStatus': status, 'postLookupStatus': 400})
        after = self.snapshot('after_all_exact_session_revocations')
        self.check('revoked_cohort_absent_from_inventory', all(item['accessor'] not in after for item in self.sessions))
        self.report['daemonAccessorsRevoked'] = self.report['operatorAccessorsRevoked'] = True
        deadline = time.monotonic() + self.module.PROCESS_SECONDS
        while time.monotonic() < deadline:
            fields = self.run.show(self.fixture.unit, 'accessor_sessions.wait_exit_' + str(self.run.phase_no),
                                  timeout=max(.01, deadline - time.monotonic()))
            if fields['ActiveState'] == 'failed':
                break
            time.sleep(min(1.0, max(0, deadline - time.monotonic())))
        else:
            raise self.module.Failure('revoked_live_daemon_original_worker_deadline')
        self.check('live_old_bearer_caused_exact_exit', int(fields['ExecMainStatus']) == 2
            and int(fields['MainPID']) == 0 and int(fields['NRestarts']) == 0
            and fields['InvocationID'] == before_unit['InvocationID'])
        time.sleep(self.module.NO_RESTART_SECONDS)
        fields = self.run.show(self.fixture.unit, 'accessor_sessions.after_no_retry_window')
        self.check('live_revocation_no_automatic_retry', fields['ActiveState'] == 'failed'
            and int(fields['MainPID']) == 0 and int(fields['NRestarts']) == 0
            and int(fields['ExecMainStatus']) == 2 and fields['InvocationID'] == before_unit['InvocationID'])
        invocation, rows = self.run.journal_rows(self.fixture.unit, 'accessor_sessions.live_failure_journal')
        failures = [row for row in rows if row.get('ok') is False]
        self.check('actual_old_bearer_denial_receipt', len(failures) == 1
            and failures[0].get('error') == 'bao_authentication_or_acl_denied'
            and failures[0].get('unknown_outcome') is False
            and failures[0].get('operator_reconciliation_required') is False
            and failures[0].get('service_recovery_required') is False)
        self.fixture.report.setdefault('managerFailureReceipts', []).append(
            {'case': 'actual_running_daemon_bearer_revoked', 'invocationId': invocation, **failures[0]})
        self.check('live_revocation_left_manifest_exact', self.run.head() == before_head)
        cgroup = fields.get('ControlGroup')
        if cgroup:
            path = Path('/sys/fs/cgroup') / cgroup.lstrip('/') / 'cgroup.procs'
            self.check('failed_daemon_cgroup_empty', not path.exists() or not path.read_text().strip())
        self.report['activeDaemonDeniedWithOldBearer'] = True

    def verify_after_cold_restart(self):
        for index, item in enumerate(self.sessions):
            self.lookup(item['accessor'], 'cold_revocation_' + str(index), expected=400)
        after = self.snapshot('cold_revocations_inventory')
        self.check('cold_revoked_cohort_absent', all(item['accessor'] not in after for item in self.sessions))
        self.report['coldRevocationsPersisted'] = True

    def finish_after_sid_denial(self, before_failed_start):
        after = self.snapshot('after_revoked_sid_failed_start')
        self.check('failed_sid_cold_start_issued_no_accessor', after == before_failed_start)
        self.check('only_one_fixture_root_token_remains', len(after) == 1)
        root = self.lookup(next(iter(after)), 'final_fixture_root')
        self.check('remaining_token_is_exact_root_policy', root.get('policies') == ['root'])
        self.report['onlyFixtureRootRemains'] = True
        self.report['ok'] = all(self.report[k] for k in ('daemonAccessorsRevoked', 'operatorAccessorsRevoked',
            'activeDaemonDeniedWithOldBearer', 'coldRevocationsPersisted', 'onlyFixtureRootRemains'))
        self.fixture.report['managerSessionTokenRevocationCoverage'] = self.report['ok']
        self.fixture.report['operatorCliSessionTokenRevocationCoverage'] = self.report['ok']
