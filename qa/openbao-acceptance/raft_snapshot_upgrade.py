#!/usr/bin/env python3
"""Real pinned legacy Raft bundle1 -> compact bundle2, private loopback only.

Reuses the existing mTLS Cluster launcher. No user-store or snapshot input exists.
The legacy pin must be filled from the independently preserved build receipt.
"""
from __future__ import annotations
import json
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
from bao_http import SafeArgumentParser
from core_isolation import ROOT, file_hash
from ha_destructive import Cluster, FixtureError, checked_binary
from online_evidence import admit_output, publish
from online_evidence import source_identity
from provider_renewal_upgrade import durable_manifest
from raft_snapshot_observation import inspect_bundle

LEGACY_SOURCE = "d26ed9d5c3bfd1cac6c669f7b767c753adc2f823"
LEGACY_SHA256 = "ac818b3551fc7b5a9612d3a1778a91502a64c2ca0226923492c9dafffa49bb89"
LEGACY_RECEIPT = ROOT / "qa/openbao-acceptance/evidence/approle-native-defaults-d26ed9d.json"

REQUIRED = frozenset({
    'legacy_checkpoint_caught_up', 'legacy_actual_byte_array_snapshot',
    'current_read_preserves_format1_bundle', 'current_reads_legacy_value',
    'explicit_snapshot_publishes_format2', 'old_process_rejects_format2',
    'old_rejection_preserves_all_raft_files', 'current_recovers_after_old_rejection',
    'recovered_write_visible_on_every_voter', 'failover_preserves_committed_value',
    'restarted_compact_node_reads_new_value', 'receipt_has_no_secrets', 'upgrade_complete',
})


def admit_legacy(receipt, expected):
    if LEGACY_SOURCE is None or LEGACY_SHA256 is None or LEGACY_RECEIPT is None:
        raise ValueError('legacy_bundle1_build_not_yet_pinned')
    identity = receipt.get('candidate_source', {})
    if (expected != LEGACY_SHA256 or receipt.get('status') != 'passed'
            or receipt.get('build_source_commit') != LEGACY_SOURCE
            or identity.get('source_commit') != LEGACY_SOURCE
            or identity.get('binary_sha256') != LEGACY_SHA256
            or identity.get('source_dirty') is not False
            or receipt.get('source_and_binary_unchanged') is not True
            or receipt.get('cases_match') is not True
            or receipt.get('runner_unchanged') is not True):
        raise ValueError('legacy_bundle1_build_receipt_mismatch')


def bundle_path(node):
    return node.root/'raft'/'state-machine'/'state-bundle.bin'


def start_voters(cluster, binary):
    for node in cluster.nodes:
        node.binary = binary
        node.start(wait=False)
    for node in cluster.nodes:
        node.wait_ready()
    cluster.wait_quorum()
    for node in cluster.nodes:
        if node.call('POST', 'sys/unseal', {'key': cluster.unseal_key})[0] != 200:
            raise FixtureError('upgrade_voter_unseal_failed')
    return cluster.leader()


def run_upgrade(cluster, candidate, legacy, checks, artifacts):
    def check(name, value):
        if type(value) is not bool or not value:
            raise FixtureError(name)
        checks.append({'case': name, 'passed': True})
    cluster.bootstrap()
    leader = cluster.leader()
    cluster.write(leader, 'bundle-upgrade-before', 'synthetic-before-snapshot')
    status, _ = leader.call('GET', 'sys/storage/raft/snapshot', token=cluster.root_token, timeout=15)
    if status != 200:raise FixtureError('legacy_snapshot_failed')
    status, response = leader.call('GET', 'sys/storage/raft/snapshot-status', token=cluster.root_token)
    frontier = response.get('data', {})
    # Runtime policy is LogsSinceLast(128). Finish with zero outstanding entries;
    # no user writes occur before the candidate pure-read observation below.
    check('legacy_checkpoint_caught_up', status == 200 and type(frontier.get('applied_index')) is int
          and frontier['applied_index'] == frontier.get('snapshot_index'))
    cluster.close()
    artifacts['legacy'] = inspect_bundle(bundle_path(leader), 1)
    check('legacy_actual_byte_array_snapshot', True)
    old_bundle = artifacts['legacy']['artifact_sha256']
    current_leader = start_voters(cluster, candidate)
    for node in cluster.nodes:
        cluster.read(node, 'bundle-upgrade-before', 'synthetic-before-snapshot')
    check('current_reads_legacy_value', True)
    artifacts['pure_read'] = inspect_bundle(bundle_path(leader), 1)
    check('current_read_preserves_format1_bundle', artifacts['pure_read']['artifact_sha256'] == old_bundle)
    status, _ = current_leader.call('GET', 'sys/storage/raft/snapshot', token=cluster.root_token, timeout=15)
    check('explicit_snapshot_publishes_format2', status == 200)
    artifacts['compact'] = inspect_bundle(bundle_path(current_leader), 2)
    cluster.close()
    before = durable_manifest(current_leader.root/'raft')
    current_leader.binary = legacy
    current_leader.start(wait=False)
    try:
        returncode = current_leader.process.wait(timeout=15)
        check('old_process_rejects_format2', returncode != 0)
    except subprocess.TimeoutExpired:
        raise FixtureError('old_process_did_not_reject_format2') from None
    finally:
        current_leader.stop()
    check('old_rejection_preserves_all_raft_files', durable_manifest(current_leader.root/'raft') == before)
    compact_node = current_leader
    current_leader = start_voters(cluster, candidate)
    for node in cluster.nodes:
        cluster.read(node, 'bundle-upgrade-before', 'synthetic-before-snapshot')
    check('current_recovers_after_old_rejection', True)
    cluster.write(current_leader, 'bundle-upgrade-after', 'synthetic-after-reopen')
    for node in cluster.nodes:
        cluster.read(node, 'bundle-upgrade-after', 'synthetic-after-reopen')
    check('recovered_write_visible_on_every_voter', True)
    current_leader.stop()
    promoted = cluster.leader()
    cluster.read(promoted, 'bundle-upgrade-after', 'synthetic-after-reopen')
    cluster.write(promoted, 'bundle-upgrade-failover', 'synthetic-after-failover')
    check('failover_preserves_committed_value', promoted is not current_leader)
    cluster.restart(current_leader)
    cluster.read(current_leader, 'bundle-upgrade-failover', 'synthetic-after-failover')
    if compact_node is not current_leader:
        compact_node.stop()
        cluster.restart(compact_node)
    cluster.read(compact_node, 'bundle-upgrade-failover', 'synthetic-after-failover')
    artifacts['recovered'] = inspect_bundle(bundle_path(compact_node), 2)
    check('restarted_compact_node_reads_new_value', True)
    safe = json.dumps({'checks': checks, 'artifacts': artifacts})
    check('receipt_has_no_secrets', not any(value and value in safe for value in
          (cluster.root_token, cluster.unseal_key, cluster.replication_key.hex())))
    check('upgrade_complete', True)


def main():
    parser = SafeArgumentParser(description=__doc__)
    for name in ('binary', 'legacy-binary', 'expected-legacy-sha256', 'build-source-commit', 'output'):
        parser.add_argument('--'+name, required=True)
    args = parser.parse_args()
    if re.fullmatch(r'[0-9a-f]{40}', args.build_source_commit) is None:
        parser.error('full build source commit required')
    if LEGACY_RECEIPT is None:raise ValueError('legacy_bundle1_build_not_yet_pinned')
    admit_legacy(json.loads(LEGACY_RECEIPT.read_text()), args.expected_legacy_sha256)
    candidate = Path(args.binary).resolve(strict=True)
    legacy = Path(args.legacy_binary).resolve(strict=True)
    checked_binary(legacy, args.expected_legacy_sha256)
    digest = checked_binary(candidate, file_hash(candidate))
    if digest == args.expected_legacy_sha256:raise ValueError('upgrade_requires_distinct_binaries')
    output = Path(args.output).absolute()
    parent = admit_output(output)
    before = source_identity(ROOT, candidate)
    work = Path(tempfile.mkdtemp(prefix='heptabao-raft-snapshot-upgrade-'))
    work.chmod(0o700)
    cluster = None
    report = {'schema': 'heptabao.raft-snapshot-upgrade.v1', 'checks': [], 'failure': None,
              'artifacts': {}, 'synthetic_only': True, 'same_host_mtls_processes': True,
              'from_bundle_format': 1, 'to_bundle_format': 2,
              'build_source_commit': args.build_source_commit, 'legacy_build_source_commit': LEGACY_SOURCE,
              'legacy_binary_sha256': args.expected_legacy_sha256,
              'legacy_receipt_sha256': file_hash(LEGACY_RECEIPT),
              'build_source_binding_basis': 'caller-supplied commit and observed binary hash; not independent attestation',
              'rolling_upgrade_qualification': False, 'power_loss_qualification': False}
    try:
        cluster = Cluster(legacy, work/'cluster')
        run_upgrade(cluster, candidate, legacy, report['checks'], report['artifacts'])
        checked_binary(legacy, args.expected_legacy_sha256)
    except Exception as error:
        report['failure'] = str(error) if isinstance(error, FixtureError) else type(error).__name__
    finally:
        try:
            if cluster is not None:cluster.close()
        except Exception:
            report['failure'] = report['failure'] or 'fixture_cleanup_failed'
        shutil.rmtree(work)
    after = source_identity(ROOT, candidate)
    publish(output, parent, report, before, after, required_cases=REQUIRED)
    print(json.dumps({'status': report['status'], 'checks': len(report['checks']), 'failure': report['failure']}))
    return 0 if report['status'] == 'passed' else 1


if __name__ == '__main__':raise SystemExit(main())
