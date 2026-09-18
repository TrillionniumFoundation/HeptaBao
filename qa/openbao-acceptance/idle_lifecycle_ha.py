#!/usr/bin/env python3
"""Observe autonomous expiry after leader loss, without triggering client reads.

Includes the existing core HA scenarios. Three synthetic local processes,
not multi-host or independent operational qualification. Audit observations are
fixture-local evidence; they are not externally authenticated attestations.
"""
import json
from datetime import datetime
from pathlib import Path
import time

from ha_destructive import Cluster
from wrapping_ha import main as run_ha


class IdleLifecycleCluster(Cluster):
    def configure(self):
        super().configure()
        for node in self.nodes:
            path = node.root / 'server.json'
            config = json.loads(path.read_text())
            config['lifecycle_interval_seconds'] = 1
            path.write_text(json.dumps(config))
            path.chmod(0o600)

    @staticmethod
    def audit_rows(node):
        return [json.loads(row)['event'] for row in
                (node.root / 'audit.jsonl').read_text().splitlines()]

    def run(self):
        super().run()
        leader = self.leader()
        self.check('idle_ha.mount', leader.call('POST', 'sys/mounts/ha-ssh',
            {'type': 'ssh'}, token=self.root_token)[0] == 204)
        self.check('idle_ha.role', leader.call('POST', 'ha-ssh/roles/test',
            {'key_type': 'otp', 'default_user': 'deploy', 'cidr_list': '127.0.0.0/8'},
            token=self.root_token)[0] == 204)
        self.check('idle_ha.tune_short_local_lease', leader.call(
            'POST', 'sys/mounts/ha-ssh/tune',
            {'default_lease_ttl': '4s', 'max_lease_ttl': '4s'}, token=self.root_token)[0] == 204)
        status, lease = leader.call('POST', 'ha-ssh/creds/test',
                                    {'ip': '127.0.0.1'}, token=self.root_token)
        self.check('idle_ha.issue', status == 200 and lease.get('lease_duration') == 4)
        status, wrapped = leader.call('POST', 'sys/wrapping/wrap',
            {'value': 'synthetic-idle-ha-value'}, token=self.root_token, wrap_ttl='4s')
        self.check('idle_ha.wrap', status == 200 and wrapped.get('wrap_info', {}).get('ttl') == 4)
        # No HTTP requests after this point until a committed worker event at a
        # time after both lifetimes is visible on a surviving process.
        expired_after = int(datetime.fromisoformat(wrapped['wrap_info']['creation_time'].replace('Z', '+00:00')).timestamp()) + 4
        survivors = [node for node in self.nodes if node is not leader]
        offsets = {node.node_id: len(self.audit_rows(node)) for node in survivors}
        leader.stop()
        self.check('idle_ha.leader_killed_before_expiry', leader.process is None)
        deadline = time.monotonic() + 18
        observed = set()
        while time.monotonic() < deadline:
            for node in survivors:
                try:
                    rows = self.audit_rows(node)[offsets[node.node_id]:]
                except (OSError, ValueError):
                    continue
                if any(row['kind'] == 'lifecycle-response' and row['status'] == 204
                       and row['time'] >= expired_after for row in rows):
                    observed.add(node.node_id)
            if observed:
                break
            time.sleep(0.05)
        self.check('idle_ha.survivor_committed_without_client_trigger', bool(observed))
        successor = self.leader()
        self.check('idle_ha.new_leader', successor is not leader)
        self.check('idle_ha.expired_otp_denied', successor.call(
            'POST', 'ha-ssh/verify', {'otp': lease['data']['key']})[0] == 400)
        self.check('idle_ha.expired_metadata_denied', successor.call(
            'POST', 'sys/leases/lookup', {'lease_id': lease['lease_id']}, token=self.root_token)[0] == 400)
        self.check('idle_ha.expired_payload_not_released', successor.call(
            'POST', 'sys/wrapping/unwrap', {}, token=wrapped['wrap_info']['token'])[0] == 400)
        self.restart(leader)
        self.leader()
        self.check('idle_ha.old_leader_restart_cannot_revive_otp', leader.call(
            'POST', 'ha-ssh/verify', {'otp': lease['data']['key']})[0] == 400)
        self.check('idle_ha.old_leader_restart_cannot_revive_wrapping', leader.call(
            'POST', 'sys/wrapping/unwrap', {}, token=wrapped['wrap_info']['token'])[0] == 400)


if __name__ == '__main__':
    raise SystemExit(run_ha(cluster_type=IdleLifecycleCluster, profile='idle-lifecycle-ha',
        runner_path=Path(__file__), scope='same-version local HA autonomous expiration after leader loss; '
        'includes core HA; no client request triggers the observed survivor expiry commit'))
