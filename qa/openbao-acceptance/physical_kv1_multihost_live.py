#!/usr/bin/env python3
"""Isolated r249 physical three-host 24MiB immutable KV1 record-root failure test.

The base life-cycle owns fixture secrets, kill/cleanup and TLS; this extension
never copies root credentials into reports. Mutations are attempted exactly
once. Fingerprints replace values in the observer's bounded working set.
"""
from __future__ import annotations

import hashlib
import json
import secrets
from pathlib import Path

import ha_multihost_live as ha

MIB = 1024 * 1024
PAYLOAD = 224 * 1024
TARGET = 24 * MIB
MOUNT = 'record-scale-mh-r251'
PREFIX = MOUNT + '/bulk/'
REQUIRED = frozenset({
    'scale_mount_v1',
    'scale_growth_offline_once',
    'scale_capacity_v5_above_16m',
    'scale_majority_exact_readback',
    'scale_snapshot_rejoined_exact_readback',
    'scale_failover_update_once',
    'scale_failover_delete_once',
    'scale_survivor_exact_readback',
    'scale_old_leader_rejoined_exact_readback',
    'scale_old_leader_deleted_absent',
    'scale_threehost_quorum_recovered_exact_readback',
    'scale_threehost_deleted_absent',
    'scale_cleanup_remaining_once',
    'scale_cleanup_absence_all',
    'scale_mount_cleanup',
})


def canonical(value: dict) -> bytes:
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(',', ':')).encode()


def digest(value: dict) -> str:
    return hashlib.sha256(canonical(value)).hexdigest()


class PhysicalKV1Scale:
    required_checks = REQUIRED
    snapshot_via_compact = True
    runner_path = Path(__file__)
    schema = 'heptabao.r251-physical-3host-kv1-record24-v1'
    scope = 'synthetic-physical-3host-record24-snapshot-failover-quorum-not-production'

    def __init__(self):
        self.context = None
        self.check = None
        self.root = ''
        self.nodes = []
        self.expected = {}
        self.byte_counts = {}
        self.deleted = set()
        self.tried = 0
        self.mutations_retried = False

    def runtime_secrets(self):
        return (self.root,) if self.root else ()

    def clear(self):
        self.root = ''
        self.expected.clear()
        self.byte_counts.clear()
        self.nodes.clear()
        self.deleted.clear()

    def _call(self, node, method, path, body=None, *, timeout=25):
        return ha.api(self.context, node, method, path, body, token=self.root, timeout=timeout)

    def _new_value(self, ordinal):
        payload = secrets.token_urlsafe(PAYLOAD * 3 // 4)
        if len(payload) != PAYLOAD:
            raise ha.FixtureError('scale_random_payload_wrong_size')
        return {'ordinal': ordinal, 'payload': payload}

    def _require(self, name, condition, **details):
        self.check(name, condition, **details)

    def _verify(self, node):
        # An HTTP 200 with stale/corrupt values is never converted to polling.
        for name in sorted(self.expected):
            status, body = self._call(node, 'GET', PREFIX + name)
            data = body.get('data')
            if status != 200 or not isinstance(data, dict) or digest(data) != self.expected[name]:
                raise ha.FixtureError('scale_exact_readback_failed_node_' + str(node.node_id))

    def _absent(self, node, key):
        status, body = self._call(node, 'GET', PREFIX + key)
        if status != 404 or isinstance(body.get('data'), dict):
            raise ha.FixtureError('scale_deleted_resurrected_node_' + str(node.node_id))

    def setup(self, context, nodes, leader, standby, root_token, check):
        del standby
        if self.context is not None or self.root:
            raise ha.FixtureError('scale_duplicate_setup')
        self.context, self.nodes, self.root, self.check = context, list(nodes), root_token, check
        status, _ = self._call(leader, 'POST', 'sys/mounts/' + MOUNT,
                               {'type': 'kv', 'options': {'version': '1'}})
        self._require('scale_mount_v1', status == 204, http_status=status)

    def majority_after_offline(self, leader, offline):
        # This is executed after the offline voter was stopped by the parent,
        # before its normal Raft compaction and rejoin.
        if offline not in self.nodes or len(self.nodes) != 3:
            raise ha.FixtureError('scale_not_3_independent_nodes')
        logical_bytes = 0
        ordinal = 0
        while logical_bytes < TARGET:
            key = f'{ordinal:04d}'
            value = self._new_value(ordinal)
            self.tried += 1
            status, _ = self._call(leader, 'PUT', PREFIX + key, value, timeout=30)
            if status != 204:
                self._require('scale_growth_offline_once', False,
                              attempted=self.tried, acknowledged=len(self.expected),
                              http_status=status, mutations_retried=False)
            self.expected[key] = digest(value)
            count = len(canonical(value))
            self.byte_counts[key] = count
            logical_bytes += count
            ordinal += 1
        self._require('scale_growth_offline_once', logical_bytes >= TARGET and logical_bytes > 16*MIB
                      and len(self.expected) >= 100,
                      acknowledged=len(self.expected), logical_payload_bytes=logical_bytes,
                      old_state_ceiling_bytes=16*MIB, mutations_retried=False)
        status, body = self._call(leader, 'GET', 'sys/internal/capacity')
        capacity = body.get('data', {})
        self._require('scale_capacity_v5_above_16m',
                      status == 200
                      and capacity.get('state_storage_format') == 'heptabao-state-records-v5'
                      and type(capacity.get('state_bytes')) is int
                      and capacity['state_bytes'] >= logical_bytes
                      and capacity.get('opaque_owner_limit_bytes') == 16*MIB,
                      http_status=status,
                      observed_state_bytes=capacity.get('state_bytes'),
                      logical_payload_bytes=logical_bytes)
        self._verify(leader)
        self._require('scale_majority_exact_readback', True, records=len(self.expected),
                      logical_payload_bytes=logical_bytes)

    def after_snapshot(self, offline):
        self._verify(offline)
        self._require('scale_snapshot_rejoined_exact_readback', True,
                      recovered_node=offline.node_id, records=len(self.expected))

    def after_failover(self, survivors, successor):
        if len(survivors) != 2 or successor not in survivors:
            raise ha.FixtureError('scale_invalid_survivor_set')
        replacement = self._new_value(10_000_000)
        self.tried += 1
        status, _ = self._call(successor, 'PUT', PREFIX + '0000', replacement)
        self._require('scale_failover_update_once', status == 204,
                      http_status=status, mutations_retried=False)
        self.expected['0000'] = digest(replacement)
        self.byte_counts['0000'] = len(canonical(replacement))
        self.tried += 1
        status, _ = self._call(successor, 'DELETE', PREFIX + '0001')
        self._require('scale_failover_delete_once', status == 204,
                      http_status=status, mutations_retried=False)
        del self.expected['0001']
        del self.byte_counts['0001']
        self.deleted.add('0001')
        for node in survivors:
            self._verify(node)
            self._absent(node, '0001')
        self._require('scale_survivor_exact_readback', True, survivors=len(survivors),
                      records=len(self.expected))

    def after_rejoin(self, node):
        self._verify(node)
        self._require('scale_old_leader_rejoined_exact_readback', True,
                      node=node.node_id, records=len(self.expected))
        self._absent(node, '0001')
        self._require('scale_old_leader_deleted_absent', True, node=node.node_id)

    def after_quorum_recovery(self, nodes):
        if len(nodes) != 3 or len(set(n.node_id for n in nodes)) != 3:
            raise ha.FixtureError('scale_final_nodes_not_distinct')
        for node in nodes:
            self._verify(node)
        self._require('scale_threehost_quorum_recovered_exact_readback', True,
                      nodes=3, records=len(self.expected),
                      logical_payload_bytes=sum(self.byte_counts.values()))
        for node in nodes:
            self._absent(node, '0001')
        self._require('scale_threehost_deleted_absent', True, nodes=3)

    def cleanup(self, leader):
        count = 0
        for name in sorted(self.expected):
            self.tried += 1
            status, _ = self._call(leader, 'DELETE', PREFIX + name)
            if status != 204:
                self._require('scale_cleanup_remaining_once', False,
                              attempted=count+1, acknowledged=count,
                              http_status=status, mutations_retried=False)
            count += 1
        self._require('scale_cleanup_remaining_once', True,
                      acknowledged=count, mutations_retried=False)
        for node in self.nodes:
            for name in self.expected:
                self._absent(node, name)
            self._absent(node, '0001')
        self._require('scale_cleanup_absence_all', True, hosts=len(self.nodes),
                      records=len(self.expected)+1)
        self.tried += 1
        status, _ = self._call(leader, 'DELETE', 'sys/mounts/' + MOUNT)
        self._require('scale_mount_cleanup', status == 204,
                      http_status=status, mutations_retried=False)


if __name__ == '__main__':
    raise SystemExit(ha.main(extension=PhysicalKV1Scale()))
