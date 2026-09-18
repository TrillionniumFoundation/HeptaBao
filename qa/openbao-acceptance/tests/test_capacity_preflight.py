"""Bounded capacity / migration preflight refuses invented evidence and writes."""
import contextlib
import copy
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import capacity_live as capacity
import migration_preflight as preflight
from bao_http import BaoError, Response
from core_isolation import ScenarioFailure


def observation():
    return dict(profile='bounded-chunked-state-v1', scope='serving-leader-local', state_bytes=40,
        state_limit_bytes=100, state_remaining_bytes=60, generation=1, retained_operations=1,
        operation_limit=10, operations_remaining=9, journal_bytes=20, journal_limit_bytes=200,
        admission_reserved=False, compaction_reclaims_operation_identities=False,
        full_openbao_compatibility=False, production_qualified=False)


class FakeClient:
    def __init__(self, side):
        self.address = 'https://' + side + ':8200'
        self.namespace = ''
        self.side = side
        self.calls = []
        self.overrides = {}
        self.cluster = side

    def health(self):
        return dict(cluster_id=self.cluster, version='2.6.2' if self.side=='source' else 'HeptaBao-0.2.0',
                    status=200, initialized=True, sealed=False)

    def request(self, method, path, payload=None):
        self.calls.append((method, path, payload))
        if method not in ('GET', 'LIST') or payload is not None:
            raise AssertionError('preflight attempted a mutation')
        if path in self.overrides:
            return self.overrides[path]
        if path == '/v1/sys/mounts':
            return Response(200, {'data': {'secret/': {'type': 'kv'}, 'top-secret-mount/': {'type': 'transit'}}})
        if path == '/v1/sys/auth':
            return Response(200, {'data': {'auth/': {'type': 'token'}}})
        if path == '/v1/sys/internal/capacity':
            return Response(200, {'data': observation()})
        return Response(200, {'data': {'keys': []}})


class CapacityObservationTests(unittest.TestCase):
    def test_valid_observation(self):
        capacity.validate_observation(observation())

    def test_bool_negative_or_missing_count_rejected(self):
        for bad in (True, -1, '40', None):
            with self.subTest(value=bad):
                data = observation(); data['state_bytes'] = bad
                with self.assertRaises(ScenarioFailure):
                    capacity.validate_observation(data)

    def test_inconsistent_remaining_and_journal_bound_rejected(self):
        for key, bad in (('state_remaining_bytes', 100), ('operations_remaining', 10), ('journal_bytes', 201)):
            data = observation(); data[key] = bad
            with self.assertRaises(ScenarioFailure):
                capacity.validate_observation(data)

    def test_inflated_claim_rejected(self):
        for key in ('admission_reserved', 'compaction_reclaims_operation_identities',
                    'full_openbao_compatibility', 'production_qualified'):
            data = observation(); data[key] = True
            with self.assertRaises(ScenarioFailure):
                capacity.validate_observation(data)


class MigrationPreflightTests(unittest.TestCase):
    def setUp(self):
        self.source, self.target = FakeClient('source'), FakeClient('target')

    def test_metadata_and_capacity_never_authorize_migration(self):
        report = preflight.collect(self.source, self.target, 50)
        self.assertFalse(report['inventory_complete'])
        self.assertFalse(report['migration_authority'])
        self.assertFalse(report['hepta_consumer_requalified'])
        self.assertEqual(
            report['observed_asset_dispositions'].get('transit_keys_ciphertexts'),
            'BOUNDED_ADAPTER',
        )
        self.assertIn(
            'bounded_adapter_not_full_instance_ready:transit_keys_ciphertexts',
            report['blockers'],
        )
        self.assertNotIn('top-secret-mount', json.dumps(report))
        self.assertTrue(all(m in ('GET', 'LIST') and b is None for m, p, b in self.source.calls+self.target.calls))

    def test_capacity_estimate_exceeds_bound(self):
        report = preflight.collect(self.source, self.target, 61)
        self.assertIn('target_state_estimate_exceeds_current_capacity', report['blockers'])

    def test_bad_estimate_rejected_before_network(self):
        for value in (True, -1, '60', 2**64):
            with self.assertRaises(BaoError):
                preflight.collect(self.source, self.target, value)
        self.assertEqual(self.source.calls, [])

    def test_unknown_or_denied_collection_never_means_empty(self):
        for status in (403, 404, 500):
            self.source.overrides['/v1/identity/entity/id'] = Response(status, {'errors':['sensitive detail']})
            report = preflight.collect(self.source, self.target)
            self.assertEqual(report['source_catalogs']['entities']['status'], 'unobserved')
            self.assertNotIn('count', report['source_catalogs']['entities'])
            self.assertNotIn('sensitive detail', json.dumps(report))

    def test_invalid_successful_keys_fail(self):
        for value in ({}, {'keys':['same','same']}, {'keys':[{}]}):
            self.source.overrides['/v1/identity/entity/id'] = Response(200, {'data': value})
            with self.assertRaises(BaoError):
                preflight.collect(self.source, self.target)

    def test_unknown_provider_name_not_reported(self):
        self.source.overrides['/v1/sys/mounts'] = Response(200, {'data': {'a/':{'type':'private-customer-plugin'}}})
        report = preflight.collect(self.source, self.target)
        self.assertEqual(report['source_catalogs']['mounts']['types'], {'other':1})
        self.assertNotIn('private-customer', json.dumps(report))
        self.assertEqual(
            report['observed_asset_dispositions'].get('other_secret_engines'),
            'NO_SAFE_TRANSFER_IMPLEMENTED',
        )
        self.assertIn(
            'asset_transfer_not_ready:other_secret_engines:NO_SAFE_TRANSFER_IMPLEMENTED',
            report['blockers'],
        )

    def test_asset_ledger_is_fail_closed_not_a_second_invented_status(self):
        with tempfile.TemporaryDirectory() as tmp:
            ledger = Path(tmp) / 'assets.json'
            ledger.write_text('{"assets": []}')
            with patch.object(preflight, 'ASSET_LEDGER', ledger):
                with self.assertRaises(BaoError):
                    preflight.collect(self.source, self.target)

    def test_missing_or_malformed_target_capacity(self):
        self.target.overrides['/v1/sys/internal/capacity'] = Response(403, {})
        self.assertIn('target_capacity_unobserved', preflight.collect(self.source, self.target)['blockers'])
        data = observation(); data['state_bytes'] = True
        self.target.overrides['/v1/sys/internal/capacity'] = Response(200, {'data': data})
        with self.assertRaises(BaoError):
            preflight.collect(self.source, self.target)

    def test_same_cluster_different_endpoint_rejected(self):
        self.target.cluster = self.source.cluster
        with self.assertRaises(BaoError):
            preflight.collect(self.source, self.target)
        self.assertEqual(self.source.calls, [])

    def test_exhausted_identities_not_reclaimed(self):
        data = observation(); data.update(retained_operations=10, operations_remaining=0)
        self.target.overrides['/v1/sys/internal/capacity'] = Response(200, {'data': data})
        self.assertIn('target_operation_identity_budget_exhausted', preflight.collect(self.source, self.target)['blockers'])

    def test_public_output_parent_rejects_before_config_or_network(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); root.chmod(0o755)
            with patch.object(preflight, 'client_from_config') as client, contextlib.redirect_stdout(io.StringIO()):
                code = preflight.main(['--config','not-read','--output',str(root/'out.json'),'--allow-read'])
            self.assertEqual(code, 2)
            client.assert_not_called()

    def test_existing_output_preserved(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'output'; path.write_text('original')
            with self.assertRaises(BaoError): preflight.require_private_new_output(path)
            self.assertEqual(path.read_text(), 'original')

    def test_cli_requires_read_permission_without_echoing_arguments(self):
        stream = io.StringIO()
        with contextlib.redirect_stderr(stream), self.assertRaises(SystemExit):
            preflight.main(['--config','secret-argument','--output','out'])
        self.assertNotIn('secret-argument', stream.getvalue())
