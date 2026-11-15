"""The capacity HA fixture must not turn unrelated failures into successful fencing."""
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import capacity_ha_live as capacity


class CapacityHaFixtureTests(unittest.TestCase):
    def cluster(self):
        cluster = capacity.CapacityCluster.__new__(capacity.CapacityCluster)
        cluster.scenarios = []
        return cluster

    def healthy_fence(self):
        return dict(ha_active=True, recovery_required=True,
                    ha_application_ready=False, sealed=False)

    def test_active_fenced_node_is_observed_without_mutation(self):
        node = Mock()
        node.call.return_value = (503, self.healthy_fence())
        cluster = self.cluster()
        cluster.wait_capacity_fence(node)
        self.assertEqual(len(cluster.scenarios), 4)
        node.call.assert_called_once_with('GET', 'sys/health', timeout=2)

    def test_inconsistent_or_successful_health_is_not_a_capacity_fence(self):
        for status, changes in [(200, {}), (500, {}),
                                (503, {'recovery_required': False}),
                                (503, {'ha_application_ready': True}),
                                (503, {'sealed': True})]:
            with self.subTest(status=status, changes=changes):
                node = Mock()
                node.call.return_value = (status, self.healthy_fence() | changes)
                with self.assertRaises(capacity.FixtureError):
                    self.cluster().wait_capacity_fence(node)

    def test_transport_failure_is_not_capacity_evidence(self):
        node = Mock()
        node.call.side_effect = TimeoutError()
        with patch.object(capacity.time, 'monotonic', side_effect=[0, 1, 31]), \
                patch.object(capacity.time, 'sleep'):
            with self.assertRaisesRegex(capacity.FixtureError, 'capacity_fenced_leader_not_observed'):
                self.cluster().wait_capacity_fence(node)

    def test_live_node_configuration_cannot_be_rewritten(self):
        node = Mock()
        node.process = object()
        with self.assertRaisesRegex(capacity.FixtureError, 'requires_stopped_process'):
            capacity.set_limit(node, capacity.LOW_LIMIT)

    def test_stopped_node_configuration_is_replaced_privately(self):
        with tempfile.TemporaryDirectory() as tmp:
            node = Mock()
            node.process = None
            node.root = Path(tmp)
            path = node.root / 'server.json'
            path.write_text(json.dumps({'listen': '127.0.0.1:8200'}))
            path.chmod(0o600)
            capacity.set_limit(node, capacity.LOW_LIMIT)
            value = json.loads(path.read_text())
            self.assertEqual(value['fixture_opaque_owner_limit_bytes'], capacity.LOW_LIMIT)
            self.assertEqual(value['listen'], '127.0.0.1:8200')
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            self.assertFalse(path.with_name('server.json.next').exists())


if __name__ == '__main__':
    unittest.main()
