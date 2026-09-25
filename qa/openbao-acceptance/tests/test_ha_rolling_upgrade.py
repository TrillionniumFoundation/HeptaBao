"""Rolling wire retirement must preserve quorum without weakening evidence."""
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import ha_rolling_upgrade as upgrade


class RollingUpgradeFixtureTests(unittest.TestCase):
    def cluster(self):
        cluster = upgrade.RollingUpgradeCluster.__new__(upgrade.RollingUpgradeCluster)
        cluster.base_digest = "a" * 64
        cluster.candidate_digest = "b" * 64
        cluster.root_token = "synthetic-unused"
        return cluster

    def test_configuration_requires_stopped_process(self):
        node = Mock(process=object())
        with self.assertRaisesRegex(upgrade.FixtureError, "requires_stopped_node"):
            self.cluster().set_legacy_forward_transition(node, True)

    def test_invalid_sender_mode_does_not_modify_configuration(self):
        with tempfile.TemporaryDirectory() as directory:
            node = Mock(process=None, root=Path(directory))
            config = node.root / "ha.json"
            config.write_text('{"cluster_id":"test-cluster"}')
            before = config.read_bytes()
            with self.assertRaisesRegex(upgrade.FixtureError, "requires_legacy_receiver"):
                self.cluster().set_legacy_forward_transition(node, False, emit_legacy=True)
            self.assertEqual(config.read_bytes(), before)

    def test_three_phases_keep_unrelated_configuration_and_private_permissions(self):
        with tempfile.TemporaryDirectory() as directory:
            node = Mock(process=None, root=Path(directory))
            config = node.root / "ha.json"
            config.write_text('{"cluster_id":"test-cluster","node_id":2}')
            cluster = self.cluster()
            for receive, send, expected in [
                (True, None, {"allow_legacy_peer_v1": True}),
                (True, False, {"allow_legacy_peer_v1": True, "emit_legacy_peer_v1": False}),
                (False, None, {}),
            ]:
                cluster.set_legacy_forward_transition(node, receive, emit_legacy=send)
                self.assertEqual(json.loads(config.read_text()),
                                 {"cluster_id": "test-cluster", "node_id": 2} | expected)
                self.assertEqual(config.stat().st_mode & 0o777, 0o600)

    def test_current_binary_cannot_use_legacy_health_exception(self):
        cluster = self.cluster()
        node = Mock()
        node.call.return_value = (200, {"ha_active": True, "standby": False})
        cluster.running = lambda: [node]
        with patch.object(upgrade, "running_digest", return_value=cluster.candidate_digest):
            with self.assertRaisesRegex(upgrade.FixtureError, "without_application_readiness"):
                cluster.leader()

    def test_unknown_binary_never_qualifies(self):
        cluster = self.cluster()
        node = Mock()
        node.call.return_value = (200, {"ha_active": True, "standby": False,
                                       "ha_application_ready": True})
        cluster.running = lambda: [node]
        with patch.object(upgrade, "running_digest", return_value="c" * 64):
            with self.assertRaisesRegex(upgrade.FixtureError, "unknown_running_binary"):
                cluster.leader()

    def test_explicitly_unready_base_is_not_admitted(self):
        cluster = self.cluster()
        node = Mock()
        node.call.return_value = (200, {"ha_active": True, "standby": False,
                                       "ha_application_ready": False})
        cluster.running = lambda: [node]
        with patch.object(upgrade, "running_digest", return_value=cluster.base_digest):
            with self.assertRaisesRegex(upgrade.FixtureError, "base_health_explicitly_not"):
                cluster.leader()

    def test_successful_stale_read_is_not_retried(self):
        node = Mock()
        node.call.return_value = (200, {"data": {"data": {"value": "wrong"}}})
        with self.assertRaisesRegex(upgrade.FixtureError, "stale_or_wrong_data"):
            self.cluster().read(node, "test", "expected")
        self.assertEqual(node.call.call_count, 1)

    def test_permanent_read_failure_is_not_retried(self):
        node = Mock()
        node.call.return_value = (403, {})
        with self.assertRaisesRegex(upgrade.FixtureError, "acknowledged_write_not_visible"):
            self.cluster().read(node, "test", "expected")
        self.assertEqual(node.call.call_count, 1)

    def test_transient_read_only_retry_requires_exact_readback(self):
        node = Mock()
        node.call.side_effect = [(503, {}), (200, {"data": {"data": {"value": "expected"}}})]
        with patch.object(upgrade.time, "sleep"):
            self.cluster().read(node, "test", "expected")
        self.assertEqual(node.call.call_count, 2)
        self.assertTrue(all(call.args[0] == "GET" for call in node.call.call_args_list))


if __name__ == "__main__":
    unittest.main()
