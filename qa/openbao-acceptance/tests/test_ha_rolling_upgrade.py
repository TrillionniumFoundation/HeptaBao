"""Rolling wire retirement must preserve quorum without weakening evidence."""
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from types import SimpleNamespace
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


class RunningBinaryIdentityTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.proc = Path(self.directory.name)
        (self.proc / "123").mkdir()
        self.executable = self.proc / "123" / "exe"
        self.executable.write_bytes(b"synthetic executable")
        self.node = SimpleNamespace(process=self.process())
        patcher = patch.object(upgrade, "Path", return_value=self.proc)
        patcher.start()
        self.addCleanup(patcher.stop)

    @staticmethod
    def process():
        return SimpleNamespace(pid=123, poll=lambda: None)

    def test_unchanged_running_executable_is_hashed_once(self):
        expected = hashlib.sha256(self.executable.read_bytes()).hexdigest()
        with patch.object(upgrade.hashlib, "sha256", wraps=hashlib.sha256) as hasher:
            self.assertEqual(upgrade.running_digest(self.node), expected)
            self.assertEqual(upgrade.running_digest(self.node), expected)
            self.assertEqual(hasher.call_count, 1)

    def test_new_process_reusing_pid_does_not_reuse_digest(self):
        with patch.object(upgrade.hashlib, "sha256", wraps=hashlib.sha256) as hasher:
            first = upgrade.running_digest(self.node)
            self.node.process = self.process()
            self.assertEqual(upgrade.running_digest(self.node), first)
            self.assertEqual(hasher.call_count, 2)

    def test_changed_executable_is_rehashed(self):
        first = upgrade.running_digest(self.node)
        before = self.executable.stat()
        self.executable.write_bytes(b"different executable")
        os.utime(self.executable, ns=(before.st_atime_ns, before.st_mtime_ns + 1000000000))
        self.assertNotEqual(upgrade.running_digest(self.node), first)

    def test_replaced_inode_is_rehashed_even_with_same_bytes(self):
        with patch.object(upgrade.hashlib, "sha256", wraps=hashlib.sha256) as hasher:
            first = upgrade.running_digest(self.node)
            other = self.executable.with_name("replacement")
            other.write_bytes(self.executable.read_bytes())
            other.replace(self.executable)
            self.assertEqual(upgrade.running_digest(self.node), first)
            self.assertEqual(hasher.call_count, 2)

    def test_dead_process_cannot_use_cached_result(self):
        upgrade.running_digest(self.node)
        self.node.process.poll = lambda: 0
        with self.assertRaisesRegex(upgrade.FixtureError, "node_not_running"):
            upgrade.running_digest(self.node)

    def test_missing_executable_cannot_use_cached_result(self):
        upgrade.running_digest(self.node)
        self.executable.unlink()
        with self.assertRaisesRegex(upgrade.FixtureError, "binary_unreadable"):
            upgrade.running_digest(self.node)

    def test_change_during_hashing_does_not_publish_cache(self):
        before = upgrade.executable_identity(self.executable.stat())
        after = before[:-1] + (before[-1] + 1,)
        with patch.object(upgrade, "executable_identity", side_effect=[before, after]):
            with self.assertRaisesRegex(upgrade.FixtureError, "changed_during_verification"):
                upgrade.running_digest(self.node)
        self.assertFalse(hasattr(self.node, "_upgrade_binary_identity"))

    def test_process_change_during_hashing_does_not_publish_cache(self):
        hasher = Mock(wraps=hashlib.sha256())
        def replace_process(data):
            self.node.process = self.process()
        hasher.update.side_effect = replace_process
        with patch.object(upgrade.hashlib, "sha256", return_value=hasher):
            with self.assertRaisesRegex(upgrade.FixtureError, "node_changed_during_verification"):
                upgrade.running_digest(self.node)
        self.assertFalse(hasattr(self.node, "_upgrade_binary_identity"))

    def test_hashing_memory_is_bounded_to_one_megabyte_chunks(self):
        data = b"x" * (2 * 1024 * 1024 + 5)
        self.executable.write_bytes(data)
        expected = hashlib.sha256(data).hexdigest()
        hasher = Mock(wraps=hashlib.sha256())
        with patch.object(upgrade.hashlib, "sha256", return_value=hasher):
            self.assertEqual(upgrade.running_digest(self.node), expected)
        self.assertEqual([len(call.args[0]) for call in hasher.update.call_args_list],
                         [1024 * 1024, 1024 * 1024, 5])


if __name__ == "__main__":
    unittest.main()
