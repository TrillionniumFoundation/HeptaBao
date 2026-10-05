"""Rolling wire retirement must preserve quorum without weakening evidence."""
import hashlib
import contextlib
import io
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

    def test_only_reviewed_exact_base_sources_select_a_wire_profile(self):
        for source, expected in [
            ("55f27e4258ea3f71ab7872cd7a44e8cbd4da1f18", "legacy"),
            ("8457a5569a31a41a4cd2f36d06d1f18125e9c88a", "current"),
        ]:
            self.assertEqual(upgrade.base_peer_wire_profile(source), expected)
        for source in ["", "main", "8457a556", "a" * 40,
                       "8457A5569A31A41A4CD2F36D06D1F18125E9C88A"]:
            with self.subTest(source=source), self.assertRaisesRegex(
                    upgrade.FixtureError, "unreviewed_base_peer_wire_profile"):
                upgrade.base_peer_wire_profile(source)

    def test_unknown_base_source_fails_before_binary_access_or_cluster_launch(self):
        args = ["fixture", "--base-source-commit", "a" * 40,
                "--base-binary", "/unused/base", "--base-sha256", "b" * 64,
                "--candidate-binary", "/unused/candidate", "--candidate-sha256", "c" * 64,
                "--work-dir", "/unused/work"]
        output = io.StringIO()
        with patch.object(sys, "argv", args), contextlib.redirect_stdout(output), \
                patch.object(upgrade, "checked_binary") as checked, \
                patch.object(upgrade, "RollingUpgradeCluster") as cluster:
            self.assertEqual(upgrade.main(), 1)
        checked.assert_not_called()
        cluster.assert_not_called()
        report = json.loads(output.getvalue())
        self.assertEqual(report["failure_class"], "unreviewed_base_peer_wire_profile")
        self.assertEqual(report["scenarios"], [])

    def test_first_candidate_configuration_matches_reviewed_base_wire(self):
        for profile, expected in [("legacy", True), ("current", False)]:
            with self.subTest(profile=profile):
                cluster = self.cluster()
                cluster.base_peer_wire = profile
                cluster.candidate_binary = Path("/candidate")
                cluster.unseal_key, cluster.scenarios = "synthetic-unused", []
                cluster.leader = Mock()
                cluster.set_legacy_forward_transition = Mock()
                node = Mock()
                node.call.return_value = (200, {})
                with patch.object(upgrade, "running_digest", return_value=cluster.candidate_digest):
                    cluster.upgrade(node, "first")
                cluster.set_legacy_forward_transition.assert_called_once_with(node, expected)
                node.start.assert_called_once_with()
                node.call.assert_called_once_with("POST", "sys/unseal", {"key": cluster.unseal_key})
                self.assertEqual(cluster.scenarios, ["first_candidate_process_digest"])

    def test_unknown_profile_cannot_construct_a_cluster(self):
        with patch.object(upgrade.Cluster, "__init__") as create, \
                patch.object(Path, "read_bytes") as read:
            with self.assertRaisesRegex(upgrade.FixtureError, "unreviewed_base_peer_wire_profile"):
                upgrade.RollingUpgradeCluster(Path("/base"), Path("/candidate"), Path("/work"),
                                              base_source_commit="a" * 40)
        read.assert_not_called()
        create.assert_not_called()

    def test_missing_source_is_rejected_before_fixture_construction(self):
        with patch.object(sys, "argv", ["fixture"]), contextlib.redirect_stderr(io.StringIO()), \
                patch.object(upgrade, "RollingUpgradeCluster") as create:
            with self.assertRaises(SystemExit) as error:
                upgrade.main()
        self.assertEqual(error.exception.code, 2)
        create.assert_not_called()

    def test_current_profile_never_opens_legacy_receive_or_claims_retirement(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "ha.json").write_text('{"cluster_id":"test-cluster"}')
            node = Mock(root=root)
            cluster = self.cluster()
            cluster.base_peer_wire, cluster.nodes, cluster.scenarios = "current", [node], []
            cluster.retire_legacy_senders()
            node.stop.assert_not_called()
            node.start.assert_not_called()
            self.assertEqual(cluster.scenarios,
                             ["rolling_upgrade_current_base_never_enabled_legacy_wire"])
            for flag in ["allow_legacy_peer_v1", "emit_legacy_peer_v1"]:
                (root / "ha.json").write_text(json.dumps({flag: False}))
                with self.assertRaises(upgrade.FixtureError):
                    cluster.retire_legacy_senders()

    def test_legacy_sender_retirement_keeps_one_write_and_all_node_readback_per_phase(self):
        with tempfile.TemporaryDirectory() as directory:
            cluster = self.cluster()
            cluster.base_peer_wire, cluster.scenarios = "legacy", []
            cluster.unseal_key = "synthetic-unused"
            cluster.nodes = []
            for node_id in (1, 2, 3):
                root = Path(directory) / str(node_id)
                root.mkdir()
                (root / "ha.json").write_text('{"allow_legacy_peer_v1":true}')
                node = Mock(node_id=node_id, root=root, process=None)
                node.call.return_value = (200, {})
                cluster.nodes.append(node)
            cluster.leader, cluster.write, cluster.read = Mock(), Mock(), Mock()
            cluster.retire_legacy_senders()
            self.assertEqual(cluster.write.call_count, 3)
            self.assertEqual(cluster.read.call_count, 9)
            for node in cluster.nodes:
                node.stop.assert_called_once_with()
                node.start.assert_called_once_with()
                self.assertEqual(json.loads((node.root / "ha.json").read_text()),
                                 {"allow_legacy_peer_v1": True, "emit_legacy_peer_v1": False})
            self.assertEqual(cluster.scenarios[-1],
                             "rolling_upgrade_all_senders_current_before_any_receiver_closes")

    def test_both_profiles_retain_strict_writes_readback_failover_and_epoch_transition(self):
        for profile in ["legacy", "current"]:
            with self.subTest(profile=profile), tempfile.TemporaryDirectory() as directory:
                cluster = self.cluster()
                cluster.base_peer_wire, cluster.scenarios = profile, []
                cluster.candidate_binary = Path("/candidate")
                cluster.unseal_key = "synthetic-unused"
                cluster.nodes = []
                for node_id in (1, 2, 3):
                    root = Path(directory) / str(node_id)
                    root.mkdir()
                    (root / "ha.json").write_text("{}")
                    node = Mock(node_id=node_id, root=root, process=object(), binary=Path("/base"))
                    node.stop.side_effect = lambda node=node: setattr(node, "process", None)
                    node.start.side_effect = lambda node=node: setattr(node, "process", object())
                    node.call.return_value = (200, {})
                    cluster.nodes.append(node)
                cluster.leader = lambda: max(
                    (node for node in cluster.nodes if node.process is not None),
                    key=lambda node: node.node_id,
                )
                cluster.write, cluster.read = Mock(), Mock()
                cluster.replay_epoch = Mock(side_effect=[0, 1])
                cluster.retire_epoch = Mock(return_value=1)
                with patch.object(upgrade.Cluster, "run"), patch.object(
                        upgrade, "running_digest",
                        side_effect=lambda node: cluster.candidate_digest
                        if node.binary == cluster.candidate_binary else cluster.base_digest):
                    cluster.run()
                writes = [call.args[1] for call in cluster.write.call_args_list]
                reads = [call.args[1] for call in cluster.read.call_args_list]
                self.assertEqual(len(writes), len(set(writes)))
                for node_id in (1, 2, 3):
                    path = f"rolling-strict-wire-{node_id}"
                    self.assertEqual(writes.count(path), 1)
                    self.assertEqual(reads.count(path), 3)
                    path = f"rolling-new-wire-{node_id}"
                    self.assertEqual(writes.count(path), int(profile == "legacy"))
                    self.assertEqual(reads.count(path), 3 if profile == "legacy" else 0)
                self.assertIn("rolling_upgrade_candidate_majority_serves_while_old_voter_down",
                              cluster.scenarios)
                self.assertIn("rolling_upgrade_post_epoch_failover", cluster.scenarios)
                self.assertIn("rolling_upgrade_post_epoch_value_converged", cluster.scenarios)
                self.assertEqual(cluster.replay_epoch.call_count, 2)
                cluster.retire_epoch.assert_called_once()

    def test_pinned_base_misbinding_uses_exact_legacy_contract(self):
        cluster = self.cluster()
        cluster.scenarios, cluster.unseal_key = [], "synthetic-unused"
        cluster.candidate_binary = Path("/candidate")
        node = Mock(binary=Path("/base"))
        node.call.side_effect = [(503, {"errors": ["HA configuration belongs to a different cluster"]}), (503, {"sealed": True})]
        with patch.object(upgrade, "checked_binary") as checked, patch.object(upgrade, "running_digest", return_value=cluster.base_digest):
            cluster.assert_misbound_rejection(node)
        checked.assert_called_once_with(node.binary, cluster.base_digest)
        node.start.assert_called_once_with()
        node.stop.assert_called_once_with()
        node.expect_startup_rejection.assert_not_called()
        self.assertEqual(len(cluster.scenarios), 2)

    def test_base_misbinding_rejects_generic_error_and_unsealed_health(self):
        for replies in [[(503, {"errors": ["unrelated error"]})], [(200, {})], [(503, {"errors": ["HA configuration belongs to a different cluster"]}), (503, {"sealed": False})]]:
            with self.subTest(replies=replies):
                cluster = self.cluster()
                cluster.scenarios, cluster.unseal_key = [], "synthetic-unused"
                cluster.candidate_binary = Path("/candidate")
                node = Mock(binary=Path("/base"))
                node.call.side_effect = replies
                with patch.object(upgrade, "checked_binary"), patch.object(upgrade, "running_digest", return_value=cluster.base_digest), self.assertRaises(upgrade.FixtureError):
                    cluster.assert_misbound_rejection(node)
                node.stop.assert_called_once_with()

    def test_current_pinned_base_can_reject_misbinding_before_api_startup(self):
        cluster = self.cluster()
        cluster.scenarios, cluster.candidate_binary = [], Path("/candidate")
        node = Mock(binary=Path("/base"))
        node.start.side_effect = upgrade.FixtureError("node_exited_during_startup")
        with patch.object(upgrade, "checked_binary") as checked, \
                patch.object(upgrade, "running_digest") as running:
            cluster.assert_misbound_rejection(node)
        self.assertEqual(checked.call_count, 2)
        checked.assert_called_with(node.binary, cluster.base_digest)
        node.start.assert_called_once_with()
        node.verify_startup_rejection.assert_called_once_with(upgrade.MISBOUND_BOOTSTRAP_ERROR)
        node.expect_startup_rejection.assert_not_called()
        node.call.assert_not_called()
        running.assert_not_called()
        node.stop.assert_called_once_with()
        self.assertEqual(cluster.scenarios, ["rolling_upgrade_base_misbound_startup_rejected"])

    def test_base_startup_failure_requires_exact_terminal_marker(self):
        for start_error, rejection_error in [
            ("node_listener_timeout", None),
            ("node_exited_during_startup", "unexpected_startup_rejection"),
            ("node_exited_during_startup", "misbound_cluster_process_did_not_exit"),
        ]:
            with self.subTest(start_error=start_error, rejection_error=rejection_error):
                cluster = self.cluster()
                cluster.scenarios, cluster.candidate_binary = [], Path("/candidate")
                node = Mock(binary=Path("/base"))
                node.start.side_effect = upgrade.FixtureError(start_error)
                if rejection_error:
                    node.verify_startup_rejection.side_effect = upgrade.FixtureError(rejection_error)
                with patch.object(upgrade, "checked_binary"), self.assertRaises(upgrade.FixtureError):
                    cluster.assert_misbound_rejection(node)
                node.start.assert_called_once_with()
                node.call.assert_not_called()
                node.stop.assert_called_once_with()
                self.assertEqual(cluster.scenarios, [])
                if start_error != "node_exited_during_startup":
                    node.verify_startup_rejection.assert_not_called()

    def test_changed_base_file_cannot_admit_a_startup_refusal(self):
        cluster = self.cluster()
        cluster.scenarios, cluster.candidate_binary = [], Path("/candidate")
        node = Mock(binary=Path("/base"))
        node.start.side_effect = upgrade.FixtureError("node_exited_during_startup")
        with patch.object(upgrade, "checked_binary", side_effect=[None, upgrade.FixtureError("binary_digest_mismatch")]), \
                self.assertRaisesRegex(upgrade.FixtureError, "binary_digest_mismatch"):
            cluster.assert_misbound_rejection(node)
        node.call.assert_not_called()
        node.stop.assert_called_once_with()
        self.assertEqual(cluster.scenarios, [])

    def test_candidate_misbinding_keeps_strict_startup_contract(self):
        cluster = self.cluster()
        cluster.scenarios, cluster.candidate_binary = [], Path("/candidate")
        node = Mock(binary=cluster.candidate_binary)
        with patch.object(upgrade, "checked_binary") as checked:
            cluster.assert_misbound_rejection(node)
        checked.assert_called_once_with(node.binary, cluster.candidate_digest)
        node.expect_startup_rejection.assert_called_once_with(upgrade.MISBOUND_BOOTSTRAP_ERROR)
        node.call.assert_not_called()
        self.assertEqual(cluster.scenarios, ["misbound_cluster_startup_rejected"])

    def test_replaced_running_base_cannot_use_legacy_contract(self):
        cluster = self.cluster()
        cluster.scenarios, cluster.candidate_binary = [], Path("/candidate")
        node = Mock(binary=Path("/base"))
        with patch.object(upgrade, "checked_binary"), patch.object(upgrade, "running_digest", return_value=cluster.candidate_digest), self.assertRaisesRegex(upgrade.FixtureError, "base_binary_changed"):
            cluster.assert_misbound_rejection(node)
        node.call.assert_not_called()
        node.stop.assert_called_once_with()
        self.assertEqual(cluster.scenarios, [])

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
