"""Rolling wire retirement must preserve quorum without weakening evidence."""
import hashlib
import contextlib
import io
import json
import os
from pathlib import Path
import sys
import subprocess
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import ha_rolling_upgrade as upgrade


class RollingUpgradeFixtureTests(unittest.TestCase):
    def base_node(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        return Mock(binary=Path("/base"), root=Path(directory.name))

    def cluster(self):
        cluster = upgrade.RollingUpgradeCluster.__new__(upgrade.RollingUpgradeCluster)
        cluster.base_source_sha = "55f27e4258ea3f71ab7872cd7a44e8cbd4da1f18"
        cluster.base_wire_profile = "legacy-v1"
        cluster.base_digest = "a" * 64
        cluster.candidate_digest = "b" * 64
        cluster.root_token = "synthetic-unused"
        return cluster

    def test_pinned_base_misbinding_uses_exact_legacy_contract(self):
        cluster = self.cluster()
        cluster.scenarios, cluster.unseal_key = [], "synthetic-unused"
        cluster.candidate_binary = Path("/candidate")
        node = self.base_node()
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
                node = self.base_node()
                node.call.side_effect = replies
                with patch.object(upgrade, "checked_binary"), patch.object(upgrade, "running_digest", return_value=cluster.base_digest), self.assertRaises(upgrade.FixtureError):
                    cluster.assert_misbound_rejection(node)
                node.stop.assert_called_once_with()

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
        node = self.base_node()
        with patch.object(upgrade, "checked_binary"), patch.object(upgrade, "running_digest", return_value=cluster.candidate_digest), self.assertRaisesRegex(upgrade.FixtureError, "base_binary_changed"):
            cluster.assert_misbound_rejection(node)
        node.call.assert_not_called()
        node.stop.assert_called_once_with()
        self.assertEqual(cluster.scenarios, [])

    def early_exit(self, returncode, delta, *, stale=b"", error="node_exited_during_startup"):
        cluster = self.cluster()
        cluster.base_source_sha = "8c1e43718c30ce5185c55b258c0460bd48936a2a"
        cluster.base_wire_profile = upgrade.base_wire_profile_for_source(cluster.base_source_sha)
        cluster.scenarios, cluster.candidate_binary = [], Path("/candidate")
        node = self.base_node()
        log_path = node.root / "process.log"
        log_path.write_bytes(stale)
        node.process.poll.return_value = returncode
        def start():
            with log_path.open("ab") as stream:
                stream.write(delta)
            raise upgrade.FixtureError(error)
        node.start.side_effect = start
        return cluster, node

    def test_modern_pinned_base_accepts_exact_startup_rejection(self):
        cluster, node = self.early_exit(1, (upgrade.MISBOUND_BOOTSTRAP_ERROR + "\n").encode())
        with patch.object(upgrade, "checked_binary") as checked, patch.object(upgrade, "running_digest") as running:
            cluster.assert_misbound_rejection(node)
        self.assertEqual(checked.call_count, 2)
        running.assert_not_called()
        node.call.assert_not_called()
        node.start.assert_called_once_with()
        node.stop.assert_called_once_with()
        self.assertEqual(cluster.scenarios, ["rolling_upgrade_base_misbound_startup_rejected"])

    def test_owner_strict_base_cannot_qualify_with_late_http_rejection(self):
        cluster = self.cluster()
        cluster.base_source_sha = "8c1e43718c30ce5185c55b258c0460bd48936a2a"
        cluster.base_wire_profile = upgrade.base_wire_profile_for_source(cluster.base_source_sha)
        cluster.scenarios, cluster.unseal_key = [], "synthetic-unused"
        cluster.candidate_binary = Path("/candidate")
        node = self.base_node()
        node.call.side_effect = [(503, {"errors": ["HA configuration belongs to a different cluster"]}), (503, {"sealed": True})]
        with patch.object(upgrade, "checked_binary"), patch.object(upgrade, "running_digest", return_value=cluster.base_digest), self.assertRaisesRegex(upgrade.FixtureError, "strict_base_started_with_misbound_cluster"):
            cluster.assert_misbound_rejection(node)
        node.call.assert_not_called()
        node.stop.assert_called_once_with()
        self.assertEqual(cluster.scenarios, [])

    def test_modern_base_rejects_arbitrary_exit_status_or_log(self):
        exact = (upgrade.MISBOUND_BOOTSTRAP_ERROR + "\n").encode()
        for code, delta in [(0, exact), (-9, exact), (2, exact), (None, exact),
                            (1, b"unrelated failure\n"), (1, b""), (1, b"\xff"),
                            (1, exact + b"later unrelated failure\n"),
                            (1, b"x" * (64 * 1024) + exact)]:
            with self.subTest(code=code, size=len(delta)):
                cluster, node = self.early_exit(code, delta)
                with patch.object(upgrade, "checked_binary"), self.assertRaises(upgrade.FixtureError):
                    cluster.assert_misbound_rejection(node)
                node.call.assert_not_called()
                node.stop.assert_called_once_with()
                self.assertEqual(cluster.scenarios, [])

    def test_old_exact_log_cannot_authorize_new_arbitrary_exit(self):
        exact = (upgrade.MISBOUND_BOOTSTRAP_ERROR + "\n").encode()
        cluster, node = self.early_exit(1, b"unrelated failure\n", stale=exact)
        with patch.object(upgrade, "checked_binary"), self.assertRaises(upgrade.FixtureError):
            cluster.assert_misbound_rejection(node)
        node.stop.assert_called_once_with()
        self.assertEqual(cluster.scenarios, [])

    def test_startup_timeout_cannot_use_modern_base_exception(self):
        exact = (upgrade.MISBOUND_BOOTSTRAP_ERROR + "\n").encode()
        cluster, node = self.early_exit(1, exact, error="node_listener_timeout")
        with patch.object(upgrade, "checked_binary"), self.assertRaisesRegex(upgrade.FixtureError, "node_listener_timeout"):
            cluster.assert_misbound_rejection(node)
        node.stop.assert_called_once_with()
        self.assertEqual(cluster.scenarios, [])

    def test_replaced_base_binary_cannot_use_startup_exception(self):
        exact = (upgrade.MISBOUND_BOOTSTRAP_ERROR + "\n").encode()
        cluster, node = self.early_exit(1, exact)
        with patch.object(upgrade, "checked_binary", side_effect=[None, upgrade.FixtureError("binary_digest_mismatch")]), self.assertRaisesRegex(upgrade.FixtureError, "binary_digest_mismatch"):
            cluster.assert_misbound_rejection(node)
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


class BaseWireProfileTests(unittest.TestCase):
    MODERN = "8c1e43718c30ce5185c55b258c0460bd48936a2a"
    HISTORICAL_MODERN = "421c19794fa4f772edb9cde7dcc0db68362c1717"
    LEGACY = "55f27e4258ea3f71ab7872cd7a44e8cbd4da1f18"

    def test_profiles_are_explicit_immutable_sources(self):
        for source in (self.MODERN, self.HISTORICAL_MODERN):
            with self.subTest(source=source):
                self.assertEqual(upgrade.base_wire_profile_for_source(source), "strict-current")
        self.assertEqual(upgrade.base_wire_profile_for_source(self.LEGACY), "legacy-v1")

    def test_mismatched_profiles_cannot_relax_or_break_known_base(self):
        for source, requested in [(self.MODERN, "legacy-v1"), (self.HISTORICAL_MODERN, "legacy-v1"), (self.LEGACY, "strict-current")]:
            with self.subTest(source=source), self.assertRaisesRegex(upgrade.FixtureError, "profile_mismatch"):
                upgrade.base_wire_profile_for_source(source, requested)

    def test_unknown_or_mutable_source_fails_closed(self):
        for source in ["a" * 40, "main", self.MODERN.upper(), "", self.MODERN + "\n"]:
            with self.subTest(source=source), self.assertRaisesRegex(upgrade.FixtureError, "unreviewed_base_source"):
                upgrade.base_wire_profile_for_source(source)

    def test_upgrade_current_and_legacy_use_distinct_wire_modes(self):
        for source, profile, expected in [(self.MODERN, "strict-current", False),
                                          (self.HISTORICAL_MODERN, "strict-current", False),
                                          (self.LEGACY, "legacy-v1", True)]:
            with self.subTest(profile=profile), tempfile.TemporaryDirectory() as directory:
                cluster = upgrade.RollingUpgradeCluster.__new__(upgrade.RollingUpgradeCluster)
                cluster.base_source_sha, cluster.base_wire_profile = source, profile
                cluster.candidate_binary, cluster.candidate_digest = Path("/candidate"), "b" * 64
                cluster.scenarios, cluster.unseal_key = [], "synthetic-unused"
                cluster.leader = Mock()
                node = Mock(binary=Path("/base"), root=Path(directory), process=None)
                node.call.return_value = (200, {})
                config = node.root / "ha.json"
                config.write_text('{"cluster_id":"synthetic"}')
                with patch.object(upgrade, "running_digest", return_value=cluster.candidate_digest):
                    cluster.upgrade(node, "test_upgrade")
                actual = json.loads(config.read_text())
                self.assertEqual(actual.get("allow_legacy_peer_v1", False), expected)
                self.assertNotIn("emit_legacy_peer_v1", actual)
                self.assertEqual(actual["cluster_id"], "synthetic")
                self.assertEqual(config.stat().st_mode & 0o777, 0o600)
                node.start.assert_called_once_with()
                self.assertEqual(cluster.scenarios, ["test_upgrade_candidate_process_digest"])

    def test_profile_and_binary_mismatches_fail_before_cluster_launch(self):
        for source, requested, fail_digest, expected in [
            (self.MODERN, "legacy-v1", False, "base_wire_profile_mismatch"),
            ("a" * 40, "strict-current", False, "unreviewed_base_source"),
            (self.MODERN, "strict-current", True, "binary_sha256_mismatch"),
        ]:
            with self.subTest(source=source, requested=requested, fail_digest=fail_digest):
                argv = ["ha_rolling_upgrade.py", "--base-binary", "/base", "--base-sha256", "a" * 64,
                        "--candidate-binary", "/candidate", "--candidate-sha256", "b" * 64,
                        "--base-source-sha", source, "--base-wire-profile", requested,
                        "--work-dir", "/fixture"]
                with patch.object(sys, "argv", argv), patch.object(upgrade, "RollingUpgradeCluster") as cluster, patch.object(upgrade, "checked_binary", side_effect=upgrade.FixtureError("binary_sha256_mismatch")) as checked, contextlib.redirect_stdout(io.StringIO()) as output:
                    self.assertEqual(upgrade.main(), 1)
                cluster.assert_not_called()
                self.assertEqual(checked.call_count, int(fail_digest))
                self.assertIn(expected, json.loads(output.getvalue())["failure_class"])


class BaseSourceWorkflowBindingTests(unittest.TestCase):
    def test_actual_clean_worktree_must_match_pr_base(self):
        workflow = (Path(__file__).resolve().parents[3] / ".github/workflows/codex-openbao-replacement-ci.yml").read_text()
        identity = 'test "$(git -C "$base_dir" rev-parse HEAD)" = "$PR_BASE"'
        clean = 'test -z "$(git -C "$base_dir" status --porcelain=v1 --untracked-files=all)"'
        self.assertIn(identity, workflow)
        self.assertIn(clean, workflow)
        self.assertIn('--base-source-sha "$PR_BASE"', workflow)
        with tempfile.TemporaryDirectory() as directory:
            def git(*args):
                return subprocess.check_output(["git", "-C", directory, *args], text=True).strip()
            git("init", "-q")
            git("-c", "user.name=Fixture Test", "-c", "user.email=fixture@example.invalid", "commit", "--allow-empty", "-qm", "synthetic")
            actual = git("rev-parse", "HEAD")
            command = "set -euo pipefail\n" + identity + "\n" + clean
            env = dict(os.environ, base_dir=directory, PR_BASE=actual)
            self.assertEqual(subprocess.run(["bash", "-c", command], env=env).returncode, 0)
            forged = dict(env, PR_BASE="f" * 40)
            self.assertNotEqual(subprocess.run(["bash", "-c", command], env=forged).returncode, 0)
            (Path(directory) / "unexpected-source").write_text("synthetic dirty source")
            self.assertNotEqual(subprocess.run(["bash", "-c", command], env=env).returncode, 0)


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
