"""Synthetic prerequisite boundaries only; no process, HTTP or HA qualification."""
from __future__ import annotations

from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from fixture_mounts import provision_secret_kv2, provision_transit
from ha_destructive import Cluster, FixtureError
from ha_rolling_upgrade import RollingUpgradeCluster


class FixtureMountTests(unittest.TestCase):
    def test_secret_setup_uses_exact_one_kv2_mutation_and_caller_budget(self):
        request = Mock(return_value=(204, {}))
        observed = provision_secret_kv2(request, token="synthetic", timeout=2)
        request.assert_called_once_with(
            "POST", "sys/mounts/secret", {"type": "kv", "options": {"version": "2"}},
            token="synthetic", timeout=2)
        self.assertEqual(observed, {"mount": "secret", "http_status": 204,
                                    "mutations_submitted": 1, "automatic_retry": False})

    def test_transit_setup_is_an_explicit_mount_without_kv_options(self):
        request = Mock(return_value=(204, {}))
        observed = provision_transit(request)
        request.assert_called_once_with("POST", "sys/mounts/transit", {"type": "transit"})
        self.assertEqual(observed["mutations_submitted"], 1)

    def test_setup_rejection_does_not_accept_conflict_or_retry(self):
        for status in (200, 400, 403, 404, 409, 500, 503, True, None):
            with self.subTest(status=status):
                request = Mock(return_value=(status, {"errors": ["private-do-not-print"]}))
                with self.assertRaisesRegex(FixtureError, "^fixture_secret_mount_setup_failed$"):
                    provision_secret_kv2(request, error_type=FixtureError)
                request.assert_called_once()

    def test_unknown_setup_outcome_is_never_replayed_or_read_as_success(self):
        for error in (TimeoutError("private-detail"), OSError("private-detail")):
            with self.subTest(error=type(error).__name__):
                request = Mock(side_effect=error)
                with self.assertRaises(type(error)) as caught:
                    provision_secret_kv2(request)
                self.assertIs(caught.exception, error)
                request.assert_called_once()


class SeedNode:
    def __init__(self, number, events, *, mount_status=204):
        self.node_id, self.events = number, events
        self.data_dir = Path("synthetic-node-" + str(number))
        self.process = None
        self.initialized = self.unsealed = self.mount_enabled = False
        self.mount_status = mount_status

    def start(self, **options):
        self.process = SimpleNamespace(pid=100 + self.node_id)
        self.events.append(("start", self.node_id, options))

    def stop(self):
        self.process = None
        self.events.append(("stop", self.node_id))

    def wait_ready(self):
        self.events.append(("ready", self.node_id))

    def call(self, method, path, body=None, **options):
        self.events.append(("request", self.node_id, method, path))
        if path == "sys/health":
            return (200, {"cluster_id": "synthetic-cluster"}) if self.initialized else (501, {})
        if path == "sys/init":
            self.initialized = True
            return 200, {"root_token": "synthetic-root", "keys_base64": ["synthetic-unseal"]}
        if path == "sys/unseal":
            self.unsealed = True
            return 200, {}
        if path == "sys/mounts/secret":
            if not self.unsealed:
                raise AssertionError("setup must follow unseal")
            if isinstance(self.mount_status, Exception):
                raise self.mount_status
            self.mount_enabled = self.mount_status == 204
            return self.mount_status, {}
        raise AssertionError("unexpected fixture request")


class ClusterSeedSetupTests(unittest.TestCase):
    def cluster(self, mount_status=204):
        events = []
        value = Cluster.__new__(Cluster)
        value.nodes = [SeedNode(i, events, mount_status=mount_status) for i in (1, 2, 3)]
        value.root_token = value.unseal_key = value.cluster_id = ""
        value.scenarios = []
        value.fixture_mount_setup = []
        value.configure_ha = Mock(side_effect=lambda: events.append(("configure_ha",)))
        value.wait_quorum = Mock(side_effect=lambda: events.append(("quorum",)))
        return value, events

    def test_seed_mount_is_committed_before_cold_copy_and_ha_start(self):
        cluster, events = self.cluster()

        def copy(source, destination):
            self.assertTrue(cluster.nodes[0].mount_enabled)
            self.assertIsNone(cluster.nodes[0].process)
            events.append(("copy", source, destination))

        with patch("ha_destructive.shutil.copytree", side_effect=copy) as copies:
            cluster.bootstrap()
        self.assertEqual(copies.call_count, 2)
        self.assertEqual(cluster.scenarios, [
            "fresh_seed_uninitialized", "fresh_seed_initialized", "seed_unsealed_before_ha",
            "seed_cluster_identity_read_back", "three_distinct_service_processes",
            "node_1_unsealed", "node_2_unsealed", "node_3_unsealed"])
        self.assertEqual(len(cluster.fixture_mount_setup), 1)
        requests = [event for event in events if event[0] == "request"]
        self.assertEqual(sum(event[3] == "sys/mounts/secret" for event in requests), 1)
        first_copy = next(i for i, event in enumerate(events) if event[0] == "copy")
        mount = events.index(("request", 1, "POST", "sys/mounts/secret"))
        self.assertLess(mount, first_copy)

    def test_denied_seed_mount_never_copies_or_starts_ha_peers(self):
        cluster, _ = self.cluster(403)
        with patch("ha_destructive.shutil.copytree") as copies:
            with self.assertRaisesRegex(FixtureError, "^fixture_secret_mount_setup_failed$"):
                cluster.bootstrap()
        copies.assert_not_called()
        cluster.configure_ha.assert_not_called()
        self.assertIsNone(cluster.nodes[1].process)
        self.assertEqual(cluster.fixture_mount_setup, [])

    def test_lost_seed_mount_reply_is_not_retried_or_cloned(self):
        cluster, events = self.cluster(TimeoutError())
        with patch("ha_destructive.shutil.copytree") as copies:
            with self.assertRaises(TimeoutError):
                cluster.bootstrap()
        copies.assert_not_called()
        self.assertEqual(events.count(("request", 1, "POST", "sys/mounts/secret")), 1)
        cluster.configure_ha.assert_not_called()


class HistoricalSeedSetupTests(unittest.TestCase):
    def cluster(self):
        value = RollingUpgradeCluster.__new__(RollingUpgradeCluster)
        value.root_token = "synthetic-root"
        value.fixture_mount_setup = []
        return value

    def test_exact_historical_kv2_is_observed_without_recreating_mount(self):
        seed = Mock()
        seed.call.return_value = (200, {"data": {"secret/": {
            "type": "kv", "options": {"version": "2"}}}})
        cluster = self.cluster()
        cluster.provision_seed_mounts(seed)
        seed.call.assert_called_once_with("GET", "sys/mounts", token="synthetic-root")
        self.assertEqual(cluster.fixture_mount_setup[0]["mutations_submitted"], 0)

    def test_empty_historical_inventory_provisions_once(self):
        seed = Mock()
        seed.call.side_effect = [(200, {"data": {}}), (204, {})]
        cluster = self.cluster()
        cluster.provision_seed_mounts(seed)
        self.assertEqual(seed.call.call_count, 2)
        self.assertEqual(cluster.fixture_mount_setup[0]["mutations_submitted"], 1)

    def test_denied_or_wrong_engine_inventory_never_mutates(self):
        for status, body in [(403, {"data": {}}), (500, {}), (200, {"data": None}),
                             (200, {"data": {"secret/": {"type": "transit"}}}),
                             (200, {"data": {"secret/": {"type": "kv", "options": {"version": "1"}}}})]:
            with self.subTest(status=status, body=body):
                seed = Mock()
                seed.call.return_value = status, body
                with self.assertRaises(FixtureError):
                    self.cluster().provision_seed_mounts(seed)
                seed.call.assert_called_once()


if __name__ == "__main__":
    unittest.main()
