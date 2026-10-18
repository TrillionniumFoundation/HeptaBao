"""Offline dispatch/custody regressions; these never claim a physical HA pass."""
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import native_v6_ha_multihost_live as native
import native_v6_ha_direct_lan_live as direct


class FixtureRecoveryTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.work = Path(self.temporary.name).resolve()
        self.nodes = [native.base.Node(index, f"fixture-{index}", f"192.168.0.{index}",
                                      f"/home/fixture/node-{index}", 46230, 46231)
                      for index in (1, 2, 3)]
        args = SimpleNamespace(work_root=self.work, source_commit="a" * 40,
                               source_tree="b" * 40)
        self.run = direct.DirectLanRun(args, self.nodes, direct.DirectLanTransport(),
                                       {}, {}, {str(index): "c" * 64 for index in (1, 2, 3)})
        self.node = self.nodes[0]
        self.root_token = "synthetic-private-root-value-for-test-only"
        self.unseal_key = "synthetic-private-unseal-value-for-test-only"
        self.initialized = {"root_token": self.root_token, "keys_base64": [self.unseal_key]}

    def read(self, name):
        return json.loads((self.work / "private-recovery" / name).read_text())

    def initialize(self):
        with mock.patch.object(native.base, "api", return_value=(200, self.initialized)) as api:
            self.run.request(self.node, "POST", "sys/init",
                             {"secret_shares": 1, "secret_threshold": 1}, authenticate=False)
        self.assertEqual(api.call_count, 1)

    def assert_public_is_secret_safe(self):
        self.assertTrue(native.base.report_is_secret_safe(self.run.report, self.run.secrets()))
        public = native.canonical(self.run.report)
        for path in (self.work / "phases").glob("*.json"):
            public += path.read_bytes()
        self.assertNotIn(self.root_token.encode(), public)
        self.assertNotIn(self.unseal_key.encode(), public)

    def test_initialization_custody_precedes_checkpoint_and_later_dispatch(self):
        def returned(*_args, **_options):
            intent = self.read("mutation-00001.intent.json")
            self.assertEqual(intent["route"], "sys/init")
            self.assertFalse((self.work / "private-recovery/credentials.json").exists())
            return 200, self.initialized

        original = self.run.event
        def checkpoint_after_custody(*args, **options):
            self.assertEqual(self.read("credentials.json")["unseal_key"], self.unseal_key)
            original(*args, **options)

        with mock.patch.object(native.base, "api", side_effect=returned), \
                mock.patch.object(self.run, "event", side_effect=checkpoint_after_custody):
            self.run.request(self.node, "POST", "sys/init",
                             {"secret_shares": 1, "secret_threshold": 1}, authenticate=False)
        folder = self.work / "private-recovery"
        self.assertEqual(stat.S_IMODE(folder.stat().st_mode), 0o700)
        for path in folder.iterdir():
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            self.assertEqual(path.stat().st_nlink, 1)
        self.assertTrue(self.run.report["fixture_recovery"]["initialization_custody_saved"])
        self.assert_public_is_secret_safe()

    def test_mutation_intent_contains_original_identity_before_send(self):
        self.initialize()
        value = {"ordinal": 5, "payload": "synthetic-history-value"}
        route = "secret/data/native-ha-" + self.run.run_id + "/history"
        body = {"options": {"cas": 6}, "data": value}
        def returned(*_args, **options):
            intent = self.read("mutation-00002.intent.json")
            self.assertEqual(intent["route"], route)
            self.assertEqual(intent["expected_cas"], 6)
            self.assertEqual(intent["expected_version"], 7)
            self.assertEqual(intent["expected_data_sha256"], native.data_digest(value))
            self.assertEqual(intent["request_body_sha256"], native.data_digest(body))
            self.assertEqual(intent["dispatch_attempts_allowed"], 1)
            self.assertEqual(options["timeout"], 15)
            return 200, {"data": {"version": 7}}
        with mock.patch.object(native.base, "api", side_effect=returned) as api:
            self.run.request(self.node, "POST", route, body)
        self.assertEqual(api.call_count, 1)
        self.assertEqual(self.read("mutation-00002.outcome.json")["response_data_version"], 7)

    def test_transport_timeout_is_unknown_once_and_never_retried(self):
        self.initialize()
        with mock.patch.object(native.base, "api", side_effect=TimeoutError(self.root_token)) as api:
            with self.assertRaises(TimeoutError):
                self.run.request(self.node, "POST", "secret/data/native-ha-timeout",
                                 {"options": {"cas": 0}, "data": {"value": "synthetic"}})
        self.assertEqual(api.call_count, 1)
        outcome = self.read("mutation-00002.outcome.json")
        self.assertIsNone(outcome["http_status"])
        self.assertEqual(outcome["dispatch_outcome"], "unknown")
        self.assertEqual(outcome["failure_type"], "TimeoutError")
        self.assertNotIn(self.root_token, json.dumps(outcome))
        self.assertFalse(outcome["automatic_retry"])
        self.assert_public_is_secret_safe()

    def test_503_keeps_commit_outcome_unknown_and_original_response(self):
        self.initialize()
        response = {"errors": ["synthetic delivery veto"]}
        with mock.patch.object(native.base, "api", return_value=(503, response)) as api:
            self.assertEqual(self.run.request(self.node, "POST", "secret/data/native-ha-veto",
                                             {"options": {"cas": 6}, "data": {"value": "synthetic"}}),
                             (503, response))
        self.assertEqual(api.call_count, 1)
        outcome = self.read("mutation-00002.outcome.json")
        self.assertEqual(outcome["http_status"], 503)
        self.assertEqual(outcome["storage_commit_outcome"], "not_inferred_from_http_or_transport")
        self.assertNotIn("zero_effect", outcome)

    def test_public_checkpoint_failure_retains_original_init_credentials(self):
        with mock.patch.object(native.base, "api", return_value=(200, self.initialized)) as api, \
                mock.patch.object(self.run, "event", side_effect=OSError("checkpoint unavailable")):
            with self.assertRaises(OSError):
                self.run.request(self.node, "POST", "sys/init", {}, authenticate=False)
        self.assertEqual(api.call_count, 1)
        self.assertEqual(self.read("credentials.json")["root_token"], self.root_token)
        self.assertEqual(self.read("mutation-00001.outcome.json")["http_status"], 200)
        self.assert_public_is_secret_safe()

    def test_late_init_response_preserves_custody_but_fails_original_budget(self):
        with mock.patch.object(native.base, "api", return_value=(200, self.initialized)) as api, \
                mock.patch.object(native.time, "monotonic", side_effect=[1.0, 17.0]):
            with self.assertRaisesRegex(native.base.FixtureError, "response_arrived_after_original_http_budget"):
                self.run.request(self.node, "POST", "sys/init", {}, authenticate=False)
        self.assertEqual(api.call_count, 1)
        self.assertEqual(self.read("credentials.json")["root_token"], self.root_token)
        self.assertFalse(self.read("mutation-00001.outcome.json")["within_original_budget"])

    def test_initialization_collision_and_repeat_refuse_before_network(self):
        path = self.work / "private-recovery/credentials.json"
        path.write_text("existing-private-fixture-data")
        path.chmod(0o600)
        with mock.patch.object(native.base, "api") as api:
            with self.assertRaisesRegex(native.base.FixtureError, "output_must_be_new"):
                self.run.request(self.node, "POST", "sys/init", {}, authenticate=False)
        api.assert_not_called()
        self.assertEqual(path.read_text(), "existing-private-fixture-data")
        path.unlink()
        self.initialize()
        with mock.patch.object(native.base, "api") as api:
            with self.assertRaisesRegex(native.base.FixtureError, "initialization_must_not_repeat"):
                self.run.request(self.node, "POST", "sys/init", {}, authenticate=False)
        api.assert_not_called()

    def test_missing_or_changed_custody_blocks_later_business_writes(self):
        self.initialize()
        path = self.work / "private-recovery/credentials.json"
        raw = path.read_bytes()
        for altered in (b"changed", None):
            with self.subTest(altered=altered):
                if altered is None:
                    path.unlink()
                else:
                    path.write_bytes(altered)
                with mock.patch.object(native.base, "api") as api:
                    with self.assertRaises((native.base.FixtureError, FileNotFoundError)):
                        self.run.request(self.node, "POST", "secret/data/owned", {"data": {"value": "x"}})
                api.assert_not_called()
                path.write_bytes(raw)
                path.chmod(0o600)

    def test_non_private_custody_and_symlink_are_rejected_before_network(self):
        self.initialize()
        path = self.work / "private-recovery/credentials.json"
        path.chmod(0o644)
        with mock.patch.object(native.base, "api") as api:
            with self.assertRaisesRegex(native.base.FixtureError, "credentials_not_private"):
                self.run.request(self.node, "POST", "sys/unseal", {"key": self.unseal_key})
        api.assert_not_called()
        path.chmod(0o600)
        retained = path.with_name("retained-fixture-custody.json")
        path.rename(retained)
        path.symlink_to(retained)
        with mock.patch.object(native.base, "api") as api:
            with self.assertRaises(OSError):
                self.run.request(self.node, "POST", "sys/unseal", {"key": self.unseal_key})
        api.assert_not_called()

    def test_mount_setup_is_recorded_once_with_unchanged_twelve_second_budget(self):
        self.initialize()
        responses = [(204, {}), (200, {"data": {"secret/": {
            "type": "kv", "options": {"version": "2"}}}})]
        with mock.patch.object(native.base, "api", side_effect=responses) as api:
            result = self.run.provision_fixture_kv2(self.node)
        self.assertTrue(result["inventory_confirmed"])
        self.assertEqual([(call.args[2], call.args[3], call.kwargs["timeout"])
                          for call in api.call_args_list],
                         [("POST", "sys/mounts/secret", 12), ("GET", "sys/mounts", 12)])
        self.assertEqual(self.read("mutation-00002.intent.json")["original_http_budget_seconds"], 12)
        self.assertEqual(len(list((self.work / "private-recovery").glob("*.intent.json"))), 2)

    def test_query_selection_and_original_denominators_do_not_change(self):
        self.assertEqual(len(native.REQUIRED_CHECKS), 89)
        self.assertEqual(len(direct.DIRECT_CHECKS), 98)
        self.assertEqual((native.REQUEST_SECONDS, native.NATIVE_ADMISSION_SECONDS), (15, 8))
        with mock.patch.object(native.base, "api", return_value=(503, {})) as api:
            self.run.read_data(self.node, "history", version=19)
        self.assertEqual(api.call_args.args[3], "secret/data/history?version=19")
        self.assertIsNone(api.call_args.args[4])
        for version in (0, -1, True, 1.0, "1"):
            with self.subTest(version=version), mock.patch.object(native.base, "api") as api:
                with self.assertRaises(native.base.FixtureError):
                    self.run.read_data(self.node, "history", version=version)
                api.assert_not_called()


if __name__ == "__main__":
    unittest.main()
