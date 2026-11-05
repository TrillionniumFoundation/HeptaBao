"""Lifecycle extension contract checks, not physical-host qualification."""
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import ha_multihost_external_keys_live as external
import ha_multihost_live as ha


class ExternalKeysMultihostTests(unittest.TestCase):
    def make(self):
        lifecycle = external.ExternalKeysLifecycle()
        lifecycle.root, lifecycle.reader, lifecycle.provider_token = "root-canary", "reader-canary", "provider-canary"
        rows = []
        def check(name, passed, **metadata):
            rows.append({"case": name, "passed": passed, **metadata})
            if not passed:
                raise ha.FixtureError(name)
        lifecycle.check = check
        return lifecycle, rows

    def test_fixed_extension_is_disjoint_and_keeps_every_baseline_check(self):
        self.assertEqual(len(external.CHECK_NAMES), 30)
        self.assertEqual(len(external.CHECK_NAMES), len(external.REQUIRED_CHECKS))
        self.assertFalse(external.REQUIRED_CHECKS & ha.REQUIRED_CHECKS)
        self.assertEqual(len(ha.REQUIRED_CHECKS | external.REQUIRED_CHECKS), len(ha.REQUIRED_CHECKS) + 30)

    def test_wrong_readback_never_leaks_response_or_token(self):
        lifecycle, rows = self.make()
        with patch.object(ha, "api", return_value=(200, {"data": {"token": "provider-canary"}})):
            with self.assertRaisesRegex(ha.FixtureError, "redaction"):
                lifecycle._call("redaction", object(), "GET", "sys/external-keys/configs/key", 200,
                                data={"token": "(redacted)"})
        self.assertEqual(rows, [{"case": "redaction", "passed": False}])
        self.assertNotIn("canary", json.dumps(rows))

    def test_denial_with_secret_payload_is_not_accepted(self):
        lifecycle, rows = self.make()
        with patch.object(ha, "api", return_value=(403, {"data": {"token": "provider-canary"}})):
            with self.assertRaises(ha.FixtureError):
                lifecycle._call("deny", object(), "POST", "sys/external-keys/configs/key", 403)
        self.assertFalse(rows[0]["passed"])

    def test_transport_uncertainty_does_not_repeat_mutation(self):
        lifecycle, rows = self.make()
        with patch.object(ha, "api", side_effect=TimeoutError("synthetic")) as api:
            with self.assertRaises(TimeoutError):
                lifecycle._call("write", object(), "POST", "sys/external-keys/configs/key", 204, {})
            self.assertEqual(api.call_count, 1)
        self.assertEqual(rows, [])

    def test_forwarded_read_cannot_replace_each_nodes_local_frontier(self):
        lifecycle, rows = self.make()
        nodes = [object(), object(), object()]
        with patch.object(ha, "capture_committed_frontier", return_value=71), patch.object(
                ha, "wait_local_frontier", side_effect=[(71, 71), (72, 72), (71, 70)]) as local:
            with self.assertRaises(ha.FixtureError):
                lifecycle._frontiers("local", nodes, nodes[0])
            self.assertEqual(local.call_count, 3)
            self.assertTrue(all(call.args[2] == 71 for call in local.call_args_list))
        self.assertFalse(rows[0]["passed"])

    def test_empty_observation_set_never_passes(self):
        lifecycle, rows = self.make()
        with self.assertRaises(ha.FixtureError):
            lifecycle._all("all", [], "sys/external-keys/configs/key", 200)
        self.assertFalse(rows[0]["passed"])

    def test_every_credential_is_checked_by_existing_report_guard_and_cleared(self):
        lifecycle, _ = self.make()
        self.assertEqual(set(lifecycle.runtime_secrets()), {"root-canary", "reader-canary", "provider-canary"})
        self.assertFalse(ha.report_is_secret_safe({"value": "provider-canary"}, lifecycle.runtime_secrets()))
        lifecycle.clear()
        self.assertEqual(lifecycle.runtime_secrets(), ())


if __name__ == "__main__":
    unittest.main()
