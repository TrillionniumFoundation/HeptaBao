"""Controller contract tests, not physical-host execution receipts."""
import sys
from pathlib import Path
import threading
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import ha_multihost_load_live as load


class LoadContractTests(unittest.TestCase):
    def test_exact_denominator_preserves_baseline(self):
        self.assertEqual(len(load.REQUIRED_CHECKS), 11)
        self.assertFalse(load.REQUIRED_CHECKS & load.ha.REQUIRED_CHECKS)
        self.assertEqual(len(load.REQUIRED_CHECKS | load.ha.REQUIRED_CHECKS), 65)

    def test_controller_full_lifecycle_submits_every_mutation_once(self):
        state, writes, deletes, checks = {}, {}, {}, []
        lock = threading.Lock()
        lifecycle = load.LoadLifecycle()

        def write(context, node, token, path, value):
            del context, node, token
            with lock:
                writes[path] = writes.get(path, 0) + 1
                self.assertNotIn(path, state)
                state[path] = value

        def api(context, node, method, path, *args, **kwargs):
            del context, node, args, kwargs
            with lock:
                if method == "DELETE":
                    key = path.removeprefix("secret/metadata/")
                    deletes[key] = deletes.get(key, 0) + 1
                    state.pop(key)
                    return 204, {}
                self.assertEqual(method, "GET")
                key = path.removeprefix("secret/data/")
                return 200, {"data": {"data": {"value": state[key]}, "metadata": {"version": 1}}}

        def absent(context, node, token, key):
            del context, node, token
            self.assertNotIn(key, state)

        def check(name, passed, **metadata):
            self.assertTrue(passed)
            self.assertNotIn(name, checks)
            self.assertNotIn("token", metadata)
            checks.append(name)

        with patch.object(load.ha, "write_once", write), patch.object(load.ha, "api", api), patch.object(load.ha, "wait_absent", absent):
            lifecycle.setup(None, [1, 2, 3], 1, 2, "synthetic-root-only", check)
            lifecycle.after_snapshot(3)
            lifecycle.after_failover([2, 3], 2)
            lifecycle.after_rejoin(1)
            lifecycle.after_quorum_recovery([1, 2, 3])
            lifecycle.cleanup(2)
        self.assertEqual(set(checks), load.REQUIRED_CHECKS)
        self.assertEqual(len(writes), 52)
        self.assertEqual(writes, deletes)
        self.assertEqual(set(writes.values()), {1})
        self.assertFalse(state)
        self.assertEqual(lifecycle.runtime_secrets(), ("synthetic-root-only",))
        lifecycle.clear()
        self.assertEqual(lifecycle.runtime_secrets(), ())
        self.assertFalse(lifecycle.values)

    def test_ambiguous_write_is_not_retried_or_admitted(self):
        lifecycle = load.LoadLifecycle()
        lifecycle.prefix = "synthetic"
        checks = []
        lifecycle.check = lambda *args, **kwargs: checks.append(args)
        with patch.object(load.ha, "write_once", side_effect=load.ha.FixtureError("synthetic_unknown_outcome")) as submit:
            with self.assertRaisesRegex(load.ha.FixtureError, "synthetic_unknown_outcome"):
                lifecycle._batch("healthy", [1], 2)
        self.assertEqual(submit.call_count, 1)
        self.assertFalse(checks)
        with self.assertRaisesRegex(load.ha.FixtureError, "repeated_phase"):
            lifecycle._batch("healthy", [1], 2)

    def test_readback_rejects_duplicate_version_and_wrong_value(self):
        lifecycle = load.LoadLifecycle()
        for version, value in [(2, "expected"), (1, "other"), (0, "expected")]:
            with self.subTest(version=version, value=value):
                with patch.object(load.ha, "api", return_value=(200, {"data": {"data": {"value": value}, "metadata": {"version": version}}})):
                    with self.assertRaisesRegex(load.ha.FixtureError, "not_exact_version_one"):
                        lifecycle._read_once(1, "path", "expected")

    def test_cleanup_failure_retains_only_safe_observation_without_retry(self):
        import json
        for body, expected in [
            ({"errors": ["HA linearizable state is unavailable"]}, "ha_linearizable_unavailable"),
            ({"errors": ["synthetic-private-error"]}, "http_503_unclassified"),
        ]:
            lifecycle = load.LoadLifecycle()
            lifecycle.values = {"synthetic-private-path-a": "synthetic-private-value",
                                "synthetic-private-path-b": "synthetic-private-value",
                                "synthetic-private-path-c": "synthetic-private-value"}
            lifecycle.root = "synthetic-private-bearer"
            checks = []
            lifecycle.check = lambda name, passed, **metadata: checks.append(
                {"case": name, "passed": passed, **metadata})
            with patch.object(load.ha, "api", side_effect=[(204, {}), (503, body)]) as submit:
                with self.assertRaisesRegex(load.ha.FixtureError, expected):
                    lifecycle.cleanup(1)
                self.assertEqual(submit.call_count, 2)
                self.assertTrue(all(call.args[2] == "DELETE" for call in submit.call_args_list))
            self.assertEqual(checks, [{"case": "load_cleanup_once", "passed": False,
                "attempted_deletes": 2, "acknowledged_deletes": 1, "http_status": 503,
                "failure_code": expected, "mutations_retried": False}])
            self.assertNotIn("synthetic-private", json.dumps(checks))

    def test_latency_summary_is_bounded_and_validates_samples(self):
        self.assertEqual(load.latency_summary([.004, .001, .003, .002]),
                         {"requests": 4, "p50_ms": 2., "p95_ms": 4., "max_ms": 4.})
        for sample in [[], [float("nan")], [float("inf")], [-1]]:
            with self.assertRaises(load.ha.FixtureError):
                load.latency_summary(sample)


if __name__ == "__main__":
    unittest.main()
