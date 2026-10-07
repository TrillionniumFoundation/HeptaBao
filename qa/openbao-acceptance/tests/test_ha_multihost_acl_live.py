"""Composed-profile contract tests, not substitute evidence for physical hosts."""
from pathlib import Path
from types import SimpleNamespace
from unittest import mock
import json
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import ha_multihost_live as base
import ha_multihost_acl_live as acl


class Response:
    status = 403
    def __enter__(self):
        return self
    def __exit__(self, *args):
        return False
    def read(self, bound):
        return b'{"errors":["synthetic denied"]}'


class MultiHostAclContractTests(unittest.TestCase):
    def lifecycle(self):
        extension = acl.AclLifecycle()
        extension.root = "synthetic-private-root"
        extension.service = "synthetic-private-service"
        extension.batch = "synthetic-private-batch"
        extension.paths = {key: "mount/data/" + key for key in ("own", "red", "blue", "max", "group")}
        rows = []
        def check(name, passed):
            rows.append({"case": name, "passed": passed is True})
            if passed is not True:
                raise base.FixtureError(name)
        extension.check = check
        return extension, rows

    def test_distinct_denominator_preserves_all_original_lifecycle_checks(self):
        self.assertEqual(len(base.REQUIRED_CHECKS), 54)
        self.assertEqual(len(acl.REQUIRED_CHECKS), 64)
        self.assertFalse(base.REQUIRED_CHECKS & acl.REQUIRED_CHECKS)
        self.assertEqual(len(base.REQUIRED_CHECKS | acl.REQUIRED_CHECKS), 118)
        for stage in (acl.SETUP_CHECKS, acl.SNAPSHOT_CHECKS, acl.FAILOVER_CHECKS,
                      acl.REJOIN_CHECKS, acl.RECOVERY_CHECKS, acl.CLEANUP_CHECKS):
            self.assertEqual(len(stage), len(set(stage)))
            self.assertTrue(set(stage) <= acl.REQUIRED_CHECKS)
        for checks in (frozenset(), frozenset({"multihost.complete"})):
            with self.assertRaisesRegex(base.FixtureError, "extension_denominator"):
                base.main(extension=SimpleNamespace(required_checks=checks))

    def test_transport_keeps_explicit_zero_separate_from_no_header(self):
        node = base.Node(1, "fixture", "100.64.1.2", "/home/fixture/fresh", 46230, 46231)
        for ttl in (None, "0", "20"):
            opener = mock.Mock()
            opener.open.return_value = Response()
            with mock.patch.object(base.urllib.request, "build_opener", return_value=opener):
                status, _ = base.api(None, node, "GET", "secret/data/item", token="synthetic", wrap_ttl=ttl)
            self.assertEqual(status, 403)
            headers = {key.lower(): value for key, value in opener.open.call_args.args[0].header_items()}
            self.assertEqual(headers.get("x-vault-wrap-ttl"), ttl)
        for bad in ("0\r\nInjected: value", "", "-1", " " * 10, "1" * 11, 0):
            with self.assertRaisesRegex(base.FixtureError, "invalid_fixture_wrap_ttl"):
                base.api(None, node, "GET", "secret/data/item", wrap_ttl=bad)

    def test_wrapped_observation_uses_subject_then_single_use_wrapper_not_root(self):
        extension, rows = self.lifecycle()
        wrapper = "synthetic-private-wrapper"
        wrapped = {"wrap_info": {"token": wrapper, "ttl": 20, "creation_path": "mount/data/own"}}
        unwrapped = {"data": {"data": {"synthetic": "own"}}}
        with mock.patch.object(base, "api", side_effect=[(200, wrapped), (200, unwrapped)]) as request:
            returned = extension._wrapped("acl_standby_original", "standby", "own", extension.service, expected="own")
        self.assertEqual(returned, wrapper)
        self.assertEqual(request.call_count, 2)
        self.assertEqual([call.args[2] for call in request.call_args_list], ["GET", "POST"])
        self.assertEqual([call.args[5] for call in request.call_args_list], [extension.service, wrapper])
        self.assertEqual(request.call_args_list[0].kwargs["wrap_ttl"], "20")
        self.assertEqual(request.call_args_list[1].args[3], "sys/wrapping/unwrap")
        self.assertTrue(all(row["passed"] for row in rows))
        self.assertTrue(base.report_is_secret_safe({"checks": rows}, extension.runtime_secrets()))
        self.assertIn(wrapper, extension.runtime_secrets())
        extension.clear()
        self.assertEqual(extension.runtime_secrets(), ())

    def test_plaintext_leak_is_failed_without_unwrap_or_reissue(self):
        extension, rows = self.lifecycle()
        response = {"data": {"data": {"synthetic": "leaked"}},
                    "wrap_info": {"token": "synthetic-wrapper", "ttl": 20, "creation_path": "mount/data/own"}}
        with mock.patch.object(base, "api", return_value=(200, response)) as request:
            with self.assertRaisesRegex(base.FixtureError, "acl_standby_original_wrapped"):
                extension._wrapped("acl_standby_original", "standby", "own", extension.service, expected="own")
        self.assertEqual(request.call_count, 1)
        self.assertEqual(rows, [{"case": "acl_standby_original_wrapped", "passed": False}])
        self.assertNotIn("leaked", json.dumps(rows))

    def test_denied_write_is_single_attempt_and_records_failure_prefix(self):
        extension, rows = self.lifecycle()
        with mock.patch.object(base, "api", return_value=(503, {"errors": ["synthetic-private-detail"]})) as request:
            with self.assertRaisesRegex(base.FixtureError, "acl_write_zero_denied"):
                extension._call("acl_write_zero_denied", "standby", "POST", "mount/data/own", 403,
                                {"data": {"synthetic": "never"}}, token=extension.service, ttl="0")
        self.assertEqual(request.call_count, 1)
        self.assertEqual(request.call_args.kwargs["wrap_ttl"], "0")
        self.assertEqual(rows, [{"case": "acl_write_zero_denied", "passed": False}])
        self.assertNotIn("synthetic-private-detail", json.dumps(rows))

    def test_restart_and_failover_do_not_replace_original_subject_tokens(self):
        extension, _ = self.lifecycle()
        with mock.patch.object(extension, "_wrapped") as read, mock.patch.object(extension, "_call"), mock.patch.object(extension, "_plain"):
            extension.after_snapshot("restarted-follower")
        self.assertEqual([call.args[3] for call in read.call_args_list], [extension.service, extension.batch])
        with mock.patch.object(extension, "_wrapped") as read, mock.patch.object(extension, "_call") as mutation, mock.patch.object(extension, "_revoked_on_all") as revoked:
            extension.after_failover(["new-leader", "survivor"], "new-leader")
        self.assertTrue(all(call.args[1] == "survivor" for call in read.call_args_list))
        self.assertEqual([call.args[3] for call in read.call_args_list], [extension.service, extension.batch])
        self.assertEqual(mutation.call_count, 1)
        self.assertEqual(mutation.call_args.args[5], {"disabled": True})
        self.assertEqual([call.args[2] for call in revoked.call_args_list], [extension.service, extension.batch])

    def test_every_survivor_is_observed_and_no_missing_peer_counts_as_revoked(self):
        extension, rows = self.lifecycle()
        with mock.patch.object(base, "api", side_effect=[(403, {"errors": []}), (200, {"data": {}})]) as request:
            with self.assertRaisesRegex(base.FixtureError, "acl_failover_service_revoked_on_survivors"):
                extension._revoked_on_all("acl_failover_service_revoked_on_survivors", ["a", "b"], extension.service)
        self.assertEqual(request.call_count, 2)
        self.assertIs(rows[-1]["passed"], False)
        with self.assertRaises(base.FixtureError):
            extension._revoked_on_all("acl_failover_service_revoked_on_survivors", [], extension.service)

    def test_composed_source_keeps_secret_redaction_cleanup_and_two_runner_bindings(self):
        source = Path(base.__file__).read_text()
        for marker in ("extension.runtime_secrets()", "extension.clear()", "initial_shared_runner_sha256",
                       "required_checks = REQUIRED_CHECKS | extension.required_checks",
                       'set(observed) == required_checks - {"multihost.complete"}',
                       "extension.after_snapshot(offline)", "extension.after_rejoin(initial)",
                       "extension.after_quorum_recovery(nodes)", "extension.cleanup(final_leader)"):
            self.assertIn(marker, source)
        self.assertNotEqual(acl.AclLifecycle.schema, "heptabao.multihost-ha.v1")
        self.assertTrue(acl.AclLifecycle.runner_path.is_file())


if __name__ == "__main__":
    unittest.main()
