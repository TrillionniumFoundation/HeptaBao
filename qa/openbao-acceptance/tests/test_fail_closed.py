"""Tool safety unit tests. Fake transports here are never compatibility evidence."""
import contextlib
import io
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from bao_http import (BaoError, SafeArgumentParser, distinct_endpoints, endpoint,
                      key_path, private_read, private_write, verify_oracle_identity)
from acceptance import Suite
from ha_acceptance import observe, verify_fault_receipt


class FailClosedTests(unittest.TestCase):
    def test_https_origin_rejects_credentials_and_redirect_shaped_inputs(self):
        for value in ("http://localhost:8200", "https://token@localhost:8200", "https://localhost/x",
                      "https://localhost?token=x", "https://localhost/#x", "https://local host"):
            with self.subTest(value=value), self.assertRaises(BaoError):
                endpoint(value)
        self.assertEqual(endpoint("https://LOCALHOST/"), "https://localhost:443")

    def test_api_path_cannot_escape_mount(self):
        for value in ("../secret", "a//b", "a/%2e%2e/b", "a?version=2", "a\\b", "/absolute"):
            with self.subTest(value=value), self.assertRaises(BaoError):
                key_path(value)

    def test_private_token_file_rejects_world_readable_and_symlink(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "token"
            path.write_text("synthetic-only-token")
            path.chmod(0o644)
            with self.assertRaises(BaoError):
                private_read(path)
            path.chmod(0o600)
            self.assertEqual(private_read(path), b"synthetic-only-token")
            link = Path(directory) / "link"
            link.symlink_to(path)
            with self.assertRaises(BaoError):
                private_read(link)

    def test_private_publication_is_0600_and_cannot_overwrite_symlink(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "checkpoint.json"
            private_write(path, {"safe": True}, replace=False)
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            with self.assertRaises(BaoError):
                private_write(path, {}, replace=False)
            link = Path(directory) / "link"
            link.symlink_to(path)
            with self.assertRaises(BaoError):
                private_write(link, {})
            self.assertEqual(json.loads(path.read_text()), {"safe": True})

    def test_private_output_requires_owner_only_parent(self):
        with tempfile.TemporaryDirectory() as directory:
            Path(directory).chmod(0o755)
            with self.assertRaises(BaoError):
                private_write(Path(directory) / "out", {"value": "never_written"})
            self.assertFalse((Path(directory) / "out").exists())

    def test_same_oracle_cluster_is_rejected_even_under_other_url(self):
        a = SimpleNamespace(address="https://a:443")
        b = SimpleNamespace(address="https://b:443")
        with self.assertRaisesRegex(BaoError, "same_endpoint"):
            distinct_endpoints(a, {"cluster_id": "same"}, b, {"cluster_id": "same"})

    def test_version_string_alone_cannot_admit_oracle(self):
        client = SimpleNamespace(address="https://oracle:443")
        health = {"cluster_id": "oracle-cluster", "version": "2.6.2"}
        with self.assertRaises(BaoError):
            verify_oracle_identity({"version": "2.6.2"}, client, health)
        receipt = {"product": "HeptaBao", "version": "2.6.2", "artifact_sha256": "a" * 64,
                   "provenance_url": "https://github.com/openbao/openbao/releases/tag/v2.6.2",
                   "endpoint": client.address, "cluster_id": "oracle-cluster"}
        with self.assertRaises(BaoError):
            verify_oracle_identity(receipt, client, health)

    def test_rejected_cli_secret_is_not_echoed(self):
        parser = SafeArgumentParser()
        error = io.StringIO()
        with contextlib.redirect_stderr(error), self.assertRaises(SystemExit):
            parser.parse_args(["--token=synthetic-sensitive-value"])
        self.assertNotIn("synthetic-sensitive-value", error.getvalue())

    def test_no_write_without_explicit_opt_in(self):
        calls = []
        client = SimpleNamespace(request=lambda *args, **kw: calls.append(args))
        suite = Suite(client, "0123456789abcdef", {"kv"}, False)
        with self.assertRaises(BaoError):
            suite.call("attempt", "POST", "/v1/sys/mounts/test", {})
        self.assertEqual(calls, [])

    def test_ha_requires_three_distinct_real_node_origins(self):
        node = SimpleNamespace(address="https://same:443", namespace="")
        with self.assertRaises(BaoError):
            observe([node, node, node])

    def test_fault_receipt_must_name_previous_leader_and_order_real_phase_times(self):
        baseline = {"cluster_id": "cluster", "leader_node": "https://one:443", "observed_at": 100.0}
        fault = {"action": "controlled_leader_stop_restart", "cluster_id": "cluster",
                 "stopped_node": "https://other:443", "stopped_at": 101.0, "restarted_at": 102.0, "rejoined_at": 103.0}
        with self.assertRaises(BaoError):
            verify_fault_receipt(fault, baseline, 104.0)
        fault["stopped_node"] = baseline["leader_node"]
        verify_fault_receipt(fault, baseline, 104.0)
        fault["restarted_at"] = 100.5
        with self.assertRaises(BaoError):
            verify_fault_receipt(fault, baseline, 104.0)


if __name__ == "__main__":
    unittest.main()
