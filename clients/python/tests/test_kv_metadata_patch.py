"""Metadata CLI merge-patch contracts from public API and pinned 2.7 help.

These tests use the real CLI dispatcher and an in-memory transport boundary.
They are not native/OpenBao runtime compatibility evidence.
"""
import contextlib
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from heptabao import cli, kv_cli
from heptabao.transport import BaoError, Response


class MetadataPatchTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.token = Path(self.tmp.name) / "token"
        self.token.write_text("synthetic-metadata-bearer")
        self.token.chmod(0o600)
        self.base = ["-address=https://localhost:8200", "-ca-cert=unused.crt", "-token-file=" + str(self.token)]

    def run_cli(self, flags, replies, environment=None):
        out, err = io.StringIO(), io.StringIO()
        with patch.dict(os.environ, environment or {}, clear=True), patch.object(kv_cli, "Client") as factory, \
                contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            factory.return_value.request.side_effect = replies
            result = cli.main(["kv", "metadata", "patch"] + self.base + flags)
        return result, out.getvalue(), err.getvalue(), factory

    @staticmethod
    def mount(path="secret/", version="2"):
        return Response(200, {"data": {"type": "kv", "path": path, "options": {"version": version}}})

    def test_actual_dispatch_sends_only_the_typed_delta_once(self):
        code, out, err, factory = self.run_cli(
            ["-mount=secret", "-format=json", "-max-versions=0", "-cas-required=false",
             "-delete-version-after=0s", "-custom-metadata=owner=next", "-custom-metadata=empty=", "nested/key"],
            [self.mount(), Response(204, {})])
        self.assertEqual((code, json.loads(out), err), (0, {}, ""))
        calls = factory.return_value.request.call_args_list
        self.assertEqual([call.args[:2] for call in calls], [
            ("GET", "/v1/sys/internal/ui/mounts/secret/nested/key"),
            ("PATCH", "/v1/secret/metadata/nested/key")])
        self.assertEqual(calls[-1].args[2], {"max_versions": 0, "cas_required": False,
                                          "delete_version_after": "0s", "custom_metadata": {"owner": "next", "empty": ""}})
        self.assertEqual(calls[-1].kwargs, {"content_type": "application/merge-patch+json"})
        self.assertNotIn("synthetic-metadata-bearer", out + err)

    def test_removal_is_null_not_a_string_and_does_not_read_existing_metadata(self):
        code, _, err, factory = self.run_cli(
            ["-custom-metadata=added=next", "-remove-custom-metadata=owner", "-remove-custom-metadata=obsolete", "secret/key"],
            [self.mount(), Response(204, {})])
        self.assertEqual((code, err), (0, ""))
        self.assertEqual(factory.return_value.request.call_count, 2)
        self.assertEqual(factory.return_value.request.call_args.args,
                         ("PATCH", "/v1/secret/metadata/key", {"custom_metadata": {"added": "next", "owner": None, "obsolete": None}}))

    def test_omitted_configuration_is_not_reset_and_bare_boolean_is_true(self):
        for flags, expected in (([], {}), (["-cas-required"], {"cas_required": True})):
            with self.subTest(flags=flags):
                code, _, _, factory = self.run_cli(flags + ["secret/key"], [self.mount(), Response(204, {})])
                self.assertEqual(code, 0)
                self.assertEqual(factory.return_value.request.call_args.args[2], expected)

    def test_nested_mount_and_namespace_use_the_existing_client_boundary(self):
        code, _, _, factory = self.run_cli(["-namespace=team/sub", "-custom-metadata=owner=next", "team/kv/nested/key"],
                                           [self.mount("team/kv/"), Response(204, {})])
        self.assertEqual(code, 0)
        self.assertEqual(factory.call_args.args[3], "team/sub")
        self.assertEqual(factory.return_value.request.call_args.args[:2], ("PATCH", "/v1/team/kv/metadata/nested/key"))

    def test_invalid_input_fails_before_credentials_or_any_transport(self):
        for flags in (["-custom-metadata=private-invalid"], ["-custom-metadata==private-value"],
                      ["-remove-custom-metadata="], ["-max-versions=-1"], ["-field=owner"], ["-namespace=team//sub"]):
            with self.subTest(flags=flags):
                code, out, err, factory = self.run_cli(flags + ["secret/key"], [])
                self.assertEqual(code, 1)
                self.assertEqual(out, "")
                factory.assert_not_called()
                self.assertNotIn("private-value", err)
                self.assertNotIn("private-invalid", err)
                self.assertNotIn("synthetic-metadata-bearer", err)

    def test_private_credential_guard_still_rejects_unsafe_token_file(self):
        self.token.chmod(0o644)
        code, out, err, factory = self.run_cli(["-custom-metadata=owner=next", "secret/key"], [])
        self.assertEqual(code, 1)
        self.assertEqual(out, "")
        self.assertEqual(json.loads(err)["code"], "file_requires_owner_only_regular_file")
        factory.assert_not_called()

    def test_api_refusals_are_not_read_write_fallbacks_and_never_echo_inputs(self):
        for status in (400, 403, 404, 500, 503):
            with self.subTest(status=status):
                code, out, err, factory = self.run_cli(["-custom-metadata=owner=private-input", "secret/key"],
                    [self.mount(), Response(status, {"errors": ["private-server-detail"]})])
                self.assertEqual((code, out), (2, ""))
                self.assertEqual(factory.return_value.request.call_count, 2)
                self.assertEqual(factory.return_value.request.call_args.args[0], "PATCH")
                diagnostic = json.loads(err)
                self.assertEqual(diagnostic["http_status"], status)
                self.assertFalse(diagnostic["automatic_retry"])
                for private in ("private-input", "private-server-detail", "synthetic-metadata-bearer"):
                    self.assertNotIn(private, err)

    def test_unknown_mutation_outcome_stays_single_attempt(self):
        code, out, err, factory = self.run_cli(["-custom-metadata=owner=private-input", "secret/key"],
            [self.mount(), BaoError("transport_outcome_unknown")])
        self.assertEqual((code, out), (2, ""))
        self.assertEqual(factory.return_value.request.call_count, 2)
        diagnostic = json.loads(err)
        self.assertEqual(diagnostic["code"], "transport_outcome_unknown")
        self.assertFalse(diagnostic["response_received"])
        self.assertFalse(diagnostic["automatic_retry"])
        self.assertNotIn("private-input", err)

    def test_v1_discovery_refuses_without_a_metadata_mutation(self):
        code, out, err, factory = self.run_cli(["-custom-metadata=owner=next", "secret/key"], [self.mount(version="1")])
        self.assertEqual((code, out), (2, ""))
        self.assertEqual(json.loads(err)["code"], "kv_v2_required")
        self.assertEqual(factory.return_value.request.call_count, 1)


if __name__ == "__main__":
    unittest.main()
