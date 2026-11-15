"""Original executable CLI regressions derived from public KV command contracts."""
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


class KVCommandTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.token = self.root / "token"
        self.token.write_text("synthetic-cli-bearer")
        self.token.chmod(0o600)
        self.base = ["-address=https://localhost:8200", "-ca-cert=unused.crt",
                     "-token-file=" + str(self.token)]

    def run_cli(self, command, responses, env=None, stdin=None):
        out, err = io.StringIO(), io.StringIO()
        with patch.dict(os.environ, env or {}, clear=True), patch.object(kv_cli, "Client") as factory, \
                contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            factory.return_value.request.side_effect = responses
            if stdin is None:
                result = cli.main(["kv"] + command)
            else:
                with patch.object(sys, "stdin", io.TextIOWrapper(io.BytesIO(stdin))):
                    result = cli.main(["kv"] + command)
        return result, out.getvalue(), err.getvalue(), factory

    def mount(self, version="2", path="secret/"):
        return Response(200, {"data": {"path": path, "type": "kv", "options": {"version": version}}})

    def value(self, version=1, data=None):
        return Response(200, {"data": {"data": data or {"value": "synthetic-output"},
                                      "metadata": {"version": version}}})

    def test_product_main_routes_kv_and_field_selects_formatted_json_without_newline(self):
        code, out, err, factory = self.run_cli(["get"] + self.base + ["-mount=secret", "-field=value", "-format=json", "nested/key"],
                                               [self.mount(), self.value()])
        self.assertEqual((code, out, err), (0, '"synthetic-output"', ""))
        self.assertEqual([call.args[:2] for call in factory.return_value.request.call_args_list],
                         [("GET", "/v1/sys/internal/ui/mounts/secret/nested/key"), ("GET", "/v1/secret/data/nested/key")])
        self.assertNotIn("synthetic-cli-bearer", out + err)

    def test_nested_combined_mount_version_and_json_response_are_preserved(self):
        response = self.value(2, {"nested": {"boolean": True}, "list": [1, None]})
        code, out, _, factory = self.run_cli(["get"] + self.base + ["-version=2", "-format=json", "team/kv/nested/key"],
                                            [self.mount(path="team/kv/"), response])
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out), response.body)
        self.assertEqual(factory.return_value.request.call_args.args[:2], ("GET", "/v1/team/kv/data/nested/key?version=2"))

    def test_v1_has_no_data_path_insertion_and_field_reads_v1_data(self):
        code, out, _, factory = self.run_cli(["get"] + self.base + ["-field=value", "secret/key"],
                                            [self.mount("1"), Response(200, {"data": {"value": "v1"}})])
        self.assertEqual((code, out), (0, "v1"))
        self.assertEqual(factory.return_value.request.call_args.args[:2], ("GET", "/v1/secret/key"))

    def test_put_cas_zero_is_explicit_and_v1_input_is_unwrapped(self):
        code, out, _, factory = self.run_cli(["put"] + self.base + ["-cas=0", "-field=version", "secret/key", "value=one"],
                                            [self.mount(), Response(200, {"data": {"version": 1}})])
        self.assertEqual((code, out), (0, "1"))
        self.assertEqual(factory.return_value.request.call_args.args, ("POST", "/v1/secret/data/key", {"data": {"value": "one"}, "options": {"cas": 0}}))
        code, _, _, factory = self.run_cli(["put"] + self.base + ["secret/key", "value=one"], [self.mount("1"), Response(204, {})])
        self.assertEqual(code, 0)
        self.assertEqual(factory.return_value.request.call_args.args[2], {"value": "one"})

    def test_api_cas_rejection_does_not_retry_or_echo_server_payload(self):
        code, out, err, factory = self.run_cli(["put"] + self.base + ["-cas=1", "secret/key", "value=secret-input"],
                                               [self.mount(), Response(400, {"errors": ["private-server-error"]})])
        self.assertEqual(code, 2)
        self.assertEqual(factory.return_value.request.call_count, 2)
        self.assertEqual(out, "")
        for secret in ("secret-input", "private-server-error", "synthetic-cli-bearer"):
            self.assertNotIn(secret, err)
        self.assertEqual(json.loads(err)["http_status"], 400)
        self.assertTrue(json.loads(err)["response_received"])
        self.assertFalse(json.loads(err)["automatic_retry"])

    def test_patch_uses_merge_patch_media_type_and_requested_cas(self):
        code, _, _, factory = self.run_cli(["patch"] + self.base + ["-cas=3", "secret/key", "added=yes"],
                                          [self.mount(), Response(200, {"data": {"version": 4}})])
        self.assertEqual(code, 0)
        call = factory.return_value.request.call_args
        self.assertEqual(call.args, ("PATCH", "/v1/secret/data/key", {"data": {"added": "yes"}, "options": {"cas": 3}}))
        self.assertEqual(call.kwargs["content_type"], "application/merge-patch+json")

    def test_patch_zero_cas_is_omitted_for_default_and_explicit_patch(self):
        for options in (["-cas=0"], ["-method=patch", "-cas=0"]):
            with self.subTest(options=options):
                code, _, _, factory = self.run_cli(["patch"] + self.base + options + ["secret/key", "added=yes"],
                                                  [self.mount(), Response(200, {"data": {"version": 4}})])
                self.assertEqual(code, 0)
                call = factory.return_value.request.call_args
                self.assertEqual(call.args, ("PATCH", "/v1/secret/data/key", {"data": {"added": "yes"}}))
                self.assertEqual(call.kwargs["content_type"], "application/merge-patch+json")

    def test_rw_patch_anchors_read_version_and_never_replays_conflicted_write(self):
        code, _, _, factory = self.run_cli(["patch"] + self.base + ["-method=rw", "-cas=999", "secret/key", "added=yes"],
                                          [self.mount(), self.value(8, {"kept": "before"}), Response(400, {})])
        self.assertEqual(code, 2)
        self.assertEqual(factory.return_value.request.call_count, 3)
        self.assertEqual(factory.return_value.request.call_args.args,
                         ("POST", "/v1/secret/data/key", {"data": {"kept": "before", "added": "yes"}, "options": {"cas": 8}}))

    def test_remove_data_only_patch_and_rw_remove_keys(self):
        for method in ("patch", "rw"):
            responses = [self.mount()]
            if method == "rw":
                responses.append(self.value(8, {"drop": "before", "kept": "yes"}))
            responses.append(Response(200, {"data": {"version": 9}}))
            code, _, _, factory = self.run_cli(["patch"] + self.base + ["-method=" + method, "-remove-data=drop", "secret/key"], responses)
            self.assertEqual(code, 0)
            call = factory.return_value.request.call_args
            self.assertEqual(call.args[2]["data"], {"drop": None} if method == "patch" else {"kept": "yes"})

    def test_default_patch_policy_fallback_anchors_cas_but_explicit_patch_never_falls_back(self):
        code, _, _, factory = self.run_cli(["patch"] + self.base + ["-cas=999", "secret/key", "added=yes"],
                                          [self.mount(), Response(403, {}), self.value(8), Response(200, {"data": {"version": 9}})])
        self.assertEqual(code, 0)
        self.assertEqual(factory.return_value.request.call_count, 4)
        self.assertEqual(factory.return_value.request.call_args.args[2]["options"], {"cas": 8})
        for options, failure in ((["-method=patch"], Response(403, {})), ([], Response(500, {})), ([], BaoError("transport_outcome_unknown"))):
            code, _, _, factory = self.run_cli(["patch"] + self.base + options + ["secret/key", "added=yes"], [self.mount(), failure])
            self.assertEqual(code, 2)
            self.assertEqual(factory.return_value.request.call_count, 2)

    def test_rw_failed_read_cannot_enter_write(self):
        code, _, _, factory = self.run_cli(["patch"] + self.base + ["-method=rw", "secret/key", "added=yes"],
                                          [self.mount(), Response(404, {})])
        self.assertEqual(code, 2)
        self.assertEqual(factory.return_value.request.call_count, 2)
        self.assertTrue(all(call.args[0] == "GET" for call in factory.return_value.request.call_args_list))

    def test_rollback_writes_historical_data_with_latest_version_cas(self):
        code, _, _, factory = self.run_cli(["rollback"] + self.base + ["-version=2", "secret/key"],
                                          [self.mount(), self.value(7), self.value(2, {"restored": "old"}), Response(200, {"data": {"version": 8}})])
        self.assertEqual(code, 0)
        self.assertEqual(factory.return_value.request.call_args.args,
                         ("POST", "/v1/secret/data/key", {"data": {"restored": "old"}, "options": {"cas": 7}}))

    def test_delete_latest_selected_undelete_destroy_route_separately(self):
        cases = [("delete", [], "DELETE", "/v1/secret/data/key", None),
                 ("delete", ["-versions=1,2", "-versions=3"], "POST", "/v1/secret/delete/key", {"versions": [1, 2, 3]}),
                 ("undelete", ["-versions=2"], "POST", "/v1/secret/undelete/key", {"versions": [2]}),
                 ("destroy", ["-versions=1"], "POST", "/v1/secret/destroy/key", {"versions": [1]})]
        for command, options, method, path, body in cases:
            with self.subTest(command=command, options=options):
                code, _, _, factory = self.run_cli([command] + self.base + options + ["secret/key"], [self.mount(), Response(204, {})])
                self.assertEqual(code, 0)
                self.assertEqual(factory.return_value.request.call_args.args, (method, path, body))

    def test_listing_root_folder_and_json_select_keys_only(self):
        for key in ("", "nested/"):
            with self.subTest(key=key):
                code, out, _, factory = self.run_cli(["list"] + self.base + ["-mount=secret", "-format=json", key],
                                                    [self.mount(), Response(200, {"data": {"keys": ["a", "folder/"]}})])
                self.assertEqual(code, 0)
                self.assertEqual(json.loads(out), ["a", "folder/"])
                self.assertEqual(factory.return_value.request.call_args.args[1], "/v1/secret/metadata/" + key.rstrip("/"))

    def test_metadata_mutations_preserve_omitted_settings_and_bool_false(self):
        code, _, _, factory = self.run_cli(["metadata", "put"] + self.base + ["-max-versions=4", "-cas-required=false", "-custom-metadata=owner=a", "secret/key"], [self.mount(), Response(204, {})])
        self.assertEqual(code, 0)
        self.assertEqual(factory.return_value.request.call_args.args, ("POST", "/v1/secret/metadata/key",
                         {"max_versions": 4, "cas_required": False, "custom_metadata": {"owner": "a"}}))
        code, _, _, factory = self.run_cli(["metadata", "put"] + self.base + ["-cas-required", "secret/key"], [self.mount(), Response(204, {})])
        self.assertEqual(code, 0)
        self.assertEqual(factory.return_value.request.call_args.args[2], {"cas_required": True})
        code, _, _, factory = self.run_cli(["metadata", "put"] + self.base + ["secret/key"], [self.mount(), Response(204, {})])
        self.assertEqual(code, 0)
        self.assertEqual(factory.return_value.request.call_args.args[2], {})

    def test_metadata_get_delete_and_table_versions(self):
        code, out, _, factory = self.run_cli(["metadata", "get"] + self.base + ["secret/key"],
                                            [self.mount(), Response(200, {"data": {"current_version": 1, "versions": {"1": {"destroyed": False}}}})])
        self.assertEqual(code, 0)
        self.assertIn("Version 1", out)
        self.assertIn("false", out)
        code, _, _, factory = self.run_cli(["metadata", "delete"] + self.base + ["secret/key"], [self.mount(), Response(204, {})])
        self.assertEqual(code, 0)
        self.assertEqual(factory.return_value.request.call_args.args[:2], ("DELETE", "/v1/secret/metadata/key"))

    def test_metadata_delete_rejects_format_flag_locally_and_ignores_format_environment(self):
        code, out, _, factory = self.run_cli(["metadata", "delete"] + self.base + ["-format=json", "secret/key"], [])
        self.assertEqual((code, out), (1, ""))
        factory.assert_not_called()
        code, out, _, factory = self.run_cli(["metadata", "delete"] + self.base + ["secret/key"], [self.mount(), Response(204, {})], {"BAO_FORMAT": "json"})
        self.assertEqual((code, out), (0, "Success!\n"))

    def test_file_and_stdin_structures_and_exact_text_input(self):
        data = self.root / "data.json"
        data.write_text('{"typed":true,"nested":{"n":1}}')
        data.chmod(0o600)
        cases = [(["@" + str(data)], None, {"typed": True, "nested": {"n": 1}}),
                 (["-"], b'{"number":2}', {"number": 2}),
                 (["value=-"], b'line\n', {"value": "line\n"}),
                 (["value=@" + str(data)], None, {"value": data.read_text()})]
        for inputs, stdin, expected in cases:
            with self.subTest(inputs=inputs):
                code, _, _, factory = self.run_cli(["put"] + self.base + ["secret/key"] + inputs, [self.mount(), Response(204, {})], stdin=stdin)
                self.assertEqual(code, 0)
                self.assertEqual(factory.return_value.request.call_args.args[2], {"data": expected})

    def test_untrusted_file_input_refused_before_any_mount_request(self):
        data = self.root / "data.json"
        data.write_text('{"sentinel":"private"}')
        data.chmod(0o644)
        for inputs in (["@" + str(data)], ["value=@" + str(data)]):
            code, out, err, factory = self.run_cli(["put"] + self.base + ["secret/key"] + inputs, [])
            self.assertEqual(code, 1)
            factory.assert_not_called()
            self.assertEqual(out, "")
            self.assertNotIn("private", err.replace("private_file_open_failed", ""))

    def test_env_bao_precedence_flags_namespace_override_and_duration(self):
        env = {"BAO_ADDR": "https://bao:8200", "VAULT_ADDR": "https://vault:8200", "BAO_CACERT": "bao.crt", "VAULT_CACERT": "vault.crt",
               "BAO_TOKEN": "bao-token", "VAULT_TOKEN": "vault-token", "BAO_NAMESPACE": "team/", "BAO_CLIENT_TIMEOUT": "350ms", "BAO_FORMAT": "json"}
        code, out, _, factory = self.run_cli(["get", "-namespace=", "secret/key"], [self.mount(), self.value()], env)
        self.assertEqual(code, 0)
        self.assertIsInstance(json.loads(out), dict)
        self.assertEqual(factory.call_args.args[:4], ("https://bao:8200", "bao.crt", "bao-token", ""))
        self.assertAlmostEqual(factory.call_args.args[4], .35)
        code, _, _, factory = self.run_cli(["get"] + self.base + ["secret/key"], [self.mount(), self.value()], env)
        self.assertEqual(code, 0)
        self.assertEqual(factory.call_args.args[0:3], ("https://localhost:8200", "unused.crt", "synthetic-cli-bearer"))

    def test_explicit_empty_token_file_cannot_fall_back_to_environment_bearer(self):
        code, out, err, factory = self.run_cli(["get"] + self.base + ["-token-file=", "secret/key"], [], {"BAO_TOKEN": "synthetic-other-bearer"})
        self.assertEqual((code, out), (1, ""))
        factory.assert_not_called()
        self.assertNotIn("synthetic-other-bearer", err)

    def test_legacy_vault_environment_and_token_path_are_owner_checked(self):
        env = {"VAULT_ADDR": "https://vault:8200", "VAULT_CACERT": "ca.crt", "VAULT_TOKEN_PATH": str(self.token)}
        code, _, _, factory = self.run_cli(["get", "secret/key"], [self.mount(), self.value()], env)
        self.assertEqual(code, 0)
        self.assertEqual(factory.call_args.args[2], "synthetic-cli-bearer")
        self.token.chmod(0o644)
        code, _, _, factory = self.run_cli(["get", "secret/key"], [], env)
        self.assertEqual(code, 1)
        factory.assert_not_called()

    def test_invalid_options_paths_inputs_fail_before_client_and_redact_arguments(self):
        cases = [["get", "-version=-1", "secret/key"], ["put", "-cas=-2", "secret/key", "value=private-input"],
                 ["get", "secret/../key"], ["get", "secret//key"], ["get", "-namespace=team//", "secret/key"],
                 ["get", "-format=invalid", "secret/key"], ["get", "-token=private-token", "secret/key"],
                 ["destroy", "secret/key"], ["delete", "-versions=0", "secret/key"], ["rollback", "secret/key"],
                 ["put", "secret/key", "not-an-assignment"], ["get", "-timeout=nan", "secret/key"],
                 ["get", "-timeout=61s", "secret/key"]]
        for values in cases:
            with self.subTest(values=values):
                command = [values[0]] + self.base + values[1:]
                code, out, err, factory = self.run_cli(command, [])
                self.assertEqual(code, 1)
                factory.assert_not_called()
                self.assertEqual(out, "")
                self.assertNotIn("private-input", err)
                self.assertNotIn("private-token", err)

    def test_discovery_failure_or_foreign_path_cannot_dispatch_data_request(self):
        cases = [Response(403, {"errors": ["private-mount-message"]}), self.mount(path="another/"), self.mount(version="3"),
                 Response(200, {"data": {"type": "transit", "path": "secret/"}})]
        for response in cases:
            code, out, err, factory = self.run_cli(["get"] + self.base + ["secret/key"], [response])
            self.assertEqual(code, 2)
            self.assertEqual(factory.return_value.request.call_count, 1)
            self.assertEqual(out, "")
            self.assertNotIn("private-mount-message", err)

    def test_v2_only_command_cannot_write_to_v1(self):
        for command in (["patch", "secret/key", "value=x"], ["undelete", "-versions=1", "secret/key"],
                        ["put", "-cas=0", "secret/key", "value=x"]):
            code, _, _, factory = self.run_cli([command[0]] + self.base + command[1:], [self.mount("1")])
            self.assertEqual(code, 2)
            self.assertEqual(factory.return_value.request.call_count, 1)

    def test_transport_unknown_write_keeps_one_attempt_and_fixed_error(self):
        code, out, err, factory = self.run_cli(["put"] + self.base + ["secret/key", "value=private-input"],
                                              [self.mount(), BaoError("transport_outcome_unknown")])
        self.assertEqual(code, 2)
        self.assertEqual(factory.return_value.request.call_count, 2)
        self.assertEqual(out, "")
        self.assertEqual(json.loads(err)["code"], "transport_outcome_unknown")
        self.assertNotIn("private-input", err)

    def test_tls_configuration_failure_is_remote_exit_and_never_requests(self):
        with patch.object(kv_cli, "Client", side_effect=BaoError("ca_configuration_invalid")) as factory, \
                contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(cli.main(["kv", "get"] + self.base + ["secret/key"]), 2)
        self.assertEqual(factory.call_count, 1)

    def test_deleted_or_destroyed_v2_get_exposes_only_returned_metadata_and_field_stays_remote_error(self):
        for destroyed in (False, True):
            body = {"data": {"data": None, "metadata": {"version": 1, "destroyed": destroyed}}}
            for flags in ([], ["-format=json"]):
                code, out, _, factory = self.run_cli(["get"] + self.base + flags + ["secret/key"], [self.mount(), Response(404, body)])
                self.assertEqual(code, 0)
                self.assertNotIn("synthetic-cli-bearer", out)
                if flags:
                    self.assertEqual(json.loads(out), body)
                else:
                    self.assertIn("Metadata", out)
                    self.assertNotIn("Data\n", out)
            code, out, _, factory = self.run_cli(["get"] + self.base + ["-field=value", "secret/key"], [self.mount(), Response(404, body)])
            self.assertEqual((code, out), (2, ""))
        for body in ({}, {"data": {"data": {"v": "unexpected"}, "metadata": {"version": 1, "destroyed": False}}}):
            code, out, _, _ = self.run_cli(["get"] + self.base + ["secret/key"], [self.mount(), Response(404, body)])
            self.assertEqual((code, out), (2, ""))

    def test_missing_field_has_local_exit_without_implicit_retry(self):
        code, out, err, factory = self.run_cli(["get"] + self.base + ["-field=missing", "secret/key"], [self.mount(), self.value()])
        self.assertEqual((code, out), (1, ""))
        self.assertEqual(factory.return_value.request.call_count, 2)
        self.assertEqual(json.loads(err)["code"], "field_not_found")

    def test_yaml_quotes_taglike_and_multiline_secrets_without_type_confusion(self):
        response = self.value(data={"yes": "true", "tag": "!!python/object:never", "multi": "a\nb", "typed": True})
        code, out, err, _ = self.run_cli(["get"] + self.base + ["-format=yaml", "secret/key"], [self.mount(), response])
        self.assertEqual(code, 0)
        self.assertEqual(err, "")
        self.assertIn('"yes": "true"', out)
        self.assertIn('"multi": "a\\nb"', out)
        self.assertIn('"typed": true', out)
        self.assertNotIn("synthetic-cli-bearer", out)

    def test_help_is_local_and_requires_no_environment_credentials(self):
        code, out, err, factory = self.run_cli(["get", "--help"], [])
        self.assertEqual(code, 0)
        self.assertIn("-mount", out)
        self.assertEqual(err, "")
        factory.assert_not_called()


if __name__ == "__main__":
    unittest.main()
