"""Completeness, real dispatch, refusal and effective budget contracts.

The original in-memory protocol here is not a native/OpenBao compatibility
trace. It deliberately injects faults into each new fixed predicate family.
"""
import contextlib
from copy import deepcopy
from email.message import Message
import importlib.util
import io
import json
import os
from pathlib import Path
import ssl
import subprocess
import sys
import tempfile
import types
import unittest
import urllib.error
from unittest.mock import patch

QA = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(QA))
sys.path.insert(0, str(QA.parents[1] / "clients/python"))
import kv_metadata_patch_cli_live as profile
import run_kv_metadata_patch_cli_bound as operator
from heptabao import cli, kv_cli
from heptabao.transport import BaoError, Response


class State:
    def __init__(self, fault=None):
        self.fault = fault
        self.values = {}
        self.metadata = {}
        self.token_modes = {"synthetic-root-token": "root"}
        self.commands = []
        self.requests = []

    def request(self, token, method, path, body=None, **options):
        self.requests.append((token, method, path, deepcopy(body), options))
        key = path.rsplit("/", 1)[-1]
        if path.startswith("/v1/sys/internal/ui/mounts/"):
            return Response(200, {"data": {"type": "kv", "path": "cli-metadata/", "options": {"version": "2"}}})
        if path.startswith("/v1/sys/policies/"):
            return Response(204, {})
        if path == "/v1/auth/token/create":
            mode = "patch" if body["policies"][0].endswith("-patch") else "update"
            value = "synthetic-scoped-" + body["policies"][0]
            self.token_modes[value] = mode
            return Response(200, {"auth": {"client_token": value}})
        if "/data/" in path:
            if method == "POST":
                self.values[key] = deepcopy(body["data"])
                self.metadata[key] = {"current_version": 1, "oldest_version": 0, "custom_metadata": {},
                    "versions": {"1": {"destroyed": False, "deletion_time": "", "created_time": "2026-01-01T00:00:00Z"}}}
                return Response(200, {"data": {"version": 1}})
            return Response(200, {"data": {"data": deepcopy(self.values[key]), "metadata": {"version": 1}}})
        if method == "POST":
            self.metadata[key]["custom_metadata"] = deepcopy(body["custom_metadata"])
            return Response(204, {})
        if method == "GET":
            if key not in self.metadata:
                return Response(404, {})
            value = deepcopy(self.metadata[key])
            if self.fault == "bool-version":
                value["current_version"] = True
            return Response(200, {"data": value})
        if method != "PATCH" or options.get("content_type") != "application/merge-patch+json":
            return Response(415, {})
        if self.token_modes[token] == "update" and self.fault != "update-allowed":
            return Response(403, {"errors": ["synthetic-private-server-detail"]})
        if key not in self.metadata:
            if self.fault != "missing-created":
                return Response(404, {})
            self.metadata[key] = {"current_version": 1, "oldest_version": 0, "versions": {"1": {}}, "custom_metadata": {}}
        if self.fault == "replace-unmentioned":
            self.metadata[key]["custom_metadata"] = {}
        for name, value in body.get("custom_metadata", {}).items():
            if value is None and self.fault != "null-string":
                self.metadata[key]["custom_metadata"].pop(name, None)
            else:
                self.metadata[key]["custom_metadata"][name] = "null" if value is None else value
        if self.fault == "history-changed":
            self.metadata[key]["versions"]["1"]["destroyed"] = True
        return Response(204, {})

    def client_class(self):
        state = self
        class Client:
            def __init__(self, address, ca, token, namespace="", timeout=2, **_):
                self.token = token
                if timeout != 2:
                    raise ValueError("test_effective_http_budget")
            def request(self, method, path, body=None, *, token=None, **options):
                return state.request(self.token if token is None else token, method, path, body, **options)
        return Client

    def execute(self, arguments, **options):
        self.commands.append((list(arguments), options))
        start = arguments.index("metadata")
        out, err = io.StringIO(), io.StringIO()
        # This intentionally executes the real Python dispatcher even for the
        # simulated bao interface; actual pinned bao execution is a live scope.
        with patch.dict(os.environ, options["env"], clear=True), patch.object(kv_cli, "Client", self.client_class()), \
                contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = cli.main(["kv"] + arguments[start:])
        stderr = err.getvalue().encode()
        if self.fault == "leak-output":
            stderr += b"synthetic-root-token"
        return subprocess.CompletedProcess(arguments, code, out.getvalue().encode(), stderr)


class ScenarioContracts(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name); self.root.chmod(0o700)

    def run_interface(self, kind="python", fault=None):
        fixture = self.root / (kind + "-" + (fault or "complete")); fixture.mkdir(mode=0o700)
        instance = {"root": str(fixture), "address": "https://localhost:8200", "ca_file": "unused.crt", "token": "synthetic-root-token"}
        state, rows = State(fault), []
        with patch.object(profile, "Client", state.client_class()), patch.object(profile.subprocess, "run", state.execute):
            profile.run_interface(kind, instance, QA.parents[1], Path("/pinned270/bao"), rows)
        return state, rows

    def test_real_python_dispatch_executes_all_16_fixed_cases_and_typed_null(self):
        state, rows = self.run_interface()
        self.assertTrue(profile.interface_complete(rows))
        self.assertEqual(len(state.commands), 5)
        mutations = [request for request in state.requests if request[1] == "PATCH"]
        self.assertEqual(len(mutations), 5)
        self.assertTrue(mutations[1][3]["custom_metadata"]["owner"] is None)
        self.assertTrue(all(request[4]["content_type"] == "application/merge-patch+json" for request in mutations))
        self.assertFalse(any(request[1] == "POST" and request[0] != "synthetic-root-token" for request in state.requests))

    def test_all_four_interfaces_use_the_same_ordered_64_checks(self):
        interfaces = {}
        for name in profile.INTERFACES:
            kind = name.rsplit("_", 1)[1]
            fixture = self.root / name; fixture.mkdir(mode=0o700)
            instance = {"root": str(fixture), "address": "https://localhost:8200", "ca_file": "unused.crt", "token": "synthetic-root-token"}
            state, rows = State(), []
            with patch.object(profile, "Client", state.client_class()), patch.object(profile.subprocess, "run", state.execute):
                profile.run_interface(kind, instance, QA.parents[1], Path("/pinned270/bao"), rows)
            interfaces[name] = rows
            for arguments, options in state.commands:
                self.assertEqual(options["timeout"], 10)
                self.assertEqual(options["stdout"], subprocess.PIPE)
                self.assertEqual(options["stderr"], subprocess.PIPE)
                self.assertFalse(options["check"])
                self.assertEqual(options["env"]["BAO_CLIENT_TIMEOUT"], "2s")
                self.assertEqual(options["env"]["VAULT_CLIENT_TIMEOUT"], "2s")
                self.assertEqual(options["env"]["BAO_MAX_RETRIES"], "0")
                self.assertEqual(options["env"]["BAO_DISABLE_REDIRECTS"], "true")
                self.assertNotIn("synthetic-root-token", arguments)
                self.assertEqual(arguments[0], sys.executable if kind == "python" else "/pinned270/bao")
        self.assertTrue(profile.all_interfaces_complete(interfaces))
        self.assertEqual(sum(map(len, interfaces.values())), 64)

    def test_semantic_faults_cannot_produce_a_complete_trace(self):
        for fault in ("replace-unmentioned", "null-string", "history-changed", "update-allowed", "missing-created", "leak-output", "bool-version"):
            with self.subTest(fault=fault), self.assertRaises(profile.ScenarioFailure):
                self.run_interface(fault=fault)

    def test_completeness_rejects_prefix_duplicate_order_failed_and_non_boolean(self):
        rows = [{"case": name, "passed": True} for name in profile.REQUIRED_INTERFACE_CASES]
        broken = [rows[:-1], rows + [rows[-1]], list(reversed(rows)), deepcopy(rows), deepcopy(rows), deepcopy(rows)]
        broken[3][2]["passed"] = False
        broken[4][2]["passed"] = 1
        broken[5][2]["response_body"] = {}
        self.assertTrue(profile.interface_complete(rows))
        for value in broken:
            self.assertFalse(profile.interface_complete(value))
        interfaces = {name: deepcopy(rows) for name in profile.INTERFACES}
        self.assertTrue(profile.all_interfaces_complete(interfaces))
        interfaces.pop("oracle_bao")
        self.assertFalse(profile.all_interfaces_complete(interfaces))
        interfaces["unknown_bao"] = rows
        self.assertFalse(profile.all_interfaces_complete(interfaces))

    def test_duplicate_execution_does_not_overwrite_existing_private_token_inputs(self):
        self.run_interface()
        path = self.root / "python-complete/python-metadata-root.token"
        self.assertTrue(profile.private_read(path) == b"synthetic-root-token")
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        with self.assertRaises(BaoError):
            profile.private_write_text(path, "new", replace=False)
        self.assertTrue(profile.private_read(path) == b"synthetic-root-token")


class BudgetContracts(unittest.TestCase):
    def make_client(self, opener):
        def initialize(client, address, ca, token, namespace="", timeout=15, **_):
            client.address, client._token, client.namespace, client.timeout, client._opener = address, token, namespace, timeout, opener
        with patch.object(profile.TransportClient, "__init__", initialize):
            return profile.Client("https://localhost:8200", "unused", "synthetic-budget-token")

    def test_actual_shared_transport_open_receives_exact_two_second_budget(self):
        observed = []
        class Reply:
            code = 204
            headers = Message()
            def __enter__(self): return self
            def __exit__(self, *_): return None
            def read(self, _): return b""
        def open_request(request, *, timeout):
            observed.append(timeout)
            return Reply()
        client = self.make_client(types.SimpleNamespace(open=open_request))
        self.assertEqual(client.request("PATCH", "/v1/cli-metadata/metadata/key", {"custom_metadata": {"owner": None}},
                                        content_type="application/merge-patch+json").status, 204)
        self.assertEqual(observed, [2])
        with self.assertRaises(ValueError):
            profile.Client("https://localhost:8200", "unused", "synthetic-budget-token", timeout=15)

    def test_tls_rejection_is_not_hidden_by_the_official_readiness_poll(self):
        error = ssl.SSLCertVerificationError(1, "synthetic TLS rejection")
        def fail(*_, **__): raise urllib.error.URLError(error)
        client = self.make_client(types.SimpleNamespace(open=fail))
        with self.assertRaises(urllib.error.URLError) as observed:
            client.request("GET", "/v1/sys/health")
        self.assertIs(observed.exception.reason, error)

    def test_real_official_launcher_post_unseal_default_client_is_also_two_seconds(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); root.chmod(0o700)
            observed, constructed = [], []
            health_reads = []
            class Reply:
                headers = Message()
                def __init__(self, code, body): self.code, self.body = code, body
                def __enter__(self): return self
                def __exit__(self, *_): return None
                def read(self, _): return json.dumps(self.body).encode()
            def open_request(request, *, timeout):
                observed.append(timeout)
                if request.full_url.endswith("/sys/init"):
                    return Reply(200, {"root_token": "synthetic-oracle-root", "keys_base64": ["synthetic-oracle-key"]})
                if request.full_url.endswith("/sys/unseal"):
                    return Reply(200, {})
                health_reads.append(True)
                return Reply(501, {}) if len(health_reads) == 1 else Reply(200, {
                    "initialized": True, "sealed": False, "version": "2.7.0", "cluster_id": "synthetic-public-cluster"})
            def initialize(client, address, ca, token, namespace="", timeout=15, **_):
                constructed.append(timeout)
                client.address, client._token, client.namespace, client.timeout = address, token, namespace, timeout
                client._opener = types.SimpleNamespace(open=open_request)
            with patch.dict(os.environ, {"HB_ORACLE_WORK_ROOT": str(root)}, clear=False), \
                    patch.object(profile.launcher, "verify_inputs", return_value=Path("synthetic-pinned-placeholder")), \
                    patch.object(profile.launcher, "certificates"), patch.object(profile.launcher.subprocess, "Popen") as process, \
                    patch.object(profile.TransportClient, "__init__", initialize), patch.object(profile.launcher, "Client", profile.Client):
                process.return_value.poll.return_value = None
                oracle = profile.launcher.start_oracle(32123, version="2.7.0")
                profile.launcher.stop_oracle(oracle)
            self.assertEqual(constructed, [2, 2])
            self.assertEqual(observed, [2, 2, 2, 2])

    def test_native_bridge_is_only_the_original_startup_health_read(self):
        class Base:
            def __init__(self, binary, root):
                self.root, self.address, self.token = root, "https://localhost:8200", ""
        instance = profile.bounded_native_instance(types.SimpleNamespace(Instance=Base), Path("unused"), Path("unused"))
        def unavailable(*_, **__):
            try: raise ConnectionRefusedError("synthetic unavailable")
            except ConnectionRefusedError: raise BaoError("transport_read_failed")
        with patch.object(profile, "Client") as client:
            client.return_value.request.side_effect = unavailable
            with self.assertRaises(ConnectionRefusedError): instance.call("GET", "sys/health")
            with self.assertRaises(BaoError): instance.call("GET", "cli-metadata/metadata/key")
            with self.assertRaises(BaoError): instance.call("POST", "sys/init", {})
            self.assertEqual(client.return_value.request.call_count, 3)

    def test_native_startup_rejects_tls_without_polling_a_second_time(self):
        spec = importlib.util.spec_from_file_location("metadata_contract_smoke", QA.parents[1] / "qa/single-node/smoke.py")
        smoke = importlib.util.module_from_spec(spec); spec.loader.exec_module(smoke)
        class Base:
            def __init__(self, binary, root):
                self.root, self.binary, self.address, self.token = root, binary, "https://localhost:8200", ""
        instance = profile.bounded_native_instance(types.SimpleNamespace(Instance=Base), Path("unused"), Path(tempfile.gettempdir()))
        error = ssl.SSLCertVerificationError(1, "synthetic TLS rejection")
        with patch.object(profile, "Client") as client, patch.object(smoke.subprocess, "Popen") as process, \
                patch("builtins.open"), patch.object(smoke.time, "sleep") as sleep:
            process.return_value.poll.return_value = None
            client.return_value.request.side_effect = error
            with self.assertRaises(RuntimeError): smoke.Instance.start(instance)
            self.assertEqual(client.return_value.request.call_count, 1)
            sleep.assert_not_called()

    def test_native_cleanup_uses_graceful_termination_before_a_forced_kill(self):
        class Base:
            def __init__(self, binary, root): pass
        instance = profile.bounded_native_instance(types.SimpleNamespace(Instance=Base), Path("unused"), Path("unused"))
        with patch.object(profile.subprocess, "Popen") as factory:
            instance.process, instance.log = factory.return_value, io.StringIO()
            instance.process.poll.return_value = None
            instance.stop()
            instance.process.terminate.assert_called_once()
            instance.process.wait.assert_called_once_with(timeout=5)
            instance.process.kill.assert_not_called()
            self.assertTrue(instance.log.closed)


class OperatorContracts(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve(); self.root.chmod(0o700)
        self.actual = {"qa_source": {"source_commit": "qa", "source_tree": "qt", "source_dirty": False},
            "cli_source": {"source_commit": "cli", "source_tree": "ct", "source_dirty": False, "files_sha256": {}},
            "candidate_source": {"source_commit": "build", "source_tree": "bt", "source_dirty": False},
            "qa_files_sha256": {name: "digest" for name in operator.QA_FILES}, "candidate_binary_sha256": "native",
            "candidate_build_receipt_sha256": "receipt", "oracle_binary_sha256": operator.PINNED_LINUX_BINARY,
            "oracle_archive_sha256": operator.PINNED_LINUX_ARCHIVE}
        self.custody = {"source_identity": self.actual["candidate_source"], "binary_sha256": "native", "receipt_sha256": "receipt"}
        self.binding = {"schema": operator.SCHEMA, "identity": self.actual, "expected_interfaces": list(profile.INTERFACES),
            "expected_cases_per_interface": list(profile.REQUIRED_INTERFACE_CASES), "expected_checks": 64,
            "budgets_seconds": {"all_http": 2, "command": 10, "outer": 120}}

    def test_distinct_build_qa_cli_identity_is_allowed_only_when_explicitly_bound(self):
        operator.validate_binding(self.binding, self.actual, self.custody)
        for field in ("qa_source", "cli_source", "candidate_source", "candidate_binary_sha256", "candidate_build_receipt_sha256"):
            bad = deepcopy(self.binding); bad["identity"][field] = "changed"
            with self.assertRaises(ValueError): operator.validate_binding(bad, self.actual, self.custody)

    def test_actual_private_build_receipt_binds_the_build_source_not_qa_source(self):
        binary = self.root / "native"; binary.write_bytes(b"synthetic binary identity only")
        source = self.actual["candidate_source"]
        receipt = {"schema": "heptabao.immutable-runtime-build-custody.v1", "exit": 0,
            "source_identity_before": source, "source_identity_after": source,
            "source_unchanged": True, "binary_sha256": profile.file_hash(binary)}
        path = self.root / "build-receipt.json"; profile.private_write(path, receipt, replace=False)
        with patch.object(profile, "git_identity", return_value=source):
            value = profile.build_custody(binary, path, self.root)
            self.assertEqual(value["source_identity"], source)
            for field, changed in (("source_identity_before", self.actual["qa_source"]),
                                   ("source_identity_after", self.actual["cli_source"]), ("binary_sha256", "wrong"), ("exit", 1)):
                bad = deepcopy(receipt); bad[field] = changed
                profile.private_write(path, bad)
                with self.assertRaises(ValueError): profile.build_custody(binary, path, self.root)

    def test_private_receipt_cannot_be_admitted_by_resolving_a_symlink_or_world_readable_mode(self):
        binary = self.root / "native"; binary.write_bytes(b"synthetic binary identity only")
        path = self.root / "receipt.json"; profile.private_write(path, {}, replace=False)
        link = self.root / "receipt-link.json"; link.symlink_to(path)
        with self.assertRaises(BaoError): profile.build_custody(binary, link, self.root)
        path.chmod(0o644)
        with self.assertRaises(BaoError): profile.build_custody(binary, path, self.root)

    def test_wrong_custody_pins_budgets_or_reduced_denominator_fail_closed(self):
        for field, value in (("expected_checks", 32), ("budgets_seconds", {"all_http": 5, "command": 10, "outer": 120}),
                             ("expected_interfaces", list(profile.INTERFACES)[:-1]), ("expected_cases_per_interface", list(profile.REQUIRED_INTERFACE_CASES)[::-1])):
            bad = deepcopy(self.binding); bad[field] = value
            with self.assertRaises(ValueError): operator.validate_binding(bad, self.actual, self.custody)
        bad = deepcopy(self.actual); bad["oracle_binary_sha256"] = "different"
        with self.assertRaises(ValueError): operator.validate_binding({**self.binding, "identity": bad}, bad, self.custody)
        bad = deepcopy(self.custody); bad["source_identity"] = self.actual["qa_source"]
        with self.assertRaises(ValueError): operator.validate_binding(self.binding, self.actual, bad)

    def test_operator_recomputes_full_trace_and_checks_all_identity_and_budget_fields(self):
        rows = [{"case": name, "passed": True} for name in profile.REQUIRED_INTERFACE_CASES]
        report = {"schema": "heptabao.kv-metadata-patch-cli-live.v1", "status": "passed", "expected_checks": 64,
            "interfaces": {name: deepcopy(rows) for name in profile.INTERFACES},
            "all_fixed_interfaces_complete": True, "all_owned_stopped": True, "forced_cleanup_exit_signals": [],
            "source_and_binary_unchanged": True, "qa_source_before": self.actual["qa_source"], "qa_source_after": self.actual["qa_source"],
            "cli_source_before": self.actual["cli_source"], "cli_source_after": self.actual["cli_source"],
            "candidate_build_custody": self.custody, "candidate_build_custody_after": self.custody,
            "runner_sha256": "digest", "checkset_sha256": "digest", "oracle_cli_sha256": operator.PINNED_LINUX_BINARY,
            "oracle_version": "2.7.0", "http_seconds": 2, "command_seconds": 10, "outer_seconds": 120,
            "all_http_clients_exact_budget": True, "client_budget_seconds_observed": [2] * 4,
            "requested_stdout_saved": False, "credentials_saved_in_report": False}
        self.assertTrue(operator.report_complete(report, self.actual, self.custody))
        for field, value in (("all_fixed_interfaces_complete", False), ("status", "failed"), ("forced_cleanup_exit_signals", [-9]),
                             ("client_budget_seconds_observed", [2, 2, 2, 15]), ("cli_source_after", self.actual["candidate_source"]),
                             ("candidate_build_custody_after", {}), ("requested_stdout_saved", True)):
            bad = deepcopy(report); bad[field] = value
            self.assertFalse(operator.report_complete(bad, self.actual, self.custody))
        bad = deepcopy(report); bad["interfaces"]["candidate_python"].pop()
        self.assertFalse(operator.report_complete(bad, self.actual, self.custody))

    def test_actual_operator_awaiter_uses_120_seconds_and_preserves_timeout_failure(self):
        with patch.object(operator.subprocess, "Popen") as factory, patch.object(operator.os, "killpg") as kill:
            factory.return_value.pid = 32123
            factory.return_value.wait.side_effect = [subprocess.TimeoutExpired("private-command", 120), 0]
            code, sid, forced = operator.run_owned(["fake-python"], self.root, {}, self.root / "run.log")
            self.assertEqual((code, sid, forced), (124, 32123, ["outer_deadline_sigterm"]))
            self.assertEqual(factory.return_value.wait.call_args_list[0].kwargs, {"timeout": 120})
            self.assertTrue(factory.call_args.kwargs["start_new_session"])
            self.assertEqual(kill.call_count, 1)

    def test_owner_audit_uses_exact_executable_and_config_root_not_broad_cmdline(self):
        proc = self.root / "proc"; proc.mkdir()
        output = self.root / "artifacts"; output.mkdir()
        binary = self.root / "server"; binary.write_bytes(b"synthetic executable placeholder")
        other = self.root / "other"; other.write_bytes(b"synthetic executable placeholder")
        for pid, sid, exe, config in ((101, 777, binary, output / "server.json"), (102, 999, binary, self.root / "outside.json"),
                                     (103, 999, other, output / "server.json")):
            entry = proc / str(pid); entry.mkdir()
            (entry / "stat").write_text(f"{pid} (synthetic worker) S 1 2 {sid} 0")
            (entry / "exe").symlink_to(exe)
            (entry / "cmdline").write_bytes(b"server\0--config\0" + os.fsencode(config) + b"\0")
        self.assertEqual(operator.owned_session(777, proc), [101])
        self.assertEqual(operator.owned_fixtures(output, (binary,), proc), [101])


if __name__ == "__main__":
    unittest.main()
