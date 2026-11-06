"""Confirmed CI harness regressions; no product, provider or real HA service.

Short Python children exercise original-handle retirement. HTTP and renewal
fixtures below are explicit test doubles and grant no protocol qualification.
"""
from __future__ import annotations

from contextlib import ExitStack, redirect_stdout
from email.message import Message
import gzip
import hashlib
import http.client
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

HERE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(HERE))
import ha_destructive as ha
import official_openbao_launcher as launcher
import renewal_cleanup
import raft_membership_live as membership
import radius_renewal_live as radius
import kubernetes_renewal_live as kubernetes


class CountedPopen(subprocess.Popen):
    def __init__(self, *args, **kwargs):
        self.wait_calls = self.kill_calls = self.terminate_calls = 0
        super().__init__(*args, **kwargs)

    def wait(self, *args, **kwargs):
        self.wait_calls += 1
        return super().wait(*args, **kwargs)

    def kill(self):
        self.kill_calls += 1
        return super().kill()

    def terminate(self):
        self.terminate_calls += 1
        return super().terminate()


def observe_exit(child):
    deadline = time.monotonic() + 5
    while child.poll() is None:
        if time.monotonic() >= deadline:
            raise AssertionError("test_child_did_not_exit_in_original_five_seconds")
        time.sleep(.01)


class OriginalHandleRegressions(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="ci-original-handles-")
        self.root = Path(self.temporary.name).resolve()
        self.children = []

    def tearDown(self):
        for child in self.children:
            if child.poll() is None:
                child.kill()
                child.wait(timeout=5)
        self.temporary.cleanup()

    def child(self, argv, **kwargs):
        for name in ("label", "action", "stop_timeout"):
            kwargs.pop(name, None)
        value = CountedPopen(argv, **kwargs)
        self.children.append(value)
        return value

    def node(self, code):
        root = self.root / ("node-" + str(len(list(self.root.iterdir()))))
        root.mkdir(mode=0o700)
        script = root / "synthetic-child.py"
        script.write_text("#!" + str(Path(sys.executable).resolve()) + "\n" + code + "\n")
        script.chmod(0o700)
        return ha.Node(1, script, root, None, ports=(12341, 12342))

    def test_expected_startup_exit_retires_original_once_without_a_kill(self):
        node = self.node("import sys\nprint(" + repr(ha.MISBOUND_BOOTSTRAP_ERROR) +
                         ", file=sys.stderr, flush=True)\nraise SystemExit(1)")
        with patch.object(ha.owned_process, "popen", side_effect=self.child):
            node.expect_startup_rejection(ha.MISBOUND_BOOTSTRAP_ERROR)
        child = self.children[-1]
        self.assertEqual((child.returncode, child.wait_calls, child.kill_calls, child.terminate_calls), (1, 1, 0, 0))
        self.assertIsNone(node.process)
        self.assertIsNone(node.log)
        node.stop()  # An idempotent owner close does not wait the old handle again.
        self.assertEqual(child.wait_calls, 1)
        with self.assertRaises(ChildProcessError):
            os.waitpid(child.pid, os.WNOHANG)

    def test_wrong_startup_exit_and_old_diagnostic_cannot_qualify_rejection(self):
        for code, line in ((0, ha.MISBOUND_BOOTSTRAP_ERROR),
                           (2, ha.MISBOUND_BOOTSTRAP_ERROR), (1, "different terminal error")):
            with self.subTest(code=code, line=line):
                node = self.node("print(" + repr(line) + ", flush=True)\nraise SystemExit(" + str(code) + ")")
                ha.private_write(node.root / "process.log", ha.MISBOUND_BOOTSTRAP_ERROR + "\n")
                with patch.object(ha.owned_process, "popen", side_effect=self.child), \
                     self.assertRaisesRegex(ha.FixtureError, "^unexpected_startup_rejection$"):
                    node.expect_startup_rejection(ha.MISBOUND_BOOTSTRAP_ERROR)
                child = self.children[-1]
                self.assertEqual(child.wait_calls, 1)
                self.assertEqual(child.kill_calls, 0)
                self.assertIsNone(node.process)
                self.assertIsNone(node.log)

    def test_unfinished_startup_negative_is_killed_but_never_admitted(self):
        node = self.node("import time\ntime.sleep(30)")
        with patch.object(ha.owned_process, "popen", side_effect=self.child), \
             patch.object(ha.owned_process, "wait", side_effect=subprocess.TimeoutExpired("fixture", 10)), \
             self.assertRaisesRegex(ha.FixtureError, "misbound_cluster_process_did_not_exit"):
            node.expect_startup_rejection(ha.MISBOUND_BOOTSTRAP_ERROR)
        child = self.children[-1]
        self.assertEqual((child.returncode, child.wait_calls, child.kill_calls), (-9, 1, 1))
        self.assertIsNone(node.process)

    def test_live_node_kill_and_already_dead_node_are_distinct_contracts(self):
        for code, failed in (("import time\ntime.sleep(30)", False), ("raise SystemExit(0)", True),
                             ("import os,signal\nos.kill(os.getpid(),signal.SIGKILL)", True)):
            with self.subTest(code=code):
                node = self.node(code)
                with patch.object(ha.owned_process, "popen", side_effect=self.child):
                    node.start(wait=False)
                child, log = node.process, node.log
                if failed:
                    observe_exit(child)
                    with self.assertRaisesRegex(ha.FixtureError, "node_exited_before_intentional_stop"):
                        node.stop()
                else:
                    node.stop()
                self.assertTrue(log.closed)
                self.assertIsNone(node.process)
                self.assertEqual(child.wait_calls, 1)
                self.assertEqual(child.kill_calls, 0 if failed else 1)

    def test_failed_node_wait_keeps_same_original_for_later_cleanup(self):
        node = self.node("import time\ntime.sleep(30)")
        with patch.object(ha.owned_process, "popen", side_effect=self.child):
            node.start(wait=False)
        child, log = node.process, node.log
        with patch.object(ha.owned_process, "stop", side_effect=subprocess.TimeoutExpired("fixture", 10)), \
             self.assertRaises(subprocess.TimeoutExpired):
            node.stop()
        self.assertIs(node.process, child)
        self.assertTrue(log.closed)
        with self.assertRaisesRegex(ha.FixtureError, "node_already_running"):
            node.start(wait=False)
        node.stop()
        self.assertIsNone(node.process)
        self.assertEqual((child.wait_calls, child.kill_calls, child.returncode), (1, 1, -9))

    def oracle(self, code="import time; time.sleep(30)"):
        path = self.root / ("oracle-" + str(len(self.children)))
        path.mkdir(mode=0o700)
        log = (path / "process.log").open("xb")
        child = self.child([sys.executable, "-B", "-c", code], stdin=subprocess.DEVNULL,
                           stdout=log, stderr=log, start_new_session=True)
        return {"root": str(path), "process": child, "log": log}, child, log

    def test_intentional_oracle_crash_does_not_reapply_graceful_stop_or_wait(self):
        oracle, child, log = self.oracle()
        row = launcher.crash_oracle(oracle)
        self.assertEqual((row["status"], row["exit_code"], row["original_wait_completed"]), ("passed", -9, True))
        self.assertTrue(log.closed)
        self.assertIsNone(oracle["process"])
        launcher.stop_oracle(oracle)
        self.assertEqual((child.wait_calls, child.kill_calls, child.terminate_calls), (1, 1, 0))
        with self.assertRaisesRegex(launcher.BaoError, "crash_requires_live_original"):
            launcher.crash_oracle(oracle)
        self.assertEqual(child.wait_calls, 1)

    def test_unexpected_oracle_death_is_retired_but_never_called_an_injected_crash(self):
        for code in ("raise SystemExit(0)", "raise SystemExit(7)",
                     "import os,signal; os.kill(os.getpid(),signal.SIGKILL)"):
            with self.subTest(code=code):
                oracle, child, log = self.oracle(code)
                observe_exit(child)
                with self.assertRaisesRegex(launcher.BaoError, "crash_requires_live_original"):
                    launcher.crash_oracle(oracle)
                self.assertEqual((child.wait_calls, child.kill_calls, child.terminate_calls), (1, 0, 0))
                self.assertEqual(oracle["process_lifecycle"][0]["status"], "failed")
                self.assertTrue(log.closed)
                launcher.stop_oracle(oracle)
                self.assertEqual(child.wait_calls, 1)

    def test_failed_crash_wait_retains_the_original_for_final_cleanup(self):
        oracle, child, log = self.oracle()
        with patch.object(launcher.owned_process, "stop", side_effect=subprocess.TimeoutExpired("private argv", 5)), \
             self.assertRaises(subprocess.TimeoutExpired):
            launcher.crash_oracle(oracle)
        self.assertIs(oracle["process"], child)
        row = oracle["process_lifecycle"][0]
        self.assertFalse(row["original_wait_completed"])
        self.assertEqual(row["status"], "failed")
        self.assertTrue(log.closed)
        self.assertNotIn("private argv", json.dumps(row))


class RenewalExitRegressions(unittest.TestCase):
    def test_every_cleanup_and_publication_runs_after_private_errors(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            private = root / "candidate"; private.mkdir()
            reference = root / "oracle"; reference.mkdir()
            calls, publications = [], []
            def fail(label):
                calls.append(label)
                raise RuntimeError("synthetic-secret-must-not-appear")
            result = {"status": "mismatch", "safe_failure_code": "original_comparison_failed", "cases": {}}
            renewal_cleanup.finish_fixture(result,
                instance=SimpleNamespace(stop=lambda: fail("candidate")),
                oracle={"root": str(reference)},
                providers=[SimpleNamespace(close=lambda: fail("provider0")),
                           SimpleNamespace(close=lambda: calls.append("provider1"))],
                private_root=private, stop_oracle=lambda _: fail("oracle"),
                validate=lambda: fail("observation"), publish=lambda value: publications.append(json.dumps(value)))
            self.assertEqual(calls, ["candidate", "oracle", "provider0", "provider1", "observation"])
            self.assertEqual(len(publications), 1)
            self.assertNotIn("synthetic-secret", publications[0])
            self.assertEqual(result["safe_failure_code"], "original_comparison_failed")
            self.assertEqual(result["status"], "failed")
            self.assertTrue(private.is_dir() and reference.is_dir())
            self.assertEqual(len(result["cleanup_failures"]), 4)

    def test_interrupt_during_cleanup_is_published_then_propagated(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "owned"; root.mkdir()
            calls = []
            def interrupt():
                raise KeyboardInterrupt()
            with self.assertRaises(KeyboardInterrupt):
                renewal_cleanup.finish_fixture({"status": "passed"},
                    instance=SimpleNamespace(stop=interrupt), oracle=None,
                    providers=[SimpleNamespace(close=lambda: calls.append("provider"))],
                    private_root=root, stop_oracle=None, validate=lambda: calls.append("validate"),
                    publish=lambda result: calls.append(result["status"]))
            self.assertEqual(calls, ["provider", "validate", "failed"])
            self.assertTrue(root.is_dir())

    def test_both_runner_finally_paths_publish_after_stop_and_provider_failures(self):
        for module in (radius, kubernetes):
            with self.subTest(module=module.__name__), tempfile.TemporaryDirectory() as temporary, ExitStack() as stack:
                parent = Path(temporary).resolve(); parent.chmod(0o700)
                output = parent / "safe-result.json"
                reference = parent / "reference"; reference.mkdir(mode=0o700)
                calls = []
                def failure(label):
                    calls.append(label)
                    raise RuntimeError("synthetic-secret-must-not-appear")
                class Instance:
                    address = "https://localhost:12345"
                    def __init__(self, binary, root):
                        self.root = root; root.mkdir(mode=0o700)
                        (root / "server.json").write_text("{}")
                        for name in ("ca.crt", "tls.crt", "tls.key"):
                            (root / name).write_text("synthetic fixture bytes")
                    def start(self): pass
                    def call(self, method, path, body=None):
                        return 200, {"root_token": "synthetic-token", "keys_base64": ["synthetic-key"]}
                    def stop(self): failure("candidate_stop")
                class Provider:
                    port = 12346
                    def __init__(self, *args, **kwargs): pass
                    def close(self): failure("provider_close")
                identity = {"binary_sha256": "b" * 64, "source_commit": "a" * 40,
                            "source_tree": "c" * 40, "source_dirty": False,
                            "source_content_sha256": "d" * 64}
                for name, value in (("source_identity", Mock(return_value=identity)),
                                    ("file_hash", Mock(return_value="b" * 64)),
                                    ("start_oracle", Mock(return_value={"root": str(reference),
                                      "address": "https://localhost:12347", "ca_file": "unused", "token_file": "unused"})),
                                    ("stop_oracle", Mock(side_effect=lambda _: failure("oracle_stop"))),
                                    ("private_read", Mock(return_value=b"synthetic-token")),
                                    ("Client", Mock()), ("run_scenarios", Mock())):
                    stack.enter_context(patch.object(module, name, value))
                if module is radius:
                    stack.enter_context(patch.object(module, "RadiusResponder", Provider))
                    stack.enter_context(patch.object(module, "run_finite_scenarios"))
                    stack.enter_context(patch.object(module, "run_native_parameter_scenarios"))
                    stack.enter_context(patch.object(module.importlib.util, "spec_from_file_location", return_value=SimpleNamespace(loader=Mock())))
                    stack.enter_context(patch.object(module.importlib.util, "module_from_spec", return_value=SimpleNamespace(Instance=Instance)))
                    stack.enter_context(patch.object(module.subprocess, "check_output",
                        side_effect=lambda argv, **kw: "a" * 40 if kw.get("text") else b""))
                else:
                    stack.enter_context(patch.object(module, "Instance", Instance))
                    stack.enter_context(patch.object(module, "Reviewer", Provider))
                    stack.enter_context(patch.object(module, "signing_key", return_value=(None, {})))
                    stack.enter_context(patch.object(module, "configuration", return_value={}))
                stack.enter_context(patch.object(sys, "argv", [module.__name__, "--binary", str(Path(sys.executable).resolve()), "--output", str(output)]))
                with redirect_stdout(io.StringIO()):
                    self.assertEqual(module.main(), 1)
                result = json.loads(output.read_text())
                self.assertEqual(result["status"], "failed")
                self.assertEqual(calls, ["candidate_stop", "oracle_stop", "provider_close", "provider_close"])
                self.assertEqual(len(result["cleanup_failures"]), 4)
                self.assertNotIn("synthetic-secret", output.read_text())
                self.assertEqual(output.stat().st_mode & 0o777, 0o600)
                for path in result["retained_private_roots"]:
                    self.assertTrue(Path(path).is_dir())
                    # These are only the fresh test-double roots, not evidence or services.
                    import shutil
                    shutil.rmtree(path)


class WireResponse(io.BytesIO):
    def __init__(self, raw, *, status=200, content_type="application/gzip", length=None):
        super().__init__(raw)
        self.status = status
        self.headers = Message()
        self.headers["Content-Type"] = content_type
        self.headers["Content-Length"] = str(len(raw) if length is None else length)


class BinarySnapshotRegressions(unittest.TestCase):
    def download(self, response):
        node = ha.Node(1, Path("/unused"), Path("/unused"), None, ports=(12341, 12342))
        opener = Mock(); opener.open.return_value = response
        with patch.object(ha.urllib.request, "build_opener", return_value=opener) as build, \
             patch.object(ha.json, "loads", side_effect=AssertionError("binary snapshot sent to JSON")):
            result = node.download_snapshot(token="synthetic-root", timeout=12)
        self.assertTrue(response.closed)
        self.assertEqual(opener.open.call_count, 1)
        request = opener.open.call_args.args[0]
        self.assertEqual(request.full_url, "https://127.0.0.1:12341/v1/sys/storage/raft/snapshot")
        self.assertEqual(opener.open.call_args.kwargs["timeout"], 12)
        self.assertEqual(build.call_args.args[0].proxies, {})
        self.assertIsInstance(build.call_args.args[1], ha.NoRedirect)
        return result

    def test_actual_non_utf8_gzip_is_binary_and_the_original_bound_is_unchanged(self):
        raw = gzip.compress(b"\xffsynthetic encrypted bytes", mtime=0)
        status, receipt = self.download(WireResponse(raw))
        self.assertEqual(status, 200)
        self.assertEqual(receipt["sha256"], hashlib.sha256(raw).hexdigest())
        self.assertEqual(receipt["bytes"], len(raw))
        self.assertFalse(receipt["archive_authentication_or_restore_claim"])

    def test_pinned_legacy_json_contract_stays_distinct_from_current_gzip(self):
        raw = b'{"data":{"format":"heptabao-encrypted-backup-v1","backup":"synthetic"}}'
        node = ha.Node(1, Path("/unused"), Path("/unused"), None, ports=(12341, 12342))
        response = WireResponse(raw, content_type="application/json")
        opener = Mock(); opener.open.return_value = response
        with patch.object(ha.urllib.request, "build_opener", return_value=opener):
            status, body = node.call("GET", "sys/storage/raft/snapshot", token="synthetic-root", timeout=15)
        self.assertEqual(status, 200)
        self.assertEqual(body["data"]["format"], "heptabao-encrypted-backup-v1")
        self.assertEqual(opener.open.call_args.kwargs["timeout"], 15)
        self.assertTrue(response.closed)
        with self.assertRaisesRegex(ha.FixtureError, "snapshot_binary_response_contract"):
            self.download(WireResponse(raw, content_type="application/json"))

    def test_failed_or_redirect_status_cannot_publish_response_payload(self):
        for code in (403, 307, 503):
            with self.subTest(status=code):
                status, receipt = self.download(WireResponse(b'private-response-token', status=code, content_type="application/json"))
                self.assertEqual(status, code)
                self.assertFalse(receipt["archive_received"])
                self.assertNotIn("sha256", receipt)
                self.assertNotIn("private-response-token", str(receipt))

    def test_json_wrong_length_duplicate_length_and_encoding_fail(self):
        raw = gzip.compress(b"fixture", mtime=0)
        responses = [WireResponse(b'{"data":{}}', content_type="application/json"),
                     WireResponse(raw, length=len(raw) - 1), WireResponse(b"", length=0),
                     WireResponse(raw), WireResponse(raw)]
        responses[-2].headers["Content-Length"] = str(len(raw))
        responses[-1].headers["Content-Encoding"] = "gzip"
        for response in responses:
            with self.subTest(headers=str(response.headers)), \
                 self.assertRaisesRegex(ha.FixtureError, "snapshot_binary_response_contract"):
                self.download(response)
            self.assertTrue(response.closed)

    def test_oversize_and_expired_original_deadline_do_not_pass(self):
        with self.assertRaisesRegex(ha.FixtureError, "snapshot_response_exceeds_fixture_bound"):
            self.download(WireResponse(b"x" * (32 * 1024 * 1024 + 1)))
        with patch.object(ha.time, "monotonic", side_effect=[1, 13]), \
             self.assertRaisesRegex(ha.FixtureError, "snapshot_response_original_deadline"):
            self.download(WireResponse(gzip.compress(b"fixture", mtime=0)))

    def test_incomplete_http_body_stays_failed_without_a_retry(self):
        response = WireResponse(gzip.compress(b"fixture", mtime=0))
        with patch.object(response, "read", side_effect=http.client.IncompleteRead(b"partial", 10)), \
             self.assertRaises(http.client.IncompleteRead):
            self.download(response)
        self.assertTrue(response.closed)

    def cluster(self):
        cluster = membership.AdminCluster.__new__(membership.AdminCluster)
        cluster.root_token = "synthetic-root"
        cluster.scenarios = []
        cluster.require_compact_snapshots = False
        return cluster

    def node(self, status):
        node = Mock()
        node.download_snapshot.return_value = (200, {"archive_received": True, "content_length_verified": True})
        node.call.return_value = (200, {"data": status})
        return node

    def test_membership_requires_binary_receipt_and_original_three_frontier_cases(self):
        cluster = self.cluster()
        node = self.node({"snapshot_index": 20, "applied_index": 21, "purged_index": 20, "membership_index": 3})
        cluster.create_snapshot(node)
        self.assertEqual(cluster.scenarios, ["snapshot_waits_durable_readback", "snapshot_committed_frontier_exists", "prejoin_logs_really_purged"])
        node.download_snapshot.assert_called_once_with(token="synthetic-root", timeout=12)
        node.call.assert_called_once_with("GET", "sys/storage/raft/snapshot-status", token="synthetic-root")
        self.assertEqual(cluster.snapshot_download["frontiers"][0]["data"]["snapshot_index"], 20)

    def test_download_success_does_not_substitute_for_missing_or_inconsistent_frontier(self):
        for value in ({}, {"snapshot_index": True, "applied_index": 10},
                      {"snapshot_index": 11, "applied_index": 10},
                      {"snapshot_index": 10, "applied_index": 10, "purged_index": 11}):
            with self.subTest(value=value), self.assertRaisesRegex(ha.FixtureError, "snapshot_committed_frontier_exists"):
                self.cluster().create_snapshot(self.node(value))

    def test_unpurged_snapshot_is_still_a_failed_original_case(self):
        cluster = self.cluster()
        node = self.node({"snapshot_index": 20, "applied_index": 20, "purged_index": None})
        with patch.object(membership.time, "monotonic", side_effect=[0, 6]), \
             self.assertRaisesRegex(ha.FixtureError, "prejoin_logs_really_purged"):
            cluster.create_snapshot(node)
        self.assertEqual(len(cluster.scenarios), 2)
        node.call.assert_called_once()


if __name__ == "__main__":
    unittest.main()
