"""Local destructive-boundary checks; these do not assert a physical HA pass."""
import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock
from urllib.parse import parse_qs, urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import native_v6_ha_multihost_live as native


def fixture_root(path):
    path.mkdir(mode=0o700)
    info = path.stat()
    marker = {"run_id": "local-fixture-only", "root": str(path),
              "production_authority": False, "root_device": info.st_dev,
              "root_inode": info.st_ino}
    native.write_private(path / native.MARKER, native.canonical(marker))
    (path / "raft").mkdir(mode=0o700)
    store = path / "raft/native-v6-ciphertext"
    store.mkdir(mode=0o700)
    leaves = {}
    for index in (1, 2):
        raw = bytes([index]) * (70_000 + index)
        name = "v6-" + hashlib.sha256(raw).hexdigest() + ".blob"
        native.write_private(store / name, raw)
        leaves[name] = raw
    native.write_private(store / ("v6-closure-" + "a" * 64 + ".manifest"), b"opaque-manifest")
    native.write_private(store / ".fixture-test-lock", b"opaque-lock")
    return store, leaves


def run_inventory(root, action, run_id="local-fixture-only"):
    source = native.CIPHER_INVENTORY_SCRIPT.replace(
        "    __STOPPED_CHECK__",
        "\n".join("    " + line for line in native.STOPPED_CHECK.splitlines()),
    )
    return subprocess.run([sys.executable, "-", action, str(root), run_id],
                          input=source, text=True, capture_output=True, timeout=10)


class NativePhysicalOwnershipTests(unittest.TestCase):
    def test_real_quarantine_preserves_manifest_and_accepts_only_exact_rebuilt_subset(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve() / "new-owned-root"
            store, leaves = fixture_root(root)
            retained = {path.name: path.read_bytes() for path in store.iterdir()
                        if path.name not in leaves}
            result = run_inventory(root, "quarantine")
            self.assertEqual(result.returncode, 0, result.stderr)
            receipt = json.loads(result.stdout)
            self.assertEqual(receipt["quarantined_count"], 2)
            self.assertEqual(receipt["remaining_count"], 0)
            for name, raw in retained.items():
                self.assertEqual((store / name).read_bytes(), raw)
            empty = run_inventory(root, "empty")
            self.assertEqual(empty.returncode, 0, empty.stderr)
            self.assertEqual(json.loads(empty.stdout)["inventory_sha256"], receipt["inventory_sha256"])
            # Only the selected closure's subset is required to be restored.
            # This local fixture does not pretend to select a Raft root or TLS.
            name, raw = next(iter(leaves.items()))
            native.write_private(store / name, raw)
            rebuilt = run_inventory(root, "recovered")
            self.assertEqual(rebuilt.returncode, 0, rebuilt.stderr)
            observed = json.loads(rebuilt.stdout)
            self.assertEqual(observed["restored_count"], 1)
            self.assertEqual(observed["restored_bytes"], len(raw))
            self.assertEqual(observed["unreferenced_quarantined_count"], 1)
            self.assertIs(observed["every_restored_sha_and_size_match"], True)
            with (store / name).open("r+b") as output:
                output.write(b"corrupt")
                output.flush()
                os.fsync(output.fileno())
            self.assertEqual(run_inventory(root, "recovered").returncode, 87)
            self.assertEqual((root / native.QUARANTINE / name).read_bytes(), raw)

    def test_quarantine_refuses_symlink_marker_change_and_any_owned_process_record(self):
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory).resolve()
            for mode in ("symlink", "marker", "process-record"):
                with self.subTest(mode=mode):
                    root = parent / mode
                    store, leaves = fixture_root(root)
                    if mode == "symlink":
                        name = next(iter(leaves))
                        outside = parent / "owner-only-synthetic-source"
                        native.write_private(outside, b"must-not-move")
                        (store / name).unlink()
                        (store / name).symlink_to(outside)
                    elif mode == "marker":
                        value = json.loads((root / native.MARKER).read_text())
                        value["root_inode"] += 1
                        (root / native.MARKER).write_bytes(native.canonical(value))
                    else:
                        native.write_private(root / "process.pid", b"999999999\n")
                    rejected = run_inventory(root, "quarantine")
                    self.assertNotEqual(rejected.returncode, 0)
                    self.assertFalse((root / native.QUARANTINE / "inventory.json").exists())
                    # All no-replace links must be admitted and durable before
                    # the implementation can remove even one source name.
                    self.assertEqual(set(leaves), {path.name for path in store.glob("*.blob")})
                    if mode == "symlink":
                        self.assertEqual(outside.read_bytes(), b"must-not-move")

    @unittest.skipUnless(sys.platform.startswith("linux") and shutil.which("cc")
                         and hasattr(os, "pidfd_open") and hasattr(signal, "pidfd_send_signal"),
                         "requires Linux pidfd and a real native test executable")
    def test_actual_native_argv_and_wrong_identity_never_signal_another_child(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve() / "owned"
            fixture_root(root)
            executable = root / "heptabao-server"
            source = root / "owned-child.c"
            source.write_text("#include <unistd.h>\nint main(void) { for (;;) pause(); }\n")
            subprocess.run(["cc", str(source), "-o", str(executable)],
                           check=True, capture_output=True, timeout=20)
            executable.chmod(0o500)
            for name in ("server.json", "ha.json"):
                native.write_private(root / name, b"{}")

            def action(kind, run_id="local-fixture-only"):
                return subprocess.run([sys.executable, "-", kind, str(root), "1", run_id],
                                      input=native.native_process_script(), text=True,
                                      capture_output=True, timeout=10)

            foreign = subprocess.Popen([str(executable), "--config", str(root / "other.json")],
                                       stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                       stderr=subprocess.DEVNULL, start_new_session=True)
            original_pid = None
            try:
                started = action("start")
                self.assertEqual(started.returncode, 0, started.stderr)
                original_pid = int(started.stdout)
                identity = json.loads((root / "process.identity.json").read_text())
                self.assertEqual(identity["arguments"][-1], "--experimental-native-v6-ha")
                self.assertEqual(identity["pid"], original_pid)
                self.assertNotEqual(original_pid, foreign.pid)
                # The exact target is alive; a missing recorded PID still
                # cannot permit quarantine through an unrecorded live process.
                saved = (root / "process.pid").read_bytes()
                identity_raw = (root / "process.identity.json").read_bytes()
                (root / "process.pid").unlink()
                (root / "process.identity.json").unlink()
                self.assertEqual(run_inventory(root, "quarantine").returncode, 93)
                native.write_private(root / "process.pid", saved)
                native.write_private(root / "process.identity.json", identity_raw)
                # A different actual Popen child must remain alive even when
                # someone overwrites this fixture's numeric PID with its PID.
                (root / "process.pid").write_text(str(foreign.pid) + "\n")
                self.assertEqual(action("stop").returncode, 79)
                self.assertIsNone(foreign.poll())
                self.assertTrue(Path("/proc", str(original_pid)).exists())
                (root / "process.pid").write_bytes(saved)
                self.assertEqual(action("stop", "wrong-owner-run").returncode, 85)
                stopped = action("stop")
                self.assertEqual(stopped.returncode, 0, stopped.stderr)
                self.assertEqual(int(stopped.stdout), original_pid)
                original_pid = None
                self.assertIsNone(foreign.poll())
                self.assertFalse((root / "process.pid").exists())
            finally:
                if original_pid is not None:
                    # Only the known test-created receipt is restored; the
                    # same production identity check still performs the signal.
                    (root / "process.pid").write_text(str(original_pid) + "\n")
                    action("stop")
                foreign.terminate()
                try:
                    foreign.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    foreign.kill()
                    foreign.wait(timeout=3)

    def test_process_cleanup_failure_still_stops_actual_owned_mesh_child(self):
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory).resolve()
            node = native.base.Node(1, "owned", "100.64.1.1", "/home/owned/new-fixture", 46230, 46231)
            mesh = native.StrictCompleteMesh()
            child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"],
                                     stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                     stderr=subprocess.DEVNULL, start_new_session=True)
            mesh.processes.append((1, child))
            run = native.NativeRun(SimpleNamespace(work_root=work, source_commit="a" * 40,
                                                   source_tree="b" * 40),
                                   [node], mesh, {}, {}, {"1": "c" * 64})
            run.started.add(node)
            try:
                with mock.patch.object(native, "process_action", side_effect=native.base.FixtureError(
                        "injected_unknown_process_stop")):
                    self.assertFalse(run.cleanup())
                self.assertIsNotNone(child.poll())
                self.assertEqual(run.report["cleanup_failure"], [1])
                observed = {row["case"]: row["passed"] for row in run.checks}
                self.assertIs(observed["owned_processes_stopped"], False)
                self.assertIs(observed["owned_mesh_stopped"], True)
            finally:
                if child.poll() is None:
                    child.kill()
                    child.wait(timeout=3)

    def test_strict_ssh_overlay_is_effective_and_restores_shared_helper(self):
        with mock.patch.object(native.base, "checked_run") as original:
            with native.strict_shared_transport():
                native.base.checked_run(["ssh", "-o", "BatchMode=yes", "owned-host", "true"])
                native.base.checked_run(["scp", "source", "owned-host:destination"])
            self.assertIs(native.base.checked_run, original)
            for call in original.call_args_list:
                self.assertEqual(call.args[0][1:3], ["-o", "StrictHostKeyChecking=yes"])

    def test_missing_receipt_refuses_before_private_root_or_network(self):
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory).resolve() / "must-not-exist"
            args = ["--binary-source", "builder:/home/builder/heptabao-server",
                    "--expected-binary-sha256", "c" * 64, "--source-commit", "a" * 40,
                    "--source-tree", "b" * 40, "--work-root", str(work), "--allow-private-tailnet"]
            for index in (1, 2, 3):
                args += ["--node", f"host-{index},100.64.1.{index},/home/test/new-{index}"]
                if index != 3:
                    args += ["--native-build-receipt",
                             f"host-{index},builder:/home/builder/receipt-{index}.json," + "d" * 64]
            with mock.patch.object(native.base, "ssh") as ssh, \
                    contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as rejected:
                native.main(args)
            self.assertEqual(rejected.exception.code, 2)
            self.assertFalse(work.exists())
            ssh.assert_not_called()


class NativePhysicalHistoryRequestTests(unittest.TestCase):
    """Exercise the real shared urllib request builder without a remote voter.

    The bounded reply adapter applies the actual HTTP parser's query-only
    selection contract. It is a wire-format regression, not an HA/TLS pass.
    """

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        work = Path(temporary.name).resolve()
        self.node = native.base.Node(1, "owned", "100.64.1.1", "/home/owned/new-fixture", 46230, 46231)
        self.run = native.NativeRun(SimpleNamespace(work_root=work, source_commit="a" * 40,
                                                   source_tree="b" * 40),
                                    [self.node], native.StrictCompleteMesh(), {}, {}, {"1": "c" * 64})
        self.run.root_token = "synthetic-root-token"
        self.requests = []

    @contextlib.contextmanager
    def wire(self, select):
        def send(request, *, timeout):
            self.requests.append((request, timeout))
            # http.rs consumes framed GET bodies but selects logical fields
            # only from the URL. In particular Request.data is not a query.
            query = parse_qs(urlsplit(request.full_url).query)
            status, body = select(query)
            response = io.BytesIO(native.canonical(body))
            response.status = status
            return response

        opener = SimpleNamespace(open=send)
        with mock.patch.object(native.base.urllib.request, "build_opener", return_value=opener):
            yield

    def assert_get(self, index, version):
        request, timeout = self.requests[index]
        self.assertEqual(request.get_method(), "GET")
        self.assertIsNone(request.data)
        self.assertEqual(timeout, 15)
        self.assertEqual(request.get_header("X-vault-token"), self.run.root_token)
        query = parse_qs(urlsplit(request.full_url).query)
        self.assertEqual(query, {} if version is None else {"version": [str(version)]})

    def test_history_query_survives_real_shared_request_construction(self):
        values = {1: {"value": "synthetic-v5-history-one"}, 2: {"value": "synthetic-v5-history-two"}}
        self.run.history = {version: native.data_digest(value) for version, value in values.items()}

        def selected(query):
            version = int(query.get("version", ["2"])[0])
            return 200, {"data": {"data": values[version], "metadata": {"version": version}}}

        with self.wire(selected):
            # This is the exact old wire bug: a successful response selects
            # current v2 even though the ignored JSON body says v1.
            status, reply = self.run.request(self.node, "GET", "secret/data/" + self.run.path, {"version": 1})
            self.assertEqual(status, 200)
            self.assertEqual(reply["data"]["metadata"]["version"], 2)
            self.assertIsNotNone(self.requests[0][0].data)
            self.run.history_reads(self.node, retired=False)
        self.assertEqual(len(self.requests), 3)
        self.assert_get(1, 1)
        self.assert_get(2, 2)

    def test_retired_versions_use_query_and_preserve_tombstone_checks(self):
        value = {"value": "synthetic-live-version"}
        self.run.history = {1: "a" * 64, 2: "b" * 64, 3: native.data_digest(value)}

        def selected(query):
            version = int(query.get("version", ["3"])[0])
            if version == 3:
                return 200, {"data": {"data": value, "metadata": {"version": 3}}}
            return 404, {"data": {"data": None, "metadata": {
                "version": version, "destroyed": version == 2,
                "deletion_time": "2026-10-18T00:00:00Z" if version == 1 else ""}}}

        with self.wire(selected):
            self.run.history_reads(self.node)
        self.assertEqual(len(self.requests), 3)
        for index, version in enumerate((1, 2, 3)):
            self.assert_get(index, version)
        for status, payload, metadata in (
            (404, {"value": "must-not-leak"}, {"version": 1, "destroyed": False, "deletion_time": "deleted"}),
            (404, None, {"version": 2, "destroyed": False, "deletion_time": "deleted"}),
            (404, None, {"version": 1, "destroyed": True, "deletion_time": "deleted"}),
            (404, None, {"version": 1, "destroyed": False, "deletion_time": ""}),
            (200, None, {"version": 1, "destroyed": False, "deletion_time": "deleted"}),
        ):
            with self.subTest(status=status, metadata=metadata):
                self.requests.clear()
                self.run.history = {1: "a" * 64}
                with self.wire(lambda query: (status, {"data": {"data": payload, "metadata": metadata}})):
                    with self.assertRaisesRegex(native.base.FixtureError, "retired_native_version_disclosed_payload"):
                        self.run.history_reads(self.node)
                self.assertEqual(len(self.requests), 1)
                self.assert_get(0, 1)

    def test_unversioned_read_and_quorum_denial_keep_body_empty(self):
        value = {"value": "synthetic-single-version"}
        with self.wire(lambda query: (200, {"data": {"data": value, "metadata": {"version": 1}}})):
            self.run.exact_read(self.node, self.run.path, native.data_digest(value))
        self.assert_get(0, None)
        denied = {"errors": ["synthetic quorum unavailable"]}
        with self.wire(lambda query: (503, denied)):
            self.assertEqual(self.run.read_data(self.node, self.run.path, version=19), (503, denied))
        self.assert_get(1, 19)

    def test_wrong_historical_bytes_or_metadata_fail_once(self):
        value = {"value": "synthetic-requested-version"}
        expected = native.data_digest(value)
        for status, payload, version in (
            (200, {"value": "synthetic-stale-version"}, 1),
            (200, value, 2),
            (404, None, 1),
            (503, value, 1),
        ):
            with self.subTest(status=status, version=version):
                self.requests.clear()
                with self.wire(lambda query: (status, {"data": {"data": payload, "metadata": {"version": version}}})):
                    with self.assertRaisesRegex(native.base.FixtureError, "native_exact_read_failed_node_1"):
                        self.run.exact_read(self.node, self.run.path, expected, version=1)
                self.assertEqual(len(self.requests), 1)
                self.assert_get(0, 1)

    def test_original_deadline_denominator_and_history_capacity_remain_fixed(self):
        self.assertEqual(len(native.REQUIRED_CHECKS), 89)
        self.assertEqual(native.REQUEST_SECONDS, 15)
        self.assertEqual(native.NATIVE_ADMISSION_SECONDS, 8)
        self.assertEqual(native.TARGET_BYTES, 34 * 1024 * 1024)
        value = {"value": "synthetic-requested-version"}
        with self.wire(lambda query: (200, {"data": {"data": value, "metadata": {"version": 1}}})):
            with mock.patch.object(native.time, "monotonic", side_effect=(100.0, 115.001)):
                with self.assertRaisesRegex(native.base.FixtureError, "response_arrived_after_original_http_budget"):
                    self.run.exact_read(self.node, self.run.path, native.data_digest(value), version=1)
            with self.assertRaisesRegex(native.base.FixtureError, "original_http_budget_must_not_increase"):
                self.run.request(self.node, "GET", "sys/health", timeout=16)
        self.assertEqual(len(self.requests), 1)
        self.assert_get(0, 1)

    def test_invalid_history_versions_fail_before_http(self):
        with self.wire(lambda query: self.fail("invalid history version reached HTTP")):
            for version in (0, -1, True, 1.0, "1", [1]):
                with self.subTest(version=version), self.assertRaisesRegex(
                        native.base.FixtureError, "exact_history_version_must_be_positive_integer"):
                    self.run.read_data(self.node, self.run.path, version=version)
        self.assertEqual(self.requests, [])


if __name__ == "__main__":
    unittest.main()
