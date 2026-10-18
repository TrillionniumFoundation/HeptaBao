"""Local destructive-boundary checks; these do not assert a physical HA pass."""
import contextlib
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import io
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
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


class NativeHistoryHttpTests(unittest.TestCase):
    def test_retained_and_retired_versions_use_real_http_query_selection(self):
        history = {version: {"fixture_version": version} for version in (1, 2)}
        retired = {}
        disclose_retired = False
        select_latest = False

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                # Model the real HTTP boundary observed on Mac: a GET body
                # does not select a KV2 version; only the URL query does.
                query = parse_qs(urlsplit(self.path).query)
                version = 2 if select_latest else int(query.get("version", ["2"])[0])
                state = retired.get(version)
                body = {"data": {
                    "data": history[version] if state is None or disclose_retired else None,
                    "metadata": {"version": version, "destroyed": state == "destroyed",
                                 "deletion_time": "fixture-deleted" if state == "deleted" else ""},
                }}
                raw = json.dumps(body).encode()
                self.send_response(404 if state is not None else 200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

            def log_message(self, *_args):
                pass

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        run = object.__new__(native.NativeRun)
        run.context = None
        run.root_token = "synthetic-history-fixture"
        run.path = "history"
        run.history = {version: native.data_digest(value) for version, value in history.items()}
        run.retired = retired
        node = SimpleNamespace(node_id=1, api_origin="http://127.0.0.1:" + str(server.server_port))
        try:
            run.history_reads(node, retired=False)
            # Successful but stale content must still fail exact readback.
            select_latest = True
            with self.assertRaises(native.base.FixtureError):
                run.history_reads(node, retired=False)
            select_latest = False
            for state in ("deleted", "destroyed"):
                with self.subTest(retired=state):
                    retired[1] = state
                    run.history_reads(node)
                    disclose_retired = True
                    with self.assertRaises(native.base.FixtureError):
                        run.history_reads(node)
                    disclose_retired = False
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)
        self.assertFalse(thread.is_alive())


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


if __name__ == "__main__":
    unittest.main()

