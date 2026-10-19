#!/usr/bin/env python3
"""Local custody tests only: never execute an installed SDK or contact a host."""
import ctypes
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import signal
import sys
import tempfile
import time
import unittest
from unittest import mock

HERE = Path(__file__).resolve()
SPEC = importlib.util.spec_from_file_location("openai_once_under_test", HERE.parents[1] / "authbus_openai_sdk_once.py")
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class CustodyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Only this disposable local test process becomes a subreaper. It can
        # wait the exact orphan fixtures that the tested controller killed,
        # without leaving local zombie test processes behind.
        library = ctypes.CDLL(None, use_errno=True)
        if library.prctl(36, 1, 0, 0, 0) != 0:
            raise OSError(ctypes.get_errno(), "local test subreaper unavailable")

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="heptabao-openai-once-unit-")
        self.root = Path(self.temporary.name)
        self.root.chmod(0o700)
        MODULE.SIGNALS.clear()

    def tearDown(self):
        MODULE.SIGNALS.clear()
        self.temporary.cleanup()

    def packet(self):
        return Path(os.environ["AUTHBUS_OPENAI_R3_PACKET"]).read_bytes()

    def test_exact_packet_and_staged_closed_tree(self):
        manifest, payloads = MODULE.decode_packet(self.packet())
        self.assertEqual((len(manifest["files"]), len(payloads)), (15, 16))
        source = self.root / "source"
        MODULE.stage_source(source, payloads, time.monotonic_ns() + 5_000_000_000)
        self.assertTrue(MODULE.verify_source(source, payloads)["exactClosedTree"])

    def test_changed_packet_fails_before_materialization(self):
        raw = bytearray(self.packet()); raw[len(raw) // 2] ^= 1
        with self.assertRaisesRegex(MODULE.Refusal, "exact_frozen_packet_required"):
            MODULE.decode_packet(raw)
        self.assertEqual(list(self.root.iterdir()), [])

    def test_extra_source_file_is_not_ignored(self):
        _, payloads = MODULE.decode_packet(self.packet())
        source = self.root / "source"
        MODULE.stage_source(source, payloads, time.monotonic_ns() + 5_000_000_000)
        (source / "unbound.mjs").write_text("export const unbound = true;\n")
        with self.assertRaisesRegex(MODULE.Refusal, "closed_staged_source_tree_required"):
            MODULE.verify_source(source, payloads)

    def test_symlink_and_empty_nonlog_input_are_refused(self):
        original = self.root / "original"; original.write_bytes(b"owned")
        link = self.root / "alias"; link.symlink_to(original)
        with self.assertRaises(OSError):
            MODULE.read_regular(link, maximum=16)
        empty = self.root / "empty"; empty.write_bytes(b"")
        with self.assertRaisesRegex(MODULE.Refusal, "bounded_regular_file_custody_required"):
            MODULE.read_regular(empty, maximum=16)
        self.assertEqual(MODULE.read_regular(empty, maximum=16, allow_empty=True)[1]["sha256"], hashlib.sha256(b"").hexdigest())

    def test_all_sdk_input_classes_bound_and_metadata_change_rejected(self):
        sdk = self.root / "sdk"; sdk.mkdir(mode=0o700)
        def entry(name, raw):
            target = sdk / name; target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(raw)
            return {"relative": name, "originalSha256": MODULE.sha(raw)}
        modules = [entry("dist/synthetic-" + str(index) + ".js", ("export const fixture = " + str(index) + ";\n").encode()) for index in range(35)]
        activation = entry("dist/extensions/openai/openclaw.plugin.json", b'{"id":"openai","enabledByDefault":true}')
        package = entry("package.json", b'{"name":"openclaw","version":"2026.7.1-2","bin":{"openclaw":"openclaw.mjs"}}')
        bin_entry = entry("openclaw.mjs", b"// synthetic unit source, not the actual SDK\n")
        manifest = {"sdkInputs": {"modules": modules, "metadata": [activation], "discoveryBindings": [package, bin_entry]}}
        with mock.patch.object(MODULE, "HOST_ROOT", self.root), mock.patch.object(MODULE, "SDK_ROOT", sdk):
            self.assertEqual(len(MODULE.verify_sdk(sdk, manifest)["files"]), 38)
            (sdk / activation["relative"]).write_bytes(b'{"id":"openai","enabledByDefault":false}')
            with self.assertRaisesRegex(MODULE.Refusal, "file_hash_mismatch"):
                MODULE.verify_sdk(sdk, manifest)

    def run_owned(self, program, seconds=5):
        journal = {}
        deadline = time.monotonic_ns() + int(seconds * 1e9)
        save = lambda: (self.root / "unit-journal.json").write_bytes(MODULE.encoded(journal))
        args = [sys.executable, "-B", "-c", program]
        value = MODULE.run_owned_once(args, cwd=self.root, environment={"PATH": "/usr/bin:/bin"},
            stdout_path=self.root / "stdout", stderr_path=self.root / "stderr", deadline_ns=deadline,
            journal=journal, save=save)
        return value, journal, deadline

    def test_normal_original_handle_is_waited_exactly_once(self):
        value, journal, deadline = self.run_owned("print('synthetic unit completion')")
        self.assertEqual(value, 0)
        self.assertEqual(journal["submissionCount"], 1)
        self.assertEqual(journal["cleanup"]["sameOriginalPopenWaitCount"], 1)
        self.assertTrue(journal["cleanup"]["ownedLiveSessionEmpty"])
        self.assertTrue(journal["cleanup"]["leaderReaped"])
        self.assertLess(journal["executionFinishedNs"], deadline)

    def test_exited_leader_does_not_hide_live_descendant(self):
        program = """import os,time
r,w=os.pipe()
child=os.fork()
if child == 0:
 os.close(r);os.write(w,b'1');os.close(w);time.sleep(12);os._exit(0)
os.close(w);os.read(r,1);os.close(r)
open('child-pid','w').write(str(child))
os._exit(0)
"""
        value, journal, _ = self.run_owned(program)
        descendant = int((self.root / "child-pid").read_text())
        try:
            self.assertEqual(value, 0)
            self.assertIn(descendant, [row["pid"] for row in journal["cleanup"]["liveMembersBefore"]])
            self.assertTrue(journal["cleanup"]["ownedLiveSessionEmpty"])
            self.assertEqual(journal["cleanup"]["leaderExitCode"], 0)
        finally:
            os.waitpid(descendant, 0)

    def test_timeout_kills_owned_new_pgid_and_never_extends_pass_deadline(self):
        program = """import os,signal,time
r,w=os.pipe()
child=os.fork()
if child == 0:
 os.close(r);os.setpgid(0,0);signal.signal(signal.SIGTERM,signal.SIG_IGN)
 os.write(w,b'1');os.close(w);time.sleep(12);os._exit(0)
os.close(w);os.read(r,1);os.close(r)
open('child-pid','w').write(str(child))
time.sleep(12)
"""
        with self.assertRaisesRegex(MODULE.Refusal, "original_180_second_deadline_expired"):
            self.run_owned(program, seconds=0.35)
        journal = json.loads((self.root / "unit-journal.json").read_bytes())
        descendant = int((self.root / "child-pid").read_text())
        try:
            self.assertTrue(journal["cleanup"]["leaderReaped"])
            self.assertTrue(journal["cleanup"]["ownedLiveSessionEmpty"])
            self.assertGreaterEqual(journal["executionFinishedNs"], journal["originalDeadlineNs"])
            self.assertEqual(journal["submissionCount"], 1)
            self.assertTrue(any(row["authority"] == "owned_session_descendant_pidfd"
                                and row["signal"] == signal.SIGKILL for row in journal["cleanup"]["signals"]))
        finally:
            os.waitpid(descendant, 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
