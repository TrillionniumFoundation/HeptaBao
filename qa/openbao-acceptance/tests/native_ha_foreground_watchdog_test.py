#!/usr/bin/env python3
"""Real owned-child tests, without SSH, sockets, credentials or Bao binaries."""
from __future__ import annotations

import argparse
import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import select
import signal
import subprocess
import sys
import time
import types
import unittest
from unittest.mock import patch


SOURCE = Path(__file__).resolve().parents[1] / "native_ha_foreground_watchdog.py"
spec = importlib.util.spec_from_file_location("foreground_test_subject", SOURCE)
w = importlib.util.module_from_spec(spec)
spec.loader.exec_module(w)
ROOT = None
RESULTS = []
REAL_POPEN = subprocess.Popen
PYTHON = Path(sys.executable).resolve(strict=True)


def private(path, raw, mode=0o600):
    w.new_file(path, raw)
    path.chmod(mode)


def fixture(name, *, exit_after=None, same_group_survivor=False):
    root = ROOT / name
    root.mkdir(mode=0o700)
    private(root / SOURCE.name, SOURCE.read_bytes())
    if same_group_survivor:
        body = ("import subprocess,sys\n"
                "subprocess.Popen([sys.executable,'-c','import time; time.sleep(60)'])\n")
    elif exit_after is not None:
        body = "import time\ntime.sleep(" + repr(exit_after) + ")\n"
    else:
        body = "import time\ntime.sleep(60)\n"
    program = ("#!" + str(PYTHON) + "\nfrom pathlib import Path\nimport os\n"
               "root=Path(__file__).resolve().parent\n"
               "with (root/'native-starts.log').open('a') as out: out.write(str(os.getpid())+'\\n')\n" + body)
    private(root / "heptabao-server", program.encode(), 0o700)
    for name in ("server.json", "ha.json"):
        private(root / name, b"{}\n")
    run_id = hashlib.sha256(str(root).encode()).hexdigest()[:32]
    info = root.stat()
    private(root / "native-ha-fixture.json", w.canonical({"root": str(root), "run_id": run_id,
        "production_authority": False, "root_device": info.st_dev, "root_inode": info.st_ino}))
    payload = {"schema": w.SCHEMA, "root": str(root), "run_id": run_id,
               "launch_id": hashlib.sha256((str(root) + "first").encode()).hexdigest()[:32],
               "binary_sha256": w.digest((root / "heptabao-server").read_bytes()),
               "helper_sha256": w.digest((root / SOURCE.name).read_bytes()),
               "source_commit": "1" * 40, "source_tree": "2" * 40,
               "expected_system": platform.system(), "expected_host": platform.node(),
               "python_path": str(PYTHON), "python_sha256": w.digest(PYTHON.read_bytes())}
    return root, payload


def start_helper(root, payload):
    stderr = open(root / ("helper-" + payload["launch_id"] + ".stderr"), "xb")
    child = REAL_POPEN([str(PYTHON), "-B", str(root / SOURCE.name), "--serve",
                       base64.b64encode(w.canonical(payload)).decode()],
                      stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=stderr,
                      start_new_session=True)
    stderr.close()
    return child


def line(child, *, seconds=7):
    until, data = time.monotonic() + seconds, b""
    while time.monotonic() < until:
        readable, _, _ = select.select([child.stdout.fileno()], [], [], min(0.1, max(0, until-time.monotonic())))
        if not readable:
            continue
        part = os.read(child.stdout.fileno(), 1)
        if not part:
            raise AssertionError("helper reached EOF before a bounded response")
        data += part
        if data.endswith(b"\n"):
            return json.loads(data)
        if len(data) > w.MAX_LINE:
            raise AssertionError("helper response exceeded bound")
    raise AssertionError("helper response deadline")


def command(child, payload, op):
    child.stdin.write(w.canonical({"op": op, "launch_id": payload["launch_id"]}))
    child.stdin.flush()


def reap_helper(child):
    # Remote/native identity assertions use its retained report. The test owns
    # this separate local helper directly; no new group signal follows wait.
    result = child.wait(timeout=6)
    if child.stdin and not child.stdin.closed:
        child.stdin.close()
    child.stdout.close()
    return result


def emergency(child):
    if child is None or child.returncode is not None:
        return
    try:
        if child.stdin and not child.stdin.closed:
            child.stdin.close()
        child.wait(timeout=6)
    except BaseException:
        # Only the test's unreaped, directly owned helper. This never selects
        # a process from an arbitrary PID, port, command pattern or old receipt.
        try:
            owner = w.capture_child(child)
            w.stop_unreaped(child, owner, until=time.monotonic()+5)
        except BaseException:
            pass


class ProcessTests(unittest.TestCase):
    def setUp(self):
        self.began = time.monotonic()

    def tearDown(self):
        RESULTS.append({"case": self._testMethodName, "elapsed_seconds": round(time.monotonic()-self.began, 6)})

    def test_explicit_sigkill_retains_parent_and_exact_one_spawn(self):
        root, payload = fixture("sigkill")
        child = start_helper(root, payload)
        try:
            ready = line(child)
            self.assertEqual(ready["event"], "ready")
            self.assertEqual(ready["child_identity"]["ps"]["ppid"], child.pid)
            self.assertEqual(w.exit_observation(child), None)
            native_pid = ready["child_identity"]["ps"]["pid"]
            self.assertEqual(w.ps_rows(native_pid)[0]["ppid"], child.pid)
            command(child, payload, "kill")
            terminal = line(child)
            self.assertTrue(terminal["ok"])
            self.assertEqual(terminal["cleanup"]["signals"], ["SIGKILL"])
            self.assertTrue(terminal["cleanup"]["leader_reaped"])
            self.assertTrue(terminal["cleanup"]["owned_live_group_empty"])
            self.assertEqual(reap_helper(child), 0)
            self.assertEqual(len((root/"native-starts.log").read_text().splitlines()), 1)
            self.assertFalse((root/"process.pid").exists())
            self.assertFalse((root/"foreground-watchdog.active.json").exists())
            durable = json.loads((root/"foreground-watchdog"/payload["launch_id"]/"terminal.json").read_text())
            self.assertFalse(durable["ok"])
            self.assertIsNone(durable["terminal_within_original_stop_deadline"])
            # A consumed nonce fails before a second native Popen, even though
            # the first child and active marker have been fully cleaned.
            duplicate = REAL_POPEN([str(PYTHON), "-B", str(root/SOURCE.name), "--serve",
                                   base64.b64encode(w.canonical(payload)).decode()],
                                  stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            stdout, stderr = duplicate.communicate(timeout=5)
            self.assertNotEqual(duplicate.returncode, 0)
            self.assertEqual(stdout, b"")
            self.assertEqual(len((root/"native-starts.log").read_text().splitlines()), 1)
        finally:
            emergency(child)

    def test_parent_eof_cleans_but_never_qualifies_sigkill_fault(self):
        root, payload = fixture("parent-eof")
        child = start_helper(root, payload)
        try:
            self.assertTrue(line(child)["ready"])
            child.stdin.close()
            terminal = line(child)
            self.assertFalse(terminal["ok"])
            self.assertEqual(terminal["stop_reason"], "foreground_parent_stdin_eof")
            self.assertTrue(terminal["stopped"])
            self.assertTrue(terminal["cleanup"]["leader_reaped"])
            self.assertTrue(terminal["cleanup"]["owned_live_group_empty"])
            self.assertEqual(reap_helper(child), 1)
            self.assertEqual(len((root/"native-starts.log").read_text().splitlines()), 1)
        finally:
            emergency(child)

    def test_normal_native_exit_is_preserved_and_never_restarted(self):
        root, payload = fixture("normal-exit", exit_after=1.5)
        child = start_helper(root, payload)
        try:
            self.assertTrue(line(child)["ready"])
            command(child, payload, "heartbeat")
            terminal = line(child)
            self.assertFalse(terminal["ok"])
            self.assertEqual(terminal["stop_reason"], "native_child_exited_without_requested_stop")
            self.assertEqual(terminal["cleanup"]["leader_exit_code"], 0)
            self.assertEqual(terminal["cleanup"]["signals"], [])
            self.assertTrue(terminal["cleanup"]["owned_live_group_empty"])
            self.assertEqual(reap_helper(child), 1)
            self.assertEqual(len((root/"native-starts.log").read_text().splitlines()), 1)
        finally:
            emergency(child)

    def test_real_zombie_and_same_pgid_survivor_need_no_live_sid_api(self):
        root, _ = fixture("zombie-survivor", same_group_survivor=True)
        child = REAL_POPEN([str(root/"heptabao-server")], stdin=subprocess.DEVNULL,
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
        owner = w.capture_child(child)
        try:
            until = time.monotonic()+3
            while w.exit_observation(child) is None and time.monotonic() < until:
                time.sleep(0.01)
            event = w.exit_observation(child)
            self.assertIsNotNone(event)
            self.assertEqual(w.exit_observation(child), event)
            self.assertIsNone(child.returncode)
            self.assertEqual(w.ps_rows(child.pid)[0]["state"][0], "Z")
            with patch.object(w.os, "getpgid", side_effect=AssertionError("zombie getpgid forbidden")), \
                 patch.object(w.os, "getsid", side_effect=AssertionError("zombie getsid forbidden")):
                # A first capture after a normal fast exit must also retain
                # the real ps/WNOWAIT identity without either live-only API.
                captured_zombie = w.capture_child(child)
                self.assertEqual(captured_zombie["ps"], owner["ps"])
                self.assertEqual(captured_zombie["captured_exit"], event)
                receipt = w.stop_unreaped(child, owner, until=time.monotonic()+5)
            self.assertTrue(receipt["live_group_before"])
            self.assertNotIn(child.pid, [row["pid"] for row in receipt["live_group_before"]])
            self.assertEqual(receipt["signals"], ["SIGKILL"])
            self.assertTrue(receipt["leader_reaped"])
            self.assertTrue(receipt["owned_live_group_empty"])
            self.assertEqual(receipt["leader_exit_code"], 0)
        finally:
            if child.returncode is None:
                w.stop_unreaped(child, owner, until=time.monotonic()+5)

    def test_changed_owner_refuses_every_signal(self):
        root, _ = fixture("changed-owner")
        child = REAL_POPEN([str(root/"heptabao-server")], stdin=subprocess.DEVNULL,
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
        owner = w.capture_child(child)
        changed = json.loads(json.dumps(owner))
        changed["ps"]["start"] += " changed"
        try:
            with patch.object(w.os, "killpg") as send:
                with self.assertRaisesRegex(w.Refusal, "identity_changed"):
                    w.stop_unreaped(child, changed, until=time.monotonic()+5)
                send.assert_not_called()
            self.assertIsNone(w.exit_observation(child))
        finally:
            w.stop_unreaped(child, owner, until=time.monotonic()+5)

    def test_stop_deadline_is_not_reset_by_delayed_observation(self):
        root, _ = fixture("stop-deadline")
        child = REAL_POPEN([str(root/"heptabao-server")], stdin=subprocess.DEVNULL,
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
        owner = w.capture_child(child)
        original = w.ps_rows
        def delayed(*args, **kwargs):
            time.sleep(0.08)
            return original(*args, **kwargs)
        try:
            with patch.object(w, "ps_rows", side_effect=delayed), patch.object(w.os, "killpg") as send:
                with self.assertRaisesRegex(w.Refusal, "deadline"):
                    w.stop_unreaped(child, owner, until=time.monotonic()+0.04)
                send.assert_not_called()
            self.assertIsNone(w.exit_observation(child))
        finally:
            w.stop_unreaped(child, owner, until=time.monotonic()+5)

    def test_local_supervisor_uses_one_foreground_channel_and_reaps_group(self):
        root, payload = fixture("supervisor")
        local_work = ROOT/"supervisor-controller"
        local_work.mkdir(mode=0o700)
        node = types.SimpleNamespace(alias="local-synthetic-only", root=str(root), node_id=1)
        session = w.ForegroundSession(node, payload["run_id"], local_work, payload["binary_sha256"], root/SOURCE.name,
            source_commit=payload["source_commit"], source_tree=payload["source_tree"],
            actual_host={"system":"Darwin", "host":platform.node()}, python_path=str(PYTHON),
            python_sha256=payload["python_sha256"])
        # The supervisor's real OS children and pipes are exercised locally.
        # Only the SSH executable transport is replaced, so no remote request is
        # possible. Linux is accurately retained as the executing test platform.
        session.payload["expected_system"] = platform.system()
        def local_transport(argv, *args, **kwargs):
            if argv[0] == "ssh":
                return REAL_POPEN([str(PYTHON), "-B", str(root/SOURCE.name), "--serve",
                                   base64.b64encode(w.canonical(session.payload)).decode()], *args, **kwargs)
            return REAL_POPEN(argv, *args, **kwargs)
        try:
            with patch.object(w.subprocess, "Popen", side_effect=local_transport):
                pid = session.start()
                session.assert_running()
                self.assertEqual(session.stop(), pid)
            self.assertEqual(session.receipt["submission_count"], 1)
            self.assertTrue(session.receipt["remote_cleanup"]["leader_reaped"])
            self.assertTrue(session.receipt["remote_cleanup"]["owned_live_group_empty"])
            self.assertTrue(session.receipt["local_ssh_cleanup"]["leader_reaped"])
            self.assertTrue(session.receipt["local_ssh_cleanup"]["owned_live_group_empty"])
            self.assertTrue(session.receipt["original_stop_deadline_satisfied"])
            self.assertIsNone(json.loads((session.phase/"complete.json").read_text())["original_stop_deadline_satisfied"])
            self.assertEqual(json.loads((session.phase/"terminal.json").read_text())["scope"],
                             "raw-remote-wire; controller-stop-deadline-not-certified")
            self.assertEqual(len((root/"native-starts.log").read_text().splitlines()), 1)
        finally:
            if not session.completed:
                try:
                    session.stop()
                except BaseException:
                    pass


def main():
    global ROOT, PYTHON
    parser=argparse.ArgumentParser()
    parser.add_argument("--work-root", type=Path, required=True)
    parser.add_argument("--child-python", type=Path, default=Path(sys.executable))
    args=parser.parse_args()
    PYTHON=args.child_python.resolve(strict=True)
    ROOT=args.work_root.resolve()
    ROOT.mkdir(mode=0o700)
    os.umask(0o077)
    began=time.monotonic()
    suite=unittest.defaultTestLoader.loadTestsFromTestCase(ProcessTests)
    result=unittest.TextTestRunner(verbosity=2).run(suite)
    receipt={"schema":"heptabao.native-foreground-owned-child-local-tests.v1",
             "status":"passed" if result.wasSuccessful() else "failed",
             "platform":platform.platform(),"python":sys.version,"pid":os.getpid(),
             "child_python_path":str(PYTHON),"child_python_sha256":w.digest(PYTHON.read_bytes()),
             "helper_sha256":w.digest(SOURCE.read_bytes()),"test_sha256":w.digest(Path(__file__).read_bytes()),
             "executed":result.testsRun,"failures":len(result.failures),"errors":len(result.errors),
             "cases":RESULTS,"elapsed_seconds":round(time.monotonic()-began,6),
             "real_processes":True,"ssh_or_remote_calls":False,"network_listeners":False,
             "actual_bao_binary_executed":False,"ha_qualification":False,
             "darwin_execution_proven":platform.system()=="Darwin",
             "zombie_live_api_negative_is_local_guard_test":True}
    w.new_file(ROOT/"receipt.json",w.canonical(receipt))
    print(json.dumps(receipt,indent=2))
    return 0 if result.wasSuccessful() else 1


if __name__=="__main__":
    raise SystemExit(main())
