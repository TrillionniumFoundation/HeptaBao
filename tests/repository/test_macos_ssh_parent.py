"""Fail-closed Mac SSH-parent fixture checks; no real network or secrets."""
from __future__ import annotations
import io
from pathlib import Path
import sys
import subprocess
import unittest
from unittest import mock

PROJECT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT / "qa" / "openbao-acceptance"))
import macos_ssh_parent as held

ROOT = "/Volumes/T5/hepta-vnext/HeptaBao-r565-crossarch-sshparent-20261012"
DIGEST = "a" * 64


class FakePopen:
    def __init__(self, line: str = "123 44\n"):
        self.stdin = io.StringIO()
        self.stdout = io.StringIO(line)
        self.stderr = io.StringIO()
        self.terminated = 0
        self.killed = 0
        self.waits = 0
        self.running = True
        self.timeout_on_first_wait = False

    def poll(self):
        return None if self.running else 0

    def terminate(self):
        self.terminated += 1
        self.running = False

    def kill(self):
        self.killed += 1
        self.running = False

    def wait(self, timeout=None):
        self.waits += 1
        if self.timeout_on_first_wait and self.waits == 1:
            raise subprocess.TimeoutExpired("synthetic", timeout)
        self.running = False
        return 0


class MacSshParentTests(unittest.TestCase):
    def test_alias_root_and_digest_are_closed(self):
        rejected = [
            ("rog-ts", ROOT, DIGEST),
            ("mac-ts", "/tmp/HeptaBao-fixture", DIGEST),
            ("mac-ts", ROOT + "/../escape", DIGEST),
            ("mac-ts", ROOT + " risky", DIGEST),
            ("mac-ts", ROOT, DIGEST.upper()),
            ("mac-ts", ROOT, "a" * 63),
        ]
        for args in rejected:
            with self.subTest(args=args):
                with self.assertRaises(held.HeldMacFixtureError):
                    held.HeldMacSshParent(*args)

    def test_single_parent_script_is_not_detached_or_privileged(self):
        script = held.startup_script(ROOT, DIGEST, ha=True)
        self.assertIn('wait "$pid"', script)
        self.assertIn('test "$parent" = "$$"', script)
        self.assertIn("--ha-config", script)
        self.assertIn('test "$actual" = ' + DIGEST, script)
        self.assertNotIn("nohup", script)
        self.assertNotIn("setsid", script)
        self.assertNotIn("sudo", script)
        self.assertNotIn("launchctl", script)
        self.assertNotIn("tccutil", script)

    def start_fake(self, line="123 44\n", ready=True):
        fake = FakePopen(line)
        session = held.HeldMacSshParent("mac-ts", ROOT, DIGEST)
        factory = mock.patch.object(held.subprocess, "Popen", return_value=fake)
        selector = mock.patch.object(
            held.select, "select",
            return_value=([fake.stdout], [], []) if ready else ([], [], []))
        return session, fake, factory, selector

    def test_live_ssh_parent_is_retained_and_original_wait_completed_once(self):
        session, fake, factory, selector = self.start_fake()
        with factory as process, selector:
            self.assertEqual(session.start(ha=True), 123)
            self.assertEqual(session.parent, 44)
            self.assertEqual(process.call_count, 1)
            argv = process.call_args.args[0]
            self.assertEqual(argv[-3:], ["mac-ts", "bash", "-s"])
            self.assertIs(session.process, fake)
        session.settle_after_verified_remote_stop()
        self.assertEqual(fake.waits, 1)
        self.assertTrue(fake.stdout.closed)
        self.assertTrue(fake.stderr.closed)

    def test_deny_missing_parent_and_close_owned_ssh(self):
        for line in ("", "123\n", "123 1\n", "not-a-pid\n"):
            with self.subTest(line=line):
                session, fake, factory, selector = self.start_fake(line)
                with factory, selector:
                    with self.assertRaises((held.HeldMacFixtureError, ValueError)):
                        session.start(ha=False)
                self.assertEqual(fake.terminated, 1)
                self.assertEqual(fake.waits, 1)
                self.assertTrue(fake.stdout.closed)
                self.assertIsNone(session.process)

    def test_startup_timeout_does_not_authorize_an_orphan(self):
        session, fake, factory, selector = self.start_fake(ready=False)
        with factory, selector:
            with self.assertRaisesRegex(held.HeldMacFixtureError, "timeout"):
                session.start(ha=True)
        self.assertEqual(fake.terminated, 1)
        self.assertIsNone(session.pid)

    def test_duplicate_start_never_sends_another_command(self):
        session, fake, factory, selector = self.start_fake()
        with factory as process, selector:
            self.assertEqual(session.start(ha=False), 123)
            with self.assertRaisesRegex(held.HeldMacFixtureError, "duplicate"):
                session.start(ha=False)
            self.assertEqual(process.call_count, 1)
        session.settle_after_verified_remote_stop()

    def test_lost_original_ssh_wait_does_not_count_as_cleanup(self):
        session, fake, factory, selector = self.start_fake()
        with factory, selector:
            self.assertEqual(session.start(ha=False), 123)
        fake.timeout_on_first_wait = True
        with self.assertRaisesRegex(held.HeldMacFixtureError, "failed_to_exit"):
            session.settle_after_verified_remote_stop()
        self.assertEqual(fake.terminated, 1)
        self.assertEqual(fake.waits, 2)
        self.assertTrue(fake.stdout.closed)

    def test_settle_without_original_process_is_rejected(self):
        session = held.HeldMacSshParent("mac-ts", ROOT, DIGEST)
        with self.assertRaisesRegex(held.HeldMacFixtureError, "owner_missing"):
            session.settle_after_verified_remote_stop()


if __name__ == "__main__":
    unittest.main()
