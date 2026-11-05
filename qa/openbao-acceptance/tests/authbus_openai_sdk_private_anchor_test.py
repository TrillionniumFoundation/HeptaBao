#!/usr/bin/env python3
"""Real local filesystem boundaries for the SDK-only private-ancestor reader."""
import hashlib
import importlib.util
import os
from pathlib import Path
import stat
import tempfile
import time
import types
import unittest
from unittest import mock


HERE = Path(__file__).resolve()
SPEC = importlib.util.spec_from_file_location("sdk_private_reader_under_test",
                                             HERE.parents[1] / "authbus_openai_sdk_once.py")
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)
RAW = b"// owned synthetic SDK input; no installed SDK executed\n"
SHA = hashlib.sha256(RAW).hexdigest()


class PrivateSdkInputChecks(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="heptabao-sdk-private-anchor-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.anchor = self.root / "private-task-root"
        self.anchor.mkdir(mode=0o700)
        self.sdk = self.anchor / "sdk-install" / "openclaw"
        self.sdk.mkdir(parents=True)
        self.path = self.sdk / "dist" / "input.js"
        self.path.parent.mkdir()
        for directory in (self.sdk.parent, self.sdk, self.path.parent):
            directory.chmod(0o775)
        self.path.write_bytes(RAW)
        self.path.chmod(0o664)
        for name, value in (("HOST_ROOT", self.anchor), ("SDK_ROOT", self.sdk)):
            patch = mock.patch.object(MODULE, name, value)
            patch.start()
            self.addCleanup(patch.stop)
        MODULE.SIGNALS.clear()

    def read(self, path=None, expected=SHA, deadline_ns=None):
        return MODULE.read_pinned_sdk_input(path or self.path, maximum=1024,
                                            expected=expected, deadline_ns=deadline_ns)

    def test_actual_group_write_modes_are_accepted_only_beneath_private_anchor(self):
        before = {p: p.stat().st_mode for p in (self.anchor, self.sdk.parent, self.sdk,
                                                self.path.parent, self.path)}
        raw, observed = self.read()
        self.assertEqual(raw, RAW)
        self.assertEqual(observed["sha256"], SHA)
        self.assertEqual(observed["mode"], "0664")
        self.assertEqual([row["mode"] for row in observed["directories"]],
                         ["0700", "0775", "0775", "0775"])
        self.assertEqual(before, {p: p.stat().st_mode for p in before})

    def test_a_nonprivate_anchor_is_rejected_before_reading_any_input_bytes(self):
        for mode in (0o750, 0o755, 0o770, 0o775):
            with self.subTest(mode=oct(mode)):
                self.anchor.chmod(mode)
                with mock.patch.object(MODULE.os, "read", wraps=os.read) as reads:
                    with self.assertRaisesRegex(MODULE.Refusal, "sdk_private_ancestor_0700_required"):
                        self.read()
                    reads.assert_not_called()
        self.anchor.chmod(0o700)

    def test_the_private_rule_cannot_be_applied_to_a_sibling_outside_the_sdk(self):
        path = self.anchor / "other.js"
        path.write_bytes(RAW)
        path.chmod(0o664)
        with mock.patch.object(MODULE.os, "read", wraps=os.read) as reads:
            with self.assertRaisesRegex(MODULE.Refusal, "fixed_sdk_private_read_scope_required"):
                self.read(path)
            reads.assert_not_called()

    def test_symlink_components_and_a_symlink_final_input_are_rejected(self):
        alias = self.sdk / "alias"
        alias.symlink_to(self.path.parent, target_is_directory=True)
        for candidate in (alias / "input.js", self.sdk / "alias.js"):
            with self.subTest(candidate=candidate.name):
                if candidate.name == "alias.js":
                    candidate.symlink_to(self.path)
                with self.assertRaisesRegex(MODULE.Refusal, "fixed_sdk_private_read_scope_required"):
                    self.read(candidate)

    def test_hardlinks_and_world_writable_input_or_directory_remain_forbidden(self):
        link = self.sdk / "extra-link.js"
        os.link(self.path, link)
        with self.assertRaisesRegex(MODULE.Refusal, "pinned_sdk_regular_custody_required"):
            self.read()
        link.unlink()
        self.path.chmod(0o666)
        with self.assertRaisesRegex(MODULE.Refusal, "pinned_sdk_regular_custody_required"):
            self.read()
        self.path.chmod(0o664)
        self.path.parent.chmod(0o777)
        with self.assertRaisesRegex(MODULE.Refusal, "sdk_directory_owner_custody_required"):
            self.read()

    def test_generic_input_and_directory_rules_keep_rejecting_group_write(self):
        with self.assertRaisesRegex(MODULE.Refusal, "bounded_regular_file_custody_required"):
            MODULE.read_regular(self.path, maximum=1024, expected=SHA)
        with self.assertRaisesRegex(MODULE.Refusal, "owned_directory_custody_required"):
            MODULE.safe_directory(self.sdk)

    def test_missing_hash_wrong_hash_and_expired_original_deadline_are_rejected(self):
        with self.assertRaisesRegex(MODULE.Refusal, "pinned_sdk_hash_required"):
            self.read(expected=None)
        with self.assertRaisesRegex(MODULE.Refusal, "file_hash_mismatch"):
            self.read(expected="0" * 64)
        with mock.patch.object(MODULE.os, "read", wraps=os.read) as reads:
            with self.assertRaisesRegex(MODULE.Refusal, "original_180_second_deadline_expired"):
                self.read(deadline_ns=time.monotonic_ns() - 1)
            reads.assert_not_called()

    def test_a_different_file_uid_is_rejected_without_chown_or_permission_changes(self):
        actual_fstat = os.fstat

        def observed(fd):
            value = actual_fstat(fd)
            if not stat.S_ISREG(value.st_mode):
                return value
            fields = {key: getattr(value, key) for key in dir(value) if key.startswith("st_")}
            fields["st_uid"] = os.geteuid() + 1
            return types.SimpleNamespace(**fields)

        with mock.patch.object(MODULE.os, "fstat", side_effect=observed):
            with self.assertRaisesRegex(MODULE.Refusal, "pinned_sdk_regular_custody_required"):
                self.read()

    def test_private_ancestor_permission_change_during_read_is_not_ignored(self):
        actual_read = os.read
        changed = False

        def changing_read(fd, limit):
            nonlocal changed
            raw = actual_read(fd, limit)
            if not changed:
                changed = True
                self.anchor.chmod(0o750)
            return raw

        with mock.patch.object(MODULE.os, "read", side_effect=changing_read):
            with self.assertRaisesRegex(MODULE.Refusal, "sdk_directory_changed_during_read"):
                self.read()
        self.anchor.chmod(0o700)

    def test_each_opened_descriptor_is_closed_after_a_failed_hash_check(self):
        actual_open = os.open
        descriptors = []

        def opened(*args, **kwargs):
            fd = actual_open(*args, **kwargs)
            descriptors.append(fd)
            return fd

        with mock.patch.object(MODULE.os, "open", side_effect=opened):
            with self.assertRaisesRegex(MODULE.Refusal, "file_hash_mismatch"):
                self.read(expected="f" * 64)
        self.assertGreaterEqual(len(descriptors), 2)
        for fd in descriptors:
            with self.assertRaises(OSError):
                os.fstat(fd)


if __name__ == "__main__":
    unittest.main(verbosity=2)
