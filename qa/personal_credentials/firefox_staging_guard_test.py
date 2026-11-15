#!/usr/bin/env python3
"""Exercise real filesystem staging while retaining the installer boundary."""
import hashlib
import importlib.util
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


ROOT = Path(__file__).resolve().parents[2]
FIXTURE = load("firefox_fixture", Path(__file__).with_name("firefox_native_cli.py"))
INSTALLER = load("firefox_installer", ROOT / "tools" / "install_personal_firefox.py")


class BinaryStaging(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.root.chmod(0o700)
        self.source = self.root / "built-browser"
        self.raw = b"#!/bin/sh\nexit 0\n"
        self.source.write_bytes(self.raw)
        self.source.chmod(0o755)
        self.destination = self.root / "staged-browser"
        self.digest = hashlib.sha256(self.raw).hexdigest()

    def stage(self):
        return FIXTURE.stage_binary(self.source, self.destination, self.digest)

    def test_cargo_style_hardlink_is_copied_without_relaxing_installer(self):
        alias = self.root / "deps-browser"
        os.link(self.source, alias)
        with self.assertRaisesRegex(INSTALLER.Refused, "owned_executable_required"):
            INSTALLER.binary_identity(self.source)
        row = self.stage()
        self.assertEqual(row["source_nlink"], 2)
        self.assertEqual(row["staged_nlink"], 1)
        self.assertEqual(self.source.stat().st_nlink, 2)
        self.assertEqual(alias.read_bytes(), self.raw)
        self.assertEqual(INSTALLER.binary_identity(self.destination),
                         {"bytes": len(self.raw), "sha256": self.digest})
        vault = self.root / "vault"
        vault.mkdir(mode=0o700)
        result = INSTALLER.install(self.destination, vault, self.root / "installation",
                                   INSTALLER.ADDON_ID, 60)
        self.assertTrue(result["prepared"])
        self.assertEqual(result["binary"]["sha256"], self.digest)
        self.assertIn(str(self.destination), Path(result["launcher"]).read_text())
        self.assertFalse(result["browser_registered"])

    def test_single_link_build_still_produces_distinct_inode(self):
        row = self.stage()
        self.assertEqual(row["source_nlink"], 1)
        self.assertNotEqual(self.source.stat().st_ino, self.destination.stat().st_ino)
        self.assertEqual(self.destination.stat().st_mode & 0o777, 0o700)
        self.assertEqual(self.destination.read_bytes(), self.raw)

    def test_existing_destination_and_symlink_are_not_overwritten(self):
        for linked in (False, True):
            with self.subTest(linked=linked):
                if linked:
                    self.destination.symlink_to(self.source)
                else:
                    self.destination.write_bytes(b"existing")
                with self.assertRaises(FileExistsError):
                    self.stage()
                self.assertEqual(self.destination.read_bytes(), self.raw if linked else b"existing")
                self.destination.unlink()
                self.assertEqual(self.source.read_bytes(), self.raw)

    def test_symlink_and_writable_build_inputs_are_refused(self):
        actual = self.root / "actual"
        self.source.rename(actual)
        self.source.symlink_to(actual)
        with self.assertRaises(OSError):
            self.stage()
        self.assertFalse(self.destination.exists())
        self.source.unlink()
        actual.rename(self.source)
        self.source.chmod(0o777)
        with self.assertRaisesRegex(FIXTURE.Failure, "owned_build_executable_required"):
            self.stage()
        self.assertFalse(self.destination.exists())

    def test_nonprivate_parent_is_refused(self):
        self.root.chmod(0o755)
        with self.assertRaisesRegex(FIXTURE.Failure, "private_binary_parent_required"):
            self.stage()
        self.assertFalse(self.destination.exists())

    def test_wrong_digest_refused_without_overwrite_retry(self):
        self.digest = "0" * 64
        with self.assertRaisesRegex(FIXTURE.Failure, "build_input_changed"):
            self.stage()
        retained = self.destination.read_bytes()
        self.digest = hashlib.sha256(self.raw).hexdigest()
        with self.assertRaises(FileExistsError):
            self.stage()
        self.assertEqual(self.destination.read_bytes(), retained)

    def test_same_size_build_input_change_during_copy_is_refused(self):
        self.source.write_bytes(b"a" * (2 * 1024 * 1024))
        self.digest = FIXTURE.sha(self.source)
        original_fdopen = os.fdopen
        source = self.source

        class ChangingStream:
            def __init__(self, stream):
                self.stream, self.changed = stream, False

            def __enter__(self):
                return self

            def __exit__(self, *args):
                return self.stream.__exit__(*args)

            def fileno(self):
                return self.stream.fileno()

            def read(self, size):
                data = self.stream.read(size)
                if data and not self.changed:
                    self.changed = True
                    with source.open("r+b") as changing:
                        changing.write(b"b")
                        changing.flush()
                        os.fsync(changing.fileno())
                return data

        def fdopen(descriptor, mode):
            stream = original_fdopen(descriptor, mode)
            return ChangingStream(stream) if mode == "rb" else stream

        with patch.object(FIXTURE.os, "fdopen", side_effect=fdopen):
            with self.assertRaisesRegex(FIXTURE.Failure, "build_input_changed"):
                self.stage()


if __name__ == "__main__":
    unittest.main(verbosity=2)
