"""Exercise actual Chromium fixture staging; no browser or binary is launched."""
import hashlib
import importlib.util
import os
from pathlib import Path
import tempfile
import unittest


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


ROOT = Path(__file__).resolve().parents[2]
FIXTURE = load("browser_live_staging", Path(__file__).with_name("browser_live.py"))
INSTALLER = load("browser_live_installer", ROOT / "tools/install_personal_browser.py")


class BrowserFixtureStagingGuards(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="browser-stage-guard-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.root.chmod(0o700)
        self.build = self.root / "shared-build"
        self.build.mkdir(mode=0o777)
        self.build.chmod(0o777)
        self.work = self.root / "work"
        self.work.mkdir(mode=0o700)
        self.expected = {}
        for name in ("heptabao-vault", "heptabao-browser"):
            source = self.build / name
            raw = b"#!/bin/sh\nexit 0\n"
            source.write_bytes(raw)
            source.chmod(0o755)
            self.expected[name] = hashlib.sha256(raw).hexdigest()

    def stage(self):
        return FIXTURE.stage_binaries(self.build, self.work, self.expected)

    def test_actual_fixture_stages_private_copies_and_installer_uses_them(self):
        source = self.build / "heptabao-browser"
        os.link(source, self.build / "cargo-deps-artifact")
        with self.assertRaisesRegex(ValueError, "unprotected_parent"):
            INSTALLER.binary_identity(source)
        destination, rows = self.stage()
        self.assertEqual(destination, self.work / "native-binaries")
        self.assertEqual(len(rows), 2)
        for row in rows:
            original, staged = Path(row["source"]), Path(row["path"])
            self.assertEqual(row["sha256"], self.expected[original.name])
            self.assertEqual(staged.read_bytes(), original.read_bytes())
            self.assertNotEqual(staged.stat().st_ino, original.stat().st_ino)
            self.assertEqual(staged.stat().st_mode & 0o777, 0o700)
            self.assertEqual(staged.stat().st_nlink, 1)
            self.assertEqual(original.stat().st_mode & 0o777, 0o755)
        self.assertEqual(source.stat().st_nlink, 2)
        self.assertEqual(self.build.stat().st_mode & 0o777, 0o777)
        vault = self.work / "vault"
        vault.mkdir(mode=0o700)
        result = INSTALLER.install(destination / "heptabao-browser", vault,
                                   self.work / "host", self.work / "manifests", "a" * 32, 60)
        self.assertTrue(result["installed"])
        self.assertIn(str(destination / "heptabao-browser"),
                      (self.work / "host/native-host").read_text())

    def test_fixture_requires_protected_work_even_with_private_leaf(self):
        self.work = self.build / "private-work"
        self.work.mkdir(mode=0o700)
        with self.assertRaisesRegex(ValueError, "unprotected_parent"):
            self.stage()
        self.assertFalse((self.work / "native-binaries").exists())

    def test_fixture_keeps_original_digest_binding(self):
        (self.build / "heptabao-vault").write_bytes(b"#!/bin/sh\nexit 1\n")
        with self.assertRaisesRegex(Exception, "build_input_changed"):
            self.stage()

    def test_fixture_does_not_overwrite_prior_staging(self):
        destination, _ = self.stage()
        with self.assertRaises(FileExistsError):
            self.stage()
        self.assertEqual({path.name: hashlib.sha256(path.read_bytes()).hexdigest()
                          for path in destination.iterdir()}, self.expected)


if __name__ == "__main__":
    unittest.main(verbosity=2)
