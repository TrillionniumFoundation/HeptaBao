"""Real filesystem admission controls; no browser or executable is launched."""
import importlib.util
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("browser_installer", ROOT / "tools/install_personal_browser.py")
INSTALLER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(INSTALLER)
FIREFOX_SPEC = importlib.util.spec_from_file_location("firefox_installer", ROOT / "tools/install_personal_firefox.py")
FIREFOX = importlib.util.module_from_spec(FIREFOX_SPEC)
FIREFOX_SPEC.loader.exec_module(FIREFOX)


class BrowserInstallerGuards(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="browser-install-guard-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.root.chmod(0o700)
        self.binary = self.root / "synthetic-browser"
        self.binary.write_bytes(b"#!/bin/sh\nexit 0\n")
        self.binary.chmod(0o755)
        self.vault = self.root / "vault"
        self.vault.mkdir(mode=0o700)
        self.installation = self.root / "installation"
        self.manifests = self.root / "browser" / "NativeMessagingHosts"

    def install(self):
        return INSTALLER.install(self.binary, self.vault, self.installation,
                                 self.manifests, "a" * 32, 60)

    def test_private_install_preserves_exact_caller_and_create_only_contract(self):
        result = self.install()
        self.assertTrue(result["installed"])
        manifest = json.loads(Path(result["manifest"]).read_text())
        self.assertEqual(manifest["allowed_origins"], ["chrome-extension://" + "a" * 32 + "/"])
        self.assertEqual(manifest["path"], str(self.installation / "native-host"))
        config = json.loads(Path(result["config"]).read_text())
        self.assertEqual(config, {"vault_root": str(self.vault), "extension_id": "a" * 32,
                                  "unlock_seconds": 60})
        self.assertIn(str(self.binary), (self.installation / "native-host").read_text())
        for directory in (self.installation, self.manifests, self.manifests.parent):
            self.assertEqual(directory.stat().st_mode & 0o777, 0o700)
        with self.assertRaises(FileExistsError):
            self.install()
        self.assertEqual(json.loads(Path(result["manifest"]).read_text()), manifest)

    def test_writable_and_setid_executables_refused_before_publication(self):
        for mode in (0o775, 0o757, 0o777, 0o4755, 0o2755, 0o644):
            with self.subTest(mode=oct(mode)):
                self.binary.chmod(mode)
                with self.assertRaisesRegex(ValueError, "owned_executable_required"):
                    self.install()
                self.assertFalse(self.installation.exists())

    def test_writable_installation_parent_refused_before_publication(self):
        for mode in (0o770, 0o777):
            with self.subTest(mode=oct(mode)):
                self.root.chmod(mode)
                with self.assertRaisesRegex(ValueError, "unprotected_parent"):
                    self.install()
                self.assertFalse(self.installation.exists())

    def test_private_leaf_does_not_hide_a_replaceable_ancestor(self):
        shared = self.root / "shared"
        shared.mkdir(mode=0o777)
        shared.chmod(0o777)
        private = shared / "private"
        private.mkdir(mode=0o700)
        self.installation = private / "installation"
        with self.assertRaisesRegex(ValueError, "unprotected_parent"):
            self.install()
        self.assertFalse(self.installation.exists())

    def test_nonprivate_installation_parent_refused(self):
        self.root.chmod(0o755)
        with self.assertRaisesRegex(ValueError, "private_directory_required"):
            self.install()
        self.assertFalse(self.installation.exists())

    def test_executable_cannot_be_replaced_through_writable_parent(self):
        shared = self.root / "shared"
        shared.mkdir(mode=0o777)
        shared.chmod(0o777)
        destination = shared / self.binary.name
        self.binary.rename(destination)
        self.binary = destination
        with self.assertRaisesRegex(ValueError, "unprotected_parent"):
            self.install()
        self.assertFalse(self.installation.exists())

    def test_existing_manifest_directory_must_be_private(self):
        self.manifests.mkdir(parents=True)
        self.manifests.chmod(0o777)
        with self.assertRaisesRegex(ValueError, "private_directory_required"):
            self.install()
        self.assertFalse(self.installation.exists())
        self.assertEqual(list(self.manifests.iterdir()), [])

    def test_symlink_and_dangling_link_never_become_executable_inputs(self):
        actual = self.binary.with_name("actual")
        self.binary.rename(actual)
        self.binary.symlink_to(actual)
        with self.assertRaisesRegex(ValueError, "symlink_rejected"):
            self.install()
        self.binary.unlink()
        self.binary.symlink_to(actual.with_name("absent"))
        with self.assertRaisesRegex(ValueError, "symlink_rejected"):
            self.install()
        self.assertFalse(self.installation.exists())

    def test_symlink_ancestor_is_refused(self):
        target = self.root / "actual"
        target.mkdir(mode=0o700)
        alias = self.root / "alias"
        alias.symlink_to(target, target_is_directory=True)
        self.manifests = alias / "NativeMessagingHosts"
        with self.assertRaisesRegex(ValueError, "symlink_rejected"):
            self.install()
        self.assertFalse(self.installation.exists())

    def test_nonregular_executable_is_refused_without_a_blocking_read(self):
        self.binary.unlink()
        os.mkfifo(self.binary, 0o700)
        with self.assertRaisesRegex(ValueError, "owned_executable_required"):
            self.install()
        self.assertFalse(self.installation.exists())

    def test_same_bytes_replacement_during_install_cannot_publish_success(self):
        original = INSTALLER.create
        changed = False

        def replace(path, *args):
            nonlocal changed
            original(path, *args)
            if not changed:
                changed = True
                replacement = self.binary.with_name("replacement")
                replacement.write_bytes(self.binary.read_bytes())
                replacement.chmod(0o755)
                os.replace(replacement, self.binary)

        with patch.object(INSTALLER, "create", side_effect=replace):
            with self.assertRaisesRegex(ValueError, "installation_changed"):
                self.install()
        self.assertTrue(changed)
        self.assertTrue(self.installation.exists())  # No uncertain cleanup/retry.


class FirefoxInstallerPathGuards(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="firefox-install-guard-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.root.chmod(0o700)
        self.binary = self.root / "synthetic-host"
        self.binary.write_bytes(b"#!/bin/sh\nexit 0\n")
        self.binary.chmod(0o700)
        self.vault = self.root / "vault"
        self.vault.mkdir(mode=0o700)
        self.installation = self.root / "installation"

    def install(self):
        return FIREFOX.install(self.binary, self.vault, self.installation, FIREFOX.ADDON_ID, 60)

    def test_private_leaf_under_replaceable_ancestor_refused(self):
        shared = self.root / "shared"
        shared.mkdir(mode=0o777)
        shared.chmod(0o777)
        private = shared / "private"
        private.mkdir(mode=0o700)
        self.installation = private / "installation"
        with self.assertRaisesRegex(FIREFOX.Refused, "unprotected_parent"):
            self.install()
        self.assertFalse(self.installation.exists())

    def test_owned_sticky_ancestor_keeps_protected_private_install_supported(self):
        sticky = self.root / "sticky"
        sticky.mkdir(mode=0o700)
        sticky.chmod(0o1777)
        private = sticky / "private"
        private.mkdir(mode=0o700)
        self.installation = private / "firefox-installation"
        self.assertTrue(self.install()["prepared"])
        chrome = INSTALLER.install(self.binary, self.vault, private / "chromium-installation",
                                   private / "manifests", "a" * 32, 60)
        self.assertTrue(chrome["installed"])

    def test_same_bytes_replacement_cannot_publish_success(self):
        original = FIREFOX.create
        replaced = False

        def replace(path, *args):
            nonlocal replaced
            original(path, *args)
            if not replaced:
                replaced = True
                replacement = self.binary.with_name("replacement")
                replacement.write_bytes(self.binary.read_bytes())
                replacement.chmod(0o700)
                os.replace(replacement, self.binary)

        with patch.object(FIREFOX, "create", side_effect=replace):
            with self.assertRaisesRegex(FIREFOX.Refused, "binary_changed"):
                self.install()
        self.assertTrue(replaced)

    def test_symlink_replacement_during_install_is_refused(self):
        original = FIREFOX.create
        replaced = False

        def replace(path, *args):
            nonlocal replaced
            original(path, *args)
            if not replaced:
                replaced = True
                target = self.binary.with_name("original")
                self.binary.rename(target)
                self.binary.symlink_to(target)

        with patch.object(FIREFOX, "create", side_effect=replace):
            with self.assertRaisesRegex(FIREFOX.Refused, "symlink_rejected"):
                self.install()
        self.assertTrue(replaced)

    def test_foreign_owned_executable_is_refused_by_both_installers(self):
        # Observe a foreign-owned system utility where available. Some container
        # images also give its ancestors a foreign owner, which must fail first.
        # Then isolate the executable-owner rule using a real private descriptor
        # with substituted owner metadata; no chown/elevation occurs.
        candidates = [path.resolve() for path in (Path("/usr/bin/true"), Path("/bin/true"))
                      if path.exists() and path.stat().st_uid != os.geteuid()]
        for module, failure in ((INSTALLER, ValueError), (FIREFOX, FIREFOX.Refused)):
            with self.subTest(installer=module.__name__):
                if candidates:
                    with self.assertRaisesRegex(failure, "^(owned_executable_required|unprotected_parent)$"):
                        module.binary_identity(candidates[0])
                observed = self.binary.stat()
                foreign = SimpleNamespace(st_mode=observed.st_mode,
                                          st_uid=os.geteuid() + 1, st_nlink=1)
                with patch.object(module.os, "fstat", return_value=foreign):
                    with self.assertRaisesRegex(failure, "^owned_executable_required$"):
                        module.binary_identity(self.binary)

    def test_nonregular_input_is_rejected_without_blocking(self):
        self.binary.unlink()
        os.mkfifo(self.binary, 0o700)
        with self.assertRaisesRegex(FIREFOX.Refused, "owned_executable_required"):
            self.install()
        self.assertFalse(self.installation.exists())


if __name__ == "__main__":
    unittest.main(verbosity=2)
