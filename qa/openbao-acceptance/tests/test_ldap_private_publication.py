"""Synthetic regression cases for exact-text, private LDAP fixture publication."""
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from ldap_openldap_live import private
from heptabao.transport import BaoError


class PrivateLdapPublicationTests(unittest.TestCase):
    def test_exact_text_is_replaced_atomically_without_changing_open_reader(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "fixture.ldif"
            before = "dn: cn=before,dc=test\n\n"
            after = "dn: cn=after,dc=test\ncn: \u03b1\n\n"
            private(path, before)
            with path.open("rb") as reader:
                private(path, after)
                self.assertEqual(reader.read(), before.encode())
            self.assertEqual(path.read_bytes(), after.encode())
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_symlink_leaf_cannot_modify_target(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "original"
            target.write_text("fixture-original")
            target.chmod(0o600)
            link = root / "fixture.ldif"
            link.symlink_to(target)
            with self.assertRaises((BaoError, OSError)):
                private(link, "fixture-replacement")
            self.assertEqual(target.read_text(), "fixture-original")
            self.assertTrue(link.is_symlink())

    def test_shared_parent_is_rejected_before_creation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            root.chmod(0o755)
            path = root / "fixture.ldif"
            try:
                with self.assertRaises((BaoError, OSError)):
                    private(path, "fixture-value")
                self.assertFalse(path.exists())
            finally:
                root.chmod(0o700)

    def test_existing_nonprivate_file_is_not_truncated_or_chmodded(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "fixture.ldif"
            path.write_text("fixture-original")
            path.chmod(0o644)
            with self.assertRaises((BaoError, OSError)):
                private(path, "fixture-replacement")
            self.assertEqual(path.read_text(), "fixture-original")
            self.assertEqual(path.stat().st_mode & 0o777, 0o644)

    def test_atomic_replacement_does_not_change_other_hardlink(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path, alias = root / "fixture.ldif", root / "retained"
            private(path, "fixture-original")
            os.link(path, alias)
            private(path, "fixture-replacement")
            self.assertEqual(alias.read_text(), "fixture-original")
            self.assertEqual(path.read_text(), "fixture-replacement")

    def test_permissive_umask_never_publishes_a_nonprivate_temporary(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "fixture.ldif"
            modes = []
            rename = os.rename
            def observed(source, destination, **kwargs):
                info = os.stat(source, dir_fd=kwargs["src_dir_fd"], follow_symlinks=False)
                modes.append(info.st_mode & 0o777)
                return rename(source, destination, **kwargs)
            previous = os.umask(0)
            try:
                with patch("heptabao.transport.os.rename", side_effect=observed):
                    private(path, "fixture-value")
            finally:
                os.umask(previous)
            self.assertEqual(modes, [0o600])
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_prepublication_fsync_failure_preserves_previous_file(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "fixture.ldif"
            private(path, "fixture-original")
            with patch("heptabao.transport.os.fsync", side_effect=OSError("fixture failure")):
                with self.assertRaises((BaoError, OSError)):
                    private(path, "fixture-replacement")
            self.assertEqual(path.read_text(), "fixture-original")
            self.assertEqual(list(Path(directory).glob(".bao-write-*")), [])


if __name__ == "__main__":
    unittest.main()
