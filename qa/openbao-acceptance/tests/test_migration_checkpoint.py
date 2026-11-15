"""The logical migration adapters retain the same private lock boundary."""
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from bao_http import BaoError
import migrate_auth_mount
import migrate_identity
import migrate_kv2
import migrate_policies
import migrate_ssh_roles

ADAPTERS = (migrate_auth_mount, migrate_identity, migrate_kv2,
            migrate_policies, migrate_ssh_roles)


class MigrationCheckpointLockTests(unittest.TestCase):
    def test_private_lock_is_exclusive_and_released(self):
        for adapter in ADAPTERS:
            with self.subTest(adapter=adapter.__name__), tempfile.TemporaryDirectory() as directory:
                checkpoint = Path(directory) / "checkpoint"
                with adapter.CheckpointLock(checkpoint) as first:
                    info = os.fstat(first.fd)
                    self.assertTrue(stat.S_ISREG(info.st_mode))
                    self.assertEqual(stat.S_IMODE(info.st_mode), 0o600)
                    self.assertEqual(info.st_uid, os.geteuid())
                    with self.assertRaisesRegex(BaoError, "^checkpoint_locked_or_inaccessible$"):
                        with adapter.CheckpointLock(checkpoint):
                            self.fail("a second owner acquired the same checkpoint")
                with adapter.CheckpointLock(checkpoint) as next_owner:
                    self.assertTrue(stat.S_ISREG(os.fstat(next_owner.fd).st_mode))

    def test_nonprivate_lock_is_rejected_and_descriptor_is_closed(self):
        original_open = os.open
        for adapter in ADAPTERS:
            with self.subTest(adapter=adapter.__name__), tempfile.TemporaryDirectory() as directory:
                checkpoint = Path(directory) / "checkpoint"
                lock_path = Path(str(checkpoint) + ".lock")
                lock_path.write_bytes(b"existing")
                lock_path.chmod(0o644)
                opened = []

                def record_open(*args, **kwargs):
                    fd = original_open(*args, **kwargs)
                    opened.append(fd)
                    return fd

                lock = adapter.CheckpointLock(checkpoint)
                with patch("os.open", side_effect=record_open):
                    with self.assertRaisesRegex(BaoError, "^checkpoint_locked_or_inaccessible$"):
                        lock.__enter__()
                self.assertEqual(len(opened), 1)
                self.assertIsNone(lock.fd)
                with self.assertRaises(OSError):
                    os.fstat(opened[0])
                self.assertEqual(lock_path.read_bytes(), b"existing")

    def test_symlink_cannot_redirect_lock(self):
        for adapter in ADAPTERS:
            with self.subTest(adapter=adapter.__name__), tempfile.TemporaryDirectory() as directory:
                checkpoint = Path(directory) / "checkpoint"
                outside = Path(directory) / "outside"
                outside.write_bytes(b"unchanged")
                outside.chmod(0o600)
                Path(str(checkpoint) + ".lock").symlink_to(outside)
                with self.assertRaisesRegex(BaoError, "^checkpoint_locked_or_inaccessible$"):
                    with adapter.CheckpointLock(checkpoint):
                        self.fail("a symlink was accepted as the checkpoint lock")
                self.assertEqual(outside.read_bytes(), b"unchanged")

    def test_directory_cannot_be_used_as_lock(self):
        for adapter in ADAPTERS:
            with self.subTest(adapter=adapter.__name__), tempfile.TemporaryDirectory() as directory:
                checkpoint = Path(directory) / "checkpoint"
                Path(str(checkpoint) + ".lock").mkdir()
                with self.assertRaisesRegex(BaoError, "^checkpoint_locked_or_inaccessible$"):
                    with adapter.CheckpointLock(checkpoint):
                        self.fail("a directory was accepted as the checkpoint lock")


if __name__ == "__main__":
    unittest.main()
