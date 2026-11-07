#!/usr/bin/env python3
"""Eight local native-return fault gates with real held files; not Mac proof."""
import ctypes
import errno
import os
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch

import whole_sqlite_bundle_r2 as whole


class NativeResult:
    def __init__(self, result, error=0, mutate=None):
        self.result, self.error, self.mutate = result, error, mutate
        self.calls = []

    def __call__(self, fd, buffer, length, options):
        self.calls.append((fd, buffer, length, options))
        assert os.fstat(fd).st_nlink == 1
        assert buffer is None and length == options == 0
        if self.mutate:
            self.mutate()
        ctypes.set_errno(self.error)
        return self.result


class DarwinXattrTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="xattr-boundary-", dir=Path(__file__).parent)
        base = Path(self.tmp.name)
        (base / "archive").mkdir(mode=0o700)
        (base / "source").mkdir(mode=0o700)
        self.path = base / "source/file"
        fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        os.write(fd, b"synthetic only")
        os.close(fd)
        self.store = whole.WholeStore(root=base / "archive", source_root=base / "source",
                                      until=time.monotonic() + 10, source_vfs="unix")
        self.pin = whole.full9(self.path.lstat())

    def tearDown(self):
        self.store.close()
        self.assertTrue(all(item["closed"] and item["closeAttempts"] == 1 for item in self.store.fds))
        self.tmp.cleanup()

    def invoke(self, result, error=0, mutate=None):
        native = NativeResult(result, error, mutate)
        class Library:
            flistxattr = native
        with patch.object(whole.sys, "platform", "darwin"), patch.object(whole.ctypes, "CDLL", return_value=Library()) as load:
            try:
                return self.store.no_xattrs(self.path, self.pin)
            finally:
                load.assert_called_once_with("/usr/lib/libSystem.B.dylib", use_errno=True)
                self.assertEqual(len(native.calls), 1)
                self.assertEqual(native.argtypes, [ctypes.c_int, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int])
                self.assertIs(native.restype, ctypes.c_ssize_t)

    def test_exact_zero_absent_passes_and_closes(self):
        self.assertTrue(self.invoke(0))
        self.assertTrue(self.store.darwin_xattr_queries[-1]["descriptorClosedOnce"])

    def test_positive_length_refused_without_attribute_read(self):
        with self.assertRaises(whole.SnapshotRefused):
            self.invoke(7)

    def test_enotsup_refused(self):
        with self.assertRaises(whole.SnapshotRefused):
            self.invoke(-1, errno.ENOTSUP)

    def test_permission_error_refused(self):
        with self.assertRaises(whole.SnapshotRefused):
            self.invoke(-1, errno.EACCES)

    def test_zero_with_nonzero_errno_refused(self):
        with self.assertRaises(whole.SnapshotRefused):
            self.invoke(0, errno.ENOTSUP)

    def test_same_held_file_content_drift_refused(self):
        def mutate():
            with self.path.open("ab") as stream:
                stream.write(b"changed")
        with self.assertRaisesRegex(whole.SnapshotRefused, "same_held_file_after"):
            self.invoke(0, mutate=mutate)

    def test_named_inode_replacement_refused(self):
        def mutate():
            self.path.rename(self.path.with_suffix(".old"))
            self.path.write_bytes(b"synthetic only")
        with self.assertRaisesRegex(whole.SnapshotRefused, "same_held_file_after"):
            self.invoke(0, mutate=mutate)

    def test_missing_native_symbol_fails_and_closes(self):
        with patch.object(whole.sys, "platform", "darwin"), patch.object(whole.ctypes, "CDLL", return_value=object()):
            with self.assertRaises(AttributeError):
                self.store.no_xattrs(self.path, self.pin)


if __name__ == "__main__":
    unittest.main(verbosity=2)
