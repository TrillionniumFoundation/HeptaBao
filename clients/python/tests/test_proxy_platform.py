import os
from pathlib import Path
import socket
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from heptabao import proxy
from heptabao.private_state import StateDirectory
from heptabao.transport import BaoError


@unittest.skipUnless(sys.platform in ('linux', 'darwin'), 'kernel Unix credentials')
class ProxyPlatformTests(unittest.TestCase):
    def test_actual_socket_peer_uid_and_closed_peer_fail(self):
        a, b = socket.socketpair()
        try:
            self.assertEqual(proxy._peer_uid(a), os.geteuid())
        finally:
            a.close()
            b.close()
        with self.assertRaises((OSError, ValueError)):
            proxy._peer_uid(a)

    def test_actual_bind_failure_preserves_cwd_and_existing_socket(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            root.chmod(0o700)
            original_cwd = os.stat('.')
            with StateDirectory(root, writer=True) as directory:
                first = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                second = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                try:
                    proxy._bind_listener(first, directory)
                    before = os.stat('api.sock', dir_fd=directory.fd, follow_symlinks=False)
                    with self.assertRaises(OSError):
                        proxy._bind_listener(second, directory)
                    after = os.stat('api.sock', dir_fd=directory.fd, follow_symlinks=False)
                    self.assertEqual((before.st_dev, before.st_ino), (after.st_dev, after.st_ino))
                    restored = os.stat('.')
                    self.assertEqual((original_cwd.st_dev, original_cwd.st_ino),
                                     (restored.st_dev, restored.st_ino))
                finally:
                    first.close()
                    second.close()
                    os.unlink('api.sock', dir_fd=directory.fd)

    def test_directory_replacement_rejects_and_cleans_only_original_socket(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            current, retired = root/'current', root/'retired'
            current.mkdir(mode=0o700)
            real = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            original_cwd = os.stat('.')

            class RenameAtBind:
                def bind(self, path):
                    current.rename(retired)
                    current.mkdir(mode=0o700)
                    (current/'keep').write_bytes(b'replacement')
                    real.bind(path)

                def __getattr__(self, name):
                    return getattr(real, name)

            with patch.object(proxy.socket, 'socket', return_value=RenameAtBind()):
                with self.assertRaisesRegex(BaoError, 'state_directory_replaced'):
                    proxy.serve({'socket_dir':str(current), 'max_runtime_seconds':1,
                                 'max_requests':1}, None, threading.Event())
            self.assertFalse((retired/'api.sock').exists())
            self.assertFalse((current/'api.sock').exists())
            self.assertEqual((current/'keep').read_bytes(), b'replacement')
            restored = os.stat('.')
            self.assertEqual((original_cwd.st_dev, original_cwd.st_ino),
                             (restored.st_dev, restored.st_ino))

    @unittest.skipUnless(sys.platform == 'darwin', 'Darwin cwd restriction')
    def test_additional_thread_rejects_before_binding(self):
        stop = threading.Event()
        worker = threading.Thread(target=stop.wait)
        worker.start()
        try:
            with tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                root.chmod(0o700)
                with StateDirectory(root, writer=True) as directory:
                    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                    try:
                        with self.assertRaisesRegex(BaoError, 'single_thread'):
                            proxy._bind_listener(listener, directory)
                        self.assertFalse((root/'api.sock').exists())
                    finally:
                        listener.close()
        finally:
            stop.set()
            worker.join(timeout=2)
        self.assertFalse(worker.is_alive())

    @unittest.skipUnless(sys.platform == 'darwin', 'Darwin cwd restoration')
    def test_restore_failure_cleans_owned_inode_and_preserves_replacement(self):
        real_fchdir = os.fchdir
        for replace in (False, True):
            with self.subTest(replace=replace), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                root.chmod(0o700)
                previous = os.open('.', os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
                listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                replacement = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                calls = []

                with StateDirectory(root, writer=True) as directory:
                    def fail_restore(fd):
                        calls.append(fd)
                        if len(calls) == 2:
                            if replace:
                                os.unlink('api.sock', dir_fd=directory.fd)
                                replacement.bind('api.sock')
                            raise OSError(5, 'injected restoration failure')
                        return real_fchdir(fd)

                    try:
                        with patch.object(proxy.os, 'fchdir', side_effect=fail_restore):
                            with self.assertRaisesRegex(OSError, 'restoration failure'):
                                proxy._bind_listener(listener, directory)
                        self.assertEqual(listener.fileno(), -1)
                        self.assertEqual((root/'api.sock').exists(), replace)
                    finally:
                        # Only the test repairs its own injected cwd failure.
                        real_fchdir(previous)
                        os.close(previous)
                        listener.close()
                        replacement.close()
                        if replace and (root/'api.sock').exists():
                            os.unlink('api.sock', dir_fd=directory.fd)



if __name__ == '__main__':
    unittest.main()
