"""Real LDAP-secret probes use anonymous bind pipes, not legacy secret files."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import openldap_secret_live as target


class OpenLdapSecretTransportTests(unittest.TestCase):
    def fixture(self, root):
        return SimpleNamespace(root=Path(root), admin_dn="cn=admin,dc=test",
            admin_password="synthetic-manager", origin="ldaps://127.0.0.1:16360",
            ldap_env={"LDAPTLS_REQCERT": "demand"})

    def test_manager_and_issued_credentials_use_pipe_only(self):
        with tempfile.TemporaryDirectory() as root:
            directory = self.fixture(root)
            for password in (None, "synthetic-issued-secret"):
                with self.subTest(issued=password is not None):
                    captured = []
                    secret = directory.admin_password if password is None else password
                    def execute(argv, **kwargs):
                        self.assertNotIn(secret, repr(argv) + repr(kwargs["env"]))
                        (fd,) = kwargs["pass_fds"]
                        captured.append(fd)
                        self.assertEqual(argv[argv.index("-y") + 1], "/dev/fd/" + str(fd))
                        self.assertEqual(os.read(fd, 4096), secret.encode())
                        self.assertEqual(os.read(fd, 1), b"")
                        self.assertEqual(kwargs["timeout"], 6)
                        return subprocess.CompletedProcess(argv, 49, "", "")
                    with patch.object(target.subprocess, "run", side_effect=execute):
                        result = target.command(directory, "ldapwhoami", dn="cn=issued,dc=test", password=password)
                    self.assertEqual(result.returncode, 49)
                    self.assertEqual(list(Path(root).iterdir()), [])
                    with self.assertRaises(OSError):
                        os.fstat(captured[0])

    def test_process_failure_closes_pipe_and_preserves_error(self):
        captured = []
        def fail(_argv, **kwargs):
            captured.extend(kwargs["pass_fds"])
            raise TimeoutError("synthetic timeout")
        with tempfile.TemporaryDirectory() as root:
            with patch.object(target.subprocess, "run", side_effect=fail):
                with self.assertRaisesRegex(TimeoutError, "synthetic timeout"):
                    target.command(self.fixture(root), "ldapwhoami")
        with self.assertRaises(OSError):
            os.fstat(captured[0])

    def test_write_failure_closes_both_fds_without_double_close(self):
        real_pipe, real_fdopen = os.pipe, os.fdopen
        captured = []
        def pipe():
            pair = real_pipe()
            captured.extend(pair)
            return pair
        class FailingStream:
            def __init__(self, fd, *args, **kwargs):
                self.inner = real_fdopen(fd, *args, **kwargs)
            def __enter__(self):
                return self
            def __exit__(self, *_):
                self.inner.close()
            def write(self, _):
                raise BrokenPipeError("synthetic write failure")
        with tempfile.TemporaryDirectory() as root:
            with patch.object(target.os, "pipe", side_effect=pipe), patch.object(target.os, "fdopen", side_effect=FailingStream):
                with patch.object(target.subprocess, "run") as run:
                    with self.assertRaisesRegex(BrokenPipeError, "synthetic write failure"):
                        target.command(self.fixture(root), "ldapwhoami")
                    run.assert_not_called()
        for fd in captured:
            with self.assertRaises(OSError):
                os.fstat(fd)
