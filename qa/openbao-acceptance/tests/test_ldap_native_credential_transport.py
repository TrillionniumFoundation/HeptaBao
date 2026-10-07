"""Native LDAP consumers share the hashed-LDIF and anonymous bind-pipe boundary."""
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from ldap_native_live import NativeDirectory
from ldap_openldap_live import Directory


class NativeCredentialTransportTests(unittest.TestCase):
    def test_native_mutations_need_no_plaintext_password_file(self):
        with tempfile.TemporaryDirectory() as directory:
            fixture = NativeDirectory.__new__(NativeDirectory)
            fixture.root = Path(directory)
            fixture.user_password = "synthetic-user-not-for-disk"
            fixture._ldap_run = Mock()
            encoded = "{CRYPT}$6$fixture$synthetic-hash"
            with patch("ldap_native_live.password_hash", return_value=encoded) as hashed:
                dn = fixture.add_user("Bob", "bob")
                hashed.assert_called_once_with(fixture.user_password)
            fixture._ldap_run.assert_called_once_with(
                "ldapadd", "-f", str(fixture.root / "native-add.ldif")
            )
            ldif = (fixture.root / "native-add.ldif").read_text()
            self.assertIn(encoded, ldif)
            self.assertNotIn(fixture.user_password, ldif)
            self.assertEqual((fixture.root / "native-add.ldif").stat().st_mode & 0o777, 0o600)
            fixture._ldap_run.reset_mock()
            fixture.alias_attribute(["opaque-alias"])
            fixture._ldap_run.assert_called_once_with(
                "ldapmodify", "-f", str(fixture.root / "native-alias-attribute.ldif")
            )
            fixture._ldap_run.reset_mock()
            fixture.delete_user(dn)
            fixture._ldap_run.assert_called_once_with("ldapdelete", dn)
            self.assertFalse(hasattr(fixture, "password_file"))

    def test_bind_secret_uses_inherited_pipe_not_argv_or_environment(self):
        fixture = Directory.__new__(Directory)
        fixture.admin_password = "synthetic-bind-secret"
        fixture.admin_dn = "cn=fixture,dc=test"
        fixture.origin = "ldaps://127.0.0.1:16360"
        fixture.ldap_env = {"LDAPTLS_REQCERT": "demand"}
        captured = []

        def execute(argv, **kwargs):
            self.assertNotIn(fixture.admin_password, repr(argv))
            self.assertNotIn(fixture.admin_password, repr(kwargs["env"]))
            (fd,) = kwargs["pass_fds"]
            self.assertEqual(argv[argv.index("-y") + 1], "/dev/fd/" + str(fd))
            self.assertEqual(os.read(fd, 4096), fixture.admin_password.encode())
            self.assertTrue(kwargs["check"])
            self.assertEqual(kwargs["timeout"], 15)
            captured.append(fd)

        with patch("ldap_openldap_live.subprocess.run", side_effect=execute):
            fixture._ldap_run("ldapdelete", "cn=target,dc=test")
        self.assertEqual(len(captured), 1)
        with self.assertRaises(OSError):
            os.fstat(captured[0])

    def test_failed_bind_closes_the_pipe_without_changing_error(self):
        fixture = Directory.__new__(Directory)
        fixture.admin_password = "synthetic-bind-secret"
        fixture.admin_dn = "cn=fixture,dc=test"
        fixture.origin = "ldaps://127.0.0.1:16360"
        fixture.ldap_env = {}
        captured = []

        def fail(_argv, **kwargs):
            captured.extend(kwargs["pass_fds"])
            raise TimeoutError("synthetic timeout")

        with patch("ldap_openldap_live.subprocess.run", side_effect=fail):
            with self.assertRaises(TimeoutError):
                fixture._ldap_run("ldapdelete", "cn=target,dc=test")
        with self.assertRaises(OSError):
            os.fstat(captured[0])
