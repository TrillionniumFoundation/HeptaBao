"""Fail-closed admission of an explicitly extracted QA-only OpenLDAP package."""
import ast
import os
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch

SOURCE = Path(__file__).resolve().parents[1] / "ldap_openldap_live.py"
TREE = ast.parse(SOURCE.read_text())
FUNCTIONS = [n for n in TREE.body if isinstance(n, ast.FunctionDef) and n.name in ("openldap_paths", "openldap_environment")]
NAMESPACE = {"Path": Path, "os": os, "shutil": shutil}
exec(compile(ast.Module(body=FUNCTIONS, type_ignores=[]), str(SOURCE), "exec"), NAMESPACE)
resolve = NAMESPACE["openldap_paths"]
child_env = NAMESPACE["openldap_environment"]


class OpenLdapPrerequisiteTests(unittest.TestCase):
    def populate(self, root):
        files = ["usr/sbin/slapd", "usr/lib/ldap/back_mdb.so"]
        files += ["etc/ldap/schema/" + name + ".schema" for name in ("core", "cosine", "nis", "inetorgperson")]
        for relative in files:
            path = root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("synthetic test input")
        (root / "usr/sbin/slapd").chmod(0o700)

    def test_private_distribution_paths_are_explicit(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            self.populate(root)
            with patch.dict(os.environ, {"HB_QA_OPENLDAP_ROOT": str(root)}):
                executable, schemas, modules, private = resolve()
                self.assertEqual(executable, root / "usr/sbin/slapd")
                self.assertEqual(schemas, root / "etc/ldap/schema")
                self.assertEqual(modules, root / "usr/lib/ldap")
                self.assertIs(private, True)

    def test_broad_access_missing_files_and_symlink_escape_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory, tempfile.TemporaryDirectory() as external:
            root = Path(directory).resolve()
            self.populate(root)
            with patch.dict(os.environ, {"HB_QA_OPENLDAP_ROOT": str(root)}):
                root.chmod(0o755)
                with self.assertRaises(ValueError):
                    resolve()
                root.chmod(0o700)
                module = root / "usr/lib/ldap/back_mdb.so"
                module.unlink()
                with self.assertRaises(FileNotFoundError):
                    resolve()
                foreign = Path(external) / "module"
                foreign.write_text("synthetic external module")
                module.symlink_to(foreign)
                with self.assertRaises(FileNotFoundError):
                    resolve()


    def test_private_loader_is_child_local_and_clears_ambient_injection(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            self.populate(root)
            libs = root / "usr/lib/test-linux-gnu"
            libs.mkdir()
            libs.chmod(0o755)
            (libs / "libslapi.so.2").write_text("synthetic shared library")
            (libs / "libslapi.so.2").chmod(0o644)
            ambient = {"LD_LIBRARY_PATH": "/untrusted", "LD_PRELOAD": "/untrusted/evil.so"}
            with patch.dict(os.environ, ambient):
                env = child_env(root / "usr/sbin/slapd", True)
                self.assertEqual(env["LD_LIBRARY_PATH"], str(libs))
                self.assertNotIn("LD_PRELOAD", env)
                self.assertEqual(os.environ["LD_LIBRARY_PATH"], "/untrusted")
                self.assertEqual(os.environ["LD_PRELOAD"], "/untrusted/evil.so")
                host = child_env(Path("/usr/sbin/slapd"), False)
                self.assertNotIn("LD_LIBRARY_PATH", host)
                self.assertNotIn("LD_PRELOAD", host)

    def test_missing_foreign_writable_and_ambiguous_libraries_fail_closed(self):
        with tempfile.TemporaryDirectory() as directory, tempfile.TemporaryDirectory() as external:
            root = Path(directory).resolve()
            self.populate(root)
            exe = root / "usr/sbin/slapd"
            with self.assertRaises(FileNotFoundError):
                child_env(exe, True)
            libs = root / "usr/lib/test-linux-gnu"
            libs.mkdir()
            libs.chmod(0o755)
            library = libs / "libslapi.so.2"
            foreign = Path(external) / "library"
            foreign.write_text("synthetic external library")
            library.symlink_to(foreign)
            with self.assertRaises(ValueError):
                child_env(exe, True)
            library.unlink()
            library.write_text("synthetic shared library")
            library.chmod(0o666)
            with self.assertRaises(ValueError):
                child_env(exe, True)
            library.chmod(0o644)
            libs.chmod(0o777)
            with self.assertRaises(ValueError):
                child_env(exe, True)
            libs.chmod(0o755)
            other = root / "usr/lib/other-linux-gnu"
            other.mkdir()
            (other / "libslapi.so.2").write_text("second architecture")
            with self.assertRaises(ValueError):
                child_env(exe, True)

    def test_relative_root_is_never_implicitly_resolved(self):
        with patch.dict(os.environ, {"HB_QA_OPENLDAP_ROOT": "."}):
            with self.assertRaises(ValueError):
                resolve()


if __name__ == "__main__":
    unittest.main()
