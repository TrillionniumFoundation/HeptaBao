import contextlib
import io
import json
import os
from pathlib import Path
import sys
import subprocess
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from heptabao import cli
from heptabao.transport import BaoError, Client, Response, decode_json


class ClientBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.token = self.root / "token"
        self.token.write_text("synthetic-secret-bearer")
        self.token.chmod(0o600)
        self.payload = self.root / "input.json"
        self.payload.write_text('{"v":"synthetic-private-payload"}')
        self.payload.chmod(0o600)
        self.base = ["--address", "https://localhost:8200", "--ca-file", "unused.crt",
                     "--token-file", str(self.token), "--output", str(self.root / "result.json")]

    def execute(self, arguments, response=None):
        stdout, stderr = io.StringIO(), io.StringIO()
        with patch.object(cli, "Client") as factory, contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            factory.return_value.request.return_value = response or Response(200, {"data":{"v":"synthetic-secret-output"}})
            code = cli.main(arguments)
        return code, stdout.getvalue(), stderr.getvalue(), factory

    def test_write_requires_explicit_admission_before_constructing_transport(self):
        code, _, err, factory = self.execute(self.base + ["write", "secret/data/a", "--input", str(self.payload)])
        self.assertEqual(code, 2); factory.assert_not_called()
        self.assertIn("explicit_write_admission_required", err)

    def test_response_is_private_and_diagnostics_are_redacted(self):
        code, out, err, factory = self.execute(self.base + ["read", "secret/data/a"])
        self.assertEqual(code, 0)
        self.assertEqual(factory.return_value.request.call_count, 1)
        for secret in ("synthetic-secret-output", "synthetic-secret-bearer", str(self.root)):
            self.assertNotIn(secret, out + err)
        self.assertEqual((self.root / "result.json").stat().st_mode & 0o777, 0o600)
        self.assertEqual(json.loads((self.root / "result.json").read_text()), {"data":{"v":"synthetic-secret-output"}})

    def test_existing_output_prevents_request(self):
        (self.root / "result.json").write_text("untouched")
        code, _, _, factory = self.execute(self.base + ["read", "secret/data/a"])
        self.assertEqual(code, 2); factory.assert_not_called()
        self.assertEqual((self.root / "result.json").read_text(), "untouched")

    def test_symlink_output_prevents_request(self):
        (self.root / "result.json").symlink_to(self.payload)
        code, _, _, factory = self.execute(self.base + ["read", "secret/data/a"])
        self.assertEqual(code, 2); factory.assert_not_called()

    def test_public_output_directory_prevents_request(self):
        self.root.chmod(0o755)
        code, _, _, factory = self.execute(self.base + ["read", "secret/data/a"])
        self.assertEqual(code, 2); factory.assert_not_called()
        self.root.chmod(0o700)

    def test_public_or_symlink_token_file_prevents_request(self):
        self.token.chmod(0o644)
        code, _, _, factory = self.execute(self.base + ["read", "secret/data/a"])
        self.assertEqual(code, 2); factory.assert_not_called()
        self.token.unlink(); self.token.symlink_to(self.payload)
        code, _, _, factory = self.execute(self.base + ["read", "secret/data/a"])
        self.assertEqual(code, 2); factory.assert_not_called()

    def test_mutation_failure_is_not_retried_or_echoed(self):
        stderr = io.StringIO()
        with patch.object(cli, "Client") as factory, contextlib.redirect_stderr(stderr):
            factory.return_value.request.side_effect = BaoError("transport_outcome_unknown")
            code = cli.main(self.base + ["--allow-write", "write", "secret/data/a", "--input", str(self.payload)])
        self.assertEqual(code, 2);self.assertEqual(factory.return_value.request.call_count, 1)
        self.assertIn('"automatic_retry": false', stderr.getvalue())
        self.assertNotIn("synthetic-private-payload", stderr.getvalue())

    def test_server_error_is_not_printed_as_a_secret(self):
        code, out, err, _ = self.execute(self.base + ["read", "a"], Response(403,{"errors":["sentinel-do-not-print"]}))
        self.assertEqual(code,1);self.assertNotIn("sentinel-do-not-print",out+err)

    def test_rejected_argv_is_not_echoed(self):
        stderr=io.StringIO()
        with contextlib.redirect_stderr(stderr),self.assertRaises(SystemExit):
            cli.main(self.base+["--token","secret-on-argv","read","a"])
        self.assertNotIn("secret-on-argv",stderr.getvalue())

    def test_duplicate_or_nonfinite_json_rejected(self):
        for data in (b'{"v":1,"v":2}',b'{"x":{"v":1,"v":2}}',b'{"v":NaN}'):
            with self.subTest(data=data),self.assertRaises(BaoError):decode_json(data)

    def test_timeout_bounds_checked_before_tls_configuration(self):
        for timeout in (0,-1,61,float("inf"),float("nan"),True):
            with self.subTest(timeout=timeout),self.assertRaisesRegex(BaoError,"invalid_timeout"):
                Client("https://localhost","not-used","synthetic",timeout=timeout)

    def test_capability_target_is_file_only_and_path_bounded(self):
        code,_,_,factory=self.execute(self.base+["capabilities","secret/data/a","--target-token-file",str(self.token)])
        self.assertEqual(code,0)
        self.assertEqual(factory.return_value.request.call_args.args[1],"/v1/sys/capabilities")
        (self.root/"result.json").unlink()
        code,_,_,factory=self.execute(self.base+["capabilities","../escape"])
        self.assertEqual(code,2);factory.assert_not_called()

    def test_unwrap_does_not_mix_two_authentication_tokens(self):
        code,_,_,factory=self.execute(self.base+["--allow-write","unwrap","--wrapping-token-file",str(self.token)])
        self.assertEqual(code,2);factory.assert_not_called()

    def test_fifo_token_file_is_rejected_without_waiting_for_a_writer(self):
        if not hasattr(os,"mkfifo"):
            self.skipTest("POSIX FIFO is required")
        path=self.root/"fifo"
        os.mkfifo(path,0o600)
        code="""from heptabao.transport import private_read, BaoError
import sys
try:
    private_read(sys.argv[1])
except BaoError as error:
    sys.exit(0 if error.code == 'file_requires_owner_only_regular_file' else 2)
sys.exit(1)
"""
        environment=os.environ.copy()
        environment["PYTHONPATH"]=str(Path(__file__).resolve().parents[1])
        result=subprocess.run([sys.executable,"-c",code,str(path)],env=environment,
                              capture_output=True,timeout=3,check=False)
        self.assertEqual(result.returncode,0)
        self.assertEqual(result.stdout,b"")
        self.assertEqual(result.stderr,b"")

    def test_ambiguous_namespace_is_not_silently_normalized(self):
        for namespace in ("/", "/team", "team//", "team//child"):
            with self.subTest(namespace=namespace),self.assertRaisesRegex(BaoError,"invalid_namespace"):
                Client("https://localhost","not-used","synthetic",namespace=namespace)

    def test_header_injection_rejected_before_network(self):
        client=object.__new__(Client)
        client._token="synthetic"
        client.namespace=""
        for ttl in ("1s\r\nX-Secret: value", "", "x"*65):
            with self.subTest(ttl=ttl),self.assertRaises(BaoError):
                client.request("POST","/v1/sys/wrapping/wrap",{},wrap_ttl=ttl)


if __name__ == "__main__":
    unittest.main()
