"""No negative transport/harness result may masquerade as a passing profile."""
import contextlib
import io
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import core_isolation
import capabilities_live
import response_wrapping
import ssh_otp_live
from bao_http import BaoError, Client, Response, SafeArgumentParser, decode_json


class DeniedTransport:
    def request(self, *args, **kwargs):
        return Response(503, {"errors": ["do-not-log-private-response"], "auth": {"client_token": "never-export"}})


class RuntimeHarnessTests(unittest.TestCase):
    def test_wrapping_failure_retains_only_safe_observation(self):
        rows=[]
        with self.assertRaisesRegex(core_isolation.ScenarioFailure,"^wrap.create$"):
            response_wrapping.run_scenarios(DeniedTransport(),rows)
        self.assertEqual(rows,[{"case":"wrap.create","status":503,"passed":False}])
        self.assertNotIn("never-export",json.dumps(rows))
        self.assertNotIn("do-not-log-private-response",json.dumps(rows))

    def test_capability_failure_retains_only_safe_observation(self):
        rows=[]
        with self.assertRaisesRegex(core_isolation.ScenarioFailure,"^caps.root$"):
            capabilities_live.run_scenarios(DeniedTransport(),rows)
        self.assertEqual(rows,[{"case":"caps.root","status":503,"passed":False}])

    def test_all_profiles_preserve_partial_sink(self):
        for runner in (response_wrapping.run_scenarios,capabilities_live.run_scenarios,ssh_otp_live.run_scenarios):
            rows=[{"case":"earlier","passed":True}]
            with self.subTest(runner=runner),self.assertRaises(core_isolation.ScenarioFailure):
                runner(DeniedTransport(),rows)
            self.assertEqual(len(rows),2)
            self.assertFalse(core_isolation.successful_comparison({"candidate":rows,"oracle":rows},{}))

    def test_ssh_failure_never_records_credentials(self):
        rows=[]
        with self.assertRaises(core_isolation.ScenarioFailure):
            ssh_otp_live.run_scenarios(DeniedTransport(),rows)
        self.assertEqual(len(rows),1)
        self.assertIs(rows[0]["passed"],False)
        self.assertNotIn("never-export",json.dumps(rows))
        self.assertNotIn("do-not-log-private-response",json.dumps(rows))

    def test_shared_transport_rejects_duplicate_json(self):
        with self.assertRaises(BaoError):decode_json(b'{"status":false,"status":true}')

    def test_wrapping_header_injection_and_token_override_are_rejected(self):
        client=object.__new__(Client);client._token="synthetic";client.namespace=""
        for parameters in ({"wrap_ttl":"1s\r\nInjected: secret"},{"token":"value\nprivate"},{"wrap_ttl":"x"*65}):
            with self.subTest(parameters=parameters),self.assertRaises(BaoError):
                client.request("POST","/v1/sys/wrapping/wrap",{},**parameters)

    def test_sensitive_option_abbreviation_is_not_accepted(self):
        parser=SafeArgumentParser();parser.add_argument("--token-file")
        err=io.StringIO()
        with contextlib.redirect_stderr(err),self.assertRaises(SystemExit):
            parser.parse_args(["--token","do-not-print-secret"])
        self.assertNotIn("do-not-print-secret",err.getvalue())


if __name__=="__main__":unittest.main()
