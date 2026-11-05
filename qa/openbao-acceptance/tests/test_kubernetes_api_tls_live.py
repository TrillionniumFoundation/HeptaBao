import copy
from pathlib import Path
import sys
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from kubernetes_api_tls_live import Failure, Trace, REQUIRED_CASES, config_variant, safe_rows
from bao_http import Response


class KubernetesApiTlsGuards(unittest.TestCase):
    def test_reviewer_variants_preserve_ca_and_do_not_alias(self):
        original = {"token_reviewer_jwt": "synthetic-secret", "kubernetes_ca_cert": "public-ca"}
        saved = copy.deepcopy(original)
        for value in ("omitted", None, ""):
            result = config_variant(original, value)
            self.assertEqual(result["kubernetes_ca_cert"], "public-ca")
            if value == "omitted":
                self.assertNotIn("token_reviewer_jwt", result)
            else:
                self.assertEqual(result["token_reviewer_jwt"], value)
        self.assertEqual(original, saved)

    def test_trace_never_copies_secret_response(self):
        class Client:
            def request(self, *args, **kwargs):
                return Response(503, {"auth": {"client_token": "sensitive-sentinel"}})
        rows = []
        with self.assertRaises(Failure):
            Trace(Client(), rows, "kubernetes").call("login", "auth/k/login", expected=200)
        self.assertNotIn("sensitive-sentinel", repr(rows))
        self.assertEqual(rows[0]["status"], 503)
        self.assertFalse(rows[0]["passed"])

    def test_trace_rejects_string_observations(self):
        rows = []
        with self.assertRaises(Failure):
            Trace(None, rows, "kubernetes").check("secret", True, bearer="synthetic-secret")
        self.assertEqual(rows, [])

    def test_completion_rejects_failure_duplicate_and_extra_secret(self):
        row = {"case": "api_tls.kubernetes.complete", "passed": True}
        valid = [{"case": "api_tls.kubernetes." + name, "passed": True} for name in sorted(REQUIRED_CASES - {"complete"})] + [row]
        self.assertTrue(safe_rows(valid))
        self.assertFalse(safe_rows([row]))
        for rows in ([], [dict(row, passed=False)], [row, row], [dict(row, bearer="secret")],
                     [dict(row, case="api_tls.kubernetes.login")]):
            self.assertFalse(safe_rows(rows))


if __name__ == "__main__":
    unittest.main()
