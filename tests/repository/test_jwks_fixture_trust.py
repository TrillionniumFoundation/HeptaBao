"""Exercise native CA configuration on both sides without launching providers."""
from __future__ import annotations

import ast
from pathlib import Path
from types import SimpleNamespace
import unittest

ROOT = Path(__file__).resolve().parents[2]
FIXTURES = ROOT / "qa/openbao-acceptance"


class NativeJwksFixtureTrustTests(unittest.TestCase):
    def test_same_per_mount_ca_is_sent_to_candidate_and_oracle(self):
        path = FIXTURES / "remote_jwks_compare.py"
        tree = ast.parse(path.read_text())
        function = next(node for node in tree.body
                        if isinstance(node, ast.FunctionDef) and node.name == "scenarios")
        namespace = {
            "signing_key": lambda *args: (None, {}),
            "token": lambda private, jwk, issuer, **claims: (issuer, claims),
        }
        exec(compile(ast.Module(body=[function], type_ignores=[]), str(path), "exec"), namespace)
        for is_oracle in (False, True):
            with self.subTest(is_oracle=is_oracle):
                issuer = SimpleNamespace(origin="https://fixture.invalid:443", documents={})
                configs = []

                def request(method, route, body):
                    status = 204
                    response = {}
                    if route.endswith("/config"):
                        configs.append(dict(body))
                        if "jwks_url" in body and "oidc_discovery_url" in body:
                            status = 400
                    elif route.endswith("/login"):
                        origin, claims = body["jwt"]
                        status = 400 if (origin != issuer.origin or claims.get("aud") == "wrong"
                                         or claims.get("exp") == 1001) else 200
                        response = {"auth": {"entity_id": "one-subject"}}
                    return SimpleNamespace(status=status, body=response)

                results = []
                namespace["scenarios"](SimpleNamespace(request=request), issuer,
                                       "fixture-ca-pem", is_oracle, results)
                self.assertEqual(len(configs), 4)
                self.assertTrue(all(case["passed"] for case in results))
                for config in configs:
                    field = "jwks_ca_pem" if "jwks_ca_pem" in config else "oidc_discovery_ca_pem"
                    self.assertEqual(config.get(field), "fixture-ca-pem")
                self.assertEqual(configs[0]["jwks_ca_pem"], configs[2]["oidc_discovery_ca_pem"])

    def test_slow_provider_profile_has_native_trust_and_untrusted_negative_case(self):
        tree = ast.parse((FIXTURES / "provider_concurrency_live.py").read_text())
        configs = [node for node in ast.walk(tree) if isinstance(node, ast.Dict)
                   and any(isinstance(key, ast.Constant) and key.value == "jwks_url"
                           for key in node.keys)]
        self.assertEqual(len(configs), 2)
        with_ca = [node for node in configs
                   if any(isinstance(key, ast.Constant) and key.value == "jwks_ca_pem"
                          for key in node.keys)]
        self.assertEqual(len(with_ca), 1)
        checks = [node.args[0].value for node in ast.walk(tree)
                  if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                  and node.func.id == "check" and node.args
                  and isinstance(node.args[0], ast.Constant)]
        self.assertIn("untrusted_jwks_configuration_rejected", checks)
        self.assertIn("durable_kv_write_completed_while_provider_blocked", checks)
        self.assertIn("remote_login_completed_after_release", checks)


if __name__ == "__main__":
    unittest.main()
