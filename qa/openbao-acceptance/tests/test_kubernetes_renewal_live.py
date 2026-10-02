"""Fail-closed guards for the synthetic Kubernetes renewal comparison."""
import base64
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from bao_http import Response
from core_isolation import ScenarioFailure, successful_comparison
from kubernetes_renewal_live import (ADAPTATION, AUDIENCE, REVIEW_PATH, Trace, assertion,
                                    configuration, issued_policy_snapshot, request_matches, role)
from remote_jwks_live import signing_key


class ReviewerStub:
    origin = "https://localhost:20000"
    reviewer = "private-reviewer-bearer"
    def __init__(self):
        self.calls = []


class ClientStub:
    def __init__(self, reviewer, *, status=200, calls_provider=False):
        self.reviewer, self.status, self.calls_provider = reviewer, status, calls_provider
    def request(self, *args, **kwargs):
        if self.calls_provider:
            self.reviewer.calls.append(REVIEW_PATH)
        return Response(self.status, {"auth": {"client_token": "private-service-bearer"},
                                     "errors": ["private-signed-jwt-and-error"]})


class KubernetesRenewalHarnessTests(unittest.TestCase):
    def test_success_cannot_hide_another_tokenreview(self):
        reviewer, rows = ReviewerStub(), []
        reviewer.calls.append(REVIEW_PATH)
        with self.assertRaisesRegex(ScenarioFailure, "^kubernetes_renewal.renew$"):
            Trace(ClientStub(reviewer, calls_provider=True), reviewer, rows).call(
                "renew", "auth/token/renew-self", no_provider=True)
        self.assertFalse(rows[-1]["no_provider_request"])
        self.assertNotIn("private", json.dumps(rows))
        self.assertFalse(successful_comparison({"candidate": rows, "oracle": rows}, {}))

    def test_provider_failure_is_not_native_renewal_success(self):
        reviewer, rows = ReviewerStub(), []
        with self.assertRaises(ScenarioFailure):
            Trace(ClientStub(reviewer, status=503), reviewer, rows).call(
                "renew", "auth/token/renew-self", no_provider=True)
        self.assertTrue(rows[-1]["no_provider_request"])
        self.assertFalse(rows[-1]["passed"])
        self.assertNotIn("private", json.dumps(rows))

    def test_requests_bind_exact_spec_and_reviewer_with_explicit_type_meta_difference(self):
        spec = {"token": "private-assertion", "audiences": [AUDIENCE]}
        oracle = {"spec": spec, "metadata": {"creationTimestamp": None}, "status": {"user": {}}}
        candidate = {"spec": spec, "apiVersion": "authentication.k8s.io/v1", "kind": "TokenReview"}
        for side, body in [("candidate", candidate), ("oracle", oracle)]:
            args = (REVIEW_PATH, body, ["Bearer private-reviewer"], "private-reviewer", "private-assertion", side)
            self.assertTrue(request_matches(*args))
            self.assertFalse(request_matches(REVIEW_PATH, body, ["Bearer wrong"], *args[3:]))
            self.assertFalse(request_matches("/wrong", *args[1:]))
            self.assertFalse(request_matches(REVIEW_PATH, dict(body, spec=dict(spec, audiences=["other"])), *args[2:]))
            self.assertFalse(request_matches(REVIEW_PATH, dict(body, spec=dict(spec, token="wrong")), *args[2:]))
            self.assertFalse(request_matches(REVIEW_PATH, body, ["Bearer private-reviewer"] * 2, *args[3:]))
        self.assertFalse(request_matches(REVIEW_PATH, oracle, ["Bearer private-reviewer"], "private-reviewer", "private-assertion", "candidate"))
        self.assertFalse(request_matches(REVIEW_PATH, candidate, ["Bearer private-reviewer"], "private-reviewer", "private-assertion", "oracle"))

    def test_assertion_has_array_audience_and_matching_serviceaccount(self):
        private, jwk = signing_key("ES256", "synthetic")
        signed = assertion(private, jwk, exp=12345)
        segment = signed.split(".")[1]
        claims = json.loads(base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4)))
        self.assertEqual(claims["aud"], [AUDIENCE])
        self.assertEqual(claims["exp"], 12345)
        self.assertEqual(claims["kubernetes.io/serviceaccount/namespace"], "workload")
        self.assertEqual(claims["kubernetes.io/serviceaccount/service-account.name"], "worker")

    def test_policy_snapshot_cannot_silently_be_replaced(self):
        self.assertTrue(issued_policy_snapshot({"token_policies": ["default", "kube-old"]}))
        for policies in [["kube-new"], ["kube-old", "kube-new"], [], "kube-old", None]:
            self.assertFalse(issued_policy_snapshot({"token_policies": policies}))

    def test_full_role_updates_and_zero_defaults_are_preserved(self):
        value = role(token_ttl=0, token_max_ttl=0, token_period=20, token_explicit_max_ttl=120)
        self.assertEqual(value["token_ttl"], 0)
        self.assertEqual(value["token_max_ttl"], 0)
        self.assertEqual(value["bound_service_account_names"], ["worker"])
        self.assertEqual(value["audience"], AUDIENCE)

    def test_configuration_adaptation_never_claims_api_parity(self):
        private, _ = signing_key("ES256", "synthetic")
        candidate = configuration("candidate", ReviewerStub(), private, "private-ca")
        oracle = configuration("oracle", ReviewerStub(), private, "private-ca")
        self.assertNotIn("pem_keys", candidate)
        self.assertEqual(candidate["kubernetes_ca_cert"], "private-ca")
        self.assertEqual(candidate["kubernetes_ca_cert"], oracle["kubernetes_ca_cert"])
        self.assertIn("PUBLIC KEY", oracle["pem_keys"][0])
        self.assertNotIn("PRIVATE KEY", json.dumps(oracle))
        self.assertEqual(candidate["token_reviewer_jwt"], oracle["token_reviewer_jwt"])
        self.assertIs(ADAPTATION["configuration_api_parity"], False)


if __name__ == "__main__":
    unittest.main()
