import importlib.util
import json
from pathlib import Path
import tempfile
import sys
import unittest


SCRIPT = Path("scripts/openbao_differential_runner_v2_4.py")
SPEC = importlib.util.spec_from_file_location("openbao_diff_v24", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)


class OpenBaoDifferentialRunnerV24Tests(unittest.TestCase):
    def write_json(self, root, name, value):
        path = Path(root) / name
        path.write_text(json.dumps(value), encoding="utf-8")
        return path

    def test_profile_requires_exact_denominator(self):
        with tempfile.TemporaryDirectory() as root:
            denominator = self.write_json(root, "denominator.json", {"surfaces": [{"surface_id": "A"}, {"surface_id": "B"}]})
            profile = self.write_json(root, "profile.json", {"surfaces": [{"surface_id": "A", "request": {"method": "GET", "path": "/v1/sys/health"}}]})
            with self.assertRaises(MODULE.CaptureError):
                MODULE.load_profile(profile, denominator)

    def test_profile_denies_embedded_credentials_and_redirects(self):
        with tempfile.TemporaryDirectory() as root:
            denominator = self.write_json(root, "denominator.json", {"surfaces": [{"surface_id": "A"}]})
            profile = self.write_json(root, "profile.json", {"surfaces": [{"surface_id": "A", "request": {"method": "GET", "path": "/v1/sys/health", "headers": {"X-Vault-Token": "secret"}}}]})
            with self.assertRaises(MODULE.CaptureError):
                MODULE.load_profile(profile, denominator)
            with self.assertRaises(MODULE.CaptureError):
                MODULE.NoRedirect().redirect_request(None, None, 302, "", {}, "https://evil.example")

    def test_secret_values_are_replaced_by_bounded_digests(self):
        value = MODULE._redact({"token": "secret-value", "nested": {"password": "pw"}, "safe": "visible"})
        encoded = json.dumps(value)
        self.assertNotIn("secret-value", encoded)
        self.assertNotIn('"pw"', encoded)
        self.assertIn("redacted_sha256", encoded)
        self.assertEqual(value["safe"], "visible")

    def test_comparison_requires_independent_oracle_and_exact_surface_match(self):
        candidate = {"mode": "candidate", "producer": "repository-controlled", "profile_sha256": "a", "denominator_sha256": "b", "surface_count": 1, "observations": [{"surface_id": "A", "status": 200, "response_bytes": 2, "canonical_sha256": "d" * 64}]}
        oracle = {"mode": "oracle", "producer": "independent-lab", "profile_sha256": "a", "denominator_sha256": "b", "surface_count": 1, "observations": [{"surface_id": "A", "status": 200, "response_bytes": 2, "canonical_sha256": "d" * 64}]}
        candidate["artifact_sha256"] = MODULE._sha256(MODULE._canonical_json_bytes(candidate))
        oracle["artifact_sha256"] = MODULE._sha256(MODULE._canonical_json_bytes(oracle))
        result = MODULE.compare_artifacts(candidate, oracle)
        self.assertTrue(result["compatible"])
        oracle["producer"] = "repository-controlled"
        with self.assertRaises(MODULE.CaptureError):
            MODULE.compare_artifacts(candidate, oracle)

    def test_tampered_artifact_digest_is_rejected(self):
        artifact = {"mode": "candidate", "producer": "repository-controlled", "profile_sha256": "a", "denominator_sha256": "b", "surface_count": 1, "observations": [{"surface_id": "A", "status": 200, "response_bytes": 0, "canonical_sha256": "0" * 64}]}
        artifact["artifact_sha256"] = MODULE._sha256(MODULE._canonical_json_bytes(artifact))
        artifact["observations"][0]["status"] = 201
        with self.assertRaises(MODULE.CaptureError):
            MODULE._validate_capture_artifact(artifact, "candidate")


if __name__ == "__main__":
    unittest.main()
