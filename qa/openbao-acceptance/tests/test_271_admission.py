"""OpenBao 2.7.1 acceptance selector: synthetic unit probes, never deployment evidence."""
import contextlib
import io
import json
from pathlib import Path
import sys
import unittest
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import acceptance
from bao_http import BaoError, verify_oracle_identity


class OpenBao271GateTests(unittest.TestCase):
    def test_explicit_271_selection_still_fails_closed_without_real_endpoints(self):
        stream = io.StringIO()
        with patch.object(acceptance.Client, "from_env", side_effect=BaoError("unconfigured")), contextlib.redirect_stdout(stream):
            code = acceptance.main(["--compare", "--oracle-version", "2.7.1"])
        receipt = json.loads(stream.getvalue())
        self.assertEqual(code, 2)
        self.assertEqual(receipt["target"], "OpenBao 2.7.1")
        self.assertFalse(receipt["production_qualified"])
        self.assertFalse(receipt["full_openbao_compatibility"])
        self.assertEqual(receipt["status"], "failed")

    def test_271_pinned_identity_requires_matching_live_version_origin_and_provenance(self):
        version = "2.7.1"
        endpoint = "https://127.0.0.1:28271"
        client = SimpleNamespace(address=endpoint)
        health = {"version": version, "cluster_id": "synthetic-unique-cluster"}
        receipt = {"product": "OpenBao", "version": version,
                   "artifact_sha256": "a"*64,
                   "provenance_url": "https://github.com/openbao/openbao/releases/tag/v2.7.1",
                   "endpoint": endpoint, "cluster_id": health["cluster_id"]}
        result = verify_oracle_identity(receipt, client, health, version=version)
        self.assertEqual(result["version"], version)
        self.assertFalse(result["independent_binary_attestation"])
        defects = [("product", "HeptaBao"), ("version", "2.7.0"),
                   ("artifact_sha256", "0"*64),
                   ("provenance_url", "https://github.com/openbao/openbao/releases/tag/v2.7.0"),
                   ("endpoint", "https://127.0.0.1:28272"),
                   ("cluster_id", "unrelated-cluster")]
        for key, bad in defects:
            with self.subTest(key=key):
                forged = dict(receipt)
                forged[key] = bad
                with self.assertRaises(BaoError):
                    verify_oracle_identity(forged, client, health, version=version)
        with self.assertRaises(BaoError):
            verify_oracle_identity(receipt, client, {**health, "version": "2.7.0"}, version=version)
        with self.assertRaises(BaoError):
            verify_oracle_identity(receipt, client, health, version="2.7.2")


if __name__ == "__main__":
    unittest.main()
