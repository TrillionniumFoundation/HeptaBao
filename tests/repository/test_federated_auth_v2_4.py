from pathlib import Path
import unittest


class FederatedAuthV24Tests(unittest.TestCase):
    def test_fail_closed_signed_and_replay_contracts_exist(self):
        source = Path("crates/heptabao-federated-auth/src/lib.rs").read_text(encoding="utf-8")
        for marker in ("DuplicateJsonKey", "AlgorithmDenied", "required_namespace", "record_once", "OutcomeUnknown", "channel_binding"):
            self.assertIn(marker, source)

    def test_open_provider_boundaries_are_documented(self):
        guide = Path("docs/modules/heptabao-federated-auth.md").read_text(encoding="utf-8")
        self.assertIn("Kubernetes, LDAP, TLS certificate and cloud-IAM adapters", guide)
        self.assertIn("independent provider qualification remain separate gates", guide)


if __name__ == "__main__":
    unittest.main()
