from pathlib import Path
import unittest


class HaMutualTlsV24Tests(unittest.TestCase):
    def test_mtls_and_certificate_node_binding_exist(self):
        source=Path("crates/heptabao-ha-service/src/lib.rs").read_text(encoding="utf-8")
        for marker in ("MutualTlsPeerTransport", "ServerName::try_from", "peer_certificates", "PinnedClientCertificateMap", "complete_io"):
            self.assertIn(marker,source)

    def test_certificate_lifecycle_boundary_is_explicit(self):
        guide=Path("docs/modules/heptabao-ha-service.md").read_text(encoding="utf-8")
        self.assertIn("Certificate issuance, revocation, rotation",guide)
        self.assertIn("external operational gates",guide)


if __name__ == "__main__":
    unittest.main()
