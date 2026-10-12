"""Strict OpenBao 2.7.1 migration oracle/version tests; no authority grant."""
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import bao_http
import official_openbao_launcher as launcher


class OpenBao271MigrationGateTests(unittest.TestCase):
    ARCHIVE = "0e2f1ce10d124e03112b50dd2fbec6b78003783253bc3a91587938f39d1e2243"
    BINARY = "535cf827b13753046757f5ec8b97ae0ef21f10a40ffe673f0d5e75616170f5ea"

    def test_legacy_oracle_behavior_profiles_remain_explicitly_unqualified(self):
        self.assertEqual(launcher.SUPPORTED_VERSIONS, ("2.6.2", "2.7.0"))
        self.assertEqual(launcher.MIGRATION_ORACLE_VERSIONS, ("2.6.2", "2.7.0", "2.7.1"))

    def test_exact_271_release_pins_and_no_unverified_architecture(self):
        assets=launcher.release_artifacts("2.7.1")
        self.assertEqual(set(assets), {("linux","amd64")})
        self.assertEqual(assets[("linux","amd64")],
                         {"artifact_sha256":self.ARCHIVE,"binary_sha256":self.BINARY})
        self.assertEqual(launcher.pinned_artifact("linux","amd64",version="2.7.1"),assets[("linux","amd64")])

    def test_271_defaults_to_pebbledb_with_only_explicit_raft_override(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)
            self.assertEqual(launcher.storage_configuration(root,version="2.7.1"),
                             {"pebbledb":{"path":str(root/"data")}})
            self.assertEqual(launcher.storage_configuration(root,version="2.7.1",raft_storage=True),
                             {"raft":{"path":str(root/"data"),"node_id":"synthetic-openbao-1"}})
            self.assertEqual(launcher.storage_configuration(root,version="2.6.2"),
                             {"file":{"path":str(root/"data")}})

    def test_migration_source_exact_known_versions_and_fail_closed_other_types(self):
        for version in ("2.6.2","2.7.0","2.7.1"):
            self.assertTrue(bao_http.supported_migration_source_version(version))
        for value in ("2.8.0","2.7.1-dev","HeptaBao-2.7.1","",None,True,["2.7.1"]):
            with self.subTest(value=value):
                self.assertFalse(bao_http.supported_migration_source_version(value))

    def test_271_unsupported_platform_denied_before_artifact_or_private_reads(self):
        with patch.object(launcher,"_platform_key",return_value=("darwin","arm64")), \
             patch.object(launcher,"file_digest") as read:
            with self.assertRaisesRegex(bao_http.BaoError,"unsupported_platform"):
                launcher.verify_inputs(version="2.7.1")
            read.assert_not_called()

    def test_271_selected_fixture_requires_exact_hash_version_and_pebble_backend(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)
            identity=root/"identity.json"
            config=root/"server.json"
            pins={"artifact_sha256":self.ARCHIVE,"binary_sha256":self.BINARY}
            backend={"pebbledb":{"path":str(root/"data")}}
            fixture={"product":"OpenBao","version":"2.7.1",**pins,
                "endpoint":"https://127.0.0.1:18881","cluster_id":"synthetic-cluster",
                "storage":"pebbledb","server_mode":"server_not_dev",
                "tls_verified":True,"synthetic_only":True,
                "archive_member_matches_executable":True,
                "provenance_url":"https://github.com/openbao/openbao/releases/tag/v2.7.1"}
            oracle={"root":str(root),"identity_file":str(identity),
                "address":fixture["endpoint"],"cluster_id":fixture["cluster_id"],
                "version":"2.7.1","storage_backend":"pebbledb",**pins}
            health={"version":"2.7.1","cluster_id":fixture["cluster_id"]}
            config.write_text(json.dumps({"storage":backend}))
            config.chmod(0o600)
            with patch.object(launcher,"_platform_key",return_value=("linux","amd64")):
                identity.write_text(json.dumps(fixture))
                identity.chmod(0o600)
                self.assertEqual(launcher.verify_selected_oracle(oracle,health,version="2.7.1")["storage"],"pebbledb")
                for field,value in (("binary_sha256","0"*64),("storage","file"),
                                    ("version","2.7.0"),("provenance_url","https://invalid.example")):
                    bad={**fixture,field:value}
                    identity.write_text(json.dumps(bad))
                    with self.subTest(field=field), self.assertRaisesRegex(bao_http.BaoError,"selected_identity_mismatch"):
                        launcher.verify_selected_oracle(oracle,health,version="2.7.1")


if __name__=="__main__":
    unittest.main()
