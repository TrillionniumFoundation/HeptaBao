"""Version identity, immutable artifact pins and isolated fixture contracts.

Synthetic archives exercise validation only; mocked processes never execute them.
These are harness unit tests, not live OpenBao compatibility evidence.
"""
from contextlib import contextmanager
import hashlib
import io
import json
import os
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import call, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import official_openbao_launcher as launcher
from bao_http import BaoError, Response


class FixtureProcess:
    def __init__(self, *args, **kwargs):
        self.running = True
    def poll(self):
        return None if self.running else 0
    def terminate(self):
        self.running = False
    def kill(self):
        self.running = False
    def wait(self, timeout=None):
        self.running = False
        return 0


class OracleVersionTests(unittest.TestCase):
    def test_historical_defaults_and_platform_aliases_are_unchanged(self):
        self.assertEqual(launcher.VERSION, "2.6.2")
        self.assertEqual(launcher.pinned_artifact("Linux", "x86_64"), {
            "artifact_sha256": "8dc11cc5fca0b539a9e352727dacb4e2d304daffcf9a66e0718ac325a20d05aa",
            "binary_sha256": "8d18052337908a74f0d7dfacc8da7a1bff5f8a4ab6a2ad136fbf5ffeae243b00"})
        self.assertEqual(launcher.pinned_artifact("Linux", "aarch64"),
                         launcher.pinned_artifact("linux", "arm64", version="2.6.2"))

    def test_new_release_has_independent_exact_archive_and_binary_pins(self):
        self.assertEqual(launcher.pinned_artifact("Linux", "x86_64", version="2.7.0"), {
            "artifact_sha256": "c3ab5de9e778223445487ccbfb16c291bf491642b688f3a3df5aeba23d9b3667",
            "binary_sha256": "9403c2b121e13fe79b3182051320d2096d10519b597ee587e322dab5e359c51e"})
        self.assertNotEqual(launcher.pinned_artifact(version="2.7.0"), launcher.pinned_artifact())

    def test_returned_pin_does_not_mutate_registry(self):
        original = launcher.pinned_artifact(version="2.7.0")
        changed = launcher.pinned_artifact(version="2.7.0")
        changed["binary_sha256"] = "0" * 64
        self.assertEqual(launcher.pinned_artifact(version="2.7.0"), original)

    def test_unknown_versions_fail_before_files_or_process_allocation(self):
        for version in (None, True, 2.7, "", "latest", "2.7", "v2.7.0", "2.7.0+unverified"):
            with self.subTest(version=version), patch.object(launcher.tempfile, "mkdtemp") as allocate, \
                 patch.object(launcher.subprocess, "Popen") as process:
                with self.assertRaisesRegex(BaoError, "official_oracle_unsupported_version"):
                    launcher.start_oracle(18200, version=version)
                allocate.assert_not_called()
                process.assert_not_called()

    def test_unverified_architecture_is_not_silently_promoted_from_legacy(self):
        for host in (("darwin", "arm64"), ("linux", "arm64"), ("linux", "s390x")):
            with self.subTest(host=host), patch.object(launcher, "_platform_key", return_value=host), \
                 patch.object(launcher, "file_digest") as read, patch.object(launcher.subprocess, "Popen") as process:
                with self.assertRaisesRegex(BaoError, "official_oracle_unsupported_platform"):
                    launcher.verify_inputs(version="2.7.0")
                read.assert_not_called()
                process.assert_not_called()

    def test_storage_preserves_non_ha_and_explicit_raft_topologies(self):
        root = Path("/synthetic/private")
        self.assertEqual(launcher.storage_configuration(root), {"file": {"path": str(root / "data")}})
        self.assertEqual(launcher.storage_configuration(root, version="2.7.0"),
                         {"pebbledb": {"path": str(root / "data")}})
        for version in launcher.SUPPORTED_VERSIONS:
            self.assertEqual(launcher.storage_configuration(root, version=version, raft_storage=True),
                             {"raft": {"path": str(root / "data"), "node_id": "synthetic-openbao-1"}})
        with self.assertRaisesRegex(BaoError, "official_oracle_invalid_storage_profile"):
            launcher.storage_configuration(root, version="2.7.0", raft_storage="true")

    @contextmanager
    def archive_fixture(self, *, payload=b"synthetic-pinned-binary", duplicate=False, link=False):
        with tempfile.TemporaryDirectory(prefix="oracle-pin-unit-") as directory:
            root = Path(directory).resolve()
            binary = root / "binary"
            binary.write_bytes(b"synthetic-pinned-binary")
            archive = root / "archive.tar.gz"
            with tarfile.open(archive, "w:gz") as handle:
                for name in (["bao", "./bao"] if duplicate else ["bao"]):
                    member = tarfile.TarInfo(name)
                    if link:
                        member.type = tarfile.SYMTYPE
                        member.linkname = "not-an-executable"
                        handle.addfile(member)
                    else:
                        member.size = len(payload)
                        handle.addfile(member, io.BytesIO(payload))
            pin = {"artifact_sha256": hashlib.sha256(archive.read_bytes()).hexdigest(),
                   "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest()}
            with patch.dict(os.environ, {"HB_ORACLE_BINARY": str(binary), "HB_ORACLE_ARCHIVE": str(archive)}), \
                 patch.object(launcher, "pinned_artifact", return_value=pin), \
                 patch.object(launcher, "_platform_key", return_value=("linux", "amd64")), \
                 patch.object(launcher.subprocess, "Popen") as process:
                yield binary, archive
                process.assert_not_called()

    def test_exact_archive_and_unique_regular_member_match_binary(self):
        with self.archive_fixture() as (binary, _archive):
            self.assertEqual(launcher.verify_inputs(version="2.7.0"), binary)

    def test_changed_binary_is_rejected(self):
        with self.archive_fixture() as (binary, _archive):
            binary.write_bytes(b"changed-binary")
            with self.assertRaisesRegex(BaoError, "official_oracle_pinned_digest_mismatch"):
                launcher.verify_inputs(version="2.7.0")

    def test_changed_archive_is_rejected(self):
        with self.archive_fixture() as (_binary, archive):
            archive.write_bytes(archive.read_bytes() + b"unexpected-trailer")
            with self.assertRaisesRegex(BaoError, "official_oracle_pinned_digest_mismatch"):
                launcher.verify_inputs(version="2.7.0")

    def test_independently_pinned_nonmatching_member_is_rejected(self):
        with self.archive_fixture(payload=b"different-archive-member"):
            with self.assertRaisesRegex(BaoError, "official_oracle_binary_not_archive_member"):
                launcher.verify_inputs(version="2.7.0")

    def test_duplicate_or_link_members_are_rejected_without_extraction(self):
        for option in ({"duplicate": True}, {"link": True}):
            with self.subTest(option=option), self.archive_fixture(**option):
                with self.assertRaisesRegex(BaoError, "official_oracle_archive_binary_missing"):
                    launcher.verify_inputs(version="2.7.0")

    @contextmanager
    def mocked_fixture(self, reported_version="2.7.0"):
        initialized = False
        processes = []
        class FixtureClient:
            def __init__(self, *args, **kwargs):
                pass
            def request(self, method, path, body=None):
                nonlocal initialized
                if method == "GET" and path == "/v1/sys/health":
                    return Response(503 if initialized else 501,
                                    {"initialized": initialized, "sealed": True})
                if method == "POST" and path == "/v1/sys/init":
                    initialized = True
                    return Response(200, {"root_token": "synthetic-private-token", "keys_base64": ["synthetic-private-share"]})
                if method == "POST" and path == "/v1/sys/unseal":
                    return Response(200, {})
                raise AssertionError("unexpected fixture request")
            def health(self):
                return {"version": reported_version, "cluster_id": "synthetic-cluster"}
        def process(*args, **kwargs):
            instance = FixtureProcess(*args, **kwargs)
            processes.append(instance)
            return instance
        def certificate_files(root):
            for name in ("ca.crt", "tls.crt", "tls.key"):
                (root / name).write_text("synthetic-not-a-certificate")
        with tempfile.TemporaryDirectory(prefix="oracle-version-unit-") as directory, \
             patch.dict(os.environ, {"HB_ORACLE_WORK_ROOT": directory}), \
             patch.object(launcher, "verify_inputs", return_value=Path("/synthetic/bao")) as verify, \
             patch.object(launcher, "certificates", side_effect=certificate_files), \
             patch.object(launcher, "Client", FixtureClient), \
             patch.object(launcher.subprocess, "Popen", side_effect=process):
            yield verify, processes

    def test_start_and_restart_retain_exact_release_and_cluster_identity(self):
        with self.mocked_fixture() as (verify, processes):
            oracle = launcher.start_oracle(18200, version="2.7.0")
            try:
                root = Path(oracle["root"])
                config = json.loads((root / "server.json").read_text())
                identity = json.loads((root / "oracle-identity.json").read_text())
                self.assertEqual(set(config["storage"]), {"pebbledb"})
                self.assertEqual(identity["version"], "2.7.0")
                self.assertEqual(identity["binary_sha256"], launcher.pinned_artifact(version="2.7.0")["binary_sha256"])
                self.assertEqual(identity["storage"], "pebbledb")
                self.assertEqual(identity["server_mode"], "server_not_dev")
                self.assertTrue(identity["tls_verified"])
                launcher.stop_oracle(oracle)
                launcher.restart_oracle(oracle)
                self.assertEqual(oracle["cluster_id"], "synthetic-cluster")
                self.assertEqual(verify.call_args_list, [call(version="2.7.0"), call(version="2.7.0")])
            finally:
                launcher.stop_oracle(oracle)
            self.assertTrue(all(not process.running for process in processes))

    def test_live_health_wrong_minor_version_is_not_accepted(self):
        with self.mocked_fixture(reported_version="2.6.2") as (_verify, processes):
            with self.assertRaisesRegex(BaoError, "official_oracle_live_version_mismatch"):
                launcher.start_oracle(18200, version="2.7.0")
            self.assertEqual(len(processes), 1)
            self.assertFalse(processes[0].running)


if __name__ == "__main__":
    unittest.main()
