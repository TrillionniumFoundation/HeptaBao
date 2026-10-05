"""Selected-version custody tests; synthetic fixtures are not migration evidence."""
from contextlib import redirect_stderr, redirect_stdout
import copy
import hashlib
import io
import json
from pathlib import Path
import sys
import tempfile
import tarfile
import subprocess
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import acceptance
import live_migration_rehearsal as kv
import migration_snapshot_live as snapshot
import official_openbao_launcher as launcher
import run_official_comparison as comparison
import transit_migration_live as transit
import policy_migration_live as policy
import identity_migration_live as identity
import ssh_role_migration_live as ssh_role
import auth_mount_migration_live as auth_mount
from bao_http import BaoError, private_write, verify_oracle_identity


class SelectedReferenceTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="migration-version-unit-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.root.chmod(0o700)
        host = patch.object(launcher, "_platform_key", return_value=("linux", "amd64"))
        host.start()
        self.addCleanup(host.stop)

    def fixture(self, version="2.7.0", *, raft=False):
        pins = launcher.pinned_artifact(version=version)
        storage = launcher.storage_configuration(self.root, version=version, raft_storage=raft)
        backend = next(iter(storage))
        receipt = {"product": "OpenBao", "version": version, **pins,
                   "endpoint": "https://localhost:18200", "cluster_id": "synthetic-cluster",
                   "storage": backend, "server_mode": "server_not_dev", "tls_verified": True,
                   "synthetic_only": True, "archive_member_matches_executable": True,
                   "provenance_url": "https://github.com/openbao/openbao/releases/tag/v" + version}
        oracle = {"root": str(self.root), "identity_file": str(self.root / "identity.json"),
                  "address": receipt["endpoint"], "cluster_id": receipt["cluster_id"],
                  "version": version, "storage_backend": backend, **pins}
        health = {"version": version, "cluster_id": receipt["cluster_id"]}
        return oracle, health, receipt, {"storage": storage}

    def verify(self, oracle, health, receipt, configuration, *, version="2.7.0", raft=False):
        private_write(self.root / "identity.json", receipt)
        private_write(self.root / "server.json", configuration)
        return launcher.verify_selected_oracle(oracle, health, version=version, raft_storage=raft)

    def test_both_exact_versions_preserve_non_ha_and_explicit_raft(self):
        for version, backend in (("2.6.2", "file"), ("2.7.0", "pebbledb")):
            for raft in (False, True):
                with self.subTest(version=version, raft=raft):
                    result = self.verify(*self.fixture(version, raft=raft), version=version, raft=raft)
                    self.assertEqual(result["version"], version)
                    self.assertEqual(result["storage"], "raft" if raft else backend)
                    self.assertEqual(result["binary_sha256"], launcher.pinned_artifact(version=version)["binary_sha256"])

    def test_wrong_health_receipt_backend_artifact_or_authority_is_rejected(self):
        defects = (
            (0, "version", "2.6.2"), (0, "storage_backend", "file"),
            (0, "artifact_sha256", "0" * 64), (1, "version", "2.6.2"),
            (1, "cluster_id", "different-cluster"), (2, "version", "2.6.2"),
            (2, "binary_sha256", launcher.pinned_artifact(version="2.6.2")["binary_sha256"]),
            (2, "artifact_sha256", "0" * 64), (2, "storage", "file"),
            (2, "tls_verified", False), (2, "synthetic_only", False),
            (2, "archive_member_matches_executable", False), (2, "server_mode", "dev"),
            (2, "endpoint", "https://other.invalid:18200"),
            (2, "provenance_url", "https://github.com/openbao/openbao/releases/tag/v2.6.2"),
            (3, "storage", {"file": {"path": str(self.root / "data")}}),
            (3, "storage", {"pebbledb": {"path": str(self.root / "other-data")}}),
        )
        for index, key, value in defects:
            with self.subTest(index=index, key=key):
                fixture = list(copy.deepcopy(self.fixture()))
                fixture[index][key] = value
                with self.assertRaisesRegex(BaoError, "selected_identity_mismatch"):
                    self.verify(*fixture)

    def test_unknown_version_or_platform_fails_before_private_reads(self):
        with patch.object(launcher, "private_json") as read:
            with self.assertRaisesRegex(BaoError, "unsupported_version"):
                launcher.verify_selected_oracle({}, {}, version="latest")
            read.assert_not_called()
        with patch.object(launcher, "_platform_key", return_value=("darwin", "arm64")), \
             patch.object(launcher, "private_json") as read:
            with self.assertRaisesRegex(BaoError, "unsupported_platform"):
                launcher.verify_selected_oracle({}, {}, version="2.7.0")
            read.assert_not_called()

    def test_generic_acceptance_requires_selected_receipt_and_live_version(self):
        oracle, health, receipt, _configuration = self.fixture()
        client = SimpleNamespace(address=oracle["address"])
        self.assertEqual(verify_oracle_identity(receipt, client, health, version="2.7.0")["version"], "2.7.0")
        with self.assertRaisesRegex(BaoError, "receipt_mismatch"):
            verify_oracle_identity(receipt, client, health)
        with self.assertRaisesRegex(BaoError, "receipt_mismatch"):
            verify_oracle_identity(receipt, client, {**health, "version": "2.6.2"}, version="2.7.0")

    def test_snapshot_profile_keeps_six_cases_and_binds_selected_cli_and_report(self):
        for version in launcher.SUPPORTED_VERSIONS:
            oracle, health, receipt, configuration = self.fixture(version, raft=True)
            self.verify(oracle, health, receipt, configuration, version=version, raft=True)
            token = self.root / "token"
            token.write_text("synthetic-token")
            token.chmod(0o600)
            oracle.update(token_file=str(token), ca_file=str(self.root / "ca.crt"))
            metadata, state = b'{"version":1}', b"synthetic-encrypted-state"
            def save(command, **kwargs):
                with tarfile.open(command[-1], "w:gz") as archive:
                    for name, payload in (("meta.json", metadata), ("state.bin", state)):
                        member = tarfile.TarInfo(name)
                        member.size = len(payload)
                        archive.addfile(member, io.BytesIO(payload))
                return subprocess.CompletedProcess(command, 0, "", "")
            def inspect(_inspector, archive, *extra):
                summary = {"schema": "heptabao.openbao-raft-snapshot-inspection.v1", "status": "passed",
                           "metadata_version": 1, "state_size": len(state),
                           "meta_sha256": hashlib.sha256(metadata).hexdigest(),
                           "state_sha256": hashlib.sha256(state).hexdigest(),
                           "restore_performed": False, "conversion_performed": False, "migration_authority": False}
                accepted = archive.name == "raft.snap" and not extra
                return subprocess.CompletedProcess([], 0 if accepted else 1, json.dumps(summary), "")
            with patch.object(snapshot, "start_oracle", return_value=oracle) as start, \
                 patch.object(snapshot, "stop_oracle"), patch.object(snapshot, "Client") as client, \
                 patch.object(snapshot, "verify_inputs", return_value=Path("/synthetic/bao")) as verify, \
                 patch.object(snapshot.subprocess, "run", side_effect=save), \
                 patch.object(snapshot, "run_inspector", side_effect=inspect), \
                 patch.object(snapshot, "file_digest", return_value="synthetic-digest"):
                client.return_value.health.return_value = health
                result = snapshot.run_fixture(Path("/synthetic/inspector"), self.root / ("snapshot-" + version),
                                              oracle_version=version)
                self.assertEqual(start.call_args.kwargs, {"raft_storage": True, "version": version})
                verify.assert_called_once_with(version=version)
                self.assertEqual(result["count"], 6)
                self.assertEqual(result["checks"][0], "official_openbao_" + version.replace(".", "_") + "_tls_oracle_ready")
                self.assertEqual(result["official_openbao_version"], version)
                self.assertEqual(result["official_storage_backend"], "raft")
                self.assertEqual(result["official_binary_sha256"], receipt["binary_sha256"])
                for field in ("restore_performed", "conversion_performed", "migration_authority", "full_format_migration", "production_authority"):
                    self.assertIs(result[field], False)


class RunnerSelectionTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="migration-cli-unit-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.root.chmod(0o700)

    def test_kv_and_transit_cli_forward_explicit_and_historical_default(self):
        for version in (None, "2.7.0"):
            selected = version or "2.6.2"
            flag = [] if version is None else ["--oracle-version", version]
            with patch.object(kv, "run", return_value=0) as run:
                self.assertEqual(kv.main(["--binary", "/absent", "--oracle-launcher", "/launcher",
                                          "--work-dir", str(self.root / "kv"), *flag]), 0)
                self.assertEqual(run.call_args.kwargs, {"oracle_version": selected})
            with patch.object(transit, "run", return_value={"status": "synthetic", "count": 0,
                                                            "full_format_migration": False}) as run, redirect_stdout(io.StringIO()):
                self.assertEqual(transit.main(["--binary", "/absent", "--output", str(self.root / "out.json"), *flag]), 0)
                self.assertEqual(run.call_args.kwargs, {"oracle_version": selected})

    def test_logical_asset_cli_keeps_exact_selected_version_and_default(self):
        for module in (policy, identity, ssh_role, auth_mount):
            for version in (None, "2.7.0"):
                with self.subTest(module=module.__name__, version=version):
                    flag = [] if version is None else ["--oracle-version", version]
                    with patch.object(module, "run", return_value={
                        "status": "synthetic", "count": 0, "full_asset_migration": False,
                    }) as run, redirect_stdout(io.StringIO()):
                        self.assertEqual(module.main([
                            "--binary", "/absent", "--output", str(self.root / "out.json"), *flag,
                        ]), 0)
                        self.assertEqual(run.call_args.kwargs, {"oracle_version": version or "2.6.2"})

    def test_logical_asset_cli_rejects_unpinned_version_before_work(self):
        for module in (policy, identity, ssh_role, auth_mount):
            with self.subTest(module=module.__name__), patch.object(module, "run") as run, \
                 redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                module.main(["--binary", "/absent", "--output", "/absent", "--oracle-version", "latest"])
            run.assert_not_called()

    def test_snapshot_cli_forwards_selected_version_without_relabeling_default(self):
        inspector = self.root / "inspector"
        inspector.write_text("synthetic-not-executed")
        for version in (None, "2.7.0"):
            flag = [] if version is None else ["--oracle-version", version]
            with patch.object(snapshot, "run_fixture", return_value={"synthetic": True}) as run, redirect_stdout(io.StringIO()):
                self.assertEqual(snapshot.main(["--inspector", str(inspector), "--work-dir", str(self.root / "snapshot"), *flag]), 0)
                self.assertEqual(run.call_args.kwargs, {"oracle_version": version or "2.6.2"})

    def test_fixed_comparison_passes_version_to_launcher_before_candidate_allocation(self):
        spec = SimpleNamespace(loader=SimpleNamespace(exec_module=lambda module: None))
        smoke = SimpleNamespace(Instance=unittest.mock.Mock())
        with patch.object(comparison.subprocess, "check_output", return_value="synthetic-source\n"), \
             patch.object(comparison.importlib.util, "spec_from_file_location", return_value=spec), \
             patch.object(comparison.importlib.util, "module_from_spec", return_value=smoke), \
             patch.object(comparison, "start_oracle", side_effect=BaoError("synthetic-stop")) as start:
            with self.assertRaisesRegex(BaoError, "synthetic-stop"):
                comparison.main(["--binary", "/absent", "--candidate-source", str(self.root),
                                 "--work-dir", str(self.root / "comparison"), "--oracle-version", "2.7.0"])
            start.assert_called_once_with(28262, version="2.7.0")
            smoke.Instance.assert_not_called()

    def test_unsupported_versions_fail_before_runner_work(self):
        invocations = ((kv, "run", ["--binary", "/absent", "--oracle-launcher", "/launcher", "--work-dir", "/absent"]),
                       (transit, "run", ["--binary", "/absent", "--output", "/absent"]),
                       (snapshot, "run_fixture", ["--inspector", "/absent", "--work-dir", "/absent"]),
                       (comparison, "start_oracle", ["--binary", "/absent", "--candidate-source", "/absent", "--work-dir", "/absent"]))
        for module, entry, arguments in invocations:
            with self.subTest(module=module.__name__), patch.object(module, entry) as run, \
                 redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                module.main(arguments + ["--oracle-version", "latest"])
            run.assert_not_called()

    def test_acceptance_target_is_selected_without_changing_case_denominator(self):
        before = copy.deepcopy(acceptance.CASES)
        output = io.StringIO()
        with patch.object(acceptance.Client, "from_env", side_effect=BaoError("synthetic-stop")), redirect_stdout(output):
            self.assertEqual(acceptance.main(["--compare", "--oracle-version", "2.7.0"]), 2)
        self.assertEqual(json.loads(output.getvalue())["target"], "OpenBao 2.7.0")
        self.assertEqual(acceptance.CASES, before)


if __name__ == "__main__":
    unittest.main()
