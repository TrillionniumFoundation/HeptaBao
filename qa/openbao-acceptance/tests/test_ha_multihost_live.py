"""The private three-host HA profile remains bounded, secret-safe and manual."""
import argparse
import ast
import importlib.util
import json
import sys
import tempfile
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[3]
SOURCE = ROOT / "qa/openbao-acceptance/ha_multihost_live.py"
DOC = ROOT / "docs/operations/HEPTABAO_MULTIHOST_HA_QUALIFICATION.md"
SPEC = importlib.util.spec_from_file_location("ha_multihost_live", SOURCE)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


class MultiHostHaContractTests(unittest.TestCase):
    def test_fixed_denominator_covers_the_real_lifecycle(self):
        required = MODULE.REQUIRED_CHECKS
        self.assertEqual(len(required), 54)
        for name in (
            "candidate_binary_digest",
            "three_distinct_remote_hosts",
            "remote_standby_write_forwarded",
            "remote_snapshot_catchup",
            "leader_changed_after_remote_sigkill",
            "three_leadership_epochs_preserve_data",
            "single_survivor_loses_authority",
            "quorum_loss_write_denied_without_data",
            "denied_quorum_write_has_no_effect",
            "all_hosts_rejoined_after_quorum_recovery",
            "synthetic_application_data_cleaned",
            "source_and_binary_unchanged",
            "report_excludes_runtime_secrets",
            "multihost.complete",
        ):
            self.assertIn(name, required)
        self.assertEqual(len([name for name in required if name.startswith("cleanup_")]), 14)

    def test_nodes_and_binary_source_require_canonical_private_tailnet_paths(self):
        node = MODULE.parse_node(
            "host-a,100.64.12.34,/home/operator/heptabao-run", 1, 46230, 46231
        )
        self.assertEqual(node.ip, "100.64.12.34")
        self.assertEqual(node.root, "/home/operator/heptabao-run")
        self.assertEqual(
            MODULE.parse_binary_source(
                "builder:/home/builder/target/debug/heptabao-server"
            ),
            ("builder", "/home/builder/target/debug/heptabao-server"),
        )
        self.assertEqual(
            MODULE.parse_binary_source("local:/home/controller/heptabao-server"),
            ("local", "/home/controller/heptabao-server"),
        )
        for value in (
            "host-a,10.0.0.2,/home/operator/run",
            "host-a,127.0.0.1,/home/operator/run",
            "host-a,100.64.1.2,/tmp/run",
            "host-a,100.64.1.2,/home/operator/../run",
            "host-a,100.64.1.2,/home/operator//run",
            "bad alias,100.64.1.2,/home/operator/run",
        ):
            with self.subTest(value=value), self.assertRaises(
                (argparse.ArgumentTypeError, ValueError)
            ):
                MODULE.parse_node(value, 1, 46230, 46231)
        for value in (
            "builder:/tmp/heptabao-server",
            "builder:/home/operator/../heptabao-server",
            "bad alias:/home/operator/heptabao-server",
            "builder:relative/path",
        ):
            with self.subTest(value=value), self.assertRaises(
                argparse.ArgumentTypeError
            ):
                MODULE.parse_binary_source(value)

    def test_local_copy_and_deterministic_compression_preserve_candidate_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "candidate"
            source.write_bytes((b"bounded-candidate-bytes\n" * 4096))
            source.chmod(0o500)
            copied = root / "copied"
            MODULE.copy_candidate_source("local", str(source), copied)
            self.assertEqual(copied.read_bytes(), source.read_bytes())
            first = root / "first.gz"
            second = root / "second.gz"
            MODULE.compress_candidate(copied, first)
            MODULE.compress_candidate(copied, second)
            self.assertEqual(first.read_bytes(), second.read_bytes())
            import gzip
            self.assertEqual(gzip.decompress(first.read_bytes()), source.read_bytes())

    def test_report_redaction_rejects_nested_keys_and_runtime_values(self):
        safe = {
            "schema": "heptabao.multihost-ha.v1",
            "source_commit": "a" * 40,
            "checks": [{"case": "bounded", "passed": True}],
        }
        self.assertTrue(MODULE.report_is_secret_safe(safe, ("synthetic-secret",)))
        nested = {**safe, "nested": [{"root_token": "synthetic-secret"}]}
        self.assertFalse(MODULE.report_is_secret_safe(nested, ()))
        copied = {**safe, "note": "contains-synthetic-secret-value"}
        self.assertFalse(MODULE.report_is_secret_safe(copied, ("synthetic-secret",)))
        redacted = MODULE.secret_safe_report(nested, ("synthetic-secret",))
        encoded = json.dumps(redacted)
        self.assertEqual(redacted["failure_code"], "report_redaction_failed")
        self.assertNotIn("synthetic-secret", encoded)
        self.assertNotIn("root_token", encoded)
        self.assertIs(redacted["production_authority"], False)

    def test_mutation_and_process_boundaries_are_fail_closed(self):
        source = SOURCE.read_text()
        tree = ast.parse(source)
        write = next(
            node for node in tree.body
            if isinstance(node, ast.FunctionDef) and node.name == "write_once"
        )
        self.assertFalse(any(isinstance(node, (ast.For, ast.While)) for node in ast.walk(write)))
        api_calls = [
            node for node in ast.walk(write)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
            and node.func.id == "api"
        ]
        self.assertEqual(len(api_calls), 1)
        for marker in (
            'exe=$(readlink -f "/proc/$pid/exe")',
            'test "$exe" = "$root/heptabao-server"',
            'case "$cmd" in (*"$root/server.json"*)',
            'kill -KILL "$pid"',
            '"mutating_requests_retried": False',
            "parent_mode.st_uid != os.getuid()",
            "parent_mode.st_mode & 0o022",
            "parent = args.work_root.parent.resolve(strict=True)",
            'if alias != "local":',
            'source.resolve(strict=True)',
            'info.st_uid != os.getuid()',
            'name not in REMOTE_EVIDENCE_FILES',
            '"ConnectionAttempts=1"',
            "gzip.GzipFile(",
            "mtime=0",
            "install_signal_handlers()",
            'report["failure_code"] = f"{stage}_controller_interrupted"',
            'archive.unlink()',
            'os.replace(temporary, final)',
        ):
            self.assertIn(marker, source)
        self.assertIn('report["failure_code"] = f"{stage}_subprocess_failure"', source)
        self.assertNotIn("error.stderr", source)
        self.assertNotIn("error.stdout", source)
        for forbidden in ("sudo ", "iptables ", "nft ", "ufw ", "systemctl "):
            self.assertNotIn(forbidden, source)

    def test_surface_mapping_is_scoped_and_does_not_claim_autopilot(self):
        work = json.loads((ROOT / "planning/HEPTABAO_SURFACE_WORK_V1.json").read_text())
        profile = work["profile_definitions"]["ha_multihost"]
        self.assertEqual(profile["script"], "qa/openbao-acceptance/ha_multihost_live.py")
        self.assertEqual(
            profile["scope"], "repository_controlled_bounded_profile_not_whole_surface"
        )
        mapped = {
            row["surface_id"] for row in work["surfaces"]
            if "ha_multihost" in row["available_scoped_profiles"]
        }
        self.assertEqual(mapped, {
            "HB-SURFACE-STORAGE-RAFT",
            "HB-SURFACE-CLUSTER-MTLS",
            "HB-SURFACE-CLUSTER-FORWARDING",
            "HB-SURFACE-CLUSTER-READ-STANDBY",
            "HB-SURFACE-CLUSTER-STEPDOWN",
        })
        self.assertNotIn("HB-SURFACE-CLUSTER-AUTOPILOT", mapped)
        self.assertTrue(all(row["whole_surface_admitted"] is False for row in work["surfaces"]))

    def test_private_lab_profile_is_not_a_default_pr_job(self):
        for workflow in (ROOT / ".github/workflows").glob("*.yml"):
            with self.subTest(workflow=workflow.name):
                self.assertNotIn("ha_multihost_live.py", workflow.read_text())
        docs = DOC.read_text()
        self.assertIn("not** part of the default GitHub-hosted PR", docs)
        self.assertIn("--allow-private-tailnet", docs)
        self.assertIn("Fixed 54-check lifecycle", docs)
        self.assertIn("Do not use a wildcard or a parent directory", docs)
        for private_name in ("x230-ts", "rog-ts", "pocket4-ts",
                             "100.97.179.109", "100.118.166.22", "100.119.126.104"):
            self.assertNotIn(private_name, docs)

    def test_runtime_claim_flags_remain_false(self):
        source = SOURCE.read_text()
        for marker in (
            '"qualification": False',
            '"independent_qualification": False',
            '"full_openbao_compatibility": False',
            '"production_authority": False',
        ):
            self.assertIn(marker, source)
        self.assertIn("physical_power_loss", source)
        self.assertIn("long_horizon_linearizability", source)
        self.assertIn("production_custody", source)


if __name__ == "__main__":
    unittest.main()
