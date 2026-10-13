"""The private three-host HA profile remains bounded, secret-safe and manual."""
import argparse
import ast
import contextlib
import importlib.util
import io
import json
import sys
import tempfile
import os
import shutil
import subprocess
from pathlib import Path
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[3]
SOURCE = ROOT / "qa/openbao-acceptance/ha_multihost_live.py"
DOC = ROOT / "docs/operations/HEPTABAO_MULTIHOST_HA_QUALIFICATION.md"
sys.path.insert(0, str(SOURCE.parent))
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
            # macOS exposes /var through /private/var. Use the canonical owner-
            # controlled path so the production guard is exercised, not bypassed.
            root = Path(directory).resolve(strict=True)
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

    def test_explicit_lan_nodes_accept_only_exact_rfc1918_ipv4_ranges(self):
        for address in (
            "10.0.0.0", "10.255.255.255", "172.16.0.0", "172.31.255.255",
            "192.168.0.0", "192.168.255.255",
        ):
            with self.subTest(address=address):
                text = f"host-a,{address},/home/operator/run"
                with self.assertRaises(argparse.ArgumentTypeError):
                    MODULE.parse_node(text, 1, 31080, 31081)
                node = MODULE.parse_node(text, 1, 31080, 31081, allow_private_lan=True)
                self.assertEqual(node.ip, address)
                self.assertEqual(node.root, "/home/operator/run")
        for address in (
            "9.255.255.255", "11.0.0.0", "172.15.255.255", "172.32.0.0",
            "192.167.255.255", "192.169.0.0", "100.64.12.34", "8.8.8.8",
            "127.0.0.1", "169.254.1.2", "224.0.0.1", "0.0.0.0", "255.255.255.255",
            "192.0.0.8", "198.18.0.1", "::1", "fe80::1", "fc00::1", "ff02::1",
            "::ffff:192.168.0.1", "2001:db8::1",
        ):
            with self.subTest(address=address), self.assertRaises(argparse.ArgumentTypeError):
                MODULE.parse_node(f"host-a,{address},/home/operator/run", 1, 31080, 31081,
                                  allow_private_lan=True)
        for root in ("/tmp/run", "/home/operator/../run", "/home/operator//run"):
            with self.subTest(root=root), self.assertRaises(argparse.ArgumentTypeError):
                MODULE.parse_node(f"host-a,192.168.0.1,{root}", 1, 31080, 31081,
                                  allow_private_lan=True)

    @staticmethod
    def _scope_argv(work, addresses, flags):
        argv = [str(SOURCE), "--binary-source", "builder:/home/builder/heptabao-server",
                "--expected-binary-sha256", "c" * 64, "--source-commit", "a" * 40,
                "--source-tree", "b" * 40, "--work-root", str(work), *flags]
        for index, address in enumerate(addresses, 1):
            argv.extend(("--node", f"host-{index},{address},/home/operator/run-{index}"))
        return argv

    def test_cli_requires_exactly_one_explicit_network_scope_before_candidate_copy(self):
        for flags in ([], ["--allow-private-tailnet", "--allow-private-lan"]):
            with self.subTest(flags=flags), tempfile.TemporaryDirectory() as directory:
                work = Path(directory).resolve() / "new-fixture"
                argv = self._scope_argv(work, ["100.64.1.1", "100.64.1.2", "100.64.1.3"], flags)
                with mock.patch.object(sys, "argv", argv), \
                        mock.patch.object(MODULE, "copy_candidate_source") as copy, \
                        mock.patch.object(MODULE, "ssh") as ssh, \
                        contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as denial:
                    MODULE.main()
                self.assertEqual(denial.exception.code, 2)
                self.assertFalse(work.exists())
                copy.assert_not_called()
                ssh.assert_not_called()

    def test_cli_scope_reaches_candidate_boundary_and_reports_matching_transport(self):
        for flag, addresses, transport in (
            ("--allow-private-tailnet", ["100.64.1.1", "100.64.1.2", "100.64.1.3"],
             "private-tailnet-mtls"),
            ("--allow-private-lan", ["10.0.0.1", "172.16.0.2", "192.168.0.3"],
             "private-lan-mtls"),
        ):
            with self.subTest(flag=flag), tempfile.TemporaryDirectory() as directory:
                work = Path(directory).resolve() / "new-fixture"
                argv = self._scope_argv(work, addresses, [flag])
                with mock.patch.object(sys, "argv", argv), \
                        mock.patch.object(MODULE, "copy_candidate_source",
                                          side_effect=MODULE.FixtureError("scope_only_probe")) as copy, \
                        mock.patch.object(MODULE, "ssh", return_value=""), \
                        contextlib.redirect_stdout(io.StringIO()):
                    self.assertEqual(MODULE.main(), 1)
                copy.assert_called_once()
                report = json.loads((work / "summary.json").read_text())
                self.assertEqual(report["transport"], transport)
                self.assertEqual(report["failure_code"], "scope_only_probe")
                self.assertEqual(report["required_check_count"], 54)
                self.assertIs(report["production_authority"], False)

    def test_response_failure_codes_are_bounded_and_secret_independent(self):
        self.assertEqual(
            MODULE.response_failure_code(
                503, {"errors": ["HA linearizable state is unavailable"]}
            ),
            "ha_linearizable_unavailable",
        )
        self.assertEqual(
            MODULE.response_failure_code(
                503, {"errors": ["synthetic secret-bearing unknown"]}
            ),
            "http_503_unclassified",
        )
        self.assertEqual(
            MODULE.response_failure_code(429, {"errors": []}),
            "http_429_without_single_error",
        )

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
        readiness = (
            "initial = wait_leader(context, [initial, standby], root_token)"
        )
        protected_read = "wait_linearizable_read_window("
        first_snapshot_write = "for index in range(8):"
        self.assertIn(readiness, source)
        readiness_offset = source.index(readiness)
        protected_read_offset = source.index(protected_read, readiness_offset)
        first_snapshot_write_offset = source.index(
            first_snapshot_write, protected_read_offset
        )
        self.assertLess(readiness_offset, protected_read_offset)
        self.assertLess(protected_read_offset, first_snapshot_write_offset)
        self.assertIn('event("snapshot_majority_ready", node=initial.node_id)', source)
        rejoin_leader = "initial = wait_leader(context, nodes, root_token, seconds=60)"
        catchup_read = "seconds=90, request_timeout=12"
        self.assertIn(rejoin_leader, source)
        self.assertIn(catchup_read, source)
        self.assertLess(source.index(rejoin_leader), source.index(catchup_read))
        self.assertIn('event("snapshot_rejoin_leader_ready", node=initial.node_id)', source)
        sigkill = 'event("leader_sigkill", node=initial.node_id, pid=killed)'
        quiet = "time.sleep(6.0)"
        passive = '"post_kill_passive_leader_observation"'
        post_kill_gate = (
            "root_token, previous=initial, seconds=60"
        )
        self.assertIn(sigkill, source)
        self.assertIn(quiet, source)
        self.assertIn(passive, source)
        self.assertIn(post_kill_gate, source)
        self.assertLess(source.index(sigkill), source.index(quiet))
        self.assertLess(source.index(quiet), source.index(passive))
        self.assertLess(source.index(passive), source.index(post_kill_gate))
        post_kill_block = source[source.index(sigkill):source.index(post_kill_gate)]
        self.assertNotIn('"POST"', post_kill_block)
        self.assertNotIn('"PUT"', post_kill_block)
        self.assertNotIn('"DELETE"', post_kill_block)
        self.assertIn('"GET", "sys/leader"', post_kill_block)
        read_window = next(
            node for node in tree.body
            if isinstance(node, ast.FunctionDef)
            and node.name == "wait_linearizable_read_window"
        )
        self.assertFalse(any(isinstance(node, (ast.For, ast.AsyncFor))
                             for node in ast.walk(read_window)))
        read_api_calls = [
            node for node in ast.walk(read_window)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
            and node.func.id == "api"
        ]
        self.assertEqual(len(read_api_calls), 1)
        method = read_api_calls[0].args[2]
        self.assertIsInstance(method, ast.Constant)
        self.assertEqual(method.value, "GET")
        for marker in (
            "actual_exe = os.readlink(proc / 'exe')",
            "observed['executable'] != exe",
            "prior != observed or not expected(observed)",
            "os.kill(pid, signal.SIGKILL)",
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


class NativeProcessIdentityTests(unittest.TestCase):
    @unittest.skipUnless(shutil.which("cc"), "native process fixture requires a C compiler")
    def test_stale_identity_and_other_fixture_pid_are_rejected_before_sigkill(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary).resolve(strict=True)
            source = directory / "probe.c"
            source.write_text("#include <unistd.h>\nint main(void) { for (;;) pause(); }\n")
            subprocess.run([shutil.which("cc"), str(source), "-o", str(directory / "probe")],
                           check=True, capture_output=True)
            roots = [directory / "fixture-a", directory / "fixture-b"]
            owned = []
            def invoke(action, root):
                return subprocess.run([sys.executable, "-c", MODULE.REMOTE_PROCESS_SCRIPT,
                                       action, str(root), "0"], capture_output=True, text=True)
            try:
                for root in roots:
                    root.mkdir(mode=0o700)
                    shutil.copyfile(directory / "probe", root / "heptabao-server")
                    (root / "heptabao-server").chmod(0o500)
                    (root / "server.json").write_text("{}")
                    result = invoke("start", root)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    owned.append(int(result.stdout.strip()))
                identity_path = roots[0] / "process.identity.json"
                original = identity_path.read_text()
                forged = json.loads(original)
                forged["start"] += "stale"
                identity_path.write_text(json.dumps(forged))
                self.assertEqual(invoke("stop", roots[0]).returncode, 79)
                os.kill(owned[0], 0)
                identity_path.write_text(original)
                # A valid identity from another fixture must not confer kill authority.
                pid_path = roots[0] / "process.pid"
                original_pid = pid_path.read_text()
                pid_path.write_text(str(owned[1]))
                identity_path.write_text((roots[1] / "process.identity.json").read_text())
                self.assertEqual(invoke("stop", roots[0]).returncode, 79)
                os.kill(owned[0], 0); os.kill(owned[1], 0)
                pid_path.write_text(original_pid); identity_path.write_text(original)
                for root in roots:
                    result = invoke("stop", root)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertFalse((root / "process.pid").exists())
                    self.assertFalse((root / "process.identity.json").exists())
                    self.assertEqual(invoke("stop", root).stdout.strip(), "none")
            finally:
                for pid in owned:
                    try:
                        os.kill(pid, 9)
                    except ProcessLookupError:
                        pass

    def test_native_binary_rejects_a_different_source_freeze(self):
        commit, tree = "a" * 40, "b" * 40
        value = "mac-ts,mac-ts:/Volumes/T5/private/heptabao-server," + "c" * 64
        self.assertEqual(MODULE.parse_node_binary(value + "," + commit + "," + tree,
                                                commit, tree)[0], "mac-ts")
        for suffix in ("," + "d" * 40 + "," + tree, "," + commit + "," + "e" * 40):
            with self.assertRaises(argparse.ArgumentTypeError):
                MODULE.parse_node_binary(value + suffix, commit, tree)


if __name__ == "__main__":
    unittest.main()
