"""Admission tests only: no HeptaBao/OpenBao executable or server is started.

Positive parser samples below are explicitly fictional, using synthetic artifact
bytes and observations. They are not build receipts or qualification evidence.
The exact retained Pocket4 selection is a fixture. Set
HEPTABAO_X230_FAILED_RECEIPT to the original Mac 09c14 failed report to exercise
that original, pinned refusal as well; no failed report is rewritten to pass.
"""
from __future__ import annotations

import contextlib
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

HERE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(HERE))
import x230_current_candidate_qualification as q
import kv2_native_fresh_directory_dr_live as dr
import acceptance

SELECTION_RAW = (HERE / "tests/fixtures/x230-current-candidate-selection.public.json").read_bytes()
FAILED_RECEIPT_SHA = "17d184d27c043a59e952ad3235497c066d8a2374d9a4d9fe816cee79eff80d0d"
REJECTIONS = (q.AdmissionFailure, dr.Failure, KeyError, TypeError, ValueError)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def selection():
    return json.loads(SELECTION_RAW)


def fictional_build():
    """Deliberately synthetic parser sample, never a live successful build."""
    selected = selection()
    server = {"sha256": digest(b"fictional-server"), "bytes": len(b"fictional-server")}
    seed = {"sha256": digest(b"fictional-seed"), "bytes": len(b"fictional-seed")}
    receipt = {
        "unit_test_fixture_not_a_build": True,
        "schema": "heptabao.convergence-normal-build-tests.v1", "status": "passed", "failure": None,
        "source_commit": q.BUILD_COMMIT, "source_tree": q.BUILD_TREE,
        "source_and_artifacts_unchanged": True, "controller_sha256": q.BUILD_CONTROLLER_SHA256,
        "selection_sha256": q.SELECTION_SHA256, "toolchain_pins": dict(q.TOOLCHAIN_PINS),
        "build_environment_overrides": selected["original_build"]["env"],
        "compiler_wrappers_disabled": True, "ambient_build_overrides_inherited": False,
        "explicit_compiler": str(q.TOOLCHAIN / "rustc"), "automatic_retry": False,
        "deadline_renewed": False, "outer_budget_seconds": 12000, "elapsed_seconds": 1000,
        "created_at_unix": 1000, "finished_at_unix": 2000,
        "production_changed": False, "production_server_started": False, "formal_kv2_qualified": False,
        "physical_ha_qualified": False, "authbus_migration_qualified": False, "full_replacement_qualified": False,
        "passed_cases": 107, "executed_passed_cases": 107, "not_qualified_cases": 0,
        "expected_denominators": selected["denominators"], "artifacts": {}, "groups": [], "enumeration": {},
        "steps": [],
    }
    for name in ("heptabao-server", "heptabao-seed", "heptabao-server-libtest", "heptabao-ha-service-libtest"):
        peer, test = name == "heptabao-ha-service-libtest", name.endswith("-libtest")
        package = "heptabao-ha-service" if peer else "heptabao-server"
        entry = "src/lib.rs" if test else "src/bin/heptabao-seed.rs" if name == "heptabao-seed" else "src/main.rs"
        actual = server if name == "heptabao-server" else seed if name == "heptabao-seed" else {
            "sha256": digest(b"fictional-libtest"), "bytes": len(b"fictional-libtest")}
        receipt["artifacts"][name] = {
            **actual, "source_commit": q.BUILD_COMMIT, "source_tree": q.BUILD_TREE,
            "normal_features_profile_and_source_verified": True, "path": str(q.PRODUCER_BUILD / "artifacts" / name),
            "cargo_source_entry": str(q.PRODUCER_SOURCE / "crates" / package / entry),
            "cargo_package_id": "path+file://" + str(q.PRODUCER_SOURCE / "crates" / package) + "#0.0.0",
            "cargo_features": ["default", "native-v6-peer-ingress"] if peer else
                              ["default", "native-v6-ha", "native-v6-storage"],
            "cargo_profile": {"opt_level": "3", "debuginfo": 0, "debug_assertions": True,
                              "overflow_checks": True, "test": test},
        }
    for group in q.selected_groups(selected):
        count = group["expected_count"]
        suffixes = group.get("argv_suffixes", [group.get("argv_suffix")])
        per_result = 1 if len(suffixes) > 1 or group.get("selection_mode") == "per-test-exact" else count
        receipt["groups"].append({
            "label": group["label"], "crate": group["crate"], "tests": list(group["tests"]),
            "expected_count": count, "passed": count, "status": "passed", "budget_renewed_per_case": False,
            "original_group_budget_seconds": group["runtime_seconds"],
            "results": [{"passed": per_result, "failed": 0, "ignored": 0, "measured": 0,
                         "reported_state": "ok", "exact_denominator_passed": True} for _ in suffixes],
        })
        receipt["enumeration"][group["label"]] = {"matched_names": sorted(group["tests"]), "matched_count": count}
    for label, argv, cap in q.expected_build_steps(selected):
        receipt["steps"].append({
            "step": label, "argv": argv, "requested_cap_seconds": cap, "effective_budget_seconds": cap,
            "attempts": 1, "exit_code": 0, "timed_out": False, "pid": 123, "seconds": 1,
            "started_at_unix": 1001, "unexpected_live_descendants_on_success": False,
            "owned_group_cleanup": {"all_owned_processes_gone": True, "abnormal_exit": False,
                                    "remaining_before_cleanup": [], "remaining_after_cleanup": [], "signals": []},
            "stdout_bytes": 0, "stderr_bytes": 0, "stdout_sha256": digest(b""), "stderr_sha256": digest(b""),
        })
    return receipt, selected, server, seed


def fictional_comparison():
    cases = {module + "." + name: {"result": "passed"}
             for module in q.MODULES for name in acceptance.CASES[module]}
    cases["totp.mount"] = {"result": "passed"}
    admission = {"pins": {"binary": {"sha256": digest(b"fictional-server")},
                           "build_receipt": {"sha256": digest(b"fictional-receipt")}}}
    result = {
        "unit_test_fixture_not_a_run": True, "schema": "heptabao.live-acceptance.v1",
        "target": "OpenBao 2.7.1", "mode": "differential", "status": "passed_scoped_cases",
        "cases_match": True, "mismatched_cases": [], "scope": list(q.MODULES),
        "full_openbao_compatibility": False, "production_qualified": False,
        "owned_cleanup_completed": True, "cleanup_errors": [], "source_and_binary_unchanged": True,
        "candidate_results": {"cases": cases, "cleanup": {"result": "passed"}},
        "oracle_results": {"cases": copy.deepcopy(cases), "cleanup": {"result": "passed"}},
        "execution_binding": {"candidate_source_sha": q.BUILD_COMMIT,
            "candidate_binary_sha256": admission["pins"]["binary"]["sha256"],
            "candidate_source_has_uncommitted_changes": False, "runner_source_sha256": q.COMPARISON_SHA256,
            "build_log_sha256": admission["pins"]["build_receipt"]["sha256"]},
        "native_storage": {"profile": "native_v6_file", "fixture_options": False, "activation_status": 204},
        "candidate": {"endpoint": "https://127.0.0.1:12345"}, "oracle": {"endpoint": "https://127.0.0.1:12346"},
    }
    return result, admission


class ReceiptGuards(unittest.TestCase):
    def setUp(self):
        self.receipt, self.selection, self.server, self.seed = fictional_build()

    def validate(self, receipt=None, selected=None, sha=None):
        return q.validate_receipt(self.receipt if receipt is None else receipt,
            self.selection if selected is None else selected, q.SELECTION_SHA256 if sha is None else sha,
            self.server, self.seed, dr)

    def test_exact_original_selection_and_fictional_parser_sample(self):
        self.assertEqual(digest(SELECTION_RAW), q.SELECTION_SHA256)
        names = [name for group in q.selected_groups(self.selection) for name in group["tests"]]
        self.assertEqual(len(names), 107)
        self.assertEqual(len(set(names)), 107)
        self.assertEqual(self.validate()["passed_cases"], 107)
        self.assertTrue(self.receipt["unit_test_fixture_not_a_build"])

    def test_failed_nonterminal_or_missing_status_refused_first(self):
        for value in (None, "failed", "running", "not_run", "cancelled"):
            with self.subTest(status=value):
                bad = copy.deepcopy(self.receipt); bad["status"] = value
                with self.assertRaisesRegex(q.AdmissionFailure, "terminal_successful_build_required"):
                    self.validate(bad)

    def test_old61_missing_unexecuted_or_extra_counts_refused(self):
        for key, value in (("passed_cases", 61), ("passed_cases", 106), ("passed_cases", 108),
                           ("passed_cases", True), ("executed_passed_cases", 88),
                           ("not_qualified_cases", 4), ("passed_cases", None)):
            with self.subTest(key=key, value=value):
                bad = copy.deepcopy(self.receipt); bad[key] = value
                with self.assertRaises(REJECTIONS): self.validate(bad)

    def test_frozen_source_controller_toolchain_and_profile_required(self):
        for key, value in (("source_commit", "4e808d0ecb1bcded22870a7ec960dfb2491cf6ec"),
                           ("source_tree", "0" * 40), ("controller_sha256", "0" * 64),
                           ("toolchain_pins", {}), ("compiler_wrappers_disabled", False),
                           ("ambient_build_overrides_inherited", True), ("build_environment_overrides", {}),
                           ("source_and_artifacts_unchanged", False), ("production_changed", True)):
            with self.subTest(key=key):
                bad = copy.deepcopy(self.receipt); bad[key] = value
                with self.assertRaises(REJECTIONS): self.validate(bad)

    def test_selection_hash_source_names_and_enumeration_are_bound(self):
        with self.assertRaises(REJECTIONS): self.validate(sha="0" * 64)
        for operation in ("selection_sha", "selection_source", "missing_group", "extra_group", "duplicate_group",
                          "missing_enum", "extra_enum", "changed_enum", "changed_names"):
            with self.subTest(operation=operation):
                bad, selected = copy.deepcopy(self.receipt), copy.deepcopy(self.selection)
                if operation == "selection_sha": bad["selection_sha256"] = "0" * 64
                elif operation == "selection_source": selected["execution_source_commit"] = "0" * 40
                elif operation == "missing_group": bad["groups"].pop()
                elif operation == "extra_group": bad["groups"].append(copy.deepcopy(bad["groups"][0]))
                elif operation == "duplicate_group": bad["groups"][-1] = copy.deepcopy(bad["groups"][0])
                elif operation == "missing_enum": bad["enumeration"].pop("ssh25")
                elif operation == "extra_enum": bad["enumeration"]["extra"] = {}
                elif operation == "changed_enum": bad["enumeration"]["ssh25"]["matched_names"][0] = "wrong"
                else: bad["groups"][0]["tests"][0] = "wrong"
                with self.assertRaises(REJECTIONS): self.validate(bad, selected)

    def test_any_failed_ignored_measured_or_missing_result_refused(self):
        for key, value in (("failed", 1), ("ignored", 1), ("measured", 1), ("passed", 24),
                           ("reported_state", "running"), ("exact_denominator_passed", False)):
            with self.subTest(key=key):
                bad = copy.deepcopy(self.receipt); bad["groups"][0]["results"][0][key] = value
                with self.assertRaises(REJECTIONS): self.validate(bad)
        for operation in ("missing", "extra", "running", "renewed"):
            bad = copy.deepcopy(self.receipt)
            if operation == "missing": bad["groups"][0]["results"].pop()
            elif operation == "extra": bad["groups"][0]["results"].append(copy.deepcopy(bad["groups"][0]["results"][0]))
            elif operation == "running": bad["groups"][0]["status"] = "running"
            else: bad["groups"][0]["budget_renewed_per_case"] = True
            with self.subTest(operation=operation), self.assertRaises(REJECTIONS): self.validate(bad)

    def test_seed_and_exact_four_artifact_bindings_required(self):
        for key, value in (("sha256", "0" * 64), ("bytes", 999), ("source_tree", "0" * 40),
                           ("path", "/tmp/wrong"), ("cargo_source_entry", "/tmp/wrong"),
                           ("cargo_features", ["default"]), ("cargo_profile", {}),
                           ("normal_features_profile_and_source_verified", False)):
            with self.subTest(key=key):
                bad = copy.deepcopy(self.receipt); bad["artifacts"]["heptabao-seed"][key] = value
                with self.assertRaises(REJECTIONS): self.validate(bad)
        for operation in ("missing_seed", "missing_libtest", "extra", "bool_profile"):
            bad = copy.deepcopy(self.receipt)
            if operation == "missing_seed": del bad["artifacts"]["heptabao-seed"]
            elif operation == "missing_libtest": del bad["artifacts"]["heptabao-ha-service-libtest"]
            elif operation == "extra": bad["artifacts"]["extra"] = {}
            else: bad["artifacts"]["heptabao-seed"]["cargo_profile"]["debuginfo"] = False
            with self.subTest(operation=operation), self.assertRaises(REJECTIONS): self.validate(bad)

    def test_build_step_closed_set_and_actual_terminal_execution(self):
        for operation in ("missing", "extra", "reordered"):
            bad = copy.deepcopy(self.receipt)
            if operation == "missing": bad["steps"].pop()
            elif operation == "extra": bad["steps"].append(copy.deepcopy(bad["steps"][-1]))
            else: bad["steps"][0], bad["steps"][1] = bad["steps"][1], bad["steps"][0]
            with self.subTest(operation=operation), self.assertRaises(REJECTIONS): self.validate(bad)
        for key, value in (("exit_code", None), ("exit_code", 101), ("exit_code", False), ("attempts", 2),
                           ("argv", []), ("timed_out", True), ("unexpected_live_descendants_on_success", True),
                           ("owned_group_cleanup", {}), ("requested_cap_seconds", 120000),
                           ("effective_budget_seconds", float("nan")), ("stdout_sha256", None),
                           ("stdout_bytes", -1), ("pid", None), ("seconds", None), ("started_at_unix", None)):
            with self.subTest(key=key, value=value):
                bad = copy.deepcopy(self.receipt); bad["steps"][0][key] = value
                with self.assertRaises(REJECTIONS): self.validate(bad)

    def test_budget_extension_and_missing_terminal_timestamps_refused(self):
        for key, value in (("automatic_retry", True), ("deadline_renewed", True), ("outer_budget_seconds", 24000),
                           ("elapsed_seconds", 12000), ("elapsed_seconds", float("inf")),
                           ("finished_at_unix", None), ("created_at_unix", 3000)):
            with self.subTest(key=key):
                bad = copy.deepcopy(self.receipt); bad[key] = value
                with self.assertRaises(REJECTIONS): self.validate(bad)

    @unittest.skipUnless(os.environ.get("HEPTABAO_X230_FAILED_RECEIPT"), "original failed receipt supplied by operator")
    def test_original_mac09_failed_receipt_is_rejected_without_rewriting(self):
        raw = Path(os.environ["HEPTABAO_X230_FAILED_RECEIPT"]).read_bytes()
        self.assertEqual(digest(raw), FAILED_RECEIPT_SHA)
        actual = dr.full.decode(raw)
        self.assertEqual(actual["status"], "failed")
        self.assertEqual(actual["source_commit"], "09c14eae7a3b52dee8ce3af3175dad5900ac59ec")
        self.assertEqual(actual["observed_test_executed_cases"], 103)
        self.assertEqual(actual["observed_test_passed_cases"], 102)
        self.assertEqual(actual["observed_test_failed_cases"], 1)
        self.assertEqual(actual["unexecuted_or_ignored_required_cases"], 4)
        with self.assertRaisesRegex(q.AdmissionFailure, "terminal_successful_build_required"):
            self.validate(actual)
        self.assertEqual(digest(raw), FAILED_RECEIPT_SHA)


class ComparisonGuards(unittest.TestCase):
    def test_complete_fictional_69_case_parser_sample(self):
        report, admission = fictional_comparison()
        self.assertEqual(len(report["candidate_results"]["cases"]), 69)
        q.validate_comparison(report, admission, acceptance)

    def test_missing_extra_nonexecuted_mismatched_or_cleanup_failure_refused(self):
        for operation in ("missing", "extra", "ignored", "not_run", "mismatch", "cleanup", "oracle_missing", "totp_mount"):
            with self.subTest(operation=operation):
                report, admission = fictional_comparison()
                cases = report["candidate_results"]["cases"]; name = next(iter(cases))
                if operation == "missing": del cases[name]
                elif operation == "extra": cases["extra.case"] = {"result": "passed"}
                elif operation in ("ignored", "not_run"): cases[name]["result"] = operation
                elif operation == "mismatch": cases[name]["observed"] = "different"
                elif operation == "cleanup": report["owned_cleanup_completed"] = False
                elif operation == "totp_mount": del cases["totp.mount"]
                else: report.pop("oracle_results")
                with self.assertRaises(REJECTIONS): q.validate_comparison(report, admission, acceptance)

    def test_original_source_driver_receipt_and_nonproduction_scope_required(self):
        for key, value in (("status", "running"), ("scope", list(q.MODULES)[:-1]),
                           ("production_qualified", True), ("full_openbao_compatibility", True),
                           ("execution_binding", {}), ("native_storage", {}), ("mode", "candidate_smoke")):
            with self.subTest(key=key):
                report, admission = fictional_comparison(); report[key] = value
                with self.assertRaises(REJECTIONS): q.validate_comparison(report, admission, acceptance)

    def test_only_distinct_loopback_tls_fixtures_allowed(self):
        for endpoint in ("http://127.0.0.1:12345", "https://192.0.2.1:12345", "https://localhost:12345",
                         "https://user:pass@127.0.0.1:12345", "https://127.0.0.1:12346",
                         "https://127.0.0.1:12345/?token=x"):
            with self.subTest(endpoint=endpoint):
                report, admission = fictional_comparison(); report["candidate"]["endpoint"] = endpoint
                with self.assertRaises(REJECTIONS): q.validate_comparison(report, admission, acceptance)


class FileAndExecutionGuards(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="x230-admission-guards-")
        self.parent = Path(self.temporary.name).resolve(); self.parent.chmod(0o700)
        self.addCleanup(self.temporary.cleanup)
        self.source = self.parent / "source"; self.source.mkdir(mode=0o700)
        self.args = SimpleNamespace(candidate_source=self.source, private_work_root=self.parent / "new-output")
        for name in ("binary", "seed_binary", "build_receipt", "comparison_driver", "oracle_binary", "oracle_archive"):
            setattr(self.args, name, self.parent / name)
        for name in ("binary", "seed_binary", "comparison_driver", "oracle_binary", "oracle_archive"):
            self.private(getattr(self.args, name), ("fictional-" + name).encode())
        self.args.binary.chmod(0o700); self.args.seed_binary.chmod(0o700)
        self.private(self.parent / "test-selection.public.json", SELECTION_RAW)
        self.deps = SimpleNamespace(dr=dr, full=dr.full, acceptance=acceptance, launcher=SimpleNamespace(verify_inputs=Mock()))

    def private(self, path, raw):
        path.write_bytes(raw); path.chmod(0o600)

    def runtime_patches(self, stack):
        stack.enter_context(patch.object(q, "parse_args", return_value=self.args))
        stack.enter_context(patch.object(q, "sys", SimpleNamespace(flags=SimpleNamespace(isolated=True, no_site=True),
                            dont_write_bytecode=True, platform="linux")))
        stack.enter_context(patch.object(q.platform, "machine", return_value="x86_64"))
        stack.enter_context(patch.object(q.platform, "node", return_value="qian-ThinkPad-X230"))
        stack.enter_context(patch.object(q, "source_snapshot", return_value={"commit": q.BUILD_COMMIT, "tree": q.BUILD_TREE}))
        stack.enter_context(patch.object(q, "load_dependencies", return_value=self.deps))

    def run_refusal(self, raw):
        self.private(self.args.build_receipt, raw); self.args.build_receipt_sha256 = digest(raw)
        with contextlib.ExitStack() as stack:
            self.runtime_patches(stack)
            # Only tiny, fictional files stand in for large artifacts. The real
            # build receipt bytes and receipt parser are never altered.
            stack.enter_context(patch.object(q, "COMPARISON_SHA256", digest(self.args.comparison_driver.read_bytes())))
            stack.enter_context(patch.object(q, "ORACLE_PINS", {name: digest(getattr(self.args, name).read_bytes())
                for name in ("oracle_binary", "oracle_archive")}))
            workload = stack.enter_context(patch.object(q, "run_workloads"))
            stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
            code = q.main([])
        workload.assert_not_called(); self.deps.launcher.verify_inputs.assert_not_called()
        self.assertEqual(code, 1)
        report = json.loads((self.args.private_work_root / "result.public.json").read_bytes())
        self.assertFalse(report["admitted"])
        self.assertEqual(report["status"], "failed")
        self.assertEqual(report["full34"]["status"], "not_run")
        self.assertEqual(report["comparison69"]["status"], "not_run")
        self.assertFalse(report["production_changed"])
        self.assertFalse(report["full_replacement_qualified"])
        return report

    def test_failed_admission_cannot_call_any_fixture_launcher(self):
        report = self.run_refusal(b'{"status":"failed","failure":"known_test_failure"}')
        self.assertEqual(report["failure"], "terminal_successful_build_required")

    @unittest.skipUnless(os.environ.get("HEPTABAO_X230_FAILED_RECEIPT"), "original failed receipt supplied by operator")
    def test_original_failed_mac_report_blocks_main_before_fixture_execution(self):
        raw = Path(os.environ["HEPTABAO_X230_FAILED_RECEIPT"]).read_bytes()
        self.assertEqual(digest(raw), FAILED_RECEIPT_SHA)
        self.assertEqual(self.run_refusal(raw)["failure"], "terminal_successful_build_required")

    def test_existing_output_is_refused_without_overwriting(self):
        self.args.private_work_root.mkdir(mode=0o700)
        sentinel = self.args.private_work_root / "keep"; self.private(sentinel, b"preserve")
        with contextlib.ExitStack() as stack:
            self.runtime_patches(stack)
            workload = stack.enter_context(patch.object(q, "run_workloads"))
            with self.assertRaisesRegex(q.AdmissionFailure, "new_disjoint_private_output_required"):
                q.main([])
        workload.assert_not_called(); self.assertEqual(sentinel.read_bytes(), b"preserve")

    def test_output_beneath_candidate_is_refused(self):
        self.args.private_work_root = self.source / "bad-output"
        with contextlib.ExitStack() as stack:
            self.runtime_patches(stack)
            with self.assertRaisesRegex(q.AdmissionFailure, "new_disjoint_private_output_required"):
                q.main([])
        self.assertFalse(self.args.private_work_root.exists())

    def test_original_json_pin_and_duplicate_keys_are_checked(self):
        self.private(self.args.build_receipt, b'{"status":"failed"}')
        with self.assertRaisesRegex(q.AdmissionFailure, "receipt_bytes_or_expected_pin_mismatch"):
            q.pinned_json(self.args.build_receipt, dr, "0" * 64)
        self.private(self.args.build_receipt, b'{"status":"failed","status":"passed"}')
        with self.assertRaises(REJECTIONS): q.pinned_json(self.args.build_receipt, dr)

    def test_symlink_or_public_receipt_cannot_be_read_as_private_original(self):
        self.private(self.args.build_receipt, b'{}')
        linked = self.parent / "linked"; linked.symlink_to(self.args.build_receipt)
        with self.assertRaises((OSError, dr.Failure)): q.pinned_json(linked, dr)
        self.args.build_receipt.chmod(0o644)
        with self.assertRaises(dr.Failure): q.pinned_json(self.args.build_receipt, dr)

    def test_postflight_change_prevents_success_even_after_mock_workloads(self):
        # This is control-flow testing; all workload calls and admission success
        # are mocks, not evidence that any executable passed qualification.
        bound = {"pins": {}, "unit_test_fixture": True}
        with contextlib.ExitStack() as stack:
            self.runtime_patches(stack)
            stack.enter_context(patch.object(q, "admit", side_effect=[bound, q.AdmissionFailure("input_changed")]))
            stack.enter_context(patch.object(q, "run_workloads"))
            self.deps.launcher.verify_inputs.return_value = self.args.oracle_binary
            stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
            code = q.main([])
        self.assertEqual(code, 1)
        report = json.loads((self.args.private_work_root / "result.public.json").read_bytes())
        self.assertEqual(report["status"], "failed")
        self.assertFalse(report["source_and_inputs_unchanged"])

    def test_ambient_service_and_proxy_configuration_is_removed(self):
        with patch.dict(os.environ, {"HB_CANDIDATE_ADDR": "https://192.0.2.1", "HTTPS_PROXY": "fixture-proxy"}):
            before = dict(os.environ)
            with q.isolated_environment(self.args):
                self.assertNotIn("HB_CANDIDATE_ADDR", os.environ)
                self.assertNotIn("HTTPS_PROXY", os.environ)
                self.assertEqual(os.environ["HB_ORACLE_BINARY"], str(self.args.oracle_binary))
                self.assertEqual(os.environ["TMPDIR"], str(self.args.private_work_root / "tmp"))
            self.assertEqual(dict(os.environ), before)

    def test_source_pin_rejects_dirty_tree_changed_dependency_and_ignored_bytecode(self):
        relative = "qa/openbao-acceptance/workload.py"
        path = self.source / relative; path.parent.mkdir(parents=True)
        raw = b"# fictional source for pin guard tests\n"
        path.write_bytes(raw)
        for directory in q.DEPENDENCY_ROOTS:
            (self.source / directory).mkdir(parents=True, exist_ok=True)
        object_id = hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()
        row = b"100644 blob " + object_id.encode() + b"\t" + relative.encode() + b"\0"

        def fake_git(root, *args):
            if args == ("rev-parse", "HEAD"): return q.BUILD_COMMIT.encode()
            if args == ("rev-parse", "HEAD^{tree}"): return q.BUILD_TREE.encode()
            if args[0] == "status": return b""
            if args[0] == "ls-tree": return row
            self.fail("unexpected source probe")

        with patch.object(q, "git", side_effect=fake_git), patch.object(q, "WORKLOAD_PINS", {relative: digest(raw)}):
            self.assertEqual(q.source_snapshot(self.source)["dependencies"], {relative: digest(raw)})
            path.write_bytes(b"changed")
            with self.assertRaisesRegex(q.AdmissionFailure, "source_dependency_differs_from_frozen_tree"):
                q.source_snapshot(self.source)
            path.write_bytes(raw)
            cached = path.with_suffix(".pyc"); cached.write_bytes(b"ignored bytecode")
            with self.assertRaisesRegex(q.AdmissionFailure, "cached_source_dependency_refused"):
                q.source_snapshot(self.source)
            cached.unlink()
            extra = path.with_name("extra.py"); extra.write_bytes(b"ignored Python source")
            with self.assertRaisesRegex(q.AdmissionFailure, "untracked_source_dependency_refused"):
                q.source_snapshot(self.source)
        with patch.object(q, "git", side_effect=lambda root, *args:
                          b" M tracked" if args[0] == "status" else fake_git(root, *args)):
            with self.assertRaisesRegex(q.AdmissionFailure, "clean_candidate_source_required"):
                q.source_snapshot(self.source)

    def test_full34_failure_stops_comparison_and_finishes_owned_custody(self):
        self.args.private_work_root.mkdir(mode=0o700)
        owner = Mock()
        owner.finish.return_value = {"passed_process_custody": True}

        @contextlib.contextmanager
        def custody():
            yield owner

        def failed_full34(argv):
            self.assertEqual(argv[-4:], ["--migration-lane", "native-large", "--profile", "full34"])
            root = self.args.private_work_root / "full34"; root.mkdir(mode=0o700)
            self.private(root / "summary.json", b'{"status":"failed","failure":"synthetic_control_test"}')
            return 1

        deps = SimpleNamespace(dr=dr, full=SimpleNamespace(main=failed_full34),
                               custody=SimpleNamespace(activated=custody))
        report = {}
        with patch.object(q.runpy, "run_path") as comparison:
            with self.assertRaisesRegex(q.AdmissionFailure, "original_full34_not_qualified"):
                q.run_workloads(self.args, deps, {}, report)
        comparison.assert_not_called(); owner.finish.assert_called_once()
        self.assertIn("process_custody", report)


class StaticReceiverAdmissionGuards(unittest.TestCase):
    """Pure bridge fixtures; fresh filesystem rechecks are explicit mocks."""
    def setUp(self):
        from test_x230_native_abi_admission import bundle, LOADER, RESOLVED, refresh
        self.capture, self.parser, _ = q.load_abi_guards(dr)
        self.refresh = refresh
        artifacts, providers, expected = bundle()
        self.build = {"artifacts": expected}
        self.compatibility = self.parser["verify_compatibility"](artifacts, providers,
            expected_artifact_pins=expected, interpreter_path=LOADER, interpreter_resolved_path=RESOLVED)
        self.value = {"unit_test_fixture_not_an_execution": True,
            "schema": "heptabao.current-native-static-abi-capture.v1", "status": "passed", "role": "receiver",
            "hostname": "qian-ThinkPad-X230", "source_commit": q.BUILD_COMMIT, "source_tree": q.BUILD_TREE,
            "normal107_job_id": q.BUILD_JOB_ID, "static_receiver_compatibility_qualified": True,
            "inputs_unchanged": True, "controller": {"sha256": q.ABI_CAPTURE_SHA256},
            "parser": {"sha256": q.ABI_PARSER_SHA256}, "target_binary_executions": 0,
            "production_changed": False, "actual_x230_runtime_qualified": False, "full_replacement_qualified": False,
            "deadline_renewed": False, "automatic_retry": False,
            "inputs": {"producer_receipt": {}, "producer_terminal": {}}, "tools": {"readelf": {}, "ldconfig": {}},
            "artifacts": artifacts, "providers": providers,
            "interpreter_pin": {"path": RESOLVED}, "compatibility": self.compatibility,
            "provider_lookup_candidates": {name: [row["pin"]["path"]] for name, row in providers.items()},
            "provider_alias_bindings": {row["pin"]["path"]: {"path": row["pin"]["path"],
                "resolved_path": row["pin"]["path"], "components": []} for row in providers.values()}}
        self.terminal = {"job_id": "actual-abi-job", "state": "succeeded", "exit_code": 0,
            "output_complete": True, "output_durable": True, "terminal_publication_confirmed": True,
            "timed_out": False, "cancelled": False, "automatic_retry": False,
            "log_bytes": {key: {"seen": 0, "stored": 0} for key in ("stdout", "stderr")},
            "log_synced": {key: True for key in ("stdout", "stderr")},
            "log_truncated": {key: False for key in ("stdout", "stderr")},
            "log_errors": {key: None for key in ("stdout", "stderr")}}
        self.fresh = Mock()
        self.capture = dict(self.capture, Capture=Mock(return_value=self.fresh))

    def validate(self):
        return q.validate_static_admission(self.value, self.terminal, "actual-abi-job", self.build,
                                           self.capture, self.parser)

    def test_public_reviewed_code_is_allowed_but_other_writable_code_is_refused(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            for name in ("x230_native_abi_capture.py", "x230_native_abi_admission.py"):
                source = Path(q.__file__).with_name(name)
                (root / name).write_bytes(source.read_bytes()); (root / name).chmod(0o644)
            with patch.object(q, "__file__", str(root / "qualification.py")):
                capture, parser, pins = q.load_abi_guards(dr)
                self.assertTrue(callable(capture["require_terminal"]))
                self.assertTrue(callable(parser["verify_compatibility"]))
                self.assertTrue(all(pin["mode"] == 0o644 for pin in pins.values()))
                (root / "x230_native_abi_capture.py").chmod(0o666)
                with self.assertRaisesRegex(q.AdmissionFailure, "owned_reviewed_abi_source_custody"):
                    q.load_abi_guards(dr)

    def test_static_match_requires_fresh_receiver_recheck_without_runtime_claim(self):
        result = self.validate()
        self.fresh.recheck.assert_called_once_with(self.value)
        self.assertTrue(result["receiver_current_pins_rechecked"])
        self.assertFalse(result["actual_x230_runtime_qualified_by_admission"])

    def test_failed_nonterminal_or_wrong_original_abi_terminal_refused(self):
        for key, value in (("state", "running"), ("state", "failed"), ("job_id", "other"),
                           ("exit_code", 1), ("timed_out", True), ("output_durable", False)):
            with self.subTest(key=key):
                before = copy.deepcopy(self.terminal); self.terminal[key] = value
                with self.assertRaises(self.capture["Refused"]): self.validate()
                self.terminal = before
        self.fresh.recheck.assert_not_called()

    def test_source_scope_and_parser_controller_hashes_remain_bound(self):
        for key, value in (("status", "running"), ("source_commit", "0" * 40), ("source_tree", "0" * 40),
                           ("normal107_job_id", "other"), ("hostname", "other"),
                           ("controller", {"sha256": "0" * 64}), ("parser", {"sha256": "0" * 64}),
                           ("inputs_unchanged", False), ("actual_x230_runtime_qualified", True)):
            with self.subTest(key=key):
                before = copy.deepcopy(self.value); self.value[key] = value
                with self.assertRaises(q.AdmissionFailure): self.validate()
                self.value = before
        self.fresh.recheck.assert_not_called()

    def test_incomplete_or_misdirected_alias_sets_and_tools_refused(self):
        for mutation in (lambda v: v["tools"].pop("ldconfig"),
                         lambda v: v["inputs"].update(extra={}),
                         lambda v: v["provider_alias_bindings"].pop(next(iter(v["provider_alias_bindings"]))),
                         lambda v: next(iter(v["provider_alias_bindings"].values())).update(resolved_path="/wrong/provider"),
                         lambda v: v.update(compatibility={})):
            before = copy.deepcopy(self.value); mutation(self.value)
            with self.assertRaises(q.AdmissionFailure): self.validate()
            self.value = before
        self.fresh.recheck.assert_not_called()

    def test_actual_version_parser_rejects_missing_middle_glibc_definition(self):
        row = self.value["providers"]["libc.so.6"]
        row["raw_readelf"] = row["raw_readelf"].replace("GLIBC_2.34", "GLIBC_2.42")
        self.refresh(row)
        with self.assertRaisesRegex(self.parser["AbiRefused"], "provider_version_set_incomplete"):
            self.validate()
        self.fresh.recheck.assert_not_called()

    def test_changed_receiver_files_or_aliases_block_admission(self):
        self.fresh.recheck.side_effect = self.capture["Refused"]("actual_loader_lookup_alias_changed")
        with self.assertRaisesRegex(self.capture["Refused"], "actual_loader_lookup_alias_changed"):
            self.validate()

    def test_requirement_row_order_is_immaterial_without_mutating_original(self):
        self.value["compatibility"]["requirements"].reverse()
        before = copy.deepcopy(self.value)
        result = self.validate()
        self.assertEqual(self.value, before)
        self.fresh.recheck.assert_called_once_with(self.value)
        self.assertFalse(result["actual_x230_runtime_qualified_by_admission"])

    def test_missing_extra_duplicate_or_changed_requirement_rows_are_refused(self):
        mutations = (
            lambda rows: rows.pop(),
            lambda rows: rows.append(copy.deepcopy(rows[0])),
            lambda rows: rows.append(dict(copy.deepcopy(rows[0]), origin="unexpected-origin")),
            lambda rows: rows[0].update(provider="unexpected-provider"),
            lambda rows: rows[0].update(required_versions=["CHANGED_VERSION"]),
        )
        for index, mutation in enumerate(mutations):
            with self.subTest(index=index):
                before = copy.deepcopy(self.value)
                mutation(self.value["compatibility"]["requirements"])
                with self.assertRaises(q.AdmissionFailure): self.validate()
                self.value = before
        self.fresh.recheck.assert_not_called()

    def test_requirement_row_shape_and_version_types_are_exact(self):
        mutations = (
            lambda c: c.update(requirements={}),
            lambda c: c["requirements"].__setitem__(0, []),
            lambda c: c["requirements"][0].update(extra=True),
            lambda c: c["requirements"][0].pop("provider"),
            lambda c: c["requirements"][0].update(origin=1),
            lambda c: c["requirements"][0].update(provider=""),
            lambda c: c["requirements"][0].update(required_versions="GLIBC_2.39"),
            lambda c: c["requirements"][0].update(required_versions=[1]),
            lambda c: c["requirements"][0].update(required_versions=[]),
            lambda c: c["requirements"][0].update(required_versions=["VERSION", "VERSION"]),
            lambda c: c["requirements"][0].update(required_versions=["VERSION_Z", "VERSION_A"]),
        )
        for index, mutation in enumerate(mutations):
            with self.subTest(index=index):
                before = copy.deepcopy(self.value)
                mutation(self.value["compatibility"])
                with self.assertRaises(q.AdmissionFailure): self.validate()
                self.value = before
        self.fresh.recheck.assert_not_called()

    def test_requirement_order_fix_preserves_all_other_compatibility_fields(self):
        mutations = (
            lambda c: c.update(interpreter_path="/different/loader"),
            lambda c: c.update(actual_x230_runtime_qualified=True),
            lambda c: c.update(static_elf_and_version_requirements_match=False),
            lambda c: c["artifacts"]["heptabao-server"].update(sha256="0" * 64),
            lambda c: c["providers"]["libc.so.6"].update(bytes=1),
        )
        for index, mutation in enumerate(mutations):
            with self.subTest(index=index):
                before = copy.deepcopy(self.value)
                # Keep the original capture rows independent of the stored
                # compatibility summary, as in a serialized public receipt.
                self.value = json.loads(json.dumps(self.value))
                mutation(self.value["compatibility"])
                with self.assertRaises(q.AdmissionFailure): self.validate()
                self.value = before
        self.fresh.recheck.assert_not_called()


class ActualReceiverRequirementOrderRegression(unittest.TestCase):
    """Exact immutable real receipts; local filesystem recheck remains a mock."""
    def test_actual_serialized_eleven_provider_closure_keeps_all_thirty_one_rows(self):
        fixtures = (
            ("HEPTABAO_X230_ACTUAL_STATIC_RECEIPT",
             "evidence/x230-static-abi-20261106-r1/current-pocket4/receiver-current-pocket4.result.original.public.json",
             "ca07a01f3c67d6934e18e1be4c9869cf90677ed735cfc3f8266f9f0e857669c6"),
            ("HEPTABAO_X230_ACTUAL_STATIC_TERMINAL",
             "evidence/x230-static-abi-20261106-r1/current-pocket4/receiver-current-pocket4.terminal.exact-tool-text.json",
             "083e3abfb39cbe4edb4270ebb5802906a59cb322192500723820bd6a51771f1c"),
            ("HEPTABAO_X230_ACTUAL_NORMAL107_RECEIPT",
             "evidence/pocket4-current-4bde9-qualification-20261106-r1/normal107-completed/normal107.result.original.public.json",
             "b52b67303587b3f94f1bed5330dfd2b0edaecabb89feb93d3fd3ff81419a47f5"),
        )
        values = []
        for variable, relative, expected in fixtures:
            raw = Path(os.environ.get(variable, str(HERE / relative))).read_bytes()
            self.assertEqual(digest(raw), expected)
            values.append(json.loads(raw))
        value, terminal, build = values
        capture, parser, _ = q.load_abi_guards(dr)
        expected = {name: build["artifacts"][name] for name in ("heptabao-server", "heptabao-seed")}
        recomputed = parser["verify_compatibility"](value["artifacts"], value["providers"],
            expected_artifact_pins=expected, interpreter_path="/lib64/ld-linux-x86-64.so.2",
            interpreter_resolved_path=value["interpreter_pin"]["path"])
        self.assertEqual(len(value["providers"]), 11)
        self.assertEqual(len(value["compatibility"]["requirements"]), 31)
        self.assertEqual(len(recomputed["requirements"]), 31)
        self.assertNotEqual(recomputed, value["compatibility"])
        self.assertEqual(q.canonical_static_compatibility(recomputed),
                         q.canonical_static_compatibility(value["compatibility"]))
        fresh = Mock()
        capture = dict(capture, Capture=Mock(return_value=fresh))
        before = copy.deepcopy(value)
        result = q.validate_static_admission(value, terminal, "1a1b277e5bb-fc05-7e22", build, capture, parser)
        self.assertEqual(value, before)
        fresh.recheck.assert_called_once_with(value)
        self.assertFalse(result["actual_x230_runtime_qualified_by_admission"])


if __name__ == "__main__":
    unittest.main()
