#!/usr/bin/env python3
"""One bounded Darwin guard run and a private in-memory old-baseline validation.
Prepared for explicit execution only after the fresh canonical QA source exists.
No product executable, provider, client, or old failed-work mutation is allowed.
"""
from __future__ import annotations
import time
START = time.monotonic()
DEADLINE = START + 52.0
import ast
import contextlib
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import signal
import stat
import subprocess
import sys
import tempfile
import unittest

ROOT = Path("/Volumes/T5/hepta-vnext-recovery-20261013/continuation-20261106-kv2-ha-convergence-r1")
SOURCE = ROOT / "source-dr25-a2577-r2"
CONTROL = ROOT / "control" / "dr25-a2577-guards-r1"
OLD_BASELINE = ROOT / "full34-dr25-r1" / "baseline" / "summary.json"
QA_COMMIT = "a25772377e9bfad91564cf6702a26e861fded16f"
QA_TREE = "d34d344e261811c406f63de56b3a7227c0e0ddf3"
PRODUCT_COMMIT = "4bde9aee03fcd27c59e13607e529b1cee594b249"
PYTHON_SHA256 = "cebfcc4ac431ff7a2179bc6eff7e5c6bdae48b564eeab2d504bef6173a2cfc13"
PINS = {
    "kv2_native_fresh_directory_dr_live.py": (75012, "2271a4ca539e1190b03e95e95d4d1c79414bd852c80ac85e205def2adac74263"),
    "tests/test_kv2_native_fresh_directory_dr_live.py": (43105, "6bbf43a640e997ebfff5ac8f539a456ead96dfa08d4c80ae3a413dffd058291f"),
    "kv2_dr_process_custody.py": (26131, "669e2cd1d9ee597529c08b88f3fc21c813d4ff7b57f3792381baa44fbdbe7008"),
    "tests/test_kv2_dr_process_custody.py": (17148, "41d3b0e079b2b17a0ece458f907adf380542cbdf96530213869636e81a447807"),
    "owned_process.py": (28442, "0ee96c9f43b50ebd57ee8f0ef95f2431c441ec02c1799992588dbf50768745d0"),
    "kv2_271_lossless_native_live.py": (49393, "383176647f0670837f40f3989496c6d1c902f8503dfa006d386b75877436b581"),
}
EXPECTED_TESTS = ('test_kv2_native_fresh_directory_dr_live.ControllerGuards.test_archive_inspection_requires_v6_and_does_not_claim_aead', 'test_kv2_native_fresh_directory_dr_live.ControllerGuards.test_archive_refuses_noncanonical_tar_header_before_extraction', 'test_kv2_native_fresh_directory_dr_live.ControllerGuards.test_archive_rejects_truncation_trailing_members_and_changed_state', 'test_kv2_native_fresh_directory_dr_live.ControllerGuards.test_backup_and_key_parent_overlap_refuses_before_product_execution', 'test_kv2_native_fresh_directory_dr_live.ControllerGuards.test_build_receipt_binds_both_actual_executables_and_completed_source', 'test_kv2_native_fresh_directory_dr_live.ControllerGuards.test_build_receipt_cannot_claim_passed_with_missing_or_partial_107_results', 'test_kv2_native_fresh_directory_dr_live.ControllerGuards.test_build_receipt_cannot_count_one_test_twice_across_groups', 'test_kv2_native_fresh_directory_dr_live.ControllerGuards.test_build_receipt_requires_pinned_selection_and_matching_enumeration', 'test_kv2_native_fresh_directory_dr_live.ControllerGuards.test_child_custody_failure_still_retains_private_outputs_and_phase', 'test_kv2_native_fresh_directory_dr_live.ControllerGuards.test_child_output_fingerprint_is_private_even_if_utility_echoes_a_credential', 'test_kv2_native_fresh_directory_dr_live.ControllerGuards.test_child_rejection_requires_real_status_and_never_retries_label', 'test_kv2_native_fresh_directory_dr_live.ControllerGuards.test_child_timeout_retains_failure_and_joins_owned_original', 'test_kv2_native_fresh_directory_dr_live.ControllerGuards.test_data_cas_denial_with_effect_fails_and_keeps_subobservations', 'test_kv2_native_fresh_directory_dr_live.ControllerGuards.test_dr25_requires_exact_unique_denominator_and_real_evidence', 'test_kv2_native_fresh_directory_dr_live.ControllerGuards.test_final_gate_rechecks_private_key_directory_even_when_files_remain_private', 'test_kv2_native_fresh_directory_dr_live.ControllerGuards.test_final_gate_requires_complete_custody_receipt_even_without_failed_flag', 'test_kv2_native_fresh_directory_dr_live.ControllerGuards.test_finish_redacts_credential_hashes_as_well_as_plaintext', 'test_kv2_native_fresh_directory_dr_live.ControllerGuards.test_full34_subclass_observes_original_check_before_callback', 'test_kv2_native_fresh_directory_dr_live.ControllerGuards.test_incomplete_finish_cannot_grant_authority_and_redacts_runtime_token', 'test_kv2_native_fresh_directory_dr_live.ControllerGuards.test_main_publishes_same_filesystem_refusal_with_real_custody_and_no_children', 'test_kv2_native_fresh_directory_dr_live.ControllerGuards.test_metadata_cas_denial_with_effect_fails_and_keeps_subobservations', 'test_kv2_native_fresh_directory_dr_live.ControllerGuards.test_nonregular_input_is_rejected_without_waiting_for_a_pipe_writer', 'test_kv2_native_fresh_directory_dr_live.ControllerGuards.test_original_full34_gate_cannot_be_replaced_by_dr_checks', 'test_kv2_native_fresh_directory_dr_live.ControllerGuards.test_parent_fd_retirement_detects_real_open_file_directory_and_closed_boundary', 'test_kv2_native_fresh_directory_dr_live.ControllerGuards.test_parent_fd_retirement_rejects_unclosed_stdio_and_observation_gaps', 'test_kv2_native_fresh_directory_dr_live.ControllerGuards.test_public_tree_summary_withholds_direct_and_aggregate_credential_fingerprints', 'test_kv2_native_fresh_directory_dr_live.ControllerGuards.test_recovery_api_requires_exact_official_response_tokens', 'test_kv2_native_fresh_directory_dr_live.ControllerGuards.test_same_filesystem_fails_before_any_server_or_official_cli', 'test_kv2_native_fresh_directory_dr_live.ControllerGuards.test_seed_stage_requires_exact_receipt_destination_and_four_private_files', 'test_kv2_native_fresh_directory_dr_live.ControllerGuards.test_snapshot_capture_accepts_small_physical_pack_with_full_logical_history', 'test_kv2_native_fresh_directory_dr_live.ControllerGuards.test_snapshot_capture_refuses_logical_shortfall_and_wrong_profile', 'test_kv2_native_fresh_directory_dr_live.ControllerGuards.test_snapshot_capture_requires_both_unique_raw_19_version_witnesses', 'test_kv2_native_fresh_directory_dr_live.ControllerGuards.test_snapshot_capture_requires_exact_checks_and_19_source_api_observations', 'test_kv2_native_fresh_directory_dr_live.ControllerGuards.test_snapshot_capture_still_refuses_mismatched_seal_with_full_history', 'test_kv2_native_fresh_directory_dr_live.ControllerGuards.test_snapshot_capture_still_refuses_truncated_archive_with_full_history', 'test_kv2_native_fresh_directory_dr_live.ControllerGuards.test_tree_manifest_preserves_rename_boundary_and_detects_byte_change', 'test_kv2_native_fresh_directory_dr_live.ControllerGuards.test_tree_manifest_refuses_hardlinks_and_symlinked_closures', 'test_kv2_dr_process_custody.ProcessCustodyTests.test_cancel_enters_final_cleanup_and_restores_original_signal_handlers', 'test_kv2_dr_process_custody.ProcessCustodyTests.test_darwin_live_esrch_never_uses_a_zombie_anchor_or_grants_retirement', 'test_kv2_dr_process_custody.ProcessCustodyTests.test_darwin_numeric_parser_rejects_session_pointer_and_uses_kernel_sid', 'test_kv2_dr_process_custody.ProcessCustodyTests.test_darwin_observed_signed_nobody_uid_is_numeric_not_a_parse_gap', 'test_kv2_dr_process_custody.ProcessCustodyTests.test_darwin_waitable_zombie_requires_original_waitid_and_exact_retained_ps_identity', 'test_kv2_dr_process_custody.ProcessCustodyTests.test_foreign_reap_loses_authority_and_never_signals_recycled_group', 'test_kv2_dr_process_custody.ProcessCustodyTests.test_gate_identity_failure_never_executes_target_or_signals_a_guessed_group', 'test_kv2_dr_process_custody.ProcessCustodyTests.test_leader_exit_with_live_descendant_is_failure_and_only_owned_group_is_killed', 'test_kv2_dr_process_custody.ProcessCustodyTests.test_legacy_raw_killpg_after_nonzero_communicate_never_signals_retired_id', 'test_kv2_dr_process_custody.ProcessCustodyTests.test_legacy_raw_killpg_live_owned_group_routes_once_and_restores_global_hook', 'test_kv2_dr_process_custody.ProcessCustodyTests.test_legacy_raw_killpg_unknown_group_is_refused_without_touching_foreign_process', 'test_kv2_dr_process_custody.ProcessCustodyTests.test_missing_wnowait_and_external_sigchld_reaper_refuse_before_spawn', 'test_kv2_dr_process_custody.ProcessCustodyTests.test_nested_owner_and_finished_owner_do_not_create_new_originals', 'test_kv2_dr_process_custody.ProcessCustodyTests.test_prior_retirement_receipt_cannot_change_when_later_originals_run', 'test_kv2_dr_process_custody.ProcessCustodyTests.test_real_target_executes_only_in_observed_original_session_and_waits_once', 'test_kv2_dr_process_custody.ProcessCustodyTests.test_retirement_gate_does_not_stop_a_live_target', 'test_kv2_dr_process_custody.ProcessCustodyTests.test_run_check_output_and_owned_process_compatibility_share_originals', 'test_kv2_dr_process_custody.ProcessCustodyTests.test_wait_timeout_keeps_original_anchor_then_declared_stop_retires_it')
CAPTURE_CASES = (
    "official_271_pins_and_live_identity", "two_distinct_owned_processes",
    "source_api_oracle_captured", "source_retained_deleted_destroyed_seeded",
    "source_metadata_cas_seeded", "source_cold_restart_exact",
    "target_pristine_before_import", "source_export_once", "source_raw_history_exact",
    "exported_soft_deleted_payload_preserved", "source_unchanged_after_export",
    "target_import_once", "target_active_native_v6", "target_full_history_exact",
    "target_storage_full_history_exact", "target_cold_restart_exact",
    "target_storage_cold_history_exact", "snapshot_download",
)
FINAL_CASES = ("source_and_binary_unchanged", "owned_processes_stopped", "report_excludes_runtime_credentials")
CUSTODY = None
LAST_RESULT = None
DEADLINE_FIRED = False
INTERRUPTED = False
CONTROL_CREATED = False
REPORT = {
    "schema": "heptabao.mac-fixed-qa55-and-private-old-baseline-validation.v1",
    "qa_source_commit": QA_COMMIT, "qa_source_tree": QA_TREE,
    "product_source_commit_unchanged": PRODUCT_COMMIT,
    "work_budget_seconds": 52, "runtime_budget_seconds": 60,
    "elapsed_observation_before_receipt_publication": True,
    "durable_completion_authority": "separate_original_runtime_terminal_with_60_second_cap",
    "deadline_renewed": False, "automatic_retry": False,
    "product_executed": False, "product_rebuilt": False,
    "provider_or_j3160_called": False, "old_baseline_modified": False,
    "private_baseline_read": False, "private_values_or_fingerprints_emitted": False,
    "production_qualified": False, "formal_kv2_qualified": False,
    "physical_ha_qualified": False, "authbus_qualified": False,
    "dr25_recovery_qualified": False, "resource_benchmark_qualified": False,
    "status": "failed", "phase": "initial",
}

class WorkInterrupted(KeyboardInterrupt):
    pass

def need(condition, label):
    if not condition:
        raise RuntimeError(label)

def checkpoint():
    if DEADLINE_FIRED or INTERRUPTED or time.monotonic() >= DEADLINE:
        raise WorkInterrupted()

def interrupt(signum, frame):
    global DEADLINE_FIRED, INTERRUPTED
    if signum == signal.SIGALRM:
        DEADLINE_FIRED = True
    else:
        INTERRUPTED = True
    owner = getattr(CUSTODY, "_ACTIVE", None) if CUSTODY is not None else None
    if owner is not None:
        # Original custody defers interruption across spawn/register and reaping.
        owner._interrupt(signum, frame)
        return
    raise WorkInterrupted()

def identity(st):
    return (st.st_dev, st.st_ino, st.st_uid, st.st_gid, st.st_mode,
            st.st_nlink, st.st_size, st.st_mtime_ns, st.st_ctime_ns)

def bounded_read(path, limit, *, private=False):
    checkpoint()
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_size <= limit,
             "regular_bounded_single_link_required")
        if private:
            need(before.st_uid == os.geteuid() and stat.S_IMODE(before.st_mode) == 0o600,
                 "private_baseline_metadata_required")
        chunks, count = [], 0
        while True:
            checkpoint()
            block = os.read(fd, 65536)
            if not block:
                break
            count += len(block)
            need(count <= limit, "bounded_read_cap")
            chunks.append(block)
        need(identity(before) == identity(os.fstat(fd)), "input_changed_during_read")
        return b"".join(chunks), identity(before)
    finally:
        os.close(fd)

def pin_inputs():
    qa = SOURCE / "qa" / "openbao-acceptance"
    out = {}
    for name, (size, expected) in PINS.items():
        raw, _ = bounded_read(qa / name, max(size, 65536))
        actual = hashlib.sha256(raw).hexdigest()
        need(len(raw) == size and actual == expected, "fixed_qa_input_pin_mismatch")
        out[name] = {"bytes": size, "sha256": actual}
    return out

def source_identity(label):
    checkpoint()
    observed = {}
    with CUSTODY.activated() as owner:
        for key, argv in (
            ("commit", ["rev-parse", "HEAD"]),
            ("tree", ["rev-parse", "HEAD^{tree}"]),
            ("status", ["status", "--porcelain=v1", "--untracked-files=all"]),
        ):
            checkpoint()
            child = subprocess.run(
                ["/usr/bin/git", "--no-optional-locks", "-c", "core.hooksPath=/dev/null", *argv],
                cwd=SOURCE, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                timeout=min(5.0, max(0.001, DEADLINE - time.monotonic())), check=False,
            )
            need(child.returncode == 0 and not child.stderr, "source_identity_command_failed")
            observed[key] = child.stdout.decode("utf-8").strip()
        owner.assert_retired()
    receipt = owner.receipt()
    need(receipt["passed_process_custody"] is True and receipt["finished"] is True,
         "source_identity_custody_incomplete")
    need(observed == {"commit": QA_COMMIT, "tree": QA_TREE, "status": ""}, "source_identity_mismatch")
    REPORT[label] = {
        "commit": observed["commit"], "tree": observed["tree"], "clean": True,
        "owned_commands": receipt["original_count"],
        "all_original_waits_completed": all(x["original_wait_completed"] for x in receipt["children"]),
        "all_original_waits_once": all(x["original_wait_count"] == 1 for x in receipt["children"]),
        "all_no_live_before_reap": all(x["no_live_members_before_reap"] for x in receipt["children"]),
        "passed_process_custody": receipt["passed_process_custody"],
    }

def flatten(suite):
    result = []
    for item in suite:
        result.extend(flatten(item) if isinstance(item, unittest.TestSuite) else [item.id()])
    return result

class ExactResult(unittest.TextTestResult):
    def __init__(self, *args, **kwargs):
        global LAST_RESULT
        super().__init__(*args, **kwargs)
        self.actual = []
        self.started = []
        LAST_RESULT = self
    def startTest(self, test):
        checkpoint()
        super().startTest(test)
        self.started.append(test.id())
    def addSuccess(self, test):
        self.actual.append({"test": test.id(), "status": "passed"})
        super().addSuccess(test)
    def addFailure(self, test, err):
        self.actual.append({"test": test.id(), "status": "failed", "error_type": err[0].__name__})
        super().addFailure(test, err)
    def addError(self, test, err):
        self.actual.append({"test": test.id(), "status": "error", "error_type": err[0].__name__})
        super().addError(test, err)
    def addSkip(self, test, reason):
        self.actual.append({"test": test.id(), "status": "skipped"})
        super().addSkip(test, reason)
    def addExpectedFailure(self, test, err):
        self.actual.append({"test": test.id(), "status": "expected_failure", "error_type": err[0].__name__})
        super().addExpectedFailure(test, err)
    def addUnexpectedSuccess(self, test):
        self.actual.append({"test": test.id(), "status": "unexpected_success"})
        super().addUnexpectedSuccess(test)
    def stopTest(self, test):
        super().stopTest(test)
        checkpoint()

def run_guards():
    checkpoint()
    REPORT["phase"] = "guards"
    originals = (subprocess.Popen, os.killpg,
                 {s: signal.getsignal(s) for s in (signal.SIGCHLD, signal.SIGTERM, signal.SIGINT, signal.SIGHUP)})
    loader = unittest.TestLoader()
    suite = unittest.TestSuite([
        loader.loadTestsFromName("test_kv2_native_fresh_directory_dr_live.ControllerGuards"),
        loader.loadTestsFromName("test_kv2_dr_process_custody.ProcessCustodyTests"),
    ])
    names = flatten(suite)
    need(not loader.errors and suite.countTestCases() == 55
         and len(set(names)) == 55 and sorted(names) == sorted(EXPECTED_TESTS),
         "exact_guard_selection_mismatch")
    REPORT["guard_enumeration"] = {"expected": 55, "dr_guards": 37, "custody_guards": 18,
                                   "actual_unique": len(set(names)), "names": names}
    result = None
    hooks_restored = False
    with (CONTROL / "guards.stdout").open("x", encoding="utf-8") as out, \
         (CONTROL / "guards.stderr").open("x", encoding="utf-8") as err:
        try:
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                result = unittest.TextTestRunner(stream=err, verbosity=2, resultclass=ExactResult).run(suite)
        finally:
            out.flush()
            err.flush()
            result = LAST_RESULT
            hooks_restored = (subprocess.Popen is originals[0] and os.killpg is originals[1]
                and all(signal.getsignal(s) == handler for s, handler in originals[2].items())
                and getattr(CUSTODY, "_ACTIVE", None) is None)
            if result is not None:
                REPORT["guards"] = {
                    "tests_run": result.testsRun, "started_names": list(result.started),
                    "completed_results": len(result.actual),
                    "passed": sum(x["status"] == "passed" for x in result.actual),
                    "failures": len(result.failures), "errors": len(result.errors),
                    "skipped": len(result.skipped), "expected_failures": len(result.expectedFailures),
                    "unexpected_successes": len(result.unexpectedSuccesses), "results": result.actual,
                    "global_hooks_restored": hooks_restored,
                }
    # The suite deliberately contains negative custody cases. Do not wrap the
    # entire suite in activated(), alter those cases, or call all owners passed.
    need(hooks_restored, "guard_global_hooks_not_restored")
    checkpoint()
    need(result is not None and result.testsRun == 55 and len(result.actual) == 55
         and {x["test"] for x in result.actual} == set(EXPECTED_TESTS)
         and all(x["status"] == "passed" for x in result.actual),
         "actual_guard_suite_not_55_passed")

def validate_old_baseline(dr):
    checkpoint()
    REPORT["phase"] = "actual_old_baseline_readonly_validation"
    raw, before = bounded_read(OLD_BASELINE, 8 * 1024 * 1024, private=True)
    REPORT["private_baseline_read"] = True
    original = json.loads(raw)
    need(isinstance(original, dict), "old_baseline_not_object")
    checks = original.get("checks")
    need(isinstance(checks, list) and len(checks) == 21 and all(isinstance(x, dict) for x in checks),
         "old_baseline_exact21_shape")
    actual_names = [x.get("case") for x in checks]
    need(actual_names == list(CAPTURE_CASES + FINAL_CASES)
         and len(set(actual_names)) == 21 and all(x.get("passed") is True for x in checks),
         "old_baseline_exact21_names_and_status")
    expected_capture = dr.full.CHECKS[:dr.full.CHECKS.index("snapshot_download") + 1]
    need(tuple(expected_capture) == CAPTURE_CASES and len(expected_capture) == 18,
         "new_helper_capture_contract_changed")
    need(original.get("status") == "failed" and original.get("production_authority") is False,
         "original_failed_private_boundary")
    original_gate, ignored_original_detail = dr.full34_snapshot_history(original)
    need(original_gate is False, "original21_must_not_be_admitted_as_capture18")
    projected = copy.deepcopy(original)
    projected["checks"] = [x for x in projected["checks"] if x["case"] not in FINAL_CASES]
    need([x["case"] for x in projected["checks"]] == list(CAPTURE_CASES), "projected_exact18")
    accepted, detail = dr.full34_snapshot_history(projected)
    wires = detail.get("source_api_observations", [])
    stages = detail.get("storage_witnesses", [])
    need(len(wires) == 19 and len(stages) == 2
         and all(len(x.get("versions", [])) == 19 for x in stages),
         "actual19_api_and_two19_raw_witnesses_required")
    # No original status, capacities, observations, payloads, digests, or
    # credential-dependent fingerprints are emitted, even on helper refusal.
    after_raw, after = bounded_read(OLD_BASELINE, 8 * 1024 * 1024, private=True)
    need(raw == after_raw and before == after, "old_baseline_changed")
    REPORT["actual_old_baseline_validator"] = {
        "original_failed_status_preserved": original["status"] == projected["status"] == "failed",
        "original_check_count": 21, "original21_exact": True,
        "only_three_fixed_final_checks_removed_in_memory": True,
        "capture_check_count": len(projected["checks"]), "capture18_exact": True,
        "original21_validator_passed": original_gate,
        "projected18_validator_passed": accepted is True,
        "source_api_observation_count": len(wires),
        "raw_witness_count": len(stages),
        "raw_witness_version_counts": [len(x["versions"]) for x in stages],
        "old_summary_unchanged": True,
        "baseline31_remains_unqualified": dr.full34_complete(original) is False and dr.full34_complete(projected) is False,
        "private_values_or_fingerprints_emitted": False,
    }
    need(accepted is True and REPORT["actual_old_baseline_validator"]["baseline31_remains_unqualified"],
         "actual_old_baseline_new_validator_refused")
    del raw, after_raw, original, projected, detail, ignored_original_detail, wires, stages
    checkpoint()

def write_result():
    data = (json.dumps(REPORT, sort_keys=True, indent=2) + "\n").encode()
    if CONTROL_CREATED:
        fd = os.open(CONTROL / "result.public.json", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
    print(json.dumps(REPORT, sort_keys=True), flush=True)

def main():
    global CUSTODY, CONTROL_CREATED
    saved_handlers = {s: signal.getsignal(s) for s in (signal.SIGALRM, signal.SIGTERM, signal.SIGINT, signal.SIGHUP)}
    saved_timer = signal.getitimer(signal.ITIMER_REAL)
    timer_installed = False
    saved_tmp = os.environ.get("TMPDIR")
    saved_tempfile_dir = tempfile.tempdir
    saved_umask = os.umask(0o077)
    try:
        need(saved_timer == (0.0, 0.0), "ambient_interval_timer_refused")
        need(sys.platform == "darwin" and os.geteuid() == 501 and sys.version_info[:3] == (3, 14, 3),
             "fixed_darwin_python_required")
        python_raw = Path(sys.executable).resolve(strict=True).read_bytes()
        need(hashlib.sha256(python_raw).hexdigest() == PYTHON_SHA256, "fixed_python_sha_mismatch")
        del python_raw
        need(all(hasattr(os, k) for k in ("waitid", "WNOWAIT", "WEXITED", "WNOHANG", "P_PID")), "wnowait_required")
        for sig in saved_handlers:
            signal.signal(sig, interrupt)
        signal.setitimer(signal.ITIMER_REAL, max(0.000001, DEADLINE - time.monotonic()))
        timer_installed = True
        checkpoint()
        parent = CONTROL.parent
        st = parent.lstat()
        need(parent.resolve(strict=True) == parent and stat.S_ISDIR(st.st_mode)
             and st.st_uid == 501 and not (stat.S_IMODE(st.st_mode) & 0o077),
             "owned_private_control_parent_required")
        need(SOURCE.resolve(strict=True) == SOURCE and SOURCE.is_dir(), "fresh_qa_source_path_required")
        CONTROL.mkdir(mode=0o700)
        CONTROL_CREATED = True
        temp_root = CONTROL / "tmp"
        temp_root.mkdir(mode=0o700)
        os.environ["TMPDIR"] = str(temp_root)
        tempfile.tempdir = str(temp_root)
        sys.dont_write_bytecode = True
        REPORT["phase"] = "source_admission"
        REPORT["input_pins_before"] = pin_inputs()
        qa = SOURCE / "qa" / "openbao-acceptance"
        sys.path[:0] = [str(qa), str(qa / "tests")]
        import kv2_dr_process_custody as custody
        import kv2_native_fresh_directory_dr_live as dr
        CUSTODY = custody
        need(Path(custody.__file__).resolve() == qa / "kv2_dr_process_custody.py"
             and Path(dr.__file__).resolve() == qa / "kv2_native_fresh_directory_dr_live.py",
             "module_origin_mismatch")
        source_identity("source_before")
        run_guards()
        validate_old_baseline(dr)
        REPORT["phase"] = "source_postflight"
        REPORT["input_pins_after"] = pin_inputs()
        need(REPORT["input_pins_before"] == REPORT["input_pins_after"], "qa_inputs_changed")
        source_identity("source_after")
        checkpoint()
        REPORT["status"] = "passed"
        REPORT["phase"] = "complete"
    except BaseException as error:
        REPORT["status"] = "failed"
        REPORT["failure_type"] = type(error).__name__
        # Closed labels only. Never serialize exception arguments in this controller.
    finally:
        work_finished = time.monotonic()
        if DEADLINE_FIRED or INTERRUPTED or work_finished >= DEADLINE:
            REPORT["status"] = "failed"
        REPORT["deadline_fired"] = DEADLINE_FIRED
        REPORT["interrupted"] = INTERRUPTED
        REPORT["work_seconds"] = round(work_finished - START, 6)
        if timer_installed:
            signal.setitimer(signal.ITIMER_REAL, 0)
            for sig, handler in saved_handlers.items():
                signal.signal(sig, handler)
        REPORT["timer_and_handlers_restored"] = (
            signal.getitimer(signal.ITIMER_REAL) == saved_timer
            and all(signal.getsignal(sig) == handler for sig, handler in saved_handlers.items()))
        if not REPORT["timer_and_handlers_restored"]:
            REPORT["status"] = "failed"
        tempfile.tempdir = saved_tempfile_dir
        if saved_tmp is None:
            os.environ.pop("TMPDIR", None)
        else:
            os.environ["TMPDIR"] = saved_tmp
        os.umask(saved_umask)
        write_result()
    return 0 if REPORT["status"] == "passed" else 1

if __name__ == "__main__":
    raise SystemExit(main())

