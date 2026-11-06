#!/usr/bin/env python3
"""Read retained public originals only; never start a process or contact a host."""
import hashlib
import json
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parent
INPUT = ROOT.parent
COMMIT = "9c68b95b152a468ab378b68730e9e3f04e6a7100"
TREE = "7f4b75930e8491a3110d8c7f8f894cfc0cfc1fdb"
JOB = "1a1b2017570-fc05-7bfe"
CASE = "service::native_v6_ha_pipeline_tests::native_large_import_tests::published_plan_tests::native_ha_published_local_plan_changed_cipher_after_actual_commit_is_unknown"


def pin(path):
    raw = path.read_bytes()
    return {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}


def read(path):
    return json.loads(path.read_bytes())


def main():
    assert pin(ROOT / "result.public.json") == {
        "bytes": 75395,
        "sha256": "b779c9c7689c3aafc82363f3bb27e1642e862c1bd110bef56a93cb93ed594dc5",
    }
    result = read(ROOT / "result.public.json")
    selection = read(ROOT / "test-selection.public.json")
    assert pin(ROOT / "test-selection.public.json") == {
        "bytes": 19919,
        "sha256": "3961122260ff03815ccf078a264ad18df5dc7eee5018d6d63e2eb489cc482c52",
    }
    assert pin(ROOT / "controller.py") == {
        "bytes": 31689,
        "sha256": "50ef1feed37b7abd31e7cc2db3b1f7feb7a77a954e347e82a6861814fb414c97",
    }
    terminal = read(ROOT / "runtime-terminal.original.json")
    assert terminal["job_id"] == JOB and terminal["state"] == "succeeded"
    assert terminal["exit_code"] == 0
    for key in ("output_complete", "output_durable", "terminal_publication_confirmed"):
        assert terminal[key] is True
    for key in ("timed_out", "cancelled", "automatic_retry"):
        assert terminal[key] is False
    runtime_stdout = (ROOT / "runtime.stdout.original").read_bytes()
    runtime_stderr = (ROOT / "runtime.stderr.original").read_bytes()
    assert len(runtime_stdout) == terminal["log_bytes"]["stdout"]["stored"] == 4247
    assert len(runtime_stderr) == terminal["log_bytes"]["stderr"]["stored"] == 0
    events = [json.loads(line) for line in runtime_stdout.splitlines()]
    assert events[-1]["event"] == "terminal"
    assert events[-1]["status"] == result["status"]
    assert result["schema"] == "heptabao.ci-publication-observation-diagnostic.v1"
    assert result["status"] == "diagnostic_selected11_passed_original_ci_failure_unresolved"
    assert result["failure"] is None and result["source_commit"] == COMMIT and result["source_tree"] == TREE
    assert result["source_and_artifacts_unchanged"] is True
    assert result["outer_budget_seconds"] == 4200 and result["elapsed_seconds"] < 4200
    assert result["automatic_retry"] is False and result["deadline_renewed"] is False

    steps = result["steps"]
    assert len(steps) == 19 and len({row["step"] for row in steps}) == 19
    starts = [row["step"] for row in events if row["event"] == "step_started"]
    finishes = [row["step"] for row in events if row["event"] == "step_finished"]
    assert starts == finishes == [row["step"] for row in steps]
    original_logs, custody = [], []
    for row in steps:
        assert row["exit_code"] == 0 and row["timed_out"] is False and row["attempts"] == 1
        assert row["unexpected_live_descendants_on_success"] is False
        group = row["owned_group_cleanup"]
        assert group["all_owned_processes_gone"] is True
        assert group["remaining_before_cleanup"] == group["remaining_after_cleanup"] == group["signals"] == []
        assert group["abnormal_exit"] is False and type(group["leader_start_ticks"]) is int
        custody.append({"step": row["step"], "pid": row["pid"], **group})
        for stream in ("stdout", "stderr"):
            name = row["step"] + "." + stream
            observed = pin(ROOT / name)
            assert observed == {"bytes": row[stream + "_bytes"], "sha256": row[stream + "_sha256"]}
            original_logs.append({"path": name, **observed})

    selected = selection["diagnostic_groups"]
    assert len(selected) == len(result["groups"]) == 2
    enumeration = (ROOT / "heptabao-server-list.stdout").read_text()
    enum_names = re.findall(r"^(.+): test$", enumeration, re.M)
    assert len(enum_names) == len(set(enum_names)) == 3760
    observed_names, group_reviews = [], []
    for index, (wanted, reported) in enumerate(zip(selected, result["groups"])):
        assert wanted["tests"] == reported["tests"]
        assert wanted["expected_count"] == reported["expected_count"] == reported["passed"]
        assert reported["status"] == "passed" and wanted["runtime_seconds"] == 60
        assert reported["budget_renewed_per_case"] is False and reported["seconds"] < 60
        step = next(row for row in steps if row["step"] == f"test-{index:02d}-{wanted['label']}-00")
        assert step["argv"][1:] == wanted["argv_suffix"]
        assert step["requested_cap_seconds"] == 60 and step["effective_budget_seconds"] <= 60
        text = (ROOT / (step["step"] + ".stdout")).read_text()
        runs = re.findall(r"^running ([0-9]+) tests?$", text, re.M)
        outcomes = re.findall(r"^test (.+) \.\.\. (ok|FAILED|ignored)$", text, re.M)
        totals = re.findall(r"^test result: (ok|FAILED)\. ([0-9]+) passed; ([0-9]+) failed; ([0-9]+) ignored; ([0-9]+) measured; ([0-9]+) filtered out;", text, re.M)
        count = wanted["expected_count"]
        assert runs == [str(count)] and len(outcomes) == count and len(totals) == 1
        assert sorted(name for name, status in outcomes) == sorted(wanted["tests"])
        assert all(status == "ok" and name in enum_names for name, status in outcomes)
        assert totals[0] == ("ok", str(count), "0", "0", "0", str(3760 - count))
        assert result["enumeration"][wanted["label"]]["matched_names"] == wanted["tests"]
        observed_names.extend(name for name, _ in outcomes)
        group_reviews.append({"label": wanted["label"], "original_step": step["step"],
                              "passed": count, "failed": 0, "ignored": 0,
                              "actual_names": [name for name, _ in outcomes]})
    assert len(observed_names) == len(set(observed_names)) == 11 and CASE in observed_names
    assert result["passed_cases"] == result["executed_passed_cases"] == 11

    artifact = result["artifacts"]["heptabao-server-libtest"]
    native = read(ROOT / "native-file-info-2.original.json")
    assert artifact["path"] == native["path"]
    assert artifact["sha256"] == native["sha256"] and artifact["bytes"] == native["size"]
    assert artifact["source_commit"] == COMMIT and artifact["source_tree"] == TREE
    profile = {"debug_assertions": True, "debuginfo": 2, "opt_level": "1", "overflow_checks": True, "test": True}
    features = ["default", "native-v6-ha", "native-v6-storage"]
    assert artifact["cargo_profile"] == profile and artifact["cargo_features"] == features
    cargo = [json.loads(line) for line in (ROOT / "14-server-libtest-build.stdout").read_text().splitlines()]
    matches = [row for row in cargo if row.get("reason") == "compiler-artifact" and row.get("executable") == artifact["cargo_artifact_path"]]
    assert len(matches) == 1
    compiled = matches[0]
    assert compiled["package_id"] == artifact["cargo_package_id"]
    assert compiled["target"]["src_path"] == artifact["cargo_source_entry"]
    assert compiled["profile"] == profile and compiled["features"] == features and compiled["fresh"] is False
    build = next(row for row in steps if row["step"] == "14-server-libtest-build")
    assert build["requested_cap_seconds"] == build["effective_budget_seconds"] == 3600
    assert build["seconds"] < 3600 and "--release" not in build["argv"]
    assert result["preflight"]["compiler_processes"] == result["postflight"]["compiler_processes"] == []

    old_expected = selection["old_retained_artifacts"]
    before, after = result["old_retained_artifacts_before"], result["old_retained_artifacts_after"]
    assert len(old_expected) == len(before) == len(after) == 25 and before == after
    missing = ["heptabao-seed", "heptabao-server", "server_libtest"]
    for name, expected in old_expected.items():
        row = before[name]
        assert row["path"] == expected["path"]
        if name in missing:
            assert row["matches_original"] is False and row["error_type"] == "FileNotFoundError"
        else:
            assert row["matches_original"] is True
            assert row["bytes"] == expected["bytes"] and row["sha256"] == expected["sha256"]
    assert result["diagnostic_legacy_before"] == result["diagnostic_legacy_after"]
    for phase in ("diagnostic_legacy_before", "diagnostic_legacy_after"):
        row = result[phase]
        assert row["retained_matching_count"] == 22 and row["observed_absent_names"] == missing
        assert row["all_25_expected_artifacts_present"] is False and row["legacy_preservation"] is False
        assert row["machine_acceptance"] == "HOLD"
    prior = result["prior_r12_result_before"]
    assert prior == result["prior_r12_result_after"]
    assert prior["bytes"] == 34946 and prior["sha256"] == "2b8d85d39c2759615f40bec8ee5b4cb630a7c257a8b352b776dbbbc0a115b7d7"

    prefix = "HBHA-REQUEST-TIMING-FAIL "
    stderr = (ROOT / "test-01-original-cipher-case1-00.stderr").read_text()
    reports = [json.loads(line[len(prefix):]) for line in stderr.splitlines() if line.startswith(prefix)]
    assert len(reports) == 1 and reports == result["case_observation"]["request_timing_reports"]
    observation = reports[0]
    assert observation["status"] == 503 and observation["request_class"] == "published_plan_corrupt_cipher_test"
    assert observation["bucket_limit"] == 64 and observation["bucket_bound_reached"] is False
    assert 0 < observation["exit_remaining_ns"] <= observation["entry_remaining_ns"] <= 15_000_000_000
    phases = {(row["scope"], row["phase"]): row for row in observation["phases"]}
    for scope, phase in [("test_native_publication", "publication_root_cas"),
                         ("test_native_publication", "publication_committed_readback"),
                         ("test_native_service_publication", "service_ha_publication")]:
        assert phases[(scope, phase)]["completed"] == 1 and phases[(scope, phase)]["failed"] == 0
    assert phases[("test_native_service_publication", "service_local_install")]["failed"] == 1

    false_flags = ["formal_kv2_qualified", "physical_ha_qualified", "authbus_migration_qualified",
                   "dr_qualified", "rollback_qualified", "cutover_qualified", "production_cutover_qualified",
                   "full_replacement_qualified", "production_changed", "production_server_started",
                   "original_ci_failure_reclassified", "compilation_performance_comparison_qualified"]
    assert all(result[key] is False for key in false_flags)
    assert result["original_ci_failure_unresolved"] is True and result["machine_acceptance"] == "HOLD"
    review = {
        "schema": "heptabao.r13-independent-public-evidence-review.v1",
        "kind": "derived_readonly_original_evidence_review",
        "runtime_job": JOB, "result": pin(ROOT / "result.public.json"),
        "selection": pin(ROOT / "test-selection.public.json"),
        "source_commit": COMMIT, "source_tree": TREE,
        "authority": result["status"], "runtime_terminal_success_complete_durable": True,
        "actual_unique_passed_cases": 11, "actual_failed_cases": 0, "actual_ignored_cases": 0,
        "actual_enumeration_count": len(enum_names), "groups": group_reviews,
        "all_38_step_stream_bytes_and_sha256_match": True, "original_step_streams": original_logs,
        "all_19_recorded_original_process_groups_retired": True, "owned_groups": custody,
        "native_artifact_file_info_matches": True, "actual_cargo_artifact_events_matching": 1,
        "artifact": artifact, "build_original_budget_seconds": 3600,
        "build_elapsed_seconds": build["seconds"], "outer_original_budget_seconds": 4200,
        "original_case_internal_deadline_seconds": 15, "diagnostic_group_budgets_seconds": [60, 60],
        "original_r12_result_before_after_exact": prior,
        "old_25_expected_pins_preserved_as_requirements": old_expected,
        "old_before_after_observation_exact": before,
        "legacy_preservation": False, "retained_matching_count": 22, "exact_missing_names": missing,
        "machine_acceptance": "HOLD", "current_compiler_scans_pre_and_post_empty": True,
        "request_timing": observation,
        "original_ci_failure_root_cause_proven": False,
        "passing_expected_503_does_not_reclassify_prior_ci_failure": True,
        "full_selected107_or_workspace_reexecution": False,
        "grants_production_rollback_dr_ha_authbus_cutover_or_cleanup": False,
    }
    raw = (json.dumps(review, sort_keys=True, indent=2) + "\n").encode()
    with (ROOT / "INDEPENDENT_R13_DIAGNOSTIC_REVIEW.public.json").open("xb") as handle:
        handle.write(raw)
    print(json.dumps({"verified": True, "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest(),
                      "cases": len(observed_names), "groups": len(custody), "legacy": "22 match / 3 missing"}))


if __name__ == "__main__":
    main()
