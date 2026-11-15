#!/usr/bin/env python3
"""Offline verification of this completed Mac run's unmodified receipts.

This verifies captured evidence, not a new server execution or current disk state.
The gzip files decompress to the complete original JSON bytes, including custody.
"""
import gzip
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent
PRODUCT = "4bde9aee03fcd27c59e13607e529b1cee594b249"
PRODUCT_TREE = "f08493a23f8ea0637073651231865ea9607b790e"
QA = "5ded017e1c858b8602a73678acc29df75386a84d"
SERVER = "5f75acb9822defded2ed21f2f0ed1c21895c5e7d8d8d595e9f1c4ee9b9eaa85c"
SEED = "203c7af52c0f9aa4ca71e591c1428acac9382f3c4105036a494631b0e1cae8e7"
BASELINE = """official_271_pins_and_live_identity two_distinct_owned_processes
source_api_oracle_captured source_retained_deleted_destroyed_seeded
source_metadata_cas_seeded source_cold_restart_exact target_pristine_before_import
source_export_once source_raw_history_exact exported_soft_deleted_payload_preserved
source_unchanged_after_export target_import_once target_active_native_v6
target_full_history_exact target_storage_full_history_exact target_cold_restart_exact
target_storage_cold_history_exact snapshot_download post_snapshot_mutation_once
snapshot_restore_once restored_cold_history_exact restored_storage_history_exact
soft_deleted_payload_undelete_exact destroyed_payload_remains_absent
data_cas_denied_without_effect metadata_cas_denied_without_effect
metadata_cas_success_counter_exact source_unchanged_after_target_mutations
source_and_binary_unchanged owned_processes_stopped report_excludes_runtime_credentials""".split()
DR = """input_source_and_binaries_pinned official_271_live_identity_verified
official_full34_api_and_raw_history_bound normal_native_v6_file_profile
preactivation_seed_export_pinned independent_backup_filesystem_verified
official_cli_v6_save_complete complete_v6_archive_seal_binding
backup_manifest_and_separate_key_custody original_processes_stopped
original_directories_quarantined fresh_recovery_directory_and_tls_identity
exact_seed_stage_verified old_closure_negative_cannot_read_history
wrong_unseal_key_denied tampered_archive_denied_without_commit
official_cli_v6_restore_once restored_api_19_versions_exact restored_raw_19_versions_exact
restored_cold_reopen_history_exact soft_deleted_payload_undelete_exact
destroyed_payload_not_resurrected data_and_metadata_cas_guards_exact
new_write_survives_cold_reopen final_custody_cleanup_and_redaction""".split()


def need(value, label):
    if not value:
        raise RuntimeError(label)


def json_file(name):
    return json.loads((ROOT / name).read_bytes())


def archived(name, compressed_sha, size, original_sha):
    data = (ROOT / name).read_bytes()
    need(hashlib.sha256(data).hexdigest() == compressed_sha, name + ": gzip hash")
    raw = gzip.decompress(data)
    need(len(raw) == size and hashlib.sha256(raw).hexdigest() == original_sha,
         name + ": complete original bytes")
    return json.loads(raw)


def exact_checks(value, required):
    rows = value["checks"]
    need(len(rows) == len(required) == len(set(required)), "exact original denominator")
    need({r["case"] for r in rows} == set(required), "exact unique case names")
    need(all(r["passed"] is True for r in rows), "every original case passed")
    need(value["status"] == "passed" and value["missing_checks"] == [], "final success")
    return {r["case"]: r.get("evidence") for r in rows}


def terminal(name, job, stdout_name):
    value = json_file(name)
    need(value["job_id"] == job and value["state"] == "succeeded"
         and value["exit_code"] == 0, "authoritative original terminal")
    need(all(value[k] is True for k in
             ("output_complete", "output_durable", "terminal_publication_confirmed")),
         "complete durable terminal")
    need(all(value[k] is False for k in ("timed_out", "cancelled", "automatic_retry")),
         "no timeout cancellation or retry")
    size = len((ROOT / stdout_name).read_bytes())
    need(value["log_bytes"] == {"stdout": {"seen": size, "stored": size},
                               "stderr": {"seen": 0, "stored": 0}}, "complete streams")
    need(all(x is None for x in value["log_errors"].values())
         and not any(value["log_truncated"].values()), "no lost log bytes")
    return value


def main():
    dr = archived("dr25-summary.original.json.gz",
        "ad0b595627cf909baf117470114fca51039c95779d5d64693dd3fe15ce7e488c", 2148370,
        "0c6ac1f18fc2b00a8abf138226742b27e0f5149516bf5060a406e76a844331af")
    baseline = archived("baseline31-summary.original.json.gz",
        "2205c047d2a1d2ec8d5d7da4bc9ffe995ad04f5f88611fb0cccd31649e7459d7", 92097,
        "89448bf85f01828b05c4ad5f310502bd116d57ea2bb29b0f368577420b79603d")
    terminal("run.terminal.original.json", "1a1b16bbf10-fc05-788f", "run.stdout.original")
    terminal("archive.terminal.original.json", "1a1b172ca8c-fc05-78d1", "archive.stdout.original")
    raw = (ROOT / "run.result.public.json").read_bytes()
    need(hashlib.sha256(raw).hexdigest() ==
         "49a6647665c3078dacc90bf36683c74f82b0df5e8803f7de97c7091a26b86ea6", "original wrapper receipt")
    run = json.loads(raw)
    need(run["status"] == "passed" and run["controller_exit_code"] == 0
         and run["baseline_31_passed"] and run["dr25_passed"] and run["all_originals_retired"],
         "completed original wrapper")
    need(run["elapsed_seconds"] < 1740 and run["runtime_outer_seconds"] == 1800
         and not run["deadline"]["fired"] and not run["deadline"]["deadline_renewed"],
         "original absolute budgets")
    d = exact_checks(dr, DR)
    exact_checks(baseline, BASELINE)
    need(dr["required_checks"] == DR and dr["required_count"] == 25,
         "original DR obligation list")
    need(dr["baseline"]["sha256"] ==
         "89448bf85f01828b05c4ad5f310502bd116d57ea2bb29b0f368577420b79603d"
         and dr["baseline"]["qualified"] is True, "baseline bound by full original digest")
    need(baseline["source_commit"] == QA and baseline["source_tree"] ==
         "9d1d040a063504ede67559fadb556897591642f2"
         and not baseline["source_dirty"] and baseline["source_unchanged_at_cleanup"], "QA source freeze")
    need(baseline["profile"] == dr["source_profile"] == "full34"
         and baseline["full34_qualified"] and baseline["api_history_qualified"]
         and baseline["target_storage_precision_qualified"] and baseline["tls_verified"],
         "actual complete normal native history baseline")
    need(baseline["live_payload_bytes"] == dr["live_payload_bytes"] == 34 * 1024**2
         and baseline["retained_live_versions"] == 17 and dr["version_count"] == 19,
         "original full history volume")
    binding = d["input_source_and_binaries_pinned"]["build_binding"]
    for name, digest in (("heptabao-server", SERVER), ("heptabao-seed", SEED)):
        artifact = binding["artifacts"][name]
        need(artifact["source_commit"] == PRODUCT and artifact["source_tree"] == PRODUCT_TREE
             and artifact["sha256"] == digest and artifact["normal_features_profile_and_source_verified"],
             "same canonical normal product artifacts")
    need(binding["build_test_observations"]["denominators"]["total_unique_cases"] == 107,
         "107 build admission binding")
    need(baseline["binary_sha256"] == SERVER, "same actual baseline binary")
    archive = d["complete_v6_archive_seal_binding"]
    need(archive["cli_archive"]["metadata"] == archive["normal_http_archive"]["metadata"],
         "actual CLI and HTTP archive metadata equal")
    logical = archive["logical_history_binding"]
    need(logical["observed_logical_payload_bytes"] >= 34 * 1024**2
         and logical["encoded_archive_state_bytes"] == 9009239
         and logical["encoded_size_used_as_logical_volume"] is False
         and logical["source_metadata_equal"] and logical["full31_and_dr25_still_required"],
         "logical history and encoded length have distinct proved bindings")
    filesystems = d["independent_backup_filesystem_verified"]
    need(filesystems["work"]["device"] != filesystems["backup_parent"]["device"],
         "distinct observed backup filesystem")
    custody = d["backup_manifest_and_separate_key_custody"]
    need(custody["key_material_absent_from_backup"] is True
         and custody["plaintext_business_values_in_witness"] is False, "separate key custody")
    fresh = d["fresh_recovery_directory_and_tls_identity"]
    need(fresh["data_directory_absent_before_stage"]
         and fresh["new_tls_certificate_sha256"] != fresh["original_tls_certificate_sha256"],
         "fresh data directory and TLS identity")
    restore = d["official_cli_v6_restore_once"]
    need(restore["valid_restore_attempt_count"] == 1
         and restore["source_bundle_imports_after_quarantine"] == 0, "one actual restore without reimport")
    need(d["wrong_unseal_key_denied"]["wrong_unseal_status"] == 400
         and d["wrong_unseal_key_denied"]["sealed"] is True, "wrong key rejection")
    need(len(d["restored_api_19_versions_exact"]["versions"]) == 19
         and len(d["restored_raw_19_versions_exact"]["versions"]) == 19, "all original versions restored")
    new = d["new_write_survives_cold_reopen"]
    need(new["version"] == 20 and new["write_status"] == new["read_status"] == 200,
         "new version after restore survives another cold reopen")
    commands = dr["commands"]
    need(len(commands) == 5 and all(c["budget_seconds"] == 15
         and c["elapsed_seconds"] < 15 and c["original_wait_completed"]
         and not c["retried"] and c["outcome"] == "response_received" for c in commands),
         "original completed command budgets")
    need({c["label"]: c["returncode"] for c in commands} ==
         {"seed_export": 0, "official_v6_save": 0, "seed_stage": 0,
          "tampered_v6_restore": 2, "official_v6_restore": 0}, "authentic negative and positive restore outcomes")
    need(len(dr["mutations"]) == 70 and all(m["outcome"] == "response_received"
         and m["retried"] is False and m["owned_leaf_wait_completed"] is True for m in dr["mutations"]),
         "no unknown or replayed mutation")
    process = dr["process_custody"]
    need(process["finished"] and process["passed_process_custody"]
         and not process["failed"] and not process["interrupted"], "final process custody")
    need(process["original_count"] == len(process["children"]) == 700
         and all(c["original_wait_completed"] and c["original_wait_count"] == 1
         and c["no_live_members_before_reap"] and c["gaps"] == [] for c in process["children"]),
         "every original child reaped once without live members or custody gaps")
    need(dr["cleanup_failures"] == [] and dr["parent_handle_retirement"]["passed"]
         and dr["parent_handle_retirement"]["no_parent_fd_matches_manifest"], "parent and cleanup closure")
    final = d["final_custody_cleanup_and_redaction"]
    need(final["key_files_unchanged_and_private"]
         and final["runtime_credentials_and_fingerprints_absent"], "final source and secret boundary")
    need(dr["original_budgets"] == {"cli_and_seed_seconds": 15, "http_seconds": 15,
                                   "migration_seconds": 360}, "unchanged runtime obligations")
    need(dr["fresh_directory_same_seal_v6_recovery_verified"] is True
         and all(dr[k] is False for k in ("ha_qualified", "independent_qualification",
         "physical_disk_independence_verified", "physical_power_loss_tested",
         "production_authority", "replacement_authority", "cross_seal_restore")), "claim boundaries")
    need(all(run[k] is False for k in ("authbus_qualified", "physical_ha_qualified",
         "production_authority", "full_replacement_qualified")), "wrapper claim boundaries")
    return {"schema": "heptabao.mac-dr25-archived-evidence-verification.v1", "status": "passed",
        "actual_job": "1a1b16bbf10-fc05-788f", "product_source_commit": PRODUCT,
        "qa_source_commit": QA, "baseline_cases": 31, "dr_cases": 25,
        "retained_live_versions": 17, "historical_versions_checked": 19,
        "new_version_surviving_cold_reopen": 20, "original_children_retired": 700,
        "elapsed_seconds": run["elapsed_seconds"], "complete_original_archives_verified": True,
        "verification_reruns_product": False, "physical_ha_qualified": False,
        "authbus_qualified": False, "production_authority": False, "full_replacement_qualified": False}


if __name__ == "__main__":
    print(json.dumps(main(), sort_keys=True, indent=2))
