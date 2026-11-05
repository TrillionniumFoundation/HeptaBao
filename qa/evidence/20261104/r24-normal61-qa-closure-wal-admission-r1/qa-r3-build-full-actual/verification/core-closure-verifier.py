#!/usr/bin/env python3
"""Lossless offline checks of original R3 QA core, exact records and six test outputs."""
import hashlib
import json
import re
import sys
from pathlib import Path

fixture = json.loads(Path(sys.argv[1]).read_text())
checks = []
def check(name, condition):
    if not condition:
        raise AssertionError(name)
    checks.append({"name": name, "passed": True})
def sha(text):
    return hashlib.sha256(text.encode()).hexdigest()
core = json.loads(fixture["core_raw"])
authority = json.loads(fixture["authority_raw"])
ack = json.loads(fixture["ack_raw"])
request = json.loads(fixture["request_raw"])
binding = json.loads(fixture["binding_raw"])
headline = json.loads(fixture["stdout_raw"])
info = json.loads(fixture["core_info_raw"])
files = fixture["command_files"]
check("core-whole-metadata", len(fixture["core_raw"].encode()) == info["size"] == 62314
      and sha(fixture["core_raw"]) == info["sha256"] == headline["result_sha256"]
      == "b8a2e83ea012f11cef7dc83bc79758d2b624df7eac2265efddbd32e2880db95e")
check("exact-request-pin", sha(fixture["request_raw"])
      == "a33f479bb171642ca82104c6295670b2caba0e8eb47679a94660a8da9f5a4ed9")
check("original-unique-job", ack["job"]["id"] == authority["job_id"] == "1a1ab68bbb6-fc05-4d8a"
      and ack["reused"] is False and ack["job"]["launch_state"] == "launched")
for key in ("host", "executable", "cwd", "args", "idempotency_key"):
    check("ack-exact-" + key, ack["job"][key] == request[key])
check("known-authority-zero", authority["state"] == "succeeded" and authority["exit_code"] == 0
      and authority["output_complete"] and authority["output_durable"]
      and authority["terminal_publication_confirmed"]
      and not authority["automatic_retry"] and not authority["cancelled"] and not authority["timed_out"])
for role in ("stdout", "stderr"):
    count = len(fixture[role + "_raw"].encode())
    check("authority-complete-" + role, authority["log_bytes"][role]["seen"] == count
          == authority["log_bytes"][role]["stored"] and authority["log_synced"][role]
          and not authority["log_truncated"][role] and authority["log_errors"][role] is None)
check("actual-full-stderr-empty", fixture["stderr_raw"] == "")
check("actual-v3-passed", core["schema"] == "heptabao.native-h2-qa.build.v3"
      and core["status"] == headline["status"] == "passed")
check("exact-builder-binding", core["controller_sha256"]
      == "7ea25347f71764f1ed3d459d24b92750ef82c361878e9c856c7a7e8fe699bc15"
      and core["binding_sha256"] == sha(fixture["binding_raw"])
      == "ac127d3e67971ad6b9ae987c0fc6437f8882ff00d9480acbc12ed149796dd12a")
check("candidate-source", core["candidate_commit"] == binding["candidate_commit"]
      == "df026fe323dd7cf0f0ec57d7d2d9c5a79897053c"
      and core["candidate_tree"] == binding["candidate_tree"]
      == "424463ccd2310ddc1e7b2bbcd7b7af29ae58c825")
check("normal-60-provenance", core["normal_product_result_sha256"]
      == "84d763e6ff948df27964f373e834f869d7b22eeb0d7efb929fbd5c299c528f1b"
      and core["normal_product_runner_sha256"]
      == "1a3fdc3a7cf6504447feb7d7dadf2f365b292512f6d0cf8cdfb4a2ea63d33d40")
caps = {"build_seconds":180,"cleanup_kill_seconds":5,"cleanup_term_seconds":5,
        "components_build_seconds":180,"components_seconds":30,"git_seconds":15,
        "list_seconds":15,"lock_seconds":20,"tool_seconds":15,"total_seconds":600}
check("all-original-caps", core["caps"] == binding["caps"] == caps and request["timeout_seconds"] == 660)
check("exact-absolute-total", core["deadline_monotonic_ns"] - core["started_monotonic_ns"]
      == 600 * 10**9 and core["started_monotonic_ns"] <= core["completed_monotonic_ns"]
      < core["deadline_monotonic_ns"] and core["completed_within_original_build_deadline"]
      and headline["completed_within_original_build_deadline"])
check("canonical-before-after", core["source_before"] == core["source_after"]
      == {"commit": core["candidate_commit"], "tree": core["candidate_tree"], "status": ""})
check("no-product-or-http", core["offline_only"] is True and core["product_modified"] is False
      and core["product_or_http_requests"] == headline["product_or_http_requests"] == 0
      and core["new_qa_components_not_added_to_product_44_7_9"] is True)
names = [
 "component_tests::native_h2_client_accepts_complete_data_eos",
 "component_tests::native_h2_client_accepts_complete_empty_trailers_eos",
 "component_tests::native_h2_client_rejects_rst_no_error_after_exact_body_before_eos",
 "component_tests::native_h2_client_rejects_eof_after_exact_body_before_eos",
 "component_tests::native_h2_client_rejects_short_eos_and_duplicate_content_length",
 "component_tests::native_h2_client_refuses_expired_or_extended_original_deadline"]
check("six-exact-component-names", core["component_names"] == names and len(set(names)) == 6)
listed = [line[:-6] for line in files["components-list.stdout"].splitlines() if line.endswith(": test")]
executed = [line[5:-7] for line in files["components.stdout"].splitlines()
            if line.startswith("test ") and line.endswith(" ... ok")]
check("six-actual-listing", len(listed) == 6 and set(listed) == set(names))
check("six-actual-pass", len(executed) == 6 and set(executed) == set(names)
      and files["components.stdout"].count("test result: ok. 6 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out;") == 1)
labels = ["source-before-commit","source-before-tree","source-before-status","rustc-version",
          "lock","build","components-build","components-list","components",
          "source-after-commit","source-after-tree","source-after-status"]
check("twelve-exact-command-records", [r["label"] for r in core["commands"]] == labels
      and len(core["command_intents"]) == 12 and {r["label"] for r in core["command_intents"]} == set(labels))
pids = set()
for record in core["commands"]:
    label = record["label"]
    observed = json.loads(files[label + ".public.json"])
    check("whole-record-equals-core-" + label, observed == record)
    check("known-closed-command-" + label, record["exit_code"] == 0 and record["timed_out"] is False
          and record["direct_child_reaped"] is True and record["remaining"] == []
          and record["completed_within_deadline"] is True)
    check("command-original-deadline-" + label, record["started_monotonic_ns"]
          <= record["completed_monotonic_ns"] < record["deadline_monotonic_ns"]
          <= core["deadline_monotonic_ns"]
          and record["deadline_monotonic_ns"] - record["started_monotonic_ns"]
          <= record["outer_cap_seconds"] * 10**9)
    pids.add(record["owned_pgid"])
check("twelve-unique-owned-children", len(pids) == 12 and len(core["owned_cleanup"]) == 12
      and {r["pid"] for r in core["owned_cleanup"]} == pids)
for i, r in enumerate(core["owned_cleanup"]):
    check("owned-once-terminal-" + str(i), r["direct_child_reaped"] is True
          and r["owned_stopped"] is True and r["remaining"] == []
          and r["stop_terminal_captured"] is True and r["wait_returncode"] == 0)
check("provenance-covers-twelve", len(core["child_provenance"]) == 12
      and {r["pid"] for r in core["child_provenance"]} == pids)
for i, r in enumerate(core["child_provenance"]):
    check("direct-popen-wnowait-" + str(i), r["custody_verified"] is True
          and r["mechanism"] == "direct_popen_unreaped_waitid_v1"
          and r["popen_returned"] is True and r["provisionally_registered_before_observation"] is True
          and r["terminal_consumed"] is True and r["wait_returncode"] == 0
          and r["terminal_event"]["expected_returncode"] == 0
          and r["terminal_event"]["not_reaped"] is True
          and r["terminal_event"]["pid"] == r["pid"])
check("overall-cleanup-known", core["all_owned_stopped"] is True
      and core["all_input_fds_closed"] is True and core["command_outcome_unknown"] is False
      and core["incomplete_command_labels"] == []
      and headline["all_owned_stopped"] and headline["all_input_fds_closed"])
check("component-record-whole-hash", sha(files["components.public.json"]) == core["component_record_sha256"])
for label, stream in (("components","components.stdout"),("components-list","components-list.stdout")):
    record = json.loads(files[label+".public.json"])
    check("component-stdout-pin-" + label, sha(files[stream]) == record["stdout_sha256"])
    check("component-original-cap-" + label, record["outer_cap_seconds"] == (30 if label == "components" else 15))
alias = core["normal_qa_binary_alias_observation"]
check("normal-two-alias-observed", alias["status"] == "observed_two_aliases"
      and alias["same_full_identity"] and alias["same_whole_sha256"]
      and alias["link_count_fully_accounted_for"] and alias["expected_links"] == 2
      and len(set(alias["aliases"])) == 2 and alias["path"] == core["executable"]["compiler_executable"])
full = list(map(int, alias["full_identity"]))
check("dynamic-source-full9", len(full) == 9 and full[2:4] == [1000,1000]
      and full[4] == 0o100700 and full[5] == 2 and full[6] == core["executable"]["bytes"])
check("alias-body-eof-budget", alias["body_bytes_read"] == alias["body_bytes_limit"] == full[6] * 2
      and alias["eof_probe_bytes_limit"] == 2 and alias["eof_probe_calls"] == 2
      and alias["eof_probe_bytes_read"] == 0 and alias["total_bytes_read"] == full[6] * 2
      and alias["total_returned_bytes_limit"] == full[6] * 2 + 2)
check("alias-once-resources", alias["fds_opened"] == alias["fds_closed_once"] == 9
      and alias["fds_remaining"] == 0 and alias["fd_close_failures"] == 0
      and len(alias["fd_closure_rows"]) == 9 and all(r["closed"] and r["close_attempted"]
      and r["close_error"] is None and r["close_errno"] is None for r in alias["fd_closure_rows"])
      and alias["iterator_created"] and alias["iterator_close_attempted"]
      and alias["iterator_closed_once"] and alias["iterator_close_error"] is None
      and not alias["iterator_open_unknown"] and not alias["open_registration_unknown"]
      and alias["all_registered_resources_closed"] and not alias["resource_outcome_unknown"])
check("alias-no-cancel-and-original-deadline", alias["cancel_signal"] is None
      and alias["completed_monotonic_ns"] < alias["original_deadline_monotonic_ns"]
      == core["deadline_monotonic_ns"] and alias["within_original_deadline"]
      and not alias["source_cache_executed"] and not alias["source_cache_written"])
for role, key, test in (("executable","executable_info_raw",False),
                        ("component_binary","component_binary_info_raw",True)):
    item = core[role]
    actual = json.loads(fixture[key])
    check("retained-independent-whole-"+role, item["path"] == actual["path"]
          and item["bytes"] == actual["size"] and item["sha256"] == actual["sha256"])
    check("retained-single-link-custody-"+role, item["links"] == actual["metadata"]["link_count"] == 1
          and item["uid"] == item["gid"] == actual["metadata"]["uid"] == actual["metadata"]["gid"] == 1000
          and item["mode"] == actual["mode"] == 0o500)
    version = ":".join(str(item[k]) for k in ("device","inode","bytes","mtime_ns","ctime_ns"))
    check("lossless-full9-version-"+role, version == actual["version"])
    check("retained-normal-profile-"+role, item["features"] == []
          and item["profile"] == {"debug_assertions":True,"debuginfo":0,"opt_level":"3",
                                 "overflow_checks":True,"test":test})
check("normal-retained-from-observed-alias", alias["sha256"] == core["executable"]["sha256"]
      and core["executable"]["inode"] != full[1])
print(json.dumps({
 "schema":"heptabao.qa-r3.actual-core-closure-check.v1","status":"passed-core-closure",
 "checks":checks,"check_count":len(checks),"job_id":authority["job_id"],
 "actual_six_components_passed":True,"owned_commands_closed":12,
 "elapsed_total_ns":str(core["completed_monotonic_ns"]-core["started_monotonic_ns"]),
 "lossless_ns_verified":True,"original_caps_preserved":True,
 "components_share_one_original_30_second_command":True,
 "full_cargo_json_and_other_command_streams_archiving_pending":True,
 "http_or_product_qualification":False,"host_or_child_calls_by_this_verifier":0
},indent=2,sort_keys=True))
