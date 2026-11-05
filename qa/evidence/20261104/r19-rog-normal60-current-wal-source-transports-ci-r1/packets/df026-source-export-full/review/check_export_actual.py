#!/usr/bin/env python3
"""Offline exact-integer review of the already-completed df026 source export.
Reads only the supplied public evidence capsule; no host/process/network access.
"""
import hashlib
import json
import pathlib
import sys

p = pathlib.Path(sys.argv[1])
x = json.loads(p.read_text())
checks = []
def require(ok, name):
    if not ok:
        raise AssertionError(name)
    checks.append(name)
def sha(text):
    return hashlib.sha256(text.encode()).hexdigest()
def original(key):
    return json.loads(x[key])
def checked_file(row):
    require(row["eof"] is True, "eof:" + row["path"])
    require(len(row["text"].encode()) == row["size"], "bytes:" + row["path"])
    require(sha(row["text"]) == row["sha256"], "sha256:" + row["path"])
def identity_matches(info, identity):
    dev, ino, size, mtime, ctime = map(int, info["version"].split(":"))
    md = info["metadata"]
    return identity == [dev, ino, md["uid"], md["gid"],
                        0o100000 | md["mode"], md["link_count"], size, mtime, ctime]
c, a, ack, streams = map(original, ("core_raw", "authority_raw", "ack_raw", "streams_raw"))
request = x["request"]
require(ack["reused"] is False and ack["job"]["launch_state"] == "launched", "single_new_launch")
for key in ("host", "executable", "args", "cwd", "idempotency_key"):
    require(ack["job"][key] == request[key], "ack_exact_" + key)
require(request["timeout_seconds"] == 330, "original_outer330")
require(a["job_id"] == ack["job"]["id"] == streams["job_id"], "job_identity")
require(a["exit_code"] == 0 and a["state"] == "succeeded", "authoritative_success")
require(all(a[k] is False for k in ("timed_out", "cancelled", "automatic_retry")), "no_timeout_cancel_retry")
require(all(a[k] is True for k in ("output_complete", "output_durable", "terminal_publication_confirmed")), "complete_durable_publication")
for name in ("stdout", "stderr"):
    stream = streams[name]
    raw = bytes.fromhex(stream["bytes_hex"])
    require(raw == stream["text"].encode(), "stream_hex_text_" + name)
    require(stream["offset"] == 0 and stream["next_offset"] == stream["size"] == len(raw)
            and stream["eof"], "stream_complete_" + name)
    require(a["log_bytes"][name] == {"seen": len(raw), "stored": len(raw)}
            and a["log_errors"][name] is None and a["log_synced"][name]
            and not a["log_truncated"][name], "authority_stream_" + name)
require(streams["stderr"]["text"] == "", "stderr_empty")
terminal = json.loads(streams["stdout"]["text"])
require(terminal["status"] == terminal["receipt_candidate_status"] == c["status"] == "exported", "exported_status")
require(terminal["publication_within_original_deadline"] is True
        and terminal["elapsed_after_publication_seconds"] < 300
        and c["elapsed_seconds"] < 300 and c["deadline_before_receipt_passed"] is True, "original_deadline_both_publications")
require(c["overall_seconds"] == 300 and c["git_command_seconds"] == 90
        and c["maximum_bundle_bytes"] == 64 * 1024 * 1024, "caps_unchanged")
commit = "df026fe323dd7cf0f0ec57d7d2d9c5a79897053c"
tree = "424463ccd2310ddc1e7b2bbcd7b7af29ae58c825"
require(c["canonical_commit"] == terminal["canonical_commit"] == commit
        and c["canonical_tree"] == terminal["canonical_tree"] == tree, "candidate_exact")
require(c["canonical_proof"] == {
    "commit": commit, "commit_count": 3757, "full_fsck_passed": True,
    "parents": ["6304a898192bfdf7eabec3c4ea40f7166e59a137"],
    "root": "67d79b3b5442ed033d38929eab2010403463e56d", "tree": tree
}, "canonical_history_full_fsck")
require(c["expected_full_commit_count"] == 3757 and c["expected_prerequisites"] == [], "standalone_history")
require(c["source_before"] == c["source_after"], "original_source_exact_before_after")
before = c["source_before"]
require(before["head"] == commit and before["tree"] == tree
        and all(before[k] is True for k in ("clean", "independent_git_directory", "no_alternates", "no_grafts", "no_partial_clone"))
        and before["shallow"] is False and not any(before["lock_files"].values()), "clean_independent_source")
require(c["source"].endswith("/heptabao-cold-h2-normal-20261105-r1/source")
        and before["git_directory"] == before["git_common_directory"] == c["source"] + "/.git", "fixed_source")
require(all(c[k] is False for k in ("compiler_started", "server_started", "source_imported",
        "runtime_qualification", "network_git_protocols_enabled"))
        and c["product_tests_executed"] == 0, "source_only_not_product")
bundle = c["bundle"]
require(bundle["header"]["version"] == 2 and bundle["header"]["heads"] == [[commit, "HEAD"]]
        and bundle["header"]["prerequisites"] == [], "single_head_zero_prerequisite")
require(bundle["bytes"] == 23429893 and bundle["sha256"] == "2f25963c59ecfd0918f786c98e6babcd7ba35daec02f00d899e987f19c28ad71", "actual_bundle_whole_pin")
wrapper = original("core_files_raw")
require(wrapper["truncated"] is False and len(wrapper["files"]) == 2, "complete_two_file_read")
for row in wrapper["files"]:
    checked_file(row)
core_row, source_row = wrapper["files"]
require(core_row["text"] == x["core_raw"] and source_row["text"] == x["expected_source"], "whole_original_core_and_controller")
require(source_row["size"] == 15324 and source_row["sha256"] == "a9b3ea4263481153c4546bd984f6a0dc496c7e459abb037eed1c78fdcdeafeaa", "frozen_exporter_pin")
core_info, bundle_info, source_info = map(original, ("core_info_raw", "bundle_info_raw", "inert_source_info_raw"))
for row, info in ((core_row, core_info), (source_row, source_info)):
    require(all(row[k] == info[k] for k in ("path", "version", "size", "sha256")), "independent_file_info:" + row["path"])
for info in (core_info, bundle_info, source_info):
    require(info["mode"] == info["metadata"]["mode"] == 0o600
            and info["metadata"]["uid"] == info["metadata"]["gid"] == 1000
            and info["metadata"]["link_count"] == 1, "private_single_link:" + info["path"])
require(core_info["path"] == terminal["receipt"], "terminal_receipt_exact")
require(bundle_info["path"] == bundle["path"] and bundle_info["size"] == bundle["bytes"]
        and bundle_info["sha256"] == bundle["sha256"] and identity_matches(bundle_info, bundle["identity"]), "bundle_fd_identity_exact_integer")
require(c["controller"]["bytes"] == source_info["size"]
        and c["controller"]["sha256"] == source_info["sha256"]
        and identity_matches(source_info, c["controller"]["identity"]), "controller_fd_identity_exact_integer")
rows = x["child_rows"]
require(len(rows) == 81 and len({r["path"] for r in rows}) == 81, "all81_original_command_files")
by_name = {}
for row in rows:
    checked_file(row)
    by_name[pathlib.PurePosixPath(row["path"]).name] = row
commands = c["commands"]
require(len(commands) == len(c["cleanup"]) == 27
        and len({r["pid"] for r in commands}) == 27
        and len({r["label"] for r in commands}) == 27, "27_unique_owned_git_children")
cleanup = {r["pid"]: r for r in c["cleanup"]}
require(len(cleanup) == 27, "27_unique_cleanup_records")
expected_failures = []
for cmd in commands:
    label = cmd["label"]
    original_record = json.loads(by_name[label + ".public.json"]["text"])
    require(original_record == cmd, "record_exact_core:" + label)
    for stream in ("stdout", "stderr"):
        raw = by_name[label + "." + stream]
        require(raw["size"] == cmd[stream + "_bytes"] and raw["sha256"] == cmd[stream + "_sha256"],
                "command_stream_exact:" + label + ":" + stream)
    require(cmd["direct_child_reaped"] is True and cmd["remaining"] == []
            and cmd["timed_out"] is False and 0 < cmd["limit_seconds"] <= 90
            and 0 <= cmd["elapsed_seconds"] < cmd["limit_seconds"], "command_deadline_and_owned:" + label)
    actual_cleanup = cleanup[cmd["pid"]]
    require(actual_cleanup == {k: cmd[k] for k in ("pid", "label", "exit_code", "direct_child_reaped", "remaining")},
            "cleanup_exact:" + label)
    expected_exit = 1 if label.endswith("-partial-config") else 0
    require(cmd["exit_code"] == expected_exit, "expected_exit:" + label)
    if expected_exit:
        expected_failures.append(label)
require(len(expected_failures) == 2, "two_explicit_absent_config_exit1")
require(c["all_owned_stopped"] is True and terminal["all_owned_stopped"] is True, "all_owned_stopped_both")
result = {
    "schema": "heptabao.df026.source-export.offline-evidence-review.v1",
    "status": "passed", "checks_passed": len(checks), "checks": checks,
    "job_id": a["job_id"], "core_sha256": sha(x["core_raw"]),
    "authority_sha256": sha(x["authority_raw"]),
    "original_integer_ns": {k: str(c[k]) for k in ("started_unix_ns", "terminal_unix_ns")},
    "controller_identity_decimal": [str(v) for v in c["controller"]["identity"]],
    "bundle_identity_decimal": [str(v) for v in bundle["identity"]],
    "bundle_version": bundle_info["version"], "core_version": core_info["version"],
    "command_count": 27, "original_command_file_count": 81,
    "expected_config_absence_exit1_labels": expected_failures,
    "ordinary_exit0_count": 25, "all_owned_stopped": True,
    "full_history_count": 3757, "prerequisites": [],
    "scope": "Offline exact-integer verification of already-completed public originals; no host or product action.",
    "not_claimed": ["No new normal60 qualification", "No desktop source import", "No archive/HTTP/TLS/CLI execution", "No independently observed numeric FD-count field in exporter core"]
}
pathlib.Path(sys.argv[2]).write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
print(json.dumps({"status": "passed", "checks_passed": len(checks), "commands": 27, "original_command_files": 81,
                  "bundle_version": bundle_info["version"], "core_sha256": result["core_sha256"]}, sort_keys=True))
