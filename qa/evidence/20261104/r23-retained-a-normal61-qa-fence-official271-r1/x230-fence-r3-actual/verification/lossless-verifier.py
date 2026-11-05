import ast
import base64
import hashlib
import json
import stat
import sys

d = json.load(sys.stdin)
req = json.loads(d["request_raw"])
ack = json.loads(d["ack_raw"])
authority = json.loads(d["authority_raw"])
read = json.loads(d["read_raw"])
report = json.loads(d["stdout_raw"])
info = json.loads(d["info_raw"])
bodyread = json.loads(d["bodyread_raw"])
marker = json.loads(d["marker_raw"])
source = req["args"][4]
checks = []
def ck(name, condition):
    assert condition, name
    checks.append({"check": name, "passed": True})
def digest(raw):
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()

allowed = {"BASE", "CONTROLS", "ROOT_NAME", "TOMBSTONE_NAME", "ORIGINAL_JOB",
           "ORIGINAL_KEY", "ORIGINAL_REQUEST_SHA256", "ORIGINAL_REQUEST_DIGEST",
           "BINDING_READY", "METADATA_EVIDENCE_SHA256", "EXPECTED_DIRECTORIES",
           "EXPECTED_CONTROLS", "SOFT_SECONDS", "READ_CAP", "TOMBSTONE_CAP",
           "OUTPUT_CAP", "SHARED_PARENT_PATHS"}
tree = ast.parse(source)
assigns = [n for n in tree.body if isinstance(n, ast.Assign)
           and len(n.targets) == 1 and isinstance(n.targets[0], ast.Name)
           and n.targets[0].id in allowed]
env = {}
exec(compile(ast.Module(body=assigns, type_ignores=[]), "<public-constants-only>", "exec"), env)
root = env["BASE"] + "/" + env["ROOT_NAME"]
path = root + "/" + env["TOMBSTONE_NAME"]
job = "1a1ab637c5e-fc05-4d3a"
ck("exact_request_whole_sha", digest(d["request_raw"]) == "a0344a7b1f9180ffaeefcc69ffd4a42b05ddcfde73780f0e2670c2435d83a716")
ck("request_exact_source_sha", digest(source) == req["args"][5] == "4b4026a62458793162a4abf05b5a193240b56adeff33e405a85c975f7fa724ae")
ck("request_fixed_identity", req["host"] == "desktop" and req["executable"] == "/usr/bin/python3"
   and req["args"][:4] == ["-I", "-S", "-B", "-c"] and len(req["args"]) == 6
   and req["cwd"] == env["BASE"] and req["timeout_seconds"] == 60
   and req["idempotency_key"] == "heptabao-x230-original-relay-effect-fence-r3-4b4026a6")
ck("ack_exact_binding", ack["job"]["host"] == "desktop" and ack["job"]["id"] == job
   and ack["job"]["args"] == req["args"] and ack["job"]["cwd"] == req["cwd"]
   and ack["job"]["executable"] == req["executable"]
   and ack["job"]["idempotency_key"] == req["idempotency_key"]
   and ack["job"]["request_digest"] == "d844d40a3dd1313c3d546608163bf85b358f0ce28b59de72994aee5fa8e4d39e"
   and ack["job"]["launch_state"] == "launched" and ack["reused"] is False)
ck("authority_known_exit0_full_durable", authority["job_id"] == job
   and authority["state"] == "succeeded" and authority["exit_code"] == 0
   and authority["output_complete"] is True and authority["output_durable"] is True
   and authority["terminal_publication_confirmed"] is True
   and authority["timed_out"] is False and authority["cancelled"] is False)
ck("read_job_binding", read["job_id"] == job)
for name, raw in [("stdout", d["stdout_raw"]), ("stderr", "")]:
    r = read[name]
    b = raw.encode("utf-8")
    ck(name + "_hex_text_size_eof", r["offset"] == 0 and r["size"] == len(b)
       and r["next_offset"] == len(b) and r["eof"] is True
       and r["text"] == raw and bytes.fromhex(r["bytes_hex"]) == b)
    ck(name + "_authority_stored_seen_synced", authority["log_bytes"][name] == {"seen": len(b), "stored": len(b)}
       and authority["log_errors"][name] is None and authority["log_truncated"][name] is False
       and authority["log_synced"][name] is True)
ck("public_report_schema_source", report["schema"] == "heptabao.x230-original-relay-effect-fence.v2"
   and report["source_sha256"] == digest(source))
ck("reported_known_success", report["status"] == "effect_fence_published" and report["error"] is None)
ck("original_unknown_unchanged", report["original_job"] == env["ORIGINAL_JOB"]
   and report["original_key"] == env["ORIGINAL_KEY"]
   and report["original_execution_state"] == "unknown"
   and report["original_job_terminal_or_cleanup_proven"] is False)
ck("no_other_effects", report["children_started"] == 0
   and all(report[k] is False for k in ("transport_started", "network_started", "signals_sent",
                                       "old_root_or_existing_file_deleted_or_modified")))
ck("all_registration_closure", len(report["descriptors"]) == 10
   and len({x["fd"] for x in report["descriptors"]}) == 10
   and all(x["open_attempted"] is True and x["opened"] is True
           and x["close_attempted"] is True and x["closed"] is True
           and x["close_errno"] is None and x["close_error_type"] is None
           for x in report["descriptors"])
   and report["all_registered_descriptors_closed"] is True
   and report["unknown_descriptor_closure"] is False)
ck("original_budget_signal_closure", report["pending_signal"] is None
   and report["soft_seconds"] == env["SOFT_SECONDS"] == 15
   and report["metadata_calls"] == 113 <= 128
   and report["bytes_read"] == 122403 <= env["READ_CAP"] == 131072
   and len(d["stdout_raw"].encode()) <= env["OUTPUT_CAP"] == 32768
   and report["body_and_cleanup_elapsed_ns"] == 53414886 < 15_000_000_000
   and report["body_and_cleanup_within_original_deadline"] is True)
ck("create_only_publication_flags", report["absence_observation"] == "absent"
   and all(report[k] is True for k in ("mkdir_attempted", "mkdir_returned_success",
                                      "parent_entry_fsynced", "tombstone_create_attempted",
                                      "tombstone_fsynced", "directory_fsynced")))
ck("fixed_shared_identity_scope", report["shared_parent_paths"] == list(env["SHARED_PARENT_PATHS"])
   and report["shared_parent_object_identity_fields"] == ["dev", "ino", "uid", "gid", "mode"]
   and report["shared_parent_mutable_metadata_proves_absence"] is False)
expected_paths = list(env["EXPECTED_DIRECTORIES"]) + [
    env["CONTROLS"] + "/" + name for name in env["EXPECTED_CONTROLS"]] + [root, path]
nodes = {n["path"]: n for n in report["nodes"]}
ck("exact_ten_nodes_and_fd_labels", len(report["nodes"]) == len(nodes) == 10
   and list(nodes) == expected_paths
   and [x["label"] for x in report["descriptors"]] == expected_paths)
ck("three_public_sources_lossless_before_after", report["sources_before"] == report["sources_after"]
   and len(report["sources_before"]) == 3)
for name, expected in env["EXPECTED_CONTROLS"].items():
    source_path = env["CONTROLS"] + "/" + name
    record = next(x for x in report["sources_before"] if x["path"] == source_path)
    n = nodes[source_path]
    ck("public_source_" + name + "_full_pin", record["bytes"] == expected["bytes"]
       and record["sha256"] == expected["sha256"] and record["blob"] == expected["blob"]
       and record["identity"] == expected["identity"])
    ck("public_source_" + name + "_full9_all_boundaries",
       n["directory"] is False and n["identity_before"] == n["identity_after"]
       == n["expected_current"] == n["expected_fixed_identity"] == expected["identity"])
for directory, expected in env["EXPECTED_DIRECTORIES"].items():
    n = nodes[directory]
    ck("directory_baseline_" + directory, n["directory"] is True
       and n["expected_fixed_identity"] == expected
       and all(len(n[k]) == 9 for k in ("identity_before", "identity_after", "expected_current")))
    if directory in env["SHARED_PARENT_PATHS"]:
        ck("shared_object_bound_" + directory,
           n["identity_before"][:5] == n["identity_after"][:5] == n["expected_current"][:5] == expected[:5])
    else:
        ck("controls_full9_unchanged",
           n["identity_before"] == n["identity_after"] == n["expected_current"] == expected)
rn, tn = nodes[root], nodes[path]
ck("created_root_object_and_exact_final9", rn["directory"] is True
   and rn["identity_before"][:6] == rn["identity_after"][:6]
   and rn["identity_after"] == rn["expected_current"]
   and stat.S_ISDIR(rn["identity_after"][4])
   and stat.S_IMODE(rn["identity_after"][4]) == 0o700
   and rn["identity_after"][2:4] == [1000, 1000]
   and rn["identity_after"][5] == 2)
ck("created_marker_full9", tn["directory"] is False
   and tn["identity_before"] == tn["identity_after"] == tn["expected_current"]
   == report["tombstone"]["identity"])
mi = tn["identity_after"]
ck("marker_exact_type_owner_mode_single_link", stat.S_ISREG(mi[4])
   and stat.S_IMODE(mi[4]) == 0o600 and mi[2:4] == [1000, 1000] and mi[5] == 1)
marker_bytes = d["marker_raw"].encode("utf-8")
marker_sha = hashlib.sha256(marker_bytes).hexdigest()
ck("marker_same_fd_and_independent_hash", len(marker_bytes) == 2709 == mi[6]
   == report["tombstone"]["bytes"] <= env["TOMBSTONE_CAP"] == 8192
   and marker_sha == "69a6a00997c2165414238ad27b699b34aab569ef003a579c0e568ea8d272ee33"
   == report["tombstone"]["sha256"]
   and report["tombstone"]["path"] == path
   and all(report["tombstone"][k] is True for k in ("same_fd_readback", "fsynced", "create_only")))
version = ":".join(str(mi[i]) for i in (0, 1, 6, 7, 8))
ck("independent_metadata_full_identity_version", info["version"] == version
   and info["path"] == path and info["size"] == mi[6] and info["sha256"] == marker_sha
   and info["mode"] == info["metadata"]["mode"] == stat.S_IMODE(mi[4])
   and info["metadata"]["uid"] == mi[2] and info["metadata"]["gid"] == mi[3]
   and info["metadata"]["link_count"] == mi[5])
ck("independent_version_pinned_body_exact", bodyread["version"] == version
   and bodyread["path"] == path and bodyread["offset"] == 0
   and bodyread["size"] == bodyread["next_offset"] == len(marker_bytes)
   and bodyread["eof"] is True and bodyread["chunk_sha256"] == marker_sha
   and base64.b64decode(bodyread["data_base64"], validate=True) == marker_bytes)
ck("total_public_read_arithmetic", report["bytes_read"] ==
   2 * sum(x["bytes"] for x in report["sources_before"]) + len(marker_bytes))
ck("marker_origin_namespace_and_source", marker["schema"] == "heptabao.x230-relay-future-effect-reservation.v1"
   and marker["original_job"] == env["ORIGINAL_JOB"] and marker["original_key"] == env["ORIGINAL_KEY"]
   and marker["original_request_sha256"] == env["ORIGINAL_REQUEST_SHA256"]
   and marker["original_controller_request_digest"] == env["ORIGINAL_REQUEST_DIGEST"]
   and marker["reservation_source_sha256"] == digest(source)
   and marker["metadata_evidence_sha256"] == env["METADATA_EVIDENCE_SHA256"]
   and marker["fixed_root"] == root)
ck("marker_lossless_parent_root_and_sources", marker["root_identity_at_creation"] == rn["identity_before"]
   and marker["parent_identity_before"] == nodes[env["BASE"]]["identity_before"]
   and marker["parent_identity_after_owned_mkdir"] == nodes[env["BASE"]]["expected_current"]
   and marker["public_sources_verified_before_creation"] == report["sources_before"]
   and marker["relay_source_sha256"] == env["EXPECTED_CONTROLS"]["relay.py"]["sha256"]
   and marker["relay_source_blob"] == env["EXPECTED_CONTROLS"]["relay.py"]["blob"])
ck("marker_limited_future_effect_scope", marker["mkdir_returned_success"] is True
   and marker["original_execution_state"] == "unknown" and marker["must_preserve_original_unknown"] is True
   and marker["scope"] == "prevent this exact relay from newly crossing mandatory ROOT.mkdir"
   and marker["remaining_possible_effects"] == ["old Python process", "read-only finally ps", "worker logs"])
output = {
 "schema": "heptabao.x230-fence-r3-lossless-actual-verification.v1",
 "checks": checks, "total": len(checks), "passed": len(checks),
 "job_id": job, "outcome": "PASS_EXACT_CREATE_ONLY_FENCE_SCOPE",
 "authority_exit_code": 0, "output_complete": True, "output_durable": True,
 "elapsed_ns": report["body_and_cleanup_elapsed_ns"],
 "registered_fds": 10, "metadata_calls": report["metadata_calls"],
 "body_bytes_read": report["bytes_read"],
 "root_final_identity_decimal_strings": [str(x) for x in rn["identity_after"]],
 "marker_identity_decimal_strings": [str(x) for x in mi],
 "marker_version": version, "marker_sha256": marker_sha,
 "root_identity_source": "actual in-controller held and named checks; no independent directory stat",
 "marker_identity_source": "actual in-controller held/named plus independent file_info/version-pinned body",
 "original_relay_state": "UNKNOWN", "original_job_termination_proven": False,
 "transport_or_product_started": False, "automatic_replay_authorized": False,
 "verification_scope": "Parse immutable public raw receipts with Python exact integers; no host/FD/mutation calls",
}
sys.stdout.write(json.dumps(output, sort_keys=True) + "\n")
