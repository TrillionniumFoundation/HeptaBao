#!/usr/bin/env python3
"""Offline verification of exact original X230 relay evidence; no candidate execution."""
import base64
import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(sys.argv[1])
OUTPUT = Path(sys.argv[2])
checks = []
def need(value, name):
    if not value:
        raise AssertionError(name)
    checks.append(name)
def sha(raw):
    return hashlib.sha256(raw).hexdigest()
def blob(raw):
    return hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()
def unique_object(pairs):
    result = {}
    for k, v in pairs:
        if k in result:
            raise ValueError("duplicate JSON key")
        result[k] = v
    return result
def parse(raw):
    return json.loads(raw, object_pairs_hook=unique_object)
def raw(path):
    return (ROOT / path).read_bytes()
def doc(path):
    return parse(raw(path))
def sdk_text(path):
    value = doc(path)
    need(value.get("isError") is not True, "SDK-not-error:" + path)
    text = [x["text"] for x in value["content"] if x["type"] == "text"]
    need(len(text) == 1, "SDK-single-text:" + path)
    return text[0].encode()
def sdk_native(sdk_path, native_path):
    need(sdk_text(sdk_path) == raw(native_path), "SDK-native-exact:" + native_path)
def full9(info):
    dev, inode, size, mt, ct = info["version"].split(":")
    need(all(x.isdecimal() for x in (dev, inode, size, mt, ct)), "version-decimals:" + info["path"])
    need(int(size) == info["size"], "version-size:" + info["path"])
    m = info["metadata"]
    return [int(dev), int(inode), m["uid"], m["gid"], 0o100000 | info["mode"],
            m["link_count"], int(size), int(mt), int(ct)]

index = doc("verification/input-index.public.json")
for f in index["files"]:
    b = raw(f["path"])
    need(len(b) == f["bytes"] and sha(b) == f["sha256"] and blob(b) == f["blob"],
         "whole-file:" + f["path"])
need(len(index["files"]) == 289, "initial-289-whole-files")

request = doc("execution/request.original.json")
sdk_native("execution/start.original.sdk.json", "execution/start.original.json")
ack = doc("execution/start.original.json")
job = ack["job"]
need(job["id"] == "1a1ad0a9524-fc05-5839" and job["host"] == request["host"] == "desktop",
     "unique-desktop-job")
for k in ("args", "cwd", "executable", "idempotency_key"):
    need(job[k] == request[k], "exact-business-request:" + k)
need(request["timeout_seconds"] == 360 and len(request["args"]) == 4,
     "original-360-four-argv")
need(job["request_digest"] == "8a40eb0744827fbc9a290b8c541be147c062539004cf7990412cc465549d3a9b"
     and job["request_fingerprint"] == 9962220792190238652,
     "exact-digest-and-lossless-u64-fingerprint")
need(ack["reused"] is False and job["launch_state"] == "launched"
     and job["launch_error"] is None and ack["launch"]["ok"] is True,
     "original-ACK-known-unique-launch")

observations = []
for label in index["observer_labels"]:
    prefix = "observations/" + label + "/"
    op_request = doc(prefix + "request.original.json")
    for phase in ("admission", "status"):
        sdk_native(prefix + phase + ".original.sdk.json", prefix + phase + ".original.json")
    admission = doc(prefix + "admission.original.json")
    status = doc(prefix + "status.original.json")
    op_id = admission["operation_id"]
    need(admission["tool_name"] == op_request["operation"]["tool"],
         "observer-admission-tool:" + label)
    need(status["operation_id"] == op_id and status["async_state"] == "completed"
         and status["result_state"] == "stored_observed"
         and status["owned_future_active"] is False, "observer-closed:" + label)
    combined = bytearray()
    offset = 0
    total = None
    expected_sha = None
    page_count = 0
    while True:
        page_prefix = prefix + "pages/" + str(offset).zfill(6) + ".original"
        sdk_native(page_prefix + ".sdk.json", page_prefix + ".json")
        page = doc(page_prefix + ".json")
        need(page["operation_id"] == op_id and page["offset"] == offset
             and page["immutable_snapshot"] is True and page["payload_kind"] == "native_result",
             "immutable-original-page:" + label + ":" + str(offset))
        if total is None:
            total = page["total_bytes"]
            expected_sha = page["result_sha256"]
        need(page["total_bytes"] == total and page["result_sha256"] == expected_sha,
             "whole-payload-binding:" + label + ":" + str(offset))
        b = base64.b64decode(page["data_base64"], validate=True)
        need(page["next_offset"] == offset + len(b)
             and page["eof"] == (page["next_offset"] == total),
             "page-range-EOF:" + label + ":" + str(offset))
        combined.extend(b)
        page_count += 1
        offset = page["next_offset"]
        if page["eof"]:
            break
        need(page_count <= 9 and offset > 0, "bounded-original-pages:" + label)
    need(bytes(combined) == raw(prefix + "payload.original.json")
         and sha(combined) == expected_sha and len(combined) == total,
         "original-payload-reconstructed:" + label)
    sdk_native(prefix + "payload.original.json", prefix + "native.original.json")
    observations.append({"label": label, "operation_id": op_id, "immutable_pages": page_count,
                         "original_payload_bytes": total, "original_payload_sha256": expected_sha})
need(len(observations) == 20 and len({x["operation_id"] for x in observations}) == 20
     and sum(x["immutable_pages"] for x in observations) == 28, "20-unique-closed-observers-28-pages")

authority = doc("observations/authority/native.original.json")
streams = doc("observations/streams/native.original.json")
need(authority["job_id"] == streams["job_id"] == job["id"]
     and authority["state"] == "succeeded" and authority["exit_code"] == 0
     and authority["output_complete"] is True and authority["output_durable"] is True
     and authority["terminal_publication_confirmed"] is True
     and authority["timed_out"] is False and authority["cancelled"] is False,
     "known-terminal-exit0-full-durable")
for stream in ("stdout", "stderr"):
    s = streams[stream]
    content = raw("actual/" + stream + ".original.txt")
    need(s["offset"] == 0 and s["next_offset"] == s["size"] == len(content)
         and s["eof"] is True and bytes.fromhex(s["bytes_hex"]) == content
         and s["text"].encode() == content, "complete-job-stream:" + stream)
    need(authority["log_bytes"][stream] == {"seen": len(content), "stored": len(content)}
         and authority["log_errors"][stream] is None
         and authority["log_synced"][stream] is True
         and authority["log_truncated"][stream] is False, "authority-stream-binding:" + stream)
need(len(raw("actual/stdout.original.txt")) == 368 and raw("actual/stderr.original.txt") == b"",
     "368-and-zero-original-streams")

for name, info_label, body_label, original_path in (
        ("core", "core-info", "core-body", index["core_path"]),
        ("receiver", "receiver-receipt-info", "receiver-receipt-body", index["receiver_path"])):
    info = doc("observations/" + info_label + "/native.original.json")
    body = doc("observations/" + body_label + "/native.original.json")
    content = raw(original_path)
    need(body["path"] == info["path"] and body["version"] == info["version"]
         and body["offset"] == 0 and body["next_offset"] == body["size"] == info["size"] == len(content)
         and body["eof"] is True, "independent-info-version-and-whole-range:" + name)
    need(base64.b64decode(body["data_base64"], validate=True) == content
         and sha(content) == info["sha256"] == body["chunk_sha256"],
         "whole-raw-body-equals-independent-SHA:" + name)
    need(info["mode"] == info["metadata"]["mode"] == 0o600
         and info["metadata"]["uid"] == info["metadata"]["gid"] == 1000
         and info["metadata"]["link_count"] == 1, "public-receipt-mode-owner-single-link:" + name)
    full9(info)

core = doc(index["core_path"])
receiver = doc(index["receiver_path"])
terminal = parse(raw("actual/stdout.original.txt"))
need(terminal["status"] == core["status"] == "transferred"
     and terminal["all_owned_stopped"] is True
     and terminal["publication_within_original_deadline"] is True
     and terminal["elapsed_after_publication_seconds"] < 300,
     "terminal-publication-within-original-300")
need(set(core["receiver"]) - set(receiver) == {"receipt", "publication_within_original_deadline"},
     "receiver-disk-versus-terminal-exact-two-fields")
need(all(core["receiver"][k] == v for k, v in receiver.items()),
     "receiver-disk-full-object-lossless-equals-core")
need(core["receiver"]["receipt"] == {
    "path": "/home/qian/heptabao-same-root-publication-normal-20261105-r1/artifacts/transfer.result.public.json",
    "bytes": len(raw(index["receiver_path"])), "sha256": sha(raw(index["receiver_path"]))},
    "terminal-receiver-receipt-pin")
need(core["receiver"]["publication_within_original_deadline"] is True,
     "receiver-publication-inside-original-deadline")

destinations = []
for i, f in enumerate(receiver["file_results"]):
    info = doc("observations/dest-info-" + str(i) + "/native.original.json")
    identity = full9(info)
    need(info["path"] == f["path"] and info["size"] == f["bytes"]
         and info["sha256"] == f["sha256"], "actual-destination-whole-content:" + str(i))
    need(identity == f["identity"], "actual-destination-lossless-full9:" + str(i))
    need(info["mode"] == info["metadata"]["mode"] == (0o500 if i == 0 else 0o400)
         and info["metadata"]["uid"] == info["metadata"]["gid"] == 1000
         and info["metadata"]["link_count"] == 1
         and f["create_only"] is True and f["fsynced"] is True,
         "actual-destination-mode-custody:" + str(i))
    need(f["same_fd_readback"] == {"bytes": info["size"], "sha256": info["sha256"]},
         "same-FD-readback-equals-independent-info:" + str(i))
    destinations.append({"index": i, "path": f["path"], "bytes": info["size"],
                         "sha256": info["sha256"], "version": info["version"],
                         "full9_decimal": list(map(str, identity))})
need(len(destinations) == 7 and sum(x["bytes"] for x in destinations) == 132647913,
     "seven-original-files-132647913-bytes")

provenance = doc("actual/command-file-provenance.public.json")
actual_rows = [x for x in provenance["files"] if x["method"] == "actual-native-read_multiple_files"]
reused_rows = [x for x in provenance["files"] if x["method"] == "root-approved-canonical-complete-bytes-reuse"]
need(len(actual_rows) == 69 and len(reused_rows) == 2
     and provenance["current_native_nul_body_rpc_count"] == 0,
     "69-actual-small-plus-two-explicit-representations")
for label in ("receiver-logs-01", "receiver-logs-02", "receiver-logs-03", "receiver-logs-04", "desktop-logs-01"):
    value = doc("observations/" + label + "/native.original.json")
    req = doc("observations/" + label + "/request.original.json")["operation"]["arguments"]
    need(value["atomic_snapshot"] is False and value["snapshot_scope"] == "independent_file"
         and value["encoding"] == "utf-8" and value["truncated"] is False
         and req["max_file_bytes"] == 65536 and req["max_response_bytes"] == 131072,
         "original-independent-small-batch-caps:" + label)
    need([f["path"] for f in value["files"]] == req["paths"] and len(req["paths"]) <= 16,
         "exact-fixed-small-batch-paths:" + label)
    for f in value["files"]:
        row = next(x for x in actual_rows if x["observation"] == label and x["native_path"] == f["path"])
        content = raw(row["archive_path"])
        need(content == f["text"].encode() and len(content) == f["size"] == row["bytes"]
             and sha(content) == f["sha256"] == row["sha256"]
             and f["version"] == row["version"] and f["eof"] is True,
             "actual-small-original-byte-chain:" + row["archive_path"])

for side, rows in (("receiver", receiver["commands"]), ("desktop", core["commands"])):
    for row in rows:
        path = "commands/" + side + "/" + row["label"] + ".public.json"
        need(doc(path) == row, "actual-original-command-full-record:" + side + ":" + row["label"])
        cleanup = next(x for x in (receiver["cleanup"] if side == "receiver" else core["cleanup"])
                       if x["label"] == row["label"])
        need(cleanup["pid"] == row["pid"] and cleanup["exit_code"] == row["exit_code"]
             and cleanup["direct_child_reaped"] is True and cleanup["remaining"] == []
             and not cleanup.get("cleanup_error_type"), "actual-owned-once-closure:" + side + ":" + row["label"])
        need(row["direct_child_reaped"] is True and row["remaining"] == []
             and row["timed_out"] is False and row["elapsed_seconds"] < row["limit_seconds"],
             "original-command-return-and-cap:" + side + ":" + row["label"])
        if side == "receiver":
            need(row["exit_code"] == (1 if row["label"] in ("013-no-sparse-config", "020-source-after-partial-config") else 0),
                 "allowed-original-Git-return-code:" + row["label"])
            for stream in ("stdout", "stderr"):
                filename = row["label"] + "." + stream
                path = ("content-representations/" if row["label"] in
                        ("011-materialized-tree", "012-materialized-index") and stream == "stdout"
                        else "commands/") + "receiver/" + filename
                content = raw(path)
                need(len(content) == row[stream + "_bytes"] and sha(content) == row[stream + "_sha256"],
                     "original-command-whole-stream:" + filename)
need(len(receiver["commands"]) == len(receiver["cleanup"]) == 21
     and len(core["commands"]) == len(core["cleanup"]) == 3,
     "21-Git-plus-three-local-original-commands")
need(doc("commands/desktop/receive-x230.stderr") == core["receiver"]
     and doc("commands/desktop/send-desktop.stderr") == core["sender"],
     "actual-endpoint-complete-stderr-lossless-equals-core")
need(raw("commands/desktop/receive-x230.stdout") == b""
     and raw("commands/desktop/x230-ts-effective-config.stderr") == b"",
     "actual-empty-endpoint-config-streams")
need(sha(raw("commands/desktop/x230-ts-effective-config.stdout")) ==
     core["ssh_preflight"]["x230-ts"]["effective_config_sha256"], "actual-strict-SSH-effective-config-hash")

reuse = doc("reference/NUL-content-reuse-GO.original.json")
need(reuse["status"] == "GO_EXACT_TWO_CONTENT_REPRESENTATIONS_ONLY"
     and reuse["original_relay_job"] == "desktop/" + job["id"], "separate-current-X230-NUL-GO")
for name, label in (("nul-tree-info", "011-materialized-tree"), ("nul-index-info", "012-materialized-index")):
    info = doc("observations/" + name + "/native.original.json")
    f = next(x for x in reuse["files"] if x["label"] == label)
    b = raw("content-representations/receiver/" + label + ".stdout")
    need(info["size"] == f["bytes"] == len(b) and info["sha256"] == f["sha256"] == sha(b)
         and info["version"] == f["version"] and list(map(str, full9(info))) == f["full9_decimal"]
         and blob(b) == f["reconstructed_content_blob"] and f["current_host_body_RPC_count"] == 0,
         "canonical-complete-bytes-bound-to-current-X230:" + label)
need(core["original_relay_state"] == "UNKNOWN" and core["original_relay_termination_proven"] is False,
     "old-relay-UNKNOWN-not-rewritten")
need(core["effect_fence_before_verified"] is True and core["effect_fence_after_cleanup_verified"] is True
     and core["effect_fence_all_descriptors_closed"] is True
     and len(core["effect_fence_descriptors"]) == 3
     and all(x["close_attempted"] is True and x["closed"] is True and x["error_type"] is None
             for x in core["effect_fence_descriptors"]), "three-held-effect-fence-FDs-closed")
need(core["remote_cleanup_unknown"] is False and core["cleanup_errors"] == []
     and core["all_owned_stopped"] is True and core["all_local_owned_stopped"] is True
     and core["remote_endpoint_completion_verified"] is True,
     "actual-local-and-remote-known-closed")
need(core["source_commit"] == receiver["source_commit"] == "4e808d0ecb1bcded22870a7ec960dfb2491cf6ec"
     and core["source_tree"] == receiver["source_tree"] == "eba5e650bd080b8ad41ea52a2bc68867f541d255"
     and receiver["canonical_proof"]["commit_count"] == 3763
     and receiver["canonical_proof"]["full_fsck_passed"] is True
     and receiver["materialized"]["tracked_files"] == 3914,
     "current-canonical-3763-3914-fsck")
need(core["server_started"] is False and core["compiler_started"] is False
     and core["production_changed"] is False and core["runtime_qualification"] is False
     and receiver["product_tests_executed"] == 0, "zero-product-or-compiler-qualification")
result = {
    "schema": "heptabao.4e808.x230-relay-complete-original-evidence-offline-verification.v1",
    "status": "PASS_ORIGINAL_TRANSPORT_AND_SOURCE_IMPORT_EVIDENCE",
    "checks_passed": len(checks), "checks": checks,
    "job_id": job["id"], "operations": observations, "native_operations_closed": 20,
    "immutable_pages": 28, "actual_small_files": 69,
    "canonical_content_representations": 2, "current_native_nul_body_RPC_count": 0,
    "original_commands": {"desktop": 3, "receiver_git": 21},
    "seven_measured_destinations": destinations,
    "source_commit": receiver["source_commit"], "source_tree": receiver["source_tree"],
    "old_relay_state": "UNKNOWN", "old_relay_termination_proven": False,
    "host_or_network_calls_in_this_verifier": 0, "candidate_code_executed": False,
    "product_runtime_qualified": False, "production_qualified": False,
    "scope": "Offline byte-chain, current file identities, original command/stream and closure verification. Core semantic peer remains separately scoped. Product/full34/comparison69 execution is not authorized by this result."
}
OUTPUT.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
print(json.dumps({"status": result["status"], "checks_passed": len(checks),
                  "report_bytes": OUTPUT.stat().st_size, "report_sha256": sha(OUTPUT.read_bytes())}))

