#!/usr/bin/env python3
"""Independent offline review of LAN prepare observation byte chains only."""
import base64
import collections
import hashlib
import json
import sys
from pathlib import Path

root = Path(sys.argv[1])
out = Path(sys.argv[2])
counts = collections.Counter()
def check(ok, category, detail):
    if not ok:
        raise AssertionError(category + ": " + detail)
    counts[category] += 1
def unique(pairs):
    d = {}
    for k, v in pairs:
        if k in d:
            raise ValueError("duplicate JSON key " + k)
        d[k] = v
    return d
def parse(b):
    return json.loads(b, object_pairs_hook=unique)
def raw(p):
    return (root / p).read_bytes()
def doc(p):
    return parse(raw(p))
def sha(b):
    return hashlib.sha256(b).hexdigest()
def git_hash(kind, b):
    return hashlib.sha1(kind.encode() + b" " + str(len(b)).encode() + b"\0" + b).hexdigest()
def text(sdk):
    check(sdk.get("isError") is not True, "outer_SDK", "non-error transport envelope")
    items = [x["text"] for x in sdk["content"] if x["type"] == "text"]
    check(len(items) == 1, "outer_SDK", "exact one native text")
    return items[0].encode()
def native_sdk(path):
    return parse(text(doc(path)))

tree = doc("peer-source-tree.original.json")
check(tree["sha"] == "f799faca211d7c34db5f386c948509e1d6219faa" and tree["truncated"] is False,
      "whole_packet", "fixed complete Git tree")
leaves = {x["path"]: x for x in tree["tree"] if x["type"] == "blob"}
check(len(leaves) == 213, "whole_packet", "213 exact leaves")
for p, item in leaves.items():
    b = raw(p)
    check(len(b) == item["size"] and git_hash("blob", b) == item["sha"]
          and item["mode"] == "100644", "whole_blob", p)
manifest = doc("MANIFEST.public.json")
listed = {x["path"]: x for x in manifest["entries"]}
check(set(listed) == set(leaves) - {"MANIFEST.public.json"}, "manifest", "exact non-self inventory")
for p, item in listed.items():
    b = raw(p)
    check(item["blob"] == leaves[p]["sha"] and item["bytes"] == len(b)
          and item["sha256"] == sha(b), "manifest", p)
dirs = {"": {}}
for p, item in leaves.items():
    components = p.split("/")
    for i in range(len(components) - 1):
        parent = "/".join(components[:i])
        name = components[i]
        child = "/".join(components[:i + 1])
        dirs.setdefault(parent, {})[name] = ("tree", child)
        dirs.setdefault(child, {})
    dirs["/".join(components[:-1])][components[-1]] = ("blob", item["sha"])
computed = {}
def node(path):
    parts = []
    for name, (kind, value) in sorted(dirs[path].items(), key=lambda kv: (kv[0] + ("/" if kv[1][0] == "tree" else "")).encode()):
        oid = node(value) if kind == "tree" else value
        parts.append(("40000" if kind == "tree" else "100644").encode() + b" " + name.encode() + b"\0" + bytes.fromhex(oid))
    computed[path] = git_hash("tree", b"".join(parts))
    return computed[path]
check(node("") == tree["sha"], "Merkle", "root")
for item in tree["tree"]:
    if item["type"] == "tree":
        check(computed[item["path"]] == item["sha"], "Merkle", item["path"])
check(len(computed) == 92, "Merkle", "92 nodes including root")

request = doc("execution/ACK/exact-request.public.json")
intent = doc("execution/intent/execution-intent.public.json")
go = doc("execution/intent/root-GO.public.json")
check(raw("execution/ACK/exact-request.public.json") == raw("execution/intent/exact-request.public.json"),
      "business_binding", "two exact request copies")
check(request == intent["request"] == go["exact_request"], "business_binding", "request/intent/GO exact")
ack_text = text(doc("execution/ACK/original-SDK.json"))
ack = parse(ack_text)
job = ack["job"]
check(job["id"] == "1a1ad1383c9-fc05-5863" and ack["reused"] is False
      and job["launch_state"] == "launched" and job["launch_error"] is None
      and ack["launch"]["ok"] is True, "business_binding", "single known original ACK")
for field in ("host", "executable", "args", "cwd", "idempotency_key"):
    check(job[field] == request[field], "business_binding", field)
typed = {
    "args": request["args"], "cpu_quota_percent": request.get("cpu_quota_percent"),
    "cwd": request.get("cwd"), "env": dict(sorted(request.get("env", {}).items())),
    "executable": request["executable"], "host": request["host"],
    "memory_max_bytes": request.get("memory_max_bytes"), "nice": request.get("nice"),
    "stdin": request.get("stdin"), "timeout_seconds": request.get("timeout_seconds")
}
canonical = json.dumps(typed, ensure_ascii=False, separators=(",", ":"))
check(canonical == intent["binding"]["canonical_json"] == go["process_binding"]["canonical_json"]
      and sha(canonical.encode()) == job["request_digest"] == intent["binding"]["request_digest"],
      "business_binding", "independent typed-canonical digest")
check(str(job["request_fingerprint"]) == intent["binding"]["request_fingerprint_decimal"]
      == go["process_binding"]["request_fingerprint_decimal"] == "15744371501096865335",
      "business_binding", "lossless u64 ACK fingerprint")
check(request["args"][-1] == "--prepare-only" and request["timeout_seconds"] == 360,
      "business_binding", "prepare-only original deadline")

labels = sorted({p.split("/")[1] for p in leaves if p.startswith("observers/") and p.endswith("/start/request.json")})
expected = {"authority0", "streams0", "output1_body0_recovery1"}
expected.update("output" + str(i) + "_info" for i in range(5))
expected.update("output" + str(i) + "_body0" for i in range(5))
check(set(labels) == expected and len(labels) == 13, "observation_inventory", "13 original observers")
ops = {}
native = {}
for label in labels:
    pre = "observers/" + label + "/"
    req = doc(pre + "start/request.json")
    if label == "output1_body0_recovery1":
        check(raw(pre + "start/request.json") == raw(pre + "intent/exact-read-request.public.json"),
              "read_intent", label + " recovery exact request")
        ri = doc(pre + "intent/recovery-intent.public.json")
    else:
        check(raw(pre + "start/request.json") == raw(pre + "intent/exact-operation-start-request.public.json"),
              "read_intent", label + " exact request")
        ri = doc(pre + "intent/read-intent.public.json")
    check(ri["request"] == req, "read_intent", label + " typed args")
    admitted = native_sdk(pre + "start/original-sdk.json")
    status = native_sdk(pre + "status-0/original-sdk.json")
    op_id = admitted["operation_id"]
    check(admitted["tool_name"] == req["operation"]["tool"] and admitted["reused"] is False
          and admitted["automatic_retry"] is False, "read_admission", label)
    check(doc(pre + "status-0/request.json") == {"operation_id": op_id},
          "same_ID", label + " status request")
    expected_state = "failed" if label == "output1_body0" else "completed"
    check(status["operation_id"] == op_id and status["async_state"] == expected_state
          and status["result_state"] == "stored_observed" and status["owned_future_active"] is False
          and status["payload_available"] is True, "positive_closure", label)
    pages = sorted((int(p[len(pre):].split("/")[0][7:]), p) for p in leaves
                   if p.startswith(pre + "result-") and p.endswith("/original-sdk.json"))
    offset = 0
    payload = bytearray()
    whole_sha = None
    total = None
    for page_no, (listed_offset, sdk_path) in enumerate(pages):
        prefix = sdk_path.rsplit("/", 1)[0]
        pr = doc(prefix + "/request.json")
        check(pr == {"operation_id": op_id, "offset": offset, "limit": 8192}
              and listed_offset == offset, "same_ID", label + " page request")
        page = native_sdk(sdk_path)
        check(page["operation_id"] == op_id and page["offset"] == offset
              and page["immutable_snapshot"] is True and page["payload_kind"] == "native_result",
              "immutable_page", label + ":" + str(offset))
        if page_no == 0:
            total, whole_sha = page["total_bytes"], page["result_sha256"]
        b = base64.b64decode(page["data_base64"], validate=True)
        check(len(b) <= 8192 and page["next_offset"] == offset + len(b)
              and page["total_bytes"] == total and page["result_sha256"] == whole_sha
              and page["eof"] == (page_no == len(pages) - 1)
              and page["eof"] == (page["next_offset"] == total),
              "page_range_EOF", label + ":" + str(offset))
        payload.extend(b)
        offset = page["next_offset"]
    check(bytes(payload) == raw(pre + "original-payload.json")
          and len(payload) == total and sha(payload) == whole_sha, "whole_original_payload", label)
    original = parse(payload)
    if label == "output1_body0":
        check(original["isError"] is True and len(payload) == 183
              and sha(payload) == "5427c6345f5256d4b857421176675d1c1dda08db0504e937fbf95611ba90b67b"
              and pre + "native-result.public.json" not in leaves,
              "known_failed_original", "183-byte error and no successful file body")
    else:
        b = text(original)
        check(b == raw(pre + "native-result.public.json"), "original_native_text", label)
        native[label] = parse(b)
    ops[label] = {"operation_id": op_id, "request_key": req["idempotency_key"],
                  "tool": req["operation"]["tool"], "async_state": status["async_state"],
                  "closed": True, "pages": len(pages), "payload_bytes": total, "payload_sha256": whole_sha}
check(len({x["operation_id"] for x in ops.values()}) == 13
      and sum(x["pages"] for x in ops.values()) == 20
      and sum(x["async_state"] == "completed" for x in ops.values()) == 12,
      "observation_inventory", "13 unique / 20 pages / 12 success plus 1 failed")

bad = "output1_body0"
recovered = "output1_body0_recovery1"
check(ops[bad]["operation_id"] == "9f8eb82a15916661a8e424e4e4b74a2b6b4b27931886284c64fe025100940a0d"
      and ops[recovered]["operation_id"] == "804b063ef1ec7b8f6701b88fde95d4106385d597180e13e7a7c3ec15e2feacfa",
      "unique_recovery", "exact old and new IDs")
recovery_go = doc("recovery/readonly-reobserve-intent/root-GO.public.json")
recovery_req_raw = raw("recovery/readonly-reobserve-intent/exact-read-request.public.json")
recovery_req = parse(recovery_req_raw)
old_req = doc("observers/" + bad + "/start/request.json")
check(recovery_go["status"] == "GO_ONE_EXACT_READONLY_RECOVERY_AFTER_KNOWN_TERMINAL_FAILURE"
      and recovery_go["original_failed_observation"] == ops[bad]["operation_id"]
      and recovery_go["maximum_recovery_submissions"] == 1
      and recovery_go["original_prepare_process_replay_authorized"] is False
      and recovery_go["live_authorized"] is False, "unique_recovery", "root GO exact one readonly recovery")
check(recovery_req == recovery_go["request"]
      and recovery_req_raw == raw("observers/" + recovered + "/start/request.json")
      and sha(recovery_req_raw) == recovery_go["exact_new_read_request"]["sha256"]
      and git_hash("blob", recovery_req_raw) == recovery_go["exact_new_read_request"]["blob"],
      "unique_recovery", "exact authorized recovery request bytes")
check(old_req["operation"] == recovery_req["operation"]
      and old_req["idempotency_key"] != recovery_req["idempotency_key"]
      and recovery_req["operation"]["arguments"]["limit"] == 3192,
      "unique_recovery", "only new recovery key; same original path/version/range/tool")
for hist, source in (
        ("start/request.json", "start/request.json"),
        ("start/original-sdk.json", "start/original-sdk.json"),
        ("status/request.json", "status-0/request.json"),
        ("status/original-sdk.json", "status-0/original-sdk.json"),
        ("result/request.json", "result-0/request.json"),
        ("result/original-sdk.json", "result-0/original-sdk.json"),
        ("original-failed-payload.json", "original-payload.json")):
    check(raw("history/output1-original-failed-body/" + hist) == raw("observers/" + bad + "/" + source),
          "failure_preservation", hist)
failure_state = doc("history/output1-original-failed-body/STATE.public.json")
check(failure_state["failed_closed_status"]["async_state"] == "failed"
      and failure_state["body1_whole_available"] is False
      and failure_state["body2_through4_submissions"] == 0
      and failure_state["LAN_live_submitted"] is False, "failure_preservation", "historical failed boundary unchanged")

authority = native["authority0"]
streams = native["streams0"]
check(authority == doc("actual/authority.public.json")
      and authority["job_id"] == streams["job_id"] == job["id"]
      and authority["state"] == "succeeded" and authority["exit_code"] == 0
      and authority["output_complete"] is True and authority["output_durable"] is True
      and authority["terminal_publication_confirmed"] is True
      and authority["timed_out"] is False and authority["cancelled"] is False,
      "actual_job", "known original prepare authority")
for name, size in (("stdout", 297), ("stderr", 0)):
    s = streams[name]
    content = raw("actual/" + name + ".public.log")
    check(s["offset"] == 0 and s["next_offset"] == s["size"] == len(content) == size
          and s["eof"] is True and s["text"].encode() == content
          and bytes.fromhex(s["bytes_hex"]) == content, "actual_job", name + " complete hex/text/EOF")
    check(authority["log_bytes"][name] == {"seen": size, "stored": size}
          and authority["log_errors"][name] is None and authority["log_synced"][name] is True
          and authority["log_truncated"][name] is False, "actual_job", name + " authority binding")

plan = doc("body-plan/body-plan.public.json")
check(plan["original_job"] == job["id"] and plan["native_body_requests"] == 5
      and plan["total_original_file_bytes"] == 52030
      and plan["maximum_single_body_limit"] == 65536
      and plan["immutable_result_page_limit"] == 8192, "five_file_plan", "frozen exact bounds")
outputs = []
for i, row in enumerate(plan["rows"]):
    info_label = "output" + str(i) + "_info"
    body_label = "output1_body0_recovery1" if i == 1 else "output" + str(i) + "_body0"
    info, body = native[info_label], native[body_label]
    info_req = doc("observers/" + info_label + "/start/request.json")["operation"]
    body_req = doc("observers/" + body_label + "/start/request.json")["operation"]
    need_path = go["observation_scope"]["exact_five_outputs"][i]
    check(row["index"] == i and info_req == {"tool": "file_info", "arguments": {"host": "desktop", "path": need_path}}
          and info["path"] == row["path"] == need_path
          and info["size"] == row["bytes"] and info["sha256"] == row["sha256"]
          and info["version"] == row["version"]
          and row["original_file_info_operation"] == ops[info_label]["operation_id"],
          "five_file_identity", str(i) + " independent actual info")
    parts = info["version"].split(":")
    check(len(parts) == 5 and all(s.isdecimal() for s in parts) and int(parts[2]) == info["size"],
          "five_file_identity", str(i) + " lossless version")
    m = info["metadata"]
    full9 = [parts[0], parts[1], str(m["uid"]), str(m["gid"]),
             str(0o100000 | info["mode"]), str(m["link_count"]), parts[2], parts[3], parts[4]]
    check(full9 == row["full9_decimal"] and info["mode"] == m["mode"] == 0o600
          and m["uid"] == m["gid"] == 1000 and m["link_count"] == 1,
          "five_file_identity", str(i) + " exact full9 decimals / 0600 / owner / single link")
    check(raw("actual/file-info/output" + str(i) + ".json") ==
          raw("observers/" + info_label + "/native-result.public.json") ==
          raw("body-plan/actual-info/output" + str(i) + ".public.json"),
          "five_file_identity", str(i) + " original info copies")
    expected_args = {"host": "desktop", "path": info["path"], "offset": 0,
                     "limit": info["size"], "expected_version": info["version"]}
    check(body_req == {"tool": "binary_read", "arguments": expected_args}
          and row["body_observation"]["args"] == expected_args,
          "five_file_body", str(i) + " exact version-bound original range")
    content = base64.b64decode(body["data_base64"], validate=True)
    target = "actual/" + info["path"].rsplit("/", 1)[1]
    check(body["path"] == info["path"] and body["version"] == info["version"]
          and body["offset"] == 0 and body["next_offset"] == body["size"] == info["size"]
          and body["eof"] is True and len(content) == info["size"]
          and sha(content) == body["chunk_sha256"] == info["sha256"]
          and content == raw(target), "five_file_body", str(i) + " complete extraction / SHA / version / EOF")
    outputs.append({"index": i, "path": info["path"], "bytes": info["size"], "sha256": info["sha256"],
                    "version": info["version"], "full9_decimal": full9,
                    "info_operation_id": ops[info_label]["operation_id"],
                    "body_operation_id": ops[body_label]["operation_id"], "archive_path": target})
check(len(outputs) == 5 and sum(x["bytes"] for x in outputs) == 52030,
      "five_file_body", "five complete originals totaling 52030 bytes")

result = {
    "schema": "heptabao.compatibility-independent-LAN-prepare-original-chain-peer.v1",
    "status": "PASS_SCOPED_ORIGINAL_OBSERVATION_CHAINS",
    "source_tree": tree["sha"], "whole_files": 213, "whole_bytes": sum(x["size"] for x in leaves.values()),
    "unique_blobs": len({x["sha"] for x in leaves.values()}), "Merkle_nodes": len(computed),
    "checks_passed": sum(counts.values()), "checks_by_category": dict(counts),
    "original_prepare_job": job["id"], "request_digest": job["request_digest"],
    "request_fingerprint_decimal": str(job["request_fingerprint"]),
    "closed_original_observers": 13, "successful_observers": 12, "known_failed_observers": 1,
    "immutable_pages": 20, "observers": ops, "actual_file_outputs": outputs,
    "known_failed_payload_bytes": 183,
    "known_failed_payload_sha256": "5427c6345f5256d4b857421176675d1c1dda08db0504e937fbf95611ba90b67b",
    "single_recovery_GO": "aa0064627e0fce8d7b1d7f32b50a0056782ef1e5",
    "failure_preserved": True, "business_replay_observed_in_packet": False,
    "Runtime_calls": 0, "host_reads": 0, "candidate_execution": False,
    "author_68_verifier_executed": False, "prepared_contract_semantics_reviewed": False,
    "old_nine_source_AST_rechecked": False, "live_GO_issued": False,
    "limits": "Only the whole original Git packet, exact original prepare request/ACK/authority/streams, 13 observation chains and five byte extractions were independently checked. No proof of external intent temporal order beyond the preserved binding record is added. Prepared semantic admission, old source AST, product execution and live authorization remain with root."
}
out.write_text(json.dumps(result, sort_keys=True, indent=2) + "\n")
print(json.dumps({"status": result["status"], "checks_passed": result["checks_passed"],
                  "report_bytes": out.stat().st_size, "report_sha256": sha(out.read_bytes())}))
