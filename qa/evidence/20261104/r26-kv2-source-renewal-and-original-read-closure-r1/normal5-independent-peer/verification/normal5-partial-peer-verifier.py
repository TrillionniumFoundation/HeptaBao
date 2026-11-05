import ast, base64, hashlib, json, stat
from pathlib import Path

ROOT = "ed0b6e2fe0f4b8e5be3c17833adefe49ef9bc736"
ADMITTED = "1c48f9519ce6d13dbe2f4484db279102c9e33676"
WORK = Path("/workspace/scratch/f86faac821c4")
data = json.loads((WORK / "normal5_peer_input.json").read_text())
admitted = json.loads((WORK / "normal5_peer_admitted_tree.json").read_text())
texts = data["files"]
raws = {p: s.encode("utf-8") for p, s in texts.items()}
checks = []
def ck(name, ok):
    checks.append({"name": name, "passed": bool(ok)})
    if not ok:
        raise AssertionError(name)
def sha(raw):
    return hashlib.sha256(raw).hexdigest()
def oid(kind, raw):
    return hashlib.sha1(kind.encode() + b" " + str(len(raw)).encode() + b"\0" + raw).hexdigest()
def j(path):
    return json.loads(texts[path])
def native(path):
    sdk = j(path)
    ck("sdk_not_error:" + path, sdk.get("isError") is False)
    ts = [x["text"] for x in sdk["content"] if x["type"] == "text"]
    ck("single_native_text:" + path, len(ts) == 1)
    return ts[0]
def tree_proof(t, expected):
    ck("tree_exact:" + expected, t["sha"] == expected and t["truncated"] is False)
    entries = {x["path"]: x for x in t["tree"]}
    ck("tree_unique:" + expected, len(entries) == len(t["tree"]))
    dirs = [""] + [p for p, e in entries.items() if e["type"] == "tree"]
    for directory in dirs:
        children = []
        for p, e in entries.items():
            par, sep, name = p.rpartition("/")
            if par == directory:
                children.append((name, e))
        children.sort(key=lambda pair: (pair[0] + ("/" if pair[1]["type"] == "tree" else "")).encode())
        body = b"".join(
            (("40000" if e["type"] == "tree" else e["mode"]) + " " + name).encode()
            + b"\0" + bytes.fromhex(e["sha"]) for name, e in children
        )
        want = expected if directory == "" else entries[directory]["sha"]
        ck("merkle:" + expected + ":" + (directory or "/"), oid("tree", body) == want)
    return entries, len(dirs)
entries, merkle_count = tree_proof(data["tree"], ROOT)
ck("actual_leaf_set", set(texts) == {p for p,e in entries.items() if e["type"] == "blob"})
for p, raw in raws.items():
    e = entries[p]
    ck("whole_blob:" + p, e["mode"] == "100644" and len(raw) == e["size"] and oid("blob", raw) == e["sha"])
manifest = j("manifest.public.json")
ck("manifest_schema", manifest["schema"] == "heptabao.whole-packet-manifest.v1")
rows = {r["path"]: r for r in manifest["files"]}
ck("manifest_complete28", len(rows) == len(manifest["files"]) == 28 and set(rows) == set(texts) - {"manifest.public.json"})
for p,r in rows.items():
    ck("manifest_whole:" + p, r["bytes"] == len(raws[p]) and r["sha256"] == sha(raws[p]) and r["git_blob_sha"] == oid("blob", raws[p]))
members, admitted_merkle_count = tree_proof(admitted, ADMITTED)

request_path = "dispatch/exact-request.json"
request = j(request_path)
ck("duplicate_request_exact", raws[request_path] == raws["submission/dispatch/exact-request.json"])
ck("request_admitted_membership", members["dispatch/inert.request.json"]["sha"] == oid("blob", raws[request_path]))
ck("request_contract", set(request) == {"host","executable","args","cwd","stdin","timeout_seconds","idempotency_key"}
   and request["host"] == "desktop" and request["executable"] == "/usr/bin/python3"
   and request["cwd"] == "/home/qian-qi/heptabao-ha-closure-20261103-r1"
   and request["timeout_seconds"] == 60 and len(request["args"]) == 5
   and request["args"][:4] == ["-I","-S","-B","-c"]
   and request["idempotency_key"] == "heptabao-4e808-normal5-controls-inert-r1-895d6cc9")
go = j("admission/root-go.public.json")
intent = j("intent.public.json")
for name,obj in [("go",go["request"]),("intent",intent)]:
    ck(name + "_request_whole", obj.get("blob", obj.get("request_blob")) == oid("blob", raws[request_path])
       and obj.get("sha256",obj.get("request_sha256")) == sha(raws[request_path]))
ck("go_request_length_mode_path", go["request"]["bytes"] == len(raws[request_path])
   and go["request"]["mode"] == "100644" and members[go["request"]["path"]]["sha"] == oid("blob", raws[request_path]))
ck("go_intent_scope", go["sourceTree"] == intent["source_tree"] == ADMITTED
   and intent["root_go_blob"] == oid("blob",raws["admission/root-go.public.json"])
   and intent["host"] == request["host"] and intent["idempotency_key"] == request["idempotency_key"]
   and intent["outer_seconds"] == request["timeout_seconds"]
   and intent["intent_state"] == "RECORDED_BEFORE_SUBMISSION" and intent["submit_once"] is True
   and intent["unknown_requires_reconciliation_not_replay"] is True)
for key in ["host","executable","cwd","idempotency_key","timeout_seconds"]:
    ck("go_exact_request_" + key, go["request"][key] == request[key])
ck("no_transport_go", go["decision"] == "GO_ONE_EXACT_INERT_PROCESS_START"
   and go["futureRelay"]["notAuthorized"] is True
   and go["scope"]["transport"] is False and go["scope"]["productExecution"] is False
   and intent["transport"] is False and intent["product_execution"] is False)

ackraw = native("submission/sdk/ack.original.json")
ck("ack_original_byte_identity", ackraw.encode() == raws["public/ack.original.json"])
ack = json.loads(ackraw)
job = ack["job"]
JOB = "1a1abd1f635-fc05-50c9"
ck("ack_single_launch", job["id"] == JOB and job["launch_state"] == "launched"
   and job["launch_error"] is None and ack["reused"] is False and ack["audit_recorded"] is True
   and ack["launch"]["ok"] is True and ack["local_record_pending"] is False)
for key in ["host","executable","args","cwd","idempotency_key"]:
    ck("ack_exact_request_" + key, job[key] == request[key])
ck("ack_env_scope", job["env_keys"] == [] and job["execution_mode"] == "operator")
authorityraw = native("sdk/authority/original-sdk.json")
ck("authority_original_byte_identity", authorityraw.encode() == raws["public/authority.original.json"])
auth = json.loads(authorityraw)
ck("authority_request", j("sdk/authority/request.json") == {"host":"desktop","job_id":JOB})
ck("authority_terminal", auth["job_id"] == JOB and auth["state"] == "succeeded" and auth["exit_code"] == 0
   and auth["output_complete"] is True and auth["output_durable"] is True
   and auth["terminal_publication_confirmed"] is True and auth["timed_out"] is False
   and auth["cancelled"] is False and auth["automatic_retry"] is False)
streams = json.loads(native("sdk/streams/original-sdk.json"))
ck("streams_request", j("sdk/streams/request.json") == {"host":"desktop","job_id":JOB,"stdout_offset":0,"stderr_offset":0,"limit":16384})
ck("streams_job", streams["job_id"] == JOB and streams["audit_recorded"] is True)
for stream,n in [("stdout",1520),("stderr",0)]:
    raw = raws["public/" + stream + ".original.txt"]
    row = streams[stream]
    ck("stream_whole_" + stream, raw == bytes.fromhex(row["bytes_hex"]) == row["text"].encode()
       and row["offset"] == 0 and row["next_offset"] == row["size"] == len(raw) == n
       and row["eof"] is True)
    ck("stream_authority_" + stream, auth["log_bytes"][stream] == {"seen":n,"stored":n}
       and auth["log_synced"][stream] is True and auth["log_errors"][stream] is None
       and auth["log_truncated"][stream] is False)
terminal = j("public/stdout.original.txt")
code = request["args"][4]
ck("inert_admitted_member", oid("blob", code.encode()) == members["candidate/inert-carrier.py"]["sha"])
module = ast.parse(code)
pins = None
for node in module.body:
    if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == "PINS" for t in node.targets):
        pins = ast.literal_eval(node.value)
calls = [n.func.id for n in ast.walk(module) if isinstance(n,ast.Call) and isinstance(n.func,ast.Name)]
ck("compile_only_not_exec_eval", calls.count("compile") == 1 and "exec" not in calls and "eval" not in calls)
ck("compile_precedes_mkdir", code.index("compile(raw, name, 'exec')") < code.index("BASE.mkdir(mode=0o700)"))
ck("no_child_import", not any(isinstance(n,ast.Import) and any(a.name in ("subprocess","socket") for a in n.names) for n in ast.walk(module)))
BASE = "/home/qian-qi/heptabao-ha-closure-20261103-r1/normal-same-root-publication-shared-artifact-controls-r1"
ck("source_scope_matches_go", go["scope"]["createOnlyDirectory"] == BASE
   and "BASE = PARENT / 'normal-same-root-publication-shared-artifact-controls-r1'" in code
   and "assert not os.path.lexists(BASE)" in code and "sys.stdin.buffer.read(262145)" in code)
ck("terminal_schema_status", terminal["schema"] == "heptabao.4e808-shared-normal5-inert-carrier.v1"
   and terminal["status"] == "prepared" and "error_type" not in terminal)
for k in ("source_executed","git_started","compiler_started","service_started","artifact_transfer_started"):
    ck("terminal_false_" + k, terminal[k] is False)
ck("terminal_compile_flag", terminal["python_compile_only"] is True)
elapsed = terminal["terminal_ns"] - terminal["started_ns"]
ck("terminal_exact_recorded_interval", elapsed == 72037986 and 0 < elapsed < 60_000_000_000)
ck("authority_after_terminal", auth["at_unix_ms"] * 1_000_000 >= terminal["terminal_ns"])
carrierraw = request["stdin"].encode()
carrier = json.loads(carrierraw)
ck("carrier_whole_admitted_member", oid("blob",carrierraw) == members["dispatch/inert.stdin.json"]["sha"])
ck("carrier_terminal_pin", terminal["stdin_bytes"] == len(carrierraw) == 44751
   and terminal["stdin_sha256"] == sha(carrierraw))
ck("carrier_schema_keys", set(carrier) == {"schema","files"} and carrier["schema"] == "heptabao.4e808-shared-normal5-inputs.v1")
names = ["sender.py","receiver.py","relay.py"]
ck("source_order_exact", list(pins) == names and set(carrier["files"]) == set(names)
   and [x["path"] for x in terminal["files"]] == [BASE + "/" + n for n in names])
for i,name in enumerate(names):
    raw = raws["sources/admitted/" + name]
    row = terminal["files"][i]
    ck("source_identity:" + name, base64.b64decode(carrier["files"][name], validate=True) == raw
       and pins[name] == [len(raw),sha(raw)] and row["bytes"] == len(raw)
       and row["sha256"] == sha(raw)
       and oid("blob",raw) == members["candidate/"+name]["sha"])
    ident = row["identity"]
    ck("reported_full9:" + name, len(ident) == 9 and all(type(v) is int for v in ident)
       and ident[2:6] == [1000,1000,stat.S_IFREG|0o600,1] and ident[6] == len(raw)
       and row["mode"] == "0600" and row["publication"] == "created")
prefix = "observations/observe_info0/"
info_request = j(prefix+"start/request.json")
ck("info0_exact_scope", info_request == {
 "idempotency_key":"ha-4e808-normal5-inert-info0-observation-r1-20261105",
 "operation":{"tool":"file_info","arguments":{"host":"desktop","path":BASE+"/sender.py"}}})
admission = json.loads(native(prefix+"start/original-sdk.json"))
status = json.loads(native(prefix+"status0/original-sdk.json"))
page = json.loads(native(prefix+"result0/original-sdk.json"))
OP = "3a2554cd41d2692bbbfdc260738ac8864fe70e83969531ab5d165a60f7b702bc"
ck("info0_same_id", admission["operation_id"] == status["operation_id"] == page["operation_id"] == OP)
ck("info0_queries_exact", j(prefix+"status0/request.json") == {"operation_id":OP}
   and j(prefix+"result0/request.json") == {"operation_id":OP,"offset":0,"limit":8192})
ck("info0_closed", status["async_state"] == "completed" and status["result_state"] == "stored_observed"
   and status["owned_future_active"] is False and status["payload_available"] is True
   and status["tool_name"] == admission["tool_name"] == "file_info")
payloadraw = base64.b64decode(page["data_base64"],validate=True)
ck("info0_immutable_page", page["immutable_snapshot"] is True and page["eof"] is True
   and page["offset"] == 0 and page["next_offset"] == page["total_bytes"] == len(payloadraw) == 613
   and page["result_sha256"] == sha(payloadraw)
   and payloadraw == raws[prefix+"payload.original.json"])
payload = json.loads(payloadraw)
ck("info0_complete_native", payload["resultType"] == "complete" and payload["isError"] is False
   and len(payload["content"]) == 1 and payload["content"][0]["type"] == "text"
   and payload["content"][0]["text"].encode() == raws[prefix+"native.original.json"])
info = j(prefix+"native.original.json")
ident = terminal["files"][0]["identity"]
ver = [int(s) for s in info["version"].split(":")]
meta = info["metadata"]
observed9 = [ver[0],ver[1],meta["uid"],meta["gid"],stat.S_IFREG|meta["mode"],meta["link_count"],ver[2],ver[3],ver[4]]
ck("info0_lossless_full9", observed9 == ident)
ck("info0_whole_binding", info["path"] == BASE+"/sender.py" and info["size"] == ident[6]
   and info["sha256"] == sha(raws["sources/admitted/sender.py"]) and info["mode"] == meta["mode"] == 0o600
   and meta["metadata_platform"] == "linux" and meta["link_count"] == 1)
assessment = j("assessment.public.json")
pending = j("pending/fixed-readback-plan.public.json")
ck("assessment_partial", assessment["job_id"] == JOB and assessment["independent_infos_completed"] == 1
   and assessment["independent_bodies_completed"] == 0 and assessment["all_independent_readbacks_complete"] is False
   and assessment["relay_go"] is False and assessment["relay_submitted"] is False
   and assessment["lan_inert_separately_authorized_but_not_submitted"] is True
   and assessment["product_or_lan_runtime_qualification"] is False and assessment["explicit_fd_ledger_present"] is False)
expected_paths = [BASE+"/"+n for n in names+["inert-stage.result.public.json"]]
ck("pending_exact_three_infos_four_bodies", assessment["remaining_infos_not_submitted"] == expected_paths[1:]
   and assessment["remaining_whole_bodies_not_submitted"] == expected_paths
   and [p["path"] for p in pending] == expected_paths)
for i in range(3):
    ck("pending_reported_full9:" + str(i), [int(v) for v in pending[i]["identity"]] == terminal["files"][i]["identity"]
       and pending[i]["bytes"] == terminal["files"][i]["bytes"] and pending[i]["sha256"] == terminal["files"][i]["sha256"])
ck("pending_receipt_unbound", all(pending[3][k] is None for k in ("bytes","sha256","identity")))
ck("only_info0_observation_in_packet", {p.split("/")[1] for p in texts if p.startswith("observations/")} == {"observe_info0"})
ck("exact_one_ack_file", [p for p in texts if p.startswith("submission/sdk/")] == ["submission/sdk/ack.original.json"])
result = {
 "schema":"heptabao.compat-peer.normal5-partial-offline-verification.v1",
 "input_tree":ROOT, "admitted_source_tree":ADMITTED,
 "status":"PASS_LIMITED_PARTIAL_EVIDENCE", "checks":len(checks),
 "files":len(raws), "bytes":sum(map(len,raws.values())), "merkle_directories":merkle_count,
 "admitted_membership_merkle_directories":admitted_merkle_count,
 "job_id":JOB, "authority_exit_code":auth["exit_code"],
 "stdout_bytes":1520, "stderr_bytes":0, "reported_interval_ns":str(elapsed),
 "info0_operation_id":OP, "info0_original_payload_bytes":len(payloadraw),
 "limits":{"other_infos_submitted":False,"body_reads_submitted":False,
 "relay_go":False,"relay_submitted":False,"lan_submitted":False,"host_or_runtime_calls_by_verifier":0,
 "candidate_module_executed":False,"per_fd_ledger_supplied":False,
 "intent_order_independently_timestamp_proved":False},
 "checks_passed":checks
}
(WORK/"normal5_peer_verification_result.json").write_text(json.dumps(result,indent=2,sort_keys=True)+"\n")
print(json.dumps({k:v for k,v in result.items() if k!="checks_passed"},sort_keys=True))
