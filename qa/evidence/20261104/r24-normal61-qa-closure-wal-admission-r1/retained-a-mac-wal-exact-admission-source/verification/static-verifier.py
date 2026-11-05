#!/usr/bin/env python3
"""Static data/AST verifier only; never import or execute any candidate module."""
import ast
import base64
import hashlib
import json
import re
import sys
from pathlib import Path

checks = []
def check(name, condition):
    if not condition:
        raise AssertionError(name)
    checks.append({"case": name, "passed": True})

def pin(raw):
    data = raw.encode("utf-8") if isinstance(raw, str) else raw
    return {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest(),
            "blob": hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()}

def strict_apply(before, diff):
    lines = before.splitlines(keepends=True)
    delta = diff.splitlines(keepends=True)
    out = []
    at = 0
    i = 0
    hunks = 0
    while i < len(delta):
        if not delta[i].startswith("@@ "):
            i += 1
            continue
        m = re.fullmatch(r"@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@[^\n]*\n", delta[i])
        if m is None:
            raise AssertionError("diff_header")
        start = int(m.group(1)) - 1
        old_count = int(m.group(2) or 1)
        new_count = int(m.group(4) or 1)
        if start < at:
            raise AssertionError("diff_order")
        out.extend(lines[at:start])
        at = start
        i += 1
        old_used = new_used = 0
        while i < len(delta) and not delta[i].startswith("@@ "):
            line = delta[i]
            if line.startswith(("--- ", "+++ ")):
                raise AssertionError("extra_diff_file")
            if line.startswith(" "):
                if at >= len(lines) or lines[at] != line[1:]:
                    raise AssertionError("diff_context")
                out.append(line[1:]); at += 1; old_used += 1; new_used += 1
            elif line.startswith("-"):
                if at >= len(lines) or lines[at] != line[1:]:
                    raise AssertionError("diff_removed")
                at += 1; old_used += 1
            elif line.startswith("+"):
                out.append(line[1:]); new_used += 1
            else:
                raise AssertionError("diff_line")
            i += 1
        if (old_used, new_used) != (old_count, new_count):
            raise AssertionError("diff_count")
        hunks += 1
    out.extend(lines[at:])
    return "".join(out), hunks

def defs(raw):
    lines = raw.splitlines(keepends=True)
    return {node.name: "".join(lines[(min([node.lineno]+[d.lineno for d in getattr(node,"decorator_list",[])])-1):node.end_lineno])
            for node in ast.parse(raw).body if isinstance(node, (ast.FunctionDef, ast.ClassDef))}

def literal_assignments(raw):
    result = {}
    for node in ast.parse(raw).body:
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    try: result[target.id] = ast.literal_eval(node.value)
                    except (ValueError, TypeError): pass
    return result

def arg_value(args, name):
    if args.count(name) != 1:
        raise AssertionError("exact_arg_count_"+name)
    return args[args.index(name)+1]

data = json.loads(Path(sys.argv[1]).read_text())
before = data["baselineCarrier"]
after = data["carrier"]
expected = data["expectedPins"]
check("source_only_no_host_permission", data["authorization"] == {"hostDispatch":False,"productionCutover":False,"sourceOnly":True})
check("baseline_carrier_blob", pin(before)["blob"] == data["baselineCarrierPin"]["blob"])
check("baseline_and_successor_carrier_lengths", len(before.encode()) == 15543 == len(after.encode()))
check("carrier_whole_pin", pin(after) == expected["carrier"])
check("diff_whole_pin", pin(data["diff"]) == expected["carrier_diff"])
rebuilt, hunks = strict_apply(before, data["diff"])
check("strict_seven_hunk_whole_reconstruction", rebuilt == after and hunks == 7)
transformed = before
for index, change in enumerate(data["transforms"]):
    check("one_exact_carrier_substitution_"+str(index), transformed.count(change["before"]) == 1)
    transformed = transformed.replace(change["before"], change["after"], 1)
check("eight_substitutions_whole", len(data["transforms"]) == 8 and transformed == after)
for change in reversed(data["transforms"]):
    check("one_exact_reverse_carrier_substitution_"+str(len(checks)), transformed.count(change["after"]) == 1)
    transformed = transformed.replace(change["after"], change["before"], 1)
check("reverse_whole_baseline", transformed == before)
old_defs, new_defs = defs(before), defs(after)
check("all_definition_names_same", list(old_defs) == list(new_defs))
for name in old_defs:
    if name != "main":
        check("unchanged_definition_"+name, old_defs[name] == new_defs[name])
main_back = new_defs["main"]
for new, old in (
    ("heptabao.mac-current-registry-wal-4e808-inert.r1","heptabao.mac-current-registry-wal-df026-inert.r1"),
    ("heptabao.mac-current-registry-wal-4e808-inert-public-inputs.r1","heptabao.mac-current-registry-wal-df026-inert-public-inputs.r1"),
    ("inert-registry-wal-4e808-result.public.json","inert-registry-wal-df026-result.public.json"),
):
    check("main_one_label_"+new, main_back.count(new) == 1)
    main_back = main_back.replace(new, old, 1)
check("main_body_exact_except_three_fixed_labels", main_back == old_defs["main"])
compile(ast.parse(after), "<new-inert-carrier>", "exec")
check("carrier_compile_only", True)

old_constants, constants = literal_assignments(before), literal_assignments(after)
check("anchor_pin_unchanged", constants["ANCHOR_SHA"] == old_constants["ANCHOR_SHA"] == "dd6dce82fb0276d7c0fd181152aef07bb2857e47506311f70ae67cce41b1eab8")
check("original_inert_45_seconds", "START=time.monotonic();UNTIL=START+45.0" in after and "START=time.monotonic();UNTIL=START+45.0" in before)
check("diskutil_30_clipped_unchanged", "until=min(UNTIL,time.monotonic()+30),maximum=262144" in new_defs["main"])
check("root_literal_exact_fresh_identity", "ROOT=Path("+repr(data["fixedRoot"])+")" in after)
check("no_old_root_literal", data["historicalRoot"] not in after)
request = json.loads(data["inertRequest"])
check("request_whole_pin", pin(data["inertRequest"]) == expected["request"])
check("request_exact_keys", set(request) == {"host","executable","args","cwd","stdin","timeout_seconds","idempotency_key"})
check("request_fixed_host_python_cwd_cap", {k:request[k] for k in ("host","executable","cwd","timeout_seconds")} == {"host":"mac","executable":"/opt/homebrew/bin/python3","cwd":"/Users/qianqi","timeout_seconds":60})
check("request_baseline_envelope_unchanged_except_key", all(request[k] == v for k,v in data["baselineEnvelope"].items() if k != "idempotency_key"))
check("request_exact_once_key", request["idempotency_key"] == "heptabao-mac-current-registry-wal-4e808-inert-9b9633f5-20261105-r1")
check("request_exact_carrier_argv", request["args"] == ["-I","-S","-B","-c",after])
payload_raw = request["stdin"]
check("stdin_whole_pin", pin(payload_raw) == expected["payload"])
check("stdin_carrier_length_sha", len(payload_raw.encode()) == constants["PAYLOAD_BYTES"] and pin(payload_raw)["sha256"] == constants["PAYLOAD_SHA"])
payload = json.loads(payload_raw)
check("payload_exact_keys_and_schema", set(payload) == {"schema","files","documents","anchorBase64"} and payload["schema"] == "heptabao.mac-current-registry-wal-4e808-inert-public-inputs.r1")
source_rows = {row["name"]:row for row in data["expectedSources"]}
check("twentytwo_sources_exact_names", len(source_rows) == 22 and set(source_rows) == set(constants["PINS"]) == set(payload["files"]))
for name, row in source_rows.items():
    raw = base64.b64decode(payload["files"][name], validate=True)
    check("whole_bound_source_"+name, pin(raw) == {k:row[k] for k in ("bytes","sha256","blob")} and constants["PINS"][name] == [len(raw), pin(raw)["sha256"]])
check("prospective_compile_18_python_4_js", sum(n.endswith(".py") for n in source_rows) == 18 and sum(n.endswith(".mjs") for n in source_rows) == 4)
check("public_documents_exact_eight", len(data["expectedDocuments"]) == 8 and set(data["expectedDocuments"]) == set(constants["DOCUMENT_PINS"]) == set(payload["documents"]))
for name, raw in data["expectedDocuments"].items():
    decoded = base64.b64decode(payload["documents"][name], validate=True)
    check("exact_public_document_"+name, decoded == raw.encode() and constants["DOCUMENT_PINS"][name] == [len(decoded), pin(decoded)["sha256"]])
    if name.startswith("proofs/"):
        check("historical_proof_carrier_pin_unchanged_"+name, constants["DOCUMENT_PINS"][name] == old_constants["DOCUMENT_PINS"][name])
anchor = base64.b64decode(payload["anchorBase64"], validate=True)
check("exact_anchor_raw_not_reserialized", anchor == data["anchorRaw"].encode() and len(anchor) == 967 and pin(anchor)["sha256"] == constants["ANCHOR_SHA"])
candidate_raw = data["expectedDocuments"]["candidate-current-manager-wal-r1.public.json"]
candidate = json.loads(candidate_raw)
old_candidate = json.loads(data["baselineCandidateRaw"])
check("candidate_whole_pin", pin(candidate_raw) == expected["candidate"])
check("candidate_current_commit_tree", candidate["sourceCommit"] == "4e808d0ecb1bcded22870a7ec960dfb2491cf6ec" and candidate["sourceTree"] == "eba5e650bd080b8ad41ea52a2bc68867f541d255")
source_pins = json.loads(data["sourcePinsRaw"])
check("source_pin_document_whole", pin(data["sourcePinsRaw"]) == expected["source_pins"])
check("candidate_sourcepins_exact_twentytwo", candidate["sourcePins"] == source_pins == {name:row["sha256"] for name,row in source_rows.items()})
check("candidate_original_budgets_unchanged", candidate["budgets"] == old_candidate["budgets"])
for key in ("syntheticBinding","nativeBinding","walBinding","publicVolumeAnchorSha256","utilityPins"):
    check("candidate_retains_"+key, candidate[key] == old_candidate[key])
check("separate_held_readback_fd_contract_preserved", "readbackUsesSeparateHeldFd" in new_defs["publish_public"] and new_defs["publish_public"] == old_defs["publish_public"])
check("two_enoent_freshroot_original_function", new_defs["fresh_root_absent"] == old_defs["fresh_root_absent"])
check("closure_and_postflush_original_body", "return 0 if report['ok'] and time.monotonic()<UNTIL else 1" in new_defs["main"] and main_back == old_defs["main"])
check("candidate_receipt_not_final_qualification_original", "candidateFileAloneIsNotQualification" in new_defs["main"] and "authoritativeExitZeroRequired" in new_defs["main"])
runtime = json.loads(data["runtimeRequest"])
old_runtime = json.loads(data["baselineRuntimeRequest"])
check("runtime_request_whole_pin", pin(data["runtimeRequest"]) == expected["runtime_request"])
check("runtime_same_request_keys", set(runtime) == set(old_runtime))
check("runtime_fixed_host_python_cwd_1080", {k:runtime[k] for k in ("host","executable","cwd","timeout_seconds")} == {"host":"mac","executable":"/opt/homebrew/bin/python3","cwd":"/Users/qianqi","timeout_seconds":1080})
check("runtime_exact_key", runtime["idempotency_key"] == "heptabao-mac-current-five-agent-registry-wal-4e808-bce47fd1-20261105-r1")
check("runtime_args_same_shape", len(runtime["args"]) == len(old_runtime["args"]) and runtime["args"][:3] == ["-I","-S","-B"])
check("runtime_exact_entry_path", runtime["args"][3] == data["fixedRoot"]+"/qa/mac_current_outer_wal_r1.py")
check("runtime_exact_candidate_path", arg_value(runtime["args"],"--candidate") == data["fixedRoot"]+"/candidate-current-manager-wal-r1.public.json")
check("runtime_candidate_sha_exact", arg_value(runtime["args"],"--candidate-sha256") == pin(candidate_raw)["sha256"])
check("runtime_sourcepins_base64_raw_exact", base64.b64decode(arg_value(runtime["args"],"--public-source-pins-base64"),validate=True) == data["sourcePinsRaw"].encode())
check("runtime_sourcepins_sha_exact", arg_value(runtime["args"],"--public-source-pins-sha256") == pin(data["sourcePinsRaw"])["sha256"])
check("runtime_anchor_base64_and_sha_unchanged", arg_value(runtime["args"],"--public-volume-anchor-base64") == arg_value(old_runtime["args"],"--public-volume-anchor-base64") == payload["anchorBase64"] and arg_value(runtime["args"],"--public-volume-anchor-sha256") == constants["ANCHOR_SHA"])
expected_runtime = dict(old_runtime)
expected_runtime["idempotency_key"] = runtime["idempotency_key"]
expected_runtime["args"] = list(old_runtime["args"])
for index, value in enumerate(expected_runtime["args"]):
    if isinstance(value,str):
        expected_runtime["args"][index] = value.replace(data["historicalRoot"],data["fixedRoot"])
for key in ("--candidate-sha256","--public-source-pins-base64","--public-source-pins-sha256"):
    expected_runtime["args"][expected_runtime["args"].index(key)+1] = arg_value(runtime["args"],key)
check("runtime_only_root_pins_key_changes", expected_runtime == runtime)
result = {
    "schema":"heptabao.mac-current-registry-wal-4e808-inert-static-result.r1",
    "ok":True,"checkCount":len(checks),"checks":checks,"strictHunks":hunks,
    "unchangedTopLevelDefinitions":list(n for n in old_defs if n != "main"),
    "mainChanges":"Three fixed schema/receipt strings only",
    "sourceCount":22,"publicDocumentCount":8,"historicalProofsUnchanged":7,
    "candidateModuleImports":0,"candidateFunctionExecutions":0,"compiledCarrierCount":1,
    "candidatePythonSourcesRecompiled":0,"actualHostCalls":0,
    "actualSqliteConnections":0,"actualSockets":0,"actualChildProcesses":0,
    "runtimePermissionGranted":False,"inertRequestSubmitted":False,
    "input":pin(Path(sys.argv[1]).read_bytes()),
    "carrier":pin(after),"payload":pin(payload_raw),
    "inertRequest":pin(data["inertRequest"]),"runtimeRequest":pin(data["runtimeRequest"])
}
sys.stdout.write(json.dumps(result,sort_keys=True,separators=(",",":"))+"\n")
