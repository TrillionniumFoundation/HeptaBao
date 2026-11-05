#!/usr/bin/env python3
"""Offline byte/identity verification of the single df026 H2 QA inert job."""
import argparse, base64, hashlib, json, stat
from pathlib import Path

p=argparse.ArgumentParser()
p.add_argument("--input",required=True)
p.add_argument("--output",required=True)
args=p.parse_args()
data=json.loads(Path(args.input).read_text())
files=data["files"]
checks=[]
def check(name,condition,details=None):
    checks.append({"name":name,"passed":bool(condition),**({"details":details} if details is not None else {})})
    if not condition:
        raise AssertionError(name)
def sha(raw):
    return hashlib.sha256(raw).hexdigest()
def raw(path):
    return files[path].encode()
def obj(path):
    return json.loads(files[path])
job="1a1aa7c3dff-fc05-439c"
base="/home/qian-qi/heptabao-native-h2-qa-controls-df026-20261105-r1"
req=obj("request/inert.exact.json")
check("exact_dispatch_whole",len(raw("request/inert.exact.json"))==376962 and sha(raw("request/inert.exact.json"))=="1a6e7dcf2ddb22f498a4c2cd31690db72548e4b318b9843c8ec6b4d69f76f7a1")
check("exact_dispatch_fields",req["host"]=="rog" and req["executable"]=="/usr/bin/python3" and req["cwd"]=="/home/qian-qi" and req["args"][:4]==["-I","-S","-B","-c"] and len(req["args"])==5 and req["timeout_seconds"]==60 and req["idempotency_key"]=="heptabao-df026-native-h2-qa-inert-cf7460ca-20261105-r1")
check("publisher_bytes",len(req["args"][4].encode())==6097 and sha(req["args"][4].encode())=="cf7460cad71ace000d61760c225da9cdac13236fe33f63212958fbefe4bbc345")
check("carrier_bytes",len(req["stdin"].encode())==370359 and sha(req["stdin"].encode())=="1cb477330f0bc9dcbaeadb5873e86cfac67c51c69ab20f5be594a81496244901")
carrier=json.loads(req["stdin"])
expected={name:base64.b64decode(value,validate=True) for name,value in carrier["files"].items()}
check("fixed_eight_names",set(expected)=={"build_native_h2_client_r1.py","build-binding.private.json","inputs/native_h2_client.rs","inputs/native_h2_client_tests.rs","inputs/Cargo.toml","inputs/canonical.Cargo.lock","inputs/owned_reference_phaseb_r3.py","inputs/official_cli_reference_r4.py"})
ack=obj("actual/ack.original.json")
check("single_ack",ack["job"]["id"]==job and ack["reused"] is False and ack["launch"]["ok"] is True and ack["job"]["launch_state"]=="launched")
check("ack_exact_invocation",all(ack["job"][key]==req[key] for key in ["host","executable","args","cwd","idempotency_key"]) and ack["job"]["env_keys"]==[])
authority=obj("native/authority.original.json")
check("authority_success",authority["job_id"]==job and authority["state"]=="succeeded" and authority["exit_code"]==0 and not authority["timed_out"] and not authority["cancelled"])
check("authority_complete_durable",authority["output_complete"] and authority["output_durable"] and authority["terminal_publication_confirmed"] and not any(authority["log_truncated"].values()) and all(authority["log_synced"].values()) and all(x is None for x in authority["log_errors"].values()))
streams=obj("native/streams.original.json")
check("streams_job",streams["job_id"]==job)
for name in ["stdout","stderr"]:
    s=streams[name]
    bs=bytes.fromhex(s["bytes_hex"])
    check(name+"_lossless_hex_text",bs==s["text"].encode()==raw("streams/"+name+".original.txt"))
    check(name+"_complete",s["offset"]==0 and s["next_offset"]==len(bs)==s["size"] and s["eof"] is True and authority["log_bytes"][name]=={"seen":len(bs),"stored":len(bs)})
check("stderr_preserved_original_warnings",streams["stderr"]["text"]=="inputs/owned_reference_phaseb_r3.py:1088: SyntaxWarning: 'return' in a 'finally' block\ninputs/official_cli_reference_r4.py:915: SyntaxWarning: 'return' in a 'finally' block\n")
core=obj("actual-files/inert-stage.result.public.json")
check("core_and_stdout_equal_lossless",json.loads(streams["stdout"]["text"])==core)
check("inert_only_status",core["status"]=="prepared" and core["python_compile_only"] is True and all(core[k] is False for k in ["source_executed","git_started","compiler_started","service_started","artifact_transfer_started"]) and "error_type" not in core)
check("receipt_carrier_binding",core["stdin_bytes"]==370359 and core["stdin_sha256"]==sha(req["stdin"].encode()))
elapsed=core["terminal_ns"]-core["started_ns"]
check("reported_inert_interval_positive_under_outer",0<elapsed<60_000_000_000,{"elapsed_ns":elapsed,"scope":"source publication interval; actual authority also confirms outer not timed out"})
entries={x["path"]:x for x in core["files"]}
check("exact_eight_published",set(entries)=={base+"/"+n for n in expected} and len(core["files"])==8)
for name,bs in expected.items():
    path=base+"/"+name
    e=entries[path]
    check("published_"+name,e["publication"]=="created" and e["bytes"]==len(bs) and e["sha256"]==sha(bs) and e["mode"]=="0600")
    identity=e["identity"]
    check("identity_"+name,len(identity)==9 and identity[2:4]==[1000,1000] and stat.S_ISREG(identity[4]) and stat.S_IMODE(identity[4])==0o600 and identity[5]==1 and identity[6]==len(bs))
    check("whole_readback_"+name,raw("actual-files/"+name)==bs)
observed={}
for name in ["files-a","files-b"]:
    native=obj("native/"+name+".original.json")
    check(name+"_complete_batch",native["truncated"] is False and native["encoding"]=="utf-8")
    for f in native["files"]:
        check("file_record_"+f["path"].removeprefix(base+"/"),f["eof"] is True and f["size"]==len(f["text"].encode()) and f["sha256"]==sha(f["text"].encode()))
        check("raw_file_text_"+f["path"].removeprefix(base+"/"),files["actual-files/"+f["path"].removeprefix(base+"/")]==f["text"])
        observed[f["path"]]=f
chunks=[obj("native/lock-chunk-000000.original.json"),obj("native/lock-chunk-065536.original.json")]
lock_bytes=b""
for i,c in enumerate(chunks):
    b=base64.b64decode(c["data_base64"],validate=True)
    check("lock_chunk_"+str(i),c["offset"]==len(lock_bytes) and c["next_offset"]==len(lock_bytes)+len(b) and c["size"]==101193 and c["version"]==chunks[0]["version"] and c["path"]==base+"/inputs/canonical.Cargo.lock" and sha(b)==c["chunk_sha256"] and c["eof"]==(i==1))
    lock_bytes+=b
check("lock_reassembled_whole",lock_bytes==expected["inputs/canonical.Cargo.lock"])
lock_info=obj("native/lock-info.original.json")
check("lock_independent_file_info",lock_info["path"]==base+"/inputs/canonical.Cargo.lock" and lock_info["version"]==chunks[0]["version"] and lock_info["size"]==len(lock_bytes) and lock_info["sha256"]==sha(lock_bytes) and lock_info["mode"]==0o600 and lock_info["metadata"]["uid"]==1000 and lock_info["metadata"]["gid"]==1000 and lock_info["metadata"]["link_count"]==1)
observed[lock_info["path"]]=lock_info
for path,e in entries.items():
    v=[int(x) for x in observed[path]["version"].split(":")]
    identity=e["identity"]
    check("exact_version_"+path.removeprefix(base+"/"),v==[identity[x] for x in [0,1,6,7,8]])
labels=["authority","streams","files-a","files-b","lock-info","lock-chunk-000000","lock-chunk-065536"]
page_count=0
for label in labels:
    admission=obj("operations/"+label+"-admission.txt")
    state=obj("operations/"+label+"-status.txt")
    check(label+"_closed_read_operation",state["operation_id"]==admission["operation_id"] and state["async_state"]=="completed" and state["payload_available"] is True and state["owned_future_active"] is False)
    pages=[json.loads(v) for k,v in files.items() if k.startswith("immutable-pages/"+label+"-")]
    pages.sort(key=lambda x:x["offset"])
    collected=b""
    for page in pages:
        bs=base64.b64decode(page["data_base64"],validate=True)
        check(label+"_immutable_page_"+str(page["offset"]),page["operation_id"]==state["operation_id"] and page["offset"]==len(collected) and page["next_offset"]==len(collected)+len(bs) and page["immutable_snapshot"] is True and page["total_bytes"]==pages[0]["total_bytes"] and page["result_sha256"]==pages[0]["result_sha256"] and page["eof"]==(page["next_offset"]==page["total_bytes"]))
        collected+=bs
    check(label+"_sdk_whole",collected==raw("original-sdk/"+label+".json") and len(collected)==pages[0]["total_bytes"] and sha(collected)==pages[0]["result_sha256"])
    sdk=json.loads(collected)
    check(label+"_native_original",sdk.get("isError") is not True and len(sdk["content"])==1 and sdk["content"][0]["type"]=="text" and sdk["content"][0]["text"]==files["native/"+label+".original.json"])
    page_count+=len(pages)
check("original_authority_unknown_observation_retained",obj("operations/authority-admission.txt")["async_state"]=="unknown" and obj("operations/authority-admission.txt")["reused"] is True)
report={
 "schema":"heptabao.df026.h2-qa-inert-actual-offline-review.v1",
 "status":"PASS_INERT_ONLY",
 "job_id":job,"checks":checks,"checks_passed":len(checks),
 "inputs_published_and_whole_readback":8,"read_operations":len(labels),"immutable_pages":page_count,
 "inert_publication_elapsed_ns":elapsed,
 "stdout_bytes":len(raw("streams/stdout.original.txt")),"stderr_bytes":len(raw("streams/stderr.original.txt")),
 "warnings_preserved":2,"lossless_integer_json":True,
 "child_processes_started_by_publisher":0,
 "source_executed":False,"cargo_executed":False,"service_started":False,"qa_build_authorized_by_this_check":False,
 "limits":["Current target identity is not rechecked by this inert step. The separately gated builder must perform its existing check.","This checker only analyzes retained original bytes and does not import or execute any candidate source.","The source publication result does not qualify Rust compilation, receiver components, real TLS/H2, native archive semantics or official CLI behavior."]
}
Path(args.output).write_text(json.dumps(report,indent=2,sort_keys=True)+"\n")
print(json.dumps({"status":report["status"],"checks_passed":len(checks),"immutable_pages":page_count,"read_operations":len(labels),"elapsed_ns":elapsed}))

