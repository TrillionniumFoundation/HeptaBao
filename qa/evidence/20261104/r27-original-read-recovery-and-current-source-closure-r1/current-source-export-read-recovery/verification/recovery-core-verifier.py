import base64, hashlib, json, stat
from pathlib import Path
W=Path("/workspace/scratch/f86faac821c4")
i=json.loads((W/"source4e808_export_recovery_input.json").read_text())
checks=[]
def ck(n,v):
 checks.append({"name":n,"passed":bool(v)})
 if not v: raise AssertionError(n)
def sha(b):return hashlib.sha256(b).hexdigest()
def j(k):return json.loads(i[k])
OP="79cdbefb4f02efdf3493dba6fe6afa05ae7ef665783011af06a6b333e99bb9a2"
JOB="1a1abe371de-fc05-5122"
COMMIT="4e808d0ecb1bcded22870a7ec960dfb2491cf6ec"
TREE="eba5e650bd080b8ad41ea52a2bc68867f541d255"
SOURCE="/home/qian-qi/heptabao-same-root-publication-normal-20261105-r2/source"
ROOT="/home/qian-qi/heptabao-same-root-publication-source-export-20261105-r1"
BUNDLE=ROOT+"/canonical-4e808-full.bundle"
request=j("original_binary_read_request"); admission=j("original_admission"); status=j("later_status")
ck("original_one_binary_read_admission",admission["operation_id"]==OP and admission["tool_name"]=="binary_read" and admission["reused"] is False)
ck("later_same_id_closed",status["operation_id"]==OP and status["async_state"]=="completed" and status["result_state"]=="stored_observed" and status["owned_future_active"] is False and status["payload_available"] is True)
parts=[];offset=0; total=None;digest=None
for n,p in enumerate(i["pages"]):
 ck("page_request_"+str(n),p["request"]=={"operation_id":OP,"offset":offset,"limit":16384})
 sdk=json.loads(p["sdk_raw"])
 ck("page_sdk_"+str(n),sdk["isError"] is False and len(sdk["content"])==1 and sdk["content"][0]["text"]==p["raw"])
 v=json.loads(p["raw"]); b=base64.b64decode(v["data_base64"],validate=True)
 if total is None:total=v["total_bytes"];digest=v["result_sha256"]
 ck("page_range_"+str(n),v["operation_id"]==OP and v["offset"]==offset and v["next_offset"]==offset+len(b) and v["immutable_snapshot"] is True and v["eof"]==(v["next_offset"]==total) and v["total_bytes"]==total and v["result_sha256"]==digest and len(b)<=16384)
 parts.append(b);offset=v["next_offset"]
raw=b"".join(parts)
ck("original_payload_whole",len(parts)==4 and len(raw)==total==offset==53354 and sha(raw)==digest=="b47aa85056850f65d1f457b8a206b5b2444f460baa25d8839866cc8b8227af99" and raw==i["payload_raw"].encode())
p=json.loads(raw);native=j("native_raw");body=i["body_raw"].encode();info=j("result_info")
ck("payload_native_exact",p["resultType"]=="complete" and p["isError"] is False and len(p["content"])==1 and p["content"][0]["text"]==i["native_raw"])
ck("body_decoded_exact",base64.b64decode(native["data_base64"],validate=True)==body and len(body)==39692 and sha(body)=="47feb984dbda306b523071e09107ecade8bda10e712d74e5116a58d164eb027b")
args=request["operation"]["arguments"]
ck("original_version_pinned_request",request["operation"]["tool"]=="binary_read" and args=={"host":"rog","path":ROOT+"/result.public.json","expected_version":"66306:28091501:39692:1793885177751063403:1793885177751063403","offset":0,"limit":65536})
ck("body_info_request_native_exact",native["path"]==info["path"]==args["path"] and native["version"]==info["version"]==args["expected_version"] and native["size"]==info["size"]==len(body) and native["chunk_sha256"]==info["sha256"]==sha(body) and native["offset"]==0 and native["next_offset"]==len(body) and native["eof"] is True)
x=json.loads(body);auth=j("authority");terminal=j("stdout");ack=j("original_ack");orig=j("original_request")
ck("unique_job_binding",ack["job"]["id"]==auth["job_id"]==JOB and ack["job"]["host"]==orig["host"]=="rog" and ack["job"]["args"]==orig["args"] and ack["job"]["cwd"]==orig["cwd"] and ack["job"]["idempotency_key"]==orig["idempotency_key"] and ack["reused"] is False)
ck("authority_success_complete",auth["state"]=="succeeded" and auth["exit_code"]==0 and auth["output_complete"] is True and auth["output_durable"] is True and auth["terminal_publication_confirmed"] is True and auth["timed_out"] is False and auth["cancelled"] is False)
for name in ("stdout","stderr"):
 b=i[name].encode();ck("authority_stream_"+name,auth["log_bytes"][name]=={"seen":len(b),"stored":len(b)} and auth["log_errors"][name] is None and auth["log_truncated"][name] is False and auth["log_synced"][name] is True)
ck("original_terminal",len(i["stdout"].encode())==534 and i["stderr"]=="" and terminal["status"]=="exported" and terminal["all_owned_stopped"] is True and terminal["publication_within_original_deadline"] is True and terminal["elapsed_after_publication_seconds"]<300)
ck("core_scope",x["schema"]=="heptabao.same-root-publication.rog-4e808-standalone-source-export.v1" and x["action"]=="export-standalone-same-root-publication-4e808" and x["status"]=="exported" and x["canonical_commit"]==COMMIT and x["canonical_tree"]==TREE and x["source"]==SOURCE)
ck("original_caps",orig["timeout_seconds"]==330 and x["overall_seconds"]==300 and x["git_command_seconds"]==90 and x["maximum_bundle_bytes"]==67108864 and x["elapsed_seconds"]<300 and x["deadline_before_receipt_passed"] is True)
for key in ("compiler_started","network_git_protocols_enabled","runtime_qualification","server_started","source_imported"):
 ck("core_false_"+key,x[key] is False)
ck("zero_product_tests",x["product_tests_executed"]==0)
ck("source_before_after_exact",x["source_before"]==x["source_after"])
s=x["source_before"]
ck("source_expected_guards",s["head"]==COMMIT and s["tree"]==TREE and s["clean"] is True and s["shallow"] is False and s["independent_git_directory"] is True and s["git_directory"]==s["git_common_directory"]==SOURCE+"/.git" and s["no_alternates"] is True and s["no_grafts"] is True and s["no_partial_clone"] is True and all(v is False for v in s["lock_files"].values()))
ck("canonical_history_full",x["canonical_proof"]=={"commit":COMMIT,"commit_count":3763,"full_fsck_passed":True,"parents":["1c66541993662f92cf717154e33717abedb2ea74"],"root":"67d79b3b5442ed033d38929eab2010403463e56d","tree":TREE} and x["expected_full_commit_count"]==3763 and x["expected_prerequisites"]==[])
ck("controller_actual_inert_identity",x["controller"]=={"bytes":15364,"sha256":"9af6738da8526ad5a0dcd6402bf4693f652a4f428eb4b22d0914761292f66d20","identity":[66306,28087373,1000,1000,33152,1,15364,1793882425581272263,1793882425582375779]})
before=[
 ("head",["rev-parse","--verify","HEAD"]),("tree",["rev-parse","HEAD^{tree}"]),
 ("status",["status","--porcelain=v1","--untracked-files=all"]),
 ("git-dir",["rev-parse","--absolute-git-dir"]),("common-dir",["rev-parse","--git-common-dir"]),
 ("shallow",["rev-parse","--is-shallow-repository"]),
 ("partial-config",["config","--local","--get-regexp","^(extensions[.]partialclone|remote[.].*[.]promisor|remote[.].*[.]partialclonefilter)$"]),
 ("origin",["config","--local","--get","remote.origin.url"]),
 ("refs",["for-each-ref","--format=%(refname) %(objectname)"])]
middle=[
 ("export-proof-kind",["cat-file","-t",COMMIT]),
 ("export-proof-tree",["rev-parse",COMMIT+"^{tree}"]),
 ("export-proof-parents",["show","-s","--format=%P",COMMIT]),
 ("export-proof-count",["rev-list","--count",COMMIT]),
 ("export-proof-roots",["rev-list","--max-parents=0",COMMIT]),
 ("export-proof-full-fsck",["fsck","--full","--strict","--no-reflogs","--no-dangling",COMMIT]),
 ("bundle-create",["bundle","create","--version=2",BUNDLE,"HEAD"]),
 ("bundle-verify",["bundle","verify",BUNDLE]),
 ("bundle-heads",["bundle","list-heads",BUNDLE])]
spec=[("source-before-"+n,a) for n,a in before]+middle+[("source-after-"+n,a) for n,a in before]
prefix=["/usr/bin/git","-c","gc.auto=0","-c","maintenance.auto=false","-c","core.hooksPath="+ROOT+"/empty-hooks","-c","core.fsmonitor=false","-c","log.showSignature=false","-c","protocol.allow=never","-c","protocol.file.allow=always","-c","pack.threads=1","-C",SOURCE]
commands=x["commands"];cleanup=x["cleanup"]
ck("commands_cleanup_unique27",len(commands)==len(cleanup)==27 and len({c["label"] for c in commands})==27 and len({c["pid"] for c in commands})==27 and len({c["label"] for c in cleanup})==27)
cm={c["label"]:c for c in cleanup}
for n,(command,(name,suffix)) in enumerate(zip(commands,spec)):
 label=f"{n:03d}-"+name
 expected_exit=1 if name.endswith("partial-config") else 0
 ck("command_exact_"+label,command["label"]==label and command["argv"]==prefix+suffix and command["exit_code"]==expected_exit and command["direct_child_reaped"] is True and command["remaining"]==[] and command["timed_out"] is False and 0<command["elapsed_seconds"]<command["limit_seconds"]<=90)
 c=cm[label]
 ck("cleanup_exact_"+label,c=={"direct_child_reaped":True,"exit_code":expected_exit,"label":label,"pid":command["pid"],"remaining":[]})
ck("all_owned_stopped",x["all_owned_stopped"] is True)
bundle=x["bundle"];ident=bundle["identity"]
ck("reported_bundle_full_identity",bundle["path"]==BUNDLE and bundle["bytes"]==22320862 and bundle["sha256"]=="bb014971cb243db71e07d04b862fbba2436ceec09d2c1bafa707e4aa558bf5ac" and ident==[66306,28091464,1000,1000,33152,1,22320862,1793885177495300186,1793885177498300179] and bundle["bytes"]<x["maximum_bundle_bytes"])
ck("reported_bundle_header",bundle["header"]=={"header_bytes":63,"header_sha256":"c86b1deb14c31b2f2e89a53afbb2be28ea8e1fd0b8dbc5e4677710d134ae9aa5","heads":[[COMMIT,"HEAD"]],"prerequisites":[],"version":2})
result={"schema":"heptabao.4e808-export-original-read-recovery-offline-checks.v1","status":"PASS_ORIGINAL_READ_RECOVERY_CORE_ONLY","checks":len(checks),"same_operation_id":OP,"whole_original_sdk_bytes":53354,"body_bytes":len(body),"body_sha256":sha(body),"command_count":len(commands),"owned_closed":len(cleanup),"source_before_equals_after":True,"bundle_reported_only":{"bytes":bundle["bytes"],"sha256":bundle["sha256"],"version":":".join(str(ident[n]) for n in (0,1,6,7,8))},"independent_bundle_info_submitted":False,"separate_command_log_reads_submitted":0,"explicit_per_fd_ledger_present":False,"historical_query_errors_preserved":True,"new_binary_read_or_exporter_submitted":False,"host_or_runtime_calls_by_verifier":0,"checks_passed":checks}
(W/"source4e808_export_recovery_verification.json").write_text(json.dumps(result,indent=2,sort_keys=True)+"\n")
print(json.dumps({k:v for k,v in result.items() if k!="checks_passed"},sort_keys=True))
