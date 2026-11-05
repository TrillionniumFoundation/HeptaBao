import hashlib,json,sys
p=json.loads(sys.argv[1]);a=json.loads(p["authority"]);c=json.loads(p["core"]);t=json.loads(p["terminal"])
checks=[]
def require(name,value):
    assert value,name
    checks.append(name)
require("authority exact job and successful durable terminal",a["job_id"]=="1a1a9579588-fc05-346f" and a["state"]=="succeeded" and a["exit_code"]==0 and a["output_complete"] and a["output_durable"] and a["terminal_publication_confirmed"] and not a["timed_out"] and not a["cancelled"])
require("terminal log exact byte count",a["log_bytes"]["stderr"]=={"seen":len(p["terminal"].encode()),"stored":len(p["terminal"].encode())} and a["log_bytes"]["stdout"]=={"seen":0,"stored":0})
require("no log loss",not any(a["log_truncated"].values()) and all(a["log_synced"].values()) and all(v is None for v in a["log_errors"].values()))
require("core exact controller",c["controller"]=={"bytes":33102,"sha256":"cdecc828fd13e6fe2509741515c23cab2913931b430ffb1823630975634bafc3"})
require("source import only",c["status"]=="complete" and c["source_imported"] and not c["server_started"] and not c["compiler_started"] and not c["runtime_qualification"] and not c["production_changed"] and not c["old_source_opened"] and not c["network_git_protocols_enabled"] and not c["input_transport_performed"] and c["product_tests_executed"]==0)
require("canonical full history exact",c["canonical_proof"]=={"commit":"3cb873919170cc77101b27f6a3ab9e98f41f8d93","tree":"7f4d48a647a81ca96e8a24a0a057c2c829459060","parents":["bf0aaec1dcafbf476c0ab3a75544bb0eafaeff24"],"root":"67d79b3b5442ed033d38929eab2010403463e56d","commit_count":3755,"full_fsck_passed":True})
require("original deadline and request caps",c["overall_seconds"]==300 and c["git_command_seconds"]==60 and c["clone_seconds"]==90 and c["within_original_deadline"] and 0<c["elapsed_seconds"]<300)
require("three inputs and exact before after integers",len(c["input_files_before"])==3 and c["input_files_before"]==c["input_files_after"] and c["input_sources_unchanged"] and c["raw_input_receipts_unchanged"] and c["export_receipt_verified"] and c["transport_receipt_verified"])
for expected,held in zip(p["inputs"],c["input_files_before"],strict=True):
    require("input pin "+expected["name"],all(held[k]==expected[k] for k in ("name","path","mode","version")) and held["same_fd_readback"]=={"bytes":expected["bytes"],"sha256":expected["sha256"]})
    x=held["identity"]
    require("input identity exact version "+expected["name"],x[2]==1000 and x[5]==1 and ":".join(map(str,(x[0],x[1],x[6],x[7],x[8])))==expected["version"])
m=c["materialized"]
require("3911 actual blob bytes and fsync",m["tracked_files"]==3911 and m["tree_equals_index"] and m["actual_git_blob_bytes_verified"] and m["no_sparse_checkout"] and m["no_symlinks_or_hardlinks"] and m["fsynced_files"]>=3911 and m["fsynced_directories"]>0)
s=c["source_after"]
require("independent clean canonical checkout",s["head"]==c["source_commit"] and s["tree"]==c["source_tree"] and s["clean"] and s["independent_git_directory"] and s["no_alternates"] and s["no_partial_clone"] and not s["shallow"] and not any(s["lock_files"].values()) and s["git_directory"]==s["git_common_directory"]=="/home/qian-qi/heptabao-ha-closure-20261103-r1/normal-phaseb-ingress-observer-source-r1/.git")
require("21 distinct owned commands",len(c["commands"])==len(c["cleanup"])==21 and len({r["pid"] for r in c["cleanup"]})==21)
for command,cleanup in zip(c["commands"],c["cleanup"],strict=True):
    require("owned "+command["label"],command["label"]==cleanup["label"] and command["pid"]==cleanup["pid"] and command["direct_child_reaped"] and cleanup["direct_child_reaped"] and not command["remaining"] and not cleanup["remaining"] and not command["timed_out"] and command["exit_code"]==cleanup["exit_code"] and command["exit_code"]==(1 if command["label"] in ("013-no-sparse-config","020-source-after-partial-config") else 0) and command["limit_seconds"]==(90 if command["label"]=="000-standalone-clone" else 60) and 0<command["elapsed_seconds"]<command["limit_seconds"])
require("all owned stopped",c["all_owned_stopped"])
require("all input and new-source descriptors closed",c["input_fd_closure"]=={"opened_files":3,"closed_files":3,"opened_directories":4,"closed_directories":4,"created_source_directory_opened":True,"created_source_directory_closed":True,"errors":[],"complete":True})
extra={"publication_within_original_deadline","receipt"}
require("terminal only publication extension",set(t)-set(c)==extra and set(c)-set(t)==set() and all(t[k]==v for k,v in c.items()) and t["publication_within_original_deadline"])
require("terminal receipt binds exact original core",t["receipt"]=={"path":"/home/qian-qi/heptabao-ha-closure-20261103-r1/normal-phaseb-ingress-observer-source-import-r1/control/result.public.json","bytes":len(p["core"].encode()),"sha256":hashlib.sha256(p["core"].encode()).hexdigest()})
print(json.dumps({"schema":"heptabao.phaseb3cb.source-import.actual-core-review.v1","status":"passed","checks":checks,"check_count":len(checks),"source_imported":True,"runtime_qualification":False,"all_owned_stopped":True,"input_fd_closure":c["input_fd_closure"],"elapsed_seconds":c["elapsed_seconds"],"original_deadline_seconds":300,"independent_child_raw_logs_reviewed":False,"pending_host_reads":0,"integer_preservation":"Python arbitrary-precision JSON, originals retained","source_commit":c["source_commit"],"source_tree":c["source_tree"]},indent=2,sort_keys=True))
