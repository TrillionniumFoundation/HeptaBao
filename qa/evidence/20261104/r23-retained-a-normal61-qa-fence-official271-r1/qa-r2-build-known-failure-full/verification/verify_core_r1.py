import hashlib,json
from pathlib import Path
p=Path(__file__).resolve().parent
i=json.loads((p/"verify-input.json").read_text())
r=json.loads(i["core"]); a=json.loads(i["authority"]); terminal=json.loads(i["terminal_stdout"])
checks=[]
def c(label,condition):
    assert condition,label
    checks.append(label)
sha=lambda x:hashlib.sha256(x).hexdigest()
c("core-whole-sha",sha(i["core"].encode())=="d19183df9ef0db22852c95d69ad2db4e8275c924b33481cc35d1cbab6cb073d9")
c("known-authority",a["job_id"]=="1a1aaf3772d-fc05-48f5" and a["exit_code"]==1 and a["state"]=="failed")
for k in ("output_complete","output_durable","terminal_publication_confirmed"): c("authority-"+k,a[k] is True)
c("not-supervisor-timeout",a["timed_out"] is False)
c("empty-terminal-stderr",i["terminal_stderr"]=="")
c("terminal-core-sha",terminal["result_sha256"]==sha(i["core"].encode()))
c("exact-failed-stage",r["status"]=="failed" and r["failure_stage"]=="offline_locked_binary" and r["failure_code"]=="regular_single_link_file_required")
c("exact-source",r["source_before"]=={"commit":"df026fe323dd7cf0f0ec57d7d2d9c5a79897053c","tree":"424463ccd2310ddc1e7b2bbcd7b7af29ae58c825","status":""})
c("original-total",r["deadline_monotonic_ns"]-r["started_monotonic_ns"]==600_000_000_000)
c("closed-in-original-total",r["completed_monotonic_ns"]<r["deadline_monotonic_ns"])
c("unknown-false",r["command_outcome_unknown"] is False and r["incomplete_command_labels"]==[])
for k in ("all_owned_stopped","all_input_fds_closed","completed_within_original_build_deadline"):c("core-"+k,r[k] is True)
c("zero-product",r["product_or_http_requests"]==0 and r["product_modified"] is False)
names=["source-before-commit","source-before-tree","source-before-status","rustc-version","lock","build"]
c("six-exact-commands",[x["label"] for x in r["commands"]]==names)
c("six-exact-intents",[x["label"] for x in r["command_intents"]]==names)
c("six-unique-cleanup",len(r["owned_cleanup"])==6 and len({x["pid"] for x in r["owned_cleanup"]})==6)
c("six-provenance",len(r["child_provenance"])==6)
files={}
for batch in i["command_batches"]:
    for f in json.loads(batch)["files"]:
        name=f["path"].rsplit("/",1)[-1]
        c("unique-"+name,name not in files)
        files[name]=f["text"]
        c("size-"+name,len(f["text"].encode())==f.get("size",f.get("bytes")))
for cmd, intent in zip(r["commands"],r["command_intents"]):
    name=cmd["label"]; pid=cmd["owned_pgid"]
    c(name+"-record",json.loads(files[name+".public.json"])==cmd)
    c(name+"-intent",json.loads(files[name+".intent.public.json"])==intent)
    c(name+"-exit",cmd["exit_code"]==0 and cmd["timed_out"] is False)
    c(name+"-closed",cmd["direct_child_reaped"] is True and cmd["remaining"]==[])
    c(name+"-deadline",cmd["completed_monotonic_ns"]<cmd["deadline_monotonic_ns"] and cmd["completed_within_deadline"] is True)
    c(name+"-cap",cmd["deadline_monotonic_ns"]-cmd["started_monotonic_ns"]<=cmd["outer_cap_seconds"]*1_000_000_000)
    c(name+"-stderr",sha(files[name+".stderr"].encode())==cmd["stderr_sha256"])
    if name!="build":c(name+"-stdout",sha(files[name+".stdout"].encode())==cmd["stdout_sha256"])
    clean=next(x for x in r["owned_cleanup"] if x["pid"]==pid)
    prov=next(x for x in r["child_provenance"] if x["pid"]==pid)
    c(name+"-cleanup",clean["owned_stopped"] is True and clean["direct_child_reaped"] is True and clean["remaining"]==[] and clean["wait_returncode"]==0 and clean["stop_terminal_captured"] is True)
    c(name+"-waitid",prov["terminal_consumed"] is True and prov["terminal_event"]["not_reaped"] is True and prov["terminal_event"]["pid"]==pid and prov["terminal_event"]["si_code"]==1 and prov["terminal_event"]["si_status"]==0 and prov["wait_returncode"]==0)
    c(name+"-capture",prov["custody_verified"] is True and prov["popen_returned"] is True and prov["provisionally_registered_before_observation"] is True)
    c(name+"-exact-requested-argv",prov["requested_argv_sha256"]==sha(b"\0".join(x.encode() for x in cmd["argv"])+b"\0"))
    c(name+"-identity",all(prov["identity_before"][k]==prov["identity_after"][k] for k in ("pid","ppid","pgid","start_ticks")) and prov["identity_before"]["start_ticks"]==clean["start_ticks"])
c("no-runtime-argv-overclaim",r["child_exec_visibility"]==[] and all(x["live_proc_argv_observed"] is False for x in r["child_provenance"]))
c("lock-subset",r["lock_subset"]["exact_version_source_checksum_subset"] is True and r["lock_subset"]["registry_package_count"]==76)
info=json.loads(i["cargo_info"])
c("pending-cargo-byte-pin",info["size"]==62672 and info["sha256"]==r["commands"][-1]["stdout_sha256"])
print(json.dumps({"schema":"heptabao.qa-r2.failed-core-checks.v1","status":"passed-evidence-checks-only","checks":checks,"check_count":len(checks),"observed_result":"known_failed","command_streams_whole_verified":11,"command_streams_pending":1,"component_tests_executed":0,"artifact_stat_fields_not_yet_observed":True,"all_original_cleanup_closed":True},indent=2,sort_keys=True))

