import ast,hashlib,json,sys
d=json.loads(sys.argv[1]); c=json.loads(d["core"]); b=json.loads(d["binding"]); st=json.loads(d["stage"]); a=json.loads(d["authority"]); s=json.loads(d["streams"]); ack=json.loads(d["ack"]); req=json.loads(d["request"]); checks=[]
def ck(name,ok):
    if not ok: raise AssertionError(name)
    checks.append(name)
def sha(x): return hashlib.sha256(x.encode()).hexdigest()
ck("authority_terminal",a["job_id"]==ack["job"]["id"] and a["state"]=="succeeded" and a["exit_code"]==0 and not a["timed_out"] and not a["cancelled"] and a["output_complete"] and a["output_durable"] and a["terminal_publication_confirmed"])
ck("authority_full_streams",a["log_bytes"]=={"stdout":{"seen":292,"stored":292},"stderr":{"seen":0,"stored":0}} and all(a["log_synced"].values()) and not any(a["log_truncated"].values()) and not any(a["log_errors"].values()))
ck("streams_same_job",s["job_id"]==a["job_id"])
for name in ("stdout","stderr"):
    x=s[name]; data=bytes.fromhex(x["bytes_hex"])
    ck("stream_"+name+"_full",x["offset"]==0 and x["eof"] and x["next_offset"]==x["size"]==len(data) and data.decode()==x["text"] and len(data)==a["log_bytes"][name]["stored"])
t=json.loads(s["stdout"]["text"])
ck("terminal_binds_core",t=={"all_owned_stopped":True,"result":b["layout"]["prepare"]+"/result.public.json","result_sha256":sha(d["core"]),"runtime_started":False,"status":"passed"})
ck("original_core_identity",len(d["core"].encode())==23565 and sha(d["core"])=="155f4d300c478c93df2209a286edc70fc1c40c5d38c2250f7296c1d77ec5f9d0")
ck("actual_binding_identity",len(d["binding"].encode())==6655 and sha(d["binding"])=="778697b6f271762ebeebebb8000fe1a92ec88593f725ea460afb62db2a5f9242" and c["binding_sha256"]==sha(d["binding"]))
ck("exact_request_ack",ack["reused"] is False and ack["job"]["args"]==req["args"] and ack["job"]["cwd"]==req["cwd"] and ack["job"]["executable"]==req["executable"] and ack["job"]["host"]==req["host"] and ack["job"]["idempotency_key"]==req["idempotency_key"])
ck("prepare_only_scope",c["schema"]=="heptabao.official271-native-cli-phaseb-r3.prepare.v1" and c["status"]=="passed" and c["failure_code"] is None and c["runtime_started"] is False and c["server_processes"]==0 and c["cli_snapshot_commands"]==0 and c["production_changed"] is False and c["readiness_is_not_runtime_qualification"] is True)
i=c["inputs"]
ck("input_host_and_binding",i["host"]==b["host"] and i["binding_sha256"]==c["binding_sha256"])
ck("canonical_source",i["source"]=={"commit":b["candidate_commit"],"tree":b["candidate_tree"],"status":""} and b["candidate_commit"]=="3cb873919170cc77101b27f6a3ab9e98f41f8d93" and b["candidate_tree"]=="7f4d48a647a81ca96e8a24a0a057c2c829459060")
module=ast.parse(d["binding_source"])
constants={}
for n in module.body:
    if isinstance(n,ast.Assign) and len(n.targets)==1 and isinstance(n.targets[0],ast.Name) and n.targets[0].id in {"BUDGETS","API_PORTS","RAFT_PORTS","PRODUCT_PINS","OFFICIAL_SOURCE_COMMIT"}:
        constants[n.targets[0].id]=ast.literal_eval(n.value)
ck("original_budgets",i["budgets"]==b["budgets"]==constants["BUDGETS"])
ck("roundtrip_string_port_keys",i["api_ports"]=={str(k):v for k,v in constants["API_PORTS"].items()} and i["raft_ports"]=={str(k):v for k,v in constants["RAFT_PORTS"].items()})
ck("official_source_and_scope",i["official_source_commit"]==constants["OFFICIAL_SOURCE_COMMIT"] and i["whole_replacement_qualification"] is False)
ck("five_product_source_pins",len(i["archive_and_audit_product_sources"])==5 and set(i["archive_and_audit_product_sources"])==set(constants["PRODUCT_PINS"]) and all((v["git_blob"],v["sha256"])==constants["PRODUCT_PINS"][k] for k,v in i["archive_and_audit_product_sources"].items()))
expected={x["path"]:x for x in st["captured_readonly_inputs"]}
expected.update({x["target"]["path"]:x["target"] for x in st["copied"]})
for x in st["qa_files"]: expected[b["layout"]["control"]+"/qa/"+x["name"]]=x
for x in st["extra_artifacts"]: expected[b["layout"]["control"]+"/artifacts/"+x["name"]]=x
views=[]
for name,bindkey in (("qa","qa_files"),("artifacts","artifacts"),("utilities","utilities")):
    ck(name+"_same_keyset",set(i["files"][name])==set(b[bindkey]))
    for key,v in i["files"][name].items():
        ck(name+"_"+key+"_binding",all(v[k]==val for k,val in b[bindkey][key].items()))
        views.append(v)
views.append(i["files"]["official_cli"])
ck("official_cli_pin",all(i["files"]["official_cli"][k]==v for k,v in b["official_cli"].items()))
ck("five_old_fences_order_and_content",len(i["files"]["old_fences"])==len(b["old_fences"])==5 and all(all(v[k]==value for k,value in pin.items()) for v,pin in zip(i["files"]["old_fences"],b["old_fences"])))
views.extend(i["files"]["old_fences"])
fields=("bytes","sha256","uid","gid","device","inode","links","mode","mtime_ns","ctime_ns")
ck("all19_full_file_identities_unchanged_since_stage",len(views)==19 and all(all(v[k]==expected[v["path"]][k] for k in fields) for v in views))
ck("three_child_guards",len(c["child_provenance"])==3 and len(c["owned_cleanup"])==3 and c["child_exec_visibility"]==[] and c["all_owned_stopped"] is True)
source=b["layout"]["source"]
commands=[["/usr/bin/git","-c","core.fsmonitor=false","-c","core.hooksPath=/dev/null","-C",source,*suffix] for suffix in (["rev-parse","HEAD"],["rev-parse","HEAD^{tree}"],["status","--porcelain","--untracked-files=all"])]
for n,(row,argv) in enumerate(zip(c["child_provenance"],commands)):
    raw=b"\0".join(x.encode() for x in argv)+b"\0"
    ck("exact_git_guard_"+str(n),row["guard_accepted"] and row["captured_only_by_original_child_guard"] and row["actual_argc"]==row["expected_argc"]==len(argv) and row["actual_cmdline_bytes"]==len(raw) and row["actual_cmdline_sha256"]==hashlib.sha256(raw).hexdigest() and row["extra_args_omitted"]==0 and row["identity"]["exe"]==argv[0] and row["identity"]["pid"]==row["identity"]["pgid"]==row["pid"])
    ck("exact_all_argv_hashes_"+str(n),len(row["args"])==len(argv) and all(x["index"]==z and x["equal"] and x["bytes"]==x["expected_bytes"]==len(arg.encode()) and x["sha256"]==x["expected_sha256"]==sha(arg) for z,(x,arg) in enumerate(zip(row["args"],argv))))
pids={r["pid"]:r["identity"]["start_ticks"] for r in c["child_provenance"]}
ck("all_owned_groups_reaped_empty",len(pids)==3 and set(pids)=={r["pid"] for r in c["owned_cleanup"]} and all(r["start_ticks"]==pids[r["pid"]] and r["direct_child_reaped"] and r["owned_stopped"] and r["stop_terminal_captured"] and r["wait_returncode"]==0 and r["remaining"]==[] for r in c["owned_cleanup"]))
ck("publication_after_admission",ack["job"]["created_unix_ms"]*1000000<=c["terminal_unix_ns"]<=a["at_unix_ms"]*1000000+1000000)
print(json.dumps({"schema":"heptabao.phaseb-3cb-readonly-prepare-evidence-review.v1","status":"passed","checks":checks,"checks_count":len(checks),"job_id":a["job_id"],"core_sha256":sha(d["core"]),"binding_sha256":sha(d["binding"]),"child_count":3,"all_owned_stopped":True,"runtime_started":False,"full_fsck_performed_by_this_prepare":False,"full_fsck_and_3911_blob_verification_source":"standalone import root review 314c5a9d4941d3ffcffc154d5ea34ecd4fe08f9e","integer_handling":"Python json arbitrary-precision integers; original raw UTF-8 preserved","product_or_candidate_code_executed_by_this_review":False},sort_keys=True,indent=2))
