import hashlib,json,sys
p=json.loads(sys.argv[1]);a=json.loads(p["authority"]);c=json.loads(p["core"]);t=json.loads(p["terminal"]);b=json.loads(p["binding"]);partial=json.loads(p["partial"]);req=json.loads(p["prepare_request"])
checks=[]
def need(name,value):
    assert value,name
    checks.append(name)
def digest(raw):return hashlib.sha256(raw.encode()).hexdigest()
def version(r):return ":".join(map(str,(r["device"],r["inode"],r["bytes"],r["mtime_ns"],r["ctime_ns"])))
def pin(r):return {k:r[k] for k in ("path","sha256","bytes","uid","mode")}
need("single authoritative successful complete terminal",a["job_id"]=="1a1a96c027d-fc05-3519" and a["state"]=="succeeded" and a["exit_code"]==0 and a["output_complete"] and a["output_durable"] and not a["timed_out"] and not a["cancelled"] and a["terminal_publication_confirmed"])
need("exact terminal and empty stderr sizes",a["log_bytes"]["stdout"]=={"seen":len(p["terminal"].encode()),"stored":len(p["terminal"].encode())} and a["log_bytes"]["stderr"]=={"seen":0,"stored":0} and all(a["log_synced"].values()) and not any(a["log_truncated"].values()) and all(v is None for v in a["log_errors"].values()))
need("stage passed and closures complete",c["status"]==t["status"]=="passed" and c["fd_close_pending"] is True and t["fd_close_pending"] is False and t["all_stage_fds_closed"] and t["fd_close_errors"]==[] and t["within_stage_deadline"] and 0<c["elapsed_ms"]<=t["elapsed_after_closure_ms"]<300000)
extras={"all_stage_fds_closed","elapsed_after_closure_ms","fd_close_errors","within_stage_deadline"}
need("terminal only allowed closure extension",set(t)-set(c)==extras and set(c)-set(t)==set() and all(t[k]==v for k,v in c.items() if k!="fd_close_pending"))
need("no product, prepare, network, child or production",not t["product_started"] and not t["readonly_prepare_started"] and t["children_spawned"]==t["network_calls"]==0 and not t["runtime_qualification"] and not t["production_changed"] and not t["source_tree_modified"] and not t["original_existing_assets_replaced"])
need("exact retained source carrier and stager",c["source_carrier_sha256"]=="2f9f8acb45e66f49b42739e64eac6bf289f06a7d5bc840eab3b2c8ce87ce0fcd" and c["external_controller_sha256"]=="4c9a4755988d486d0adb80b03aecddf8297d884cabf1a52cd8053a82268e992c" and c["external_controller_self_attestation_claimed"] is False)
need("exact diagnostic candidate",c["source_commit"]==b["candidate_commit"]=="3cb873919170cc77101b27f6a3ab9e98f41f8d93" and c["source_tree"]==b["candidate_tree"]=="7f4d48a647a81ca96e8a24a0a057c2c829459060" and c["source_metadata_unchanged"])
need("stage does not replace Git prepare gate",not c["source_full_git_verification_performed_by_stage"] and c["source_full_git_verification_required_in_readonly_prepare"])
views={r["path"]:r for r in p["independent_files"]}
native=json.loads(p["native_info"]);server=json.loads(p["server_info"])
views[native["path"]]={"path":native["path"],"size":native["size"],"sha256":native["sha256"],"version":native["version"],"eof":True}
views[server["path"]]={"path":server["path"],"size":server["size"],"sha256":server["sha256"],"version":server["version"],"eof":True}
need("five QA and five artifact output records",len(c["qa_files"])==5 and len(c["copied"])==3 and len(c["extra_artifacts"])==2)
records=[(b["layout"]["control"]+"/qa/"+r["name"],r) for r in c["qa_files"]]+[(r["target"]["path"],r["target"]) for r in c["copied"]]+[(b["layout"]["control"]+"/artifacts/"+r["name"],r) for r in c["extra_artifacts"]]+[(c["binding"]["path"],c["binding"])]
pins={r["path"]:r for cat in ("qa_files","artifacts") for r in b[cat].values()}
for path,row in records:
    v=views[path]
    need("independent output bytes/version "+path.rsplit("/",1)[1],v["size"]==row["bytes"] and v["sha256"]==row["sha256"] and v["version"]==version(row) and v["eof"] and row["uid"]==1000 and row["links"]==1)
    if path in pins:
        need("binding output pin "+path.rsplit("/",1)[1],all(row[k]==pins[path][k] for k in ("bytes","sha256","uid","mode")))
for info in (native,server):
    need("independent custody "+info["path"].rsplit("/",1)[1],info["metadata"]["uid"]==1000 and info["metadata"]["link_count"]==1 and info["metadata"]["mode"]==info["mode"]==(320 if info is server else 384))
need("binding original raw exact pin",len(p["binding"].encode())==6655 and digest(p["binding"])==c["binding"]["sha256"]=="778697b6f271762ebeebebb8000fe1a92ec88593f725ea460afb62db2a5f9242" and c["binding"]["mode"]==384 and c["binding"]["create_only"])
shared={r["path"]:r for r in p["shared"]}
for entry in c["copied"]:
    r=entry["source"];old=shared[r["path"]]
    need("shared incoming exact "+r["path"].rsplit("/",1)[1],version(r)==old["version"] and all(r[k]==old[k] for k in ("bytes","sha256","mode")) and entry["create_only"] and entry["same_fd_readback"])
captured={r["path"]:r for r in c["captured_readonly_inputs"]}
expected=partial
expected["utilities"]={name:pin(captured[v["path"]]) for name,v in partial["utilities"].items()}
expected["official_cli"]=pin(captured[partial["official_cli"]["path"]])
oldpaths={r["path"]:r for r in partial["old_fences"]}
for r in c["captured_readonly_inputs"]:
    if r["path"] in oldpaths:
        need("protected old fence "+r["path"],r["sha256"]==oldpaths[r["path"]]["sha256"] and r["bytes"]==oldpaths[r["path"]]["bytes"])
expected["old_fences"]=[pin(r) for r in c["captured_readonly_inputs"] if r["path"] in oldpaths]
expected["ready_for_readonly_prepare"]=True
need("concrete binding equals original partial plus actual captures",expected==b and json.dumps(expected,indent=2,sort_keys=True)+"\n"==p["binding"])
need("private basename/fresh fixed layout retained",b["layout"]=={"control":"/home/qian-qi/heptabao-ha-closure-20261103-r1/official271-native-cli-phaseb-r3-control-r2","source":"/home/qian-qi/heptabao-ha-closure-20261103-r1/normal-phaseb-ingress-observer-source-r1","work":"/home/qian-qi/heptabao-ha-closure-20261103-r1/official271-native-cli-phaseb-r3-live-r2","prepare":"/home/qian-qi/heptabao-ha-closure-20261103-r1/official271-native-cli-phaseb-r3-control-r2/prepare-r1"})
need("actual-derived exact prepare request only",req["host"]=="desktop" and req["executable"]==b["utilities"]["python"]["path"]=="/usr/bin/python3.12" and req["args"]==["-I","-S","-B",b["qa_files"]["phaseb_controller_r3.py"]["path"],"--binding",c["binding"]["path"],"--binding-sha256",digest(p["binding"]),"--prepare-only"] and req["timeout_seconds"]==330 and req["idempotency_key"]=="heptabao-phaseb-3cb-prepare-10816-20261105-r1")
print(json.dumps({"schema":"heptabao.phaseb3cb.local-stage-actual-review.v1","status":"passed","checks":checks,"check_count":len(checks),"job_id":a["job_id"],"actual_binding_sha256":digest(p["binding"]),"actual_binding_bytes":len(p["binding"].encode()),"elapsed_after_closure_ms":t["elapsed_after_closure_ms"],"all_stage_fds_closed":True,"all_five_qa_full_readback_exact":True,"all_four_text_artifacts_full_readback_exact":True,"server_independent_whole_hash_and_version_verified":True,"prepare_dispatched":False,"product_runtime_started":False,"integer_handling":"Original texts unchanged; Python arbitrary-precision JSON for identities and ns versions"},indent=2,sort_keys=True))
