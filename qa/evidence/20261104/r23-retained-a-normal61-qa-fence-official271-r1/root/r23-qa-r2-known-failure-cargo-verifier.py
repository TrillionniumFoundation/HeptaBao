import hashlib,json,stat
import sys
original=json.loads(sys.argv[1]); more=json.loads(sys.argv[2])
core=json.loads(original["core"]); info=json.loads(more["artifact_info"])
checks=[]
def c(name,condition):
    assert condition,name
    checks.append(name)
sha=lambda s:hashlib.sha256(s.encode()).hexdigest()
raw=more["cargo_stdout"];events=[json.loads(line) for line in raw.splitlines()]
c("cargo-whole-size-sha",len(raw.encode())==62672 and sha(raw)==core["commands"][-1]["stdout_sha256"])
c("all-75-events",len(events)==75 and all(type(e) is dict for e in events))
c("one-build-success",len([e for e in events if e.get("reason")=="build-finished" and e.get("success") is True])==1)
artifacts=[e for e in events if e.get("reason")=="compiler-artifact" and e.get("target",{}).get("name")=="heptabao-native-h2-qa" and e.get("executable")]
c("one-qa-artifact",len(artifacts)==1); event=artifacts[0]
expected="/home/qian-qi/heptabao-cold-h2-normal-20261105-r1/target-normal-r3/release/heptabao-native-h2-qa"
c("exact-compiler-output",event["executable"]==expected and event["filenames"]==[expected])
c("default-qa-features",event["features"]==[])
c("original-profile",event["profile"]=={"opt_level":"3","debuginfo":0,"debug_assertions":True,"overflow_checks":True,"test":False})
c("actual-new-compile",event["fresh"] is False)
c("exact-owned-manifest",event["manifest_path"]=="/home/qian-qi/heptabao-native-h2-qa-df026-20261105-r2/project/Cargo.toml")
c("native-info-path",info["path"]==event["executable"])
c("actual-artifact-size",info["size"]==4616576)
c("actual-artifact-sha",info["sha256"]=="1f1c6eccf1ac9652a69572cb270b1d3d99a3402eaabf6d7feed6e4b2c4d55b13")
c("actual-artifact-version",info["version"]=="66306:31633993:4616576:1793869496670294192:1793869496695294129")
c("actual-artifact-owner-mode",info["metadata"]["uid"]==1000 and info["metadata"]["gid"]==1000 and info["mode"]==0o700 and info["metadata"]["mode"]==0o700)
c("actual-nlink-two",info["metadata"]["link_count"]==2)
c("generic-single-link-predicate-false",info["metadata"]["link_count"]!=1)
c("expected-failure-boundary",core["failure_code"]=="regular_single_link_file_required" and core["failure_stage"]=="offline_locked_binary")
c("no-component-execution",len(core["commands"])==6 and all(not e["label"].startswith("components") for e in core["commands"]))
c("no-product-execution",core["product_or_http_requests"]==0)
print(json.dumps({"schema":"heptabao.qa-r2.cargo-and-artifact-observation-checks.v1","status":"passed-evidence-checks-only","check_count":len(checks),"checks":checks,"original_combined_status":"failed","original_failure_not_replayed":True,"cargo_exit_code":0,"artifact_info_is_later_observation":True,"alias_set_observed":False,"artifact_execution_count":0,"component_tests_executed":0},sort_keys=True,indent=2))

