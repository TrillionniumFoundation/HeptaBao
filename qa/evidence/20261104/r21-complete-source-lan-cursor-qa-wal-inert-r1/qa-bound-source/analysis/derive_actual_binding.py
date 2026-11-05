#!/usr/bin/env python3
"""Derive one QA binding from original fixed read payloads; offline only."""
import ast, hashlib, json, re, stat
from pathlib import Path
HERE=Path(__file__).parent
data=json.loads((HERE/"h2_qa_binding_actual_input.json").read_text())
checks=[]
def need(ok,name):
    assert ok,name
    checks.append(name)
def sha(raw):return hashlib.sha256(raw).hexdigest()
def parse(raw):
    def pairs(values):
        out={}
        for key,value in values:
            assert key not in out,"duplicate key"
            out[key]=value
        return out
    return json.loads(raw,object_pairs_hook=pairs)
binding=json.loads(json.dumps(data["partial"]))
need(binding["ready"] is False and binding["target_identity"] is None,"unbound_input")
need(sha(data["creatorSource"].encode())=="98b7838cd4550467b76bc3c9fd3b4925b806075536b7e22dc1cba1c79063bde3","actual_creator_source_whole_pin")
creator=ast.parse(data["creatorSource"])
identity=next(n for n in creator.body if isinstance(n,ast.FunctionDef) and n.name=="identity")
need(len(identity.body)==1 and isinstance(identity.body[0],ast.Return) and isinstance(identity.body[0].value,ast.Tuple),"actual_identity_single_tuple")
fields=[n.attr for n in identity.body[0].value.elts]
need(fields==["st_dev","st_ino","st_uid","st_gid","st_mode","st_nlink","st_size","st_mtime_ns","st_ctime_ns"],"actual_nine_field_identity_order")
target_kw=next(k for n in ast.walk(creator) if isinstance(n,ast.Call) for k in n.keywords if k.arg=="target_identity_after")
need(ast.dump(target_kw.value,include_attributes=False)==ast.dump(ast.parse("list(identity(os.fstat(target_fd)))",mode="eval").body,include_attributes=False),"actual_target_is_held_fd_identity")
preflight=parse(data["preflightRaw"])
need(sha(data["preflightRaw"].encode())=="9d8fc768b35116a2404bc31d4d9d924a6bce1b7d90f911c77fbc510c080bf076","actual_original_preflight_hash")
need(preflight["schema"]=="heptabao.cold-h2-normal-target-admission.v1" and preflight["status"]=="admitted","actual_preflight_schema")
need(preflight["source_commit"]==binding["candidate_commit"] and preflight["source_tree"]==binding["candidate_tree"] and preflight["target"]==binding["target"],"actual_preflight_candidate_and_target")
fresh=preflight["fresh_target_preparation"]
need(fresh["status"]=="prepared" and fresh["target"]==binding["target"] and fresh["all_opened_descriptors_closed"] is True and fresh["completed_before_original_outer_deadline"] is True,"actual_target_preparation_complete")
ids=fresh["target_identity_after"]
need(type(ids) is list and len(ids)==9 and all(type(v) is int and v>=0 for v in ids),"lossless_original_integer_identity")
need(ids[:4]==[66306,31606588,1000,1000] and stat.S_ISDIR(ids[4]) and stat.S_IMODE(ids[4])==0o700,"historical_owned_directory_exact")
binding["target_identity"]={"device":ids[0],"inode":ids[1],"uid":ids[2],"gid":ids[3],"mode":stat.S_IMODE(ids[4])}
for label in ("python","git","cargo","rustc"):
    info=parse(data["infoRaw"][label]); pin=binding["tools"][label]
    need(info["path"]==pin["path"],label+"_fixed_path")
    need(type(info["size"]) is int and 0<info["size"]<=512*1024*1024 and re.fullmatch("[0-9a-f]{64}",info["sha256"]) is not None,label+"_whole_file_shape")
    meta=info["metadata"]
    need(meta["metadata_platform"]=="linux" and type(meta["link_count"]) is int and meta["link_count"]==1 and meta["uid"] in (0,1000),label+"_owner_single_link")
    need(info["mode"]==meta["mode"] and not stat.S_IMODE(info["mode"])&0o022 and info["mode"]==0o755,label+"_exact_nonwritable_mode")
    parts=info["version"].split(":")
    need(len(parts)==5 and all(x.isdigit() for x in parts) and int(parts[2])==info["size"],label+"_exact_version_size")
    binding["tools"][label]={"path":info["path"],"sha256":info["sha256"],"bytes":info["size"],"uid":meta["uid"],"mode":stat.S_IMODE(info["mode"])}
machine=parse(data["infoRaw"]["machine-id"])
need(machine["path"]=="/etc/machine-id" and machine["size"]==33 and machine["metadata"]["link_count"]==1 and re.fullmatch("[0-9a-f]{64}",machine["sha256"]) is not None,"machine_hash_only_actual")
binding["host"]["machine_id_sha256"]=machine["sha256"]
need(data["normalRaw"]==data["normalQualifiedRaw"] and len(data["normalRaw"].encode())==48188 and sha(data["normalRaw"].encode())==binding["normal_product_result"]["sha256"],"normal60_exact_qualified_raw")
normal=parse(data["normalRaw"])
need(normal["source_commit"]==binding["candidate_commit"] and normal["source_tree"]==binding["candidate_tree"] and normal["status"]=="passed" and normal["selected_test_total"]==60 and normal["test_count"]==44,"normal60_candidate_and_counts")
need(normal["controller_sha256"]=="1a3fdc3a7cf6504447feb7d7dadf2f365b292512f6d0cf8cdfb4a2ea63d33d40" and normal["original_44_status"]==normal["original_44_and_ingress_7_status"]=="passed" and normal["ingress_observer_regression"]["status"]==normal["cold_h2_regression"]["status"]=="passed","normal44_7_9_gate")
need(len(normal["cleanup"])==46 and all(r["direct_child_reaped"] is True and r["remaining"]==[] and not r.get("cleanup_error_type") for r in normal["cleanup"]),"normal46_owned_stopped")
binding["ready"]=True
builder=ast.parse(data["builderSource"])
caps=ast.literal_eval(next(n.value for n in builder.body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=="CAPS" for t in n.targets)))
need(binding["caps"]==caps,"original_build_caps_unchanged")
unbound=data["partial"]
reverse=json.loads(json.dumps(binding));reverse["ready"]=unbound["ready"];reverse["target_identity"]=unbound["target_identity"];reverse["tools"]=unbound["tools"];reverse["host"]=unbound["host"]
need(reverse==unbound,"only_actual_ready_target_tools_machine_fields_change")
raw=json.dumps(binding,indent=2)+"\n"
(HERE/"h2_qa_build_binding.actual.private.json").write_text(raw)
report={"schema":"heptabao.native-h2-qa.df026.actual-binding-derivation.r1","status":"passed_offline_derivation_only","checks":checks,"check_count":len(checks),"binding_bytes":len(raw.encode()),"binding_sha256":sha(raw.encode()),"target_identity":binding["target_identity"],"target_identity_is_historical_preflight":True,"builder_must_recheck_current_target":True,"target_creator_blob":"8e2f73cf6a286077522268c8c1857ca4004cf258","creator_identity_fields":fields,"original_preflight_ns_retained_exact_in_raw_input":True,"nanoseconds_in_binding":False,"source_executed":False,"candidate_host_stage_or_build_executed":False}
(HERE/"h2_qa_build_binding_derivation.public.json").write_text(json.dumps(report,indent=2,sort_keys=True)+"\n")
print(json.dumps({"status":report["status"],"checks":len(checks),"binding_bytes":report["binding_bytes"],"binding_sha256":report["binding_sha256"],"target_identity":binding["target_identity"]}))
