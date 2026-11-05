#!/usr/bin/env python3
"""Independent fresh HTTPS reproduction of CG wrapping-token effect counts."""
import argparse, hashlib, http.client, json, os, ssl, sys, time
from urllib.parse import urlsplit
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/"qa/openbao-acceptance"))
sys.path.insert(0,str(ROOT/"qa/single-node"))
sys.path.insert(0,str(ROOT/"clients/python/src"))
def call(addr,ca,method,path,token="",body=None):
    u=urlsplit(addr)
    c=http.client.HTTPSConnection(u.hostname,u.port,context=ssl.create_default_context(cafile=str(ca)),timeout=15)
    headers={"Connection":"close","Content-Type":"application/json"}
    if token:headers["X-Vault-Token"]=token
    try:
        c.request(method,"/v1/"+path,body=None if body is None else json.dumps(body).encode(),headers=headers)
        r=c.getresponse();raw=r.read(1024*1024+1)
        if len(raw)>1024*1024:raise RuntimeError("oversize_response")
        return r.status,json.loads(raw) if raw else {}
    finally:c.close()
from smoke import Instance
from bao_http import private_write,private_read
from official_openbao_launcher import start_oracle,stop_oracle,restart_oracle,verify_inputs,pinned_artifact
from oidc_renewal_live import free_port
import owned_process

def sha(path):
    h=hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda:f.read(1024*1024),b""):h.update(block)
    return h.hexdigest()

def profile(label,addr,ca,root,restart,audit,result):
    rows=result["rows"]
    def req(case,method,path,body=None,token=None,expect=(200,204)):
        s,d=call(addr,ca,method,path,root if token is None else token,body)
        rows.append({"case":case,"method":method,"path":path,"status":s,"passed":s in expect})
        if s not in expect and case.startswith("setup_"):raise RuntimeError(case)
        return s,d
    req("setup_mount","POST","sys/mounts/secret",{"type":"kv","options":{"version":"2"}},expect=(204,))
    req("setup_auth","POST","sys/auth/approle",{"type":"approle"},expect=(204,))
    policy='path "secret/data/replay" { capabilities=["create","update"] control_group={ ttl="30s" factor "ops" { controlled_capabilities=["create","update"] identity { group_names=["ops"] approvals=1 } } } }'
    review='path "sys/control-group/*" { capabilities=["update"] }'
    req("setup_request_policy","PUT","sys/policies/acl/request",{"policy":policy},expect=(204,))
    req("setup_reviewer_policy","PUT","sys/policies/acl/reviewer",{"policy":review},expect=(204,))
    users={};entities={}
    for name,policies in (("requester",["request"]),("reviewer",["reviewer"])):
        req("setup_"+name+"_role","POST","auth/approle/role/"+name,{"token_policies":policies},expect=(204,))
        _,r=req("setup_"+name+"_roleid","GET","auth/approle/role/"+name+"/role-id",expect=(200,))
        _,s=req("setup_"+name+"_secret","POST","auth/approle/role/"+name+"/secret-id",{},expect=(200,))
        _,a=req("setup_"+name+"_login","POST","auth/approle/login",{"role_id":r["data"]["role_id"],"secret_id":s["data"]["secret_id"]},token="",expect=(200,))
        users[name]=a["auth"]["client_token"];entities[name]=a["auth"]["entity_id"]
    req("setup_group","POST","identity/group",{"name":"ops","type":"internal","member_entity_ids":[entities["reviewer"]]},expect=(200,))
    issued=time.monotonic()
    _,d=req("deferred","POST","secret/data/replay",{"data":{"value":"synthetic-replay-effect"}},users["requester"],(200,))
    wrap=d.get("wrap_info",{})
    if not isinstance(wrap.get("token"),str) or not isinstance(wrap.get("accessor"),str):raise RuntimeError("deferred_wrapper_missing")
    token=wrap["token"];accessor=wrap["accessor"]
    s,d=req("deferred_effect_absent","GET","secret/data/replay",expect=(404,))
    _,d=req("approved","POST","sys/control-group/authorize",{"accessor":accessor},users["reviewer"],(200,))
    rows.append({"case":"quorum_true","passed":d.get("data",{}).get("approved") is True})
    effect_versions=result["effect_versions"]
    for index in (1,2,3):
        if index==3:
            restart();rows.append({"case":"owned_sigkill_restart","passed":True,"fault":"SIGKILL"})
        s,d=req("unwrap_"+str(index),"POST","sys/wrapping/unwrap",{},token,(200,) if index==1 else (400,403))
        s,m=req("effect_after_"+str(index),"GET","secret/metadata/replay",expect=(200,))
        version=m.get("data",{}).get("current_version")
        effect_versions.append(version)
        rows.append({"case":"effect_count_"+str(index),"current_version":version,"passed":version==1})
    remaining=issued+31.1-time.monotonic()
    if remaining>0:time.sleep(remaining)
    s,d=req("expired_unwrap","POST","sys/wrapping/unwrap",{},token,(400,403))
    s,m=req("expired_final_effect","GET","secret/metadata/replay",expect=(200,))
    rows.append({"case":"expiry_no_effect","current_version":m.get("data",{}).get("current_version"),"passed":m.get("data",{}).get("current_version")==effect_versions[-1]})
    return {"rows":rows,"effect_versions":effect_versions,"live_replay_observed":effect_versions==[1,2,3],"candidate_single_execution_verified":effect_versions==[1,1,1] and all(r["passed"] for r in rows),"audit_sha256":sha(audit),"audit_bytes":audit.stat().st_size}

def main():
    p=argparse.ArgumentParser();p.add_argument("--binary",type=Path,required=True);p.add_argument("--private-root",type=Path,required=True);p.add_argument("--output",type=Path,required=True);p.add_argument("--candidate-source",required=True);a=p.parse_args();os.umask(0o077)
    if a.output.exists():raise RuntimeError("report_exists")
    a.private_root.mkdir(mode=0o700,parents=False,exist_ok=False);os.environ["HB_ORACLE_WORK_ROOT"]=str(a.private_root);verify_inputs(version="2.7.1")
    report={"schema":"heptabao.controlgroups271.wrap-effect-reproducer.v1","official":pinned_artifact(version="2.7.1"),"candidate_source_commit":a.candidate_source,"candidate_binary_sha256":sha(a.binary),"reproducer_sha256":sha(Path(__file__)),"tls_verified":True,"synthetic_only":True,"production_authority":False,"replacement_authority":False,"profiles":{},"failures":{}}
    for label in ("official","candidate"):
        instance=None;oracle=None
        try:
            if label=="official":
                oracle=start_oracle(free_port(),version="2.7.1",audit_file=True);addr=oracle["address"];ca=Path(oracle["ca_file"]);raw=private_read(Path(oracle["token_file"]));root=(raw.decode() if isinstance(raw,bytes) else raw).strip();work=Path(oracle["root"]);audit=work/"audit.jsonl"
                def restart():
                    owned_process.stop(oracle["process"],action="KILL",timeout=5,expected_codes=(-9,));oracle["log"].close();restart_oracle(oracle)
            else:
                instance=Instance(a.binary,a.private_root/"candidate");instance.start();s,d=instance.call("POST","sys/init",{"secret_shares":1,"secret_threshold":1})
                if s!=200:raise RuntimeError("candidate_init")
                root=d["root_token"];key=d["keys_base64"][0];instance.token=root
                if instance.call("POST","sys/unseal",{"key":key})[0]!=200:raise RuntimeError("candidate_unseal")
                addr=instance.address;ca=instance.root/"ca.crt";work=instance.root;audit=work/"audit.jsonl"
                def restart():
                    instance.stop();instance.start()
                    if instance.call("POST","sys/unseal",{"key":key})[0]!=200:raise RuntimeError("candidate_restart_unseal")
            report["profiles"][label]={"rows":[],"effect_versions":[]}
            completed=profile(label,addr,ca,root,restart,audit,report["profiles"][label])
            report["profiles"][label].update(completed)
            report["profiles"][label]["server_log_sha256"]=sha(work/"server.log")
        except BaseException as error:
            report["failures"][label]=str(error) if isinstance(error,RuntimeError) or str(error).startswith("official_") else type(error).__name__
            import traceback
            report.setdefault("failure_frames",{})[label]=[{"file":Path(f.filename).name,"line":f.lineno,"function":f.name} for f in traceback.extract_tb(error.__traceback__)]
        finally:
            try:
                if instance is not None:instance.stop()
                if oracle is not None:stop_oracle(oracle)
            except BaseException as error:report["failures"][label+"_cleanup"]=type(error).__name__
    report["candidate_binary_unchanged"]=report["candidate_binary_sha256"]==sha(a.binary)
    report["status"]="HOLD"
    private_write(a.output,report,replace=False)
    print(json.dumps({"status":report["status"],"failures":report["failures"],"profiles":{k:{"effect_versions":v["effect_versions"],"live_replay_observed":v.get("live_replay_observed"),"candidate_single_execution_verified":v.get("candidate_single_execution_verified")} for k,v in report["profiles"].items()}}))
    return 0 if not report["failures"] and report["candidate_binary_unchanged"] and len(report["profiles"])==2 else 1
if __name__=="__main__":raise SystemExit(main())

