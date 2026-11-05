#!/usr/bin/env python3
"""Pinned OpenBao 2.7.1 ControlGroups differential. Fresh private HTTPS fixtures only."""
from __future__ import annotations
import argparse, base64, hashlib, hmac, http.client, json, os, re, ssl, sys, time
from pathlib import Path
from urllib.parse import urlsplit
ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/"qa/openbao-acceptance"))
sys.path.insert(0,str(ROOT/"qa/single-node"))
sys.path.insert(0,str(ROOT/"clients/python/src"))
from smoke import Instance
from bao_http import private_write, private_read
from official_openbao_launcher import start_oracle,stop_oracle,restart_oracle,verify_inputs,pinned_artifact
from oidc_renewal_live import free_port
from online_evidence import source_identity
import owned_process

REQUIRED_CASES = frozenset(["all_factors_met","all_factors_met_semantics","approved_still_deferred_absent","audit_authorize","audit_client_tokens_redacted","audit_deferred_operation","audit_fixture_configured","audit_unwrap","complete","duplicate_entity_not_counted","duplicate_entity_not_counted_semantics","duplicate_ops_one","duplicate_ops_one_approved","expired_approval_denied","expired_defer","expired_defer_wrapped","expired_never_executed","expired_review_denied","expired_unwrap_denied","foreign_namespace_approve_denied","foreign_namespace_no_approval_effect","foreign_namespace_no_approval_effect_semantics","foreign_namespace_review_denied","foreign_namespace_unwrap_denied","global_requester_login","global_requester_role_policy","global_requester_roleid","global_requester_sid","global_self_auth_allowed_policy","global_self_authorization_true","global_self_authorization_true_approved","global_self_defer","global_self_defer_wrapped","global_self_execute","global_self_review","global_self_review_semantics","global_self_value","mount_approle","mount_kv","namespace_correct_approval","namespace_correct_approval_approved","namespace_correct_execute","namespace_correct_value","namespace_create","namespace_owner_defer","namespace_owner_defer_wrapped","one_approval_threshold_unmet","one_approval_threshold_unmet_semantics","ops-one_entity","ops-one_login","ops-one_role","ops-one_roleid","ops-one_sid","ops-two_entity","ops-two_login","ops-two_role","ops-two_roleid","ops-two_sid","ops_group","ops_one_approval","ops_one_approval_approved","ops_two_overlap_approval","ops_two_overlap_approval_approved","outsider_cannot_authorize","outsider_does_not_count","outsider_does_not_count_semantics","outsider_entity","outsider_login","outsider_role","outsider_roleid","outsider_sid","owned_restart_completed","read_capability_seed","reboot_approved_before_restart","reboot_approved_before_restart_approved","reboot_defer","reboot_defer_wrapped","reboot_execute","reboot_one_use","reboot_preexecution_absent","reboot_review_preserved","reboot_review_preserved_semantics","reboot_value","requester_entity","requester_login","requester_policy","requester_role","requester_roleid","requester_sid","reviewer_policy","sec-one_entity","sec-one_login","sec-one_role","sec-one_roleid","sec-one_sid","security_group","security_met_ops_unmet","security_met_ops_unmet_semantics","security_one_approval","security_one_approval_approved","self_authorization_false_denied","self_authorization_true","self_authorization_true_approved","self_no_defer","self_no_defer_wrapped","self_no_execute","self_no_executed_exactly_once","self_no_one_use","self_no_other_approval","self_no_other_approval_approved","self_no_review","self_no_review_semantics","self_no_value","self_yes_defer","self_yes_defer_wrapped","self_yes_execute","self_yes_review","self_yes_review_semantics","self_yes_value","threshold_after_execute_value","threshold_after_unapproved_absent","threshold_before_approval_absent","threshold_defer","threshold_defer_wrapped","threshold_execute","threshold_executed_exactly_once","threshold_initial_review","threshold_initial_review_semantics","threshold_one_use","threshold_unapproved_unwrap","uncontrolled_read","uncontrolled_read_returns_value"])

def call(addr,ca,method,path,token="",body=None,namespace=""):
    u=urlsplit(addr)
    c=http.client.HTTPSConnection(u.hostname,u.port,context=ssl.create_default_context(cafile=str(ca)),timeout=15)
    headers={"Connection":"close","Content-Type":"application/json"}
    if token:headers["X-Vault-Token"]=token
    if namespace:headers["X-Vault-Namespace"]=namespace
    try:
        c.request(method,"/v1/"+path,body=None if body is None else json.dumps(body).encode(),headers=headers)
        r=c.getresponse();raw=r.read(1024*1024+1)
        if len(raw)>1024*1024:raise RuntimeError("oversize_response")
        return r.status,json.loads(raw) if raw else {}
    finally:c.close()

def scenario(label,addr,ca,root,restart,rows,audit):
    expected_operations={};expected_requests={};wrappers=[]
    def check(case,condition,status=None,observation=None):
        row={"case":case,"passed":condition is True}
        if status is not None:row["status"]=status
        if observation is not None:row["observation"]=observation
        rows.append(row)
    def req(case,method,path,body=None,token=None,expected=(200,204),ns="",required=False):
        s,d=call(addr,ca,method,path,root if token is None else token,body,ns)
        check(case,s in expected,s)
        if required and s not in expected:raise RuntimeError(case)
        return s,d
    def review(case,accessor,token,approved=None,count=None):
        s,d=req(case,"POST","sys/control-group/request",{"accessor":accessor},token,(200,))
        data=d.get("data",{})
        expected=expected_requests.get(accessor,{})
        condition=s==200 and data.get("request_operation")==expected_operations.get(accessor) and data.get("request_path")==expected.get("path") and data.get("request_data")==expected.get("body") and data.get("request_entity",{}).get("ID")==expected.get("entity")
        if approved is not None:condition=condition and data.get("approved") is approved
        if count is not None:condition=condition and len(data.get("authorizations",[]))==count
        check(case+"_semantics",condition,observation={"approved":data.get("approved"),"authorizations_count":len(data.get("authorizations",[])),"operation":data.get("request_operation"),"path_matches":data.get("request_path")==expected.get("path"),"payload_matches":data.get("request_data")==expected.get("body"),"requester_matches":data.get("request_entity",{}).get("ID")==expected.get("entity")})
        return data
    def approve(case,accessor,token,approved):
        s,d=req(case,"POST","sys/control-group/authorize",{"accessor":accessor},token,(200,))
        check(case+"_approved",s==200 and d.get("data",{}).get("approved") is approved,observation={"approved":d.get("data",{}).get("approved")})
    def deferred(case,path,token,value):
        prior_status,_=call(addr,ca,"GET","secret/metadata/"+path,root)
        if prior_status not in (200,404):raise RuntimeError(case+"_existence_authority_failed")
        s,d=req(case,"POST","secret/data/"+path,{"data":{"value":value}},token,(200,),required=True)
        w=d.get("wrap_info",{})
        check(case+"_wrapped",bool(w.get("token")) and bool(w.get("accessor")) and not d.get("data") and w.get("creation_path")=="secret/data/"+path)
        if not w.get("token") or not w.get("accessor"):raise RuntimeError(case+"_not_deferred")
        expected_operations[w["accessor"]]="update" if prior_status==200 else "create"
        expected_requests[w["accessor"]]={"path":"secret/data/"+path,"body":{"data":{"value":value}},"entity":next((entities[n] for n,v in users.items() if v==token),None)}
        wrappers.append(w["token"])
        return w["token"],w["accessor"]
    def rootvalue(case,path,expected=None,absent=False):
        s,d=call(addr,ca,"GET","secret/data/"+path,root)
        if absent:check(case,s==404 and not d.get("data"),s)
        else:check(case,s==200 and d.get("data",{}).get("data",{}).get("value")==expected,s)
        return d
    def unwrap(case,token,expected=(200,),value=None):
        s,d=req(case,"POST","sys/wrapping/unwrap",{},token,expected)
        if value is not None:check(case+"_value",d.get("data",{}).get("data",{}).get("value")==value)
        return s,d
    req("mount_kv","POST","sys/mounts/secret",{"type":"kv","options":{"version":"2"}},expected=(204,),required=True)
    req("mount_approle","POST","sys/auth/approle",{"type":"approle"},expected=(204,),required=True)
    check("audit_fixture_configured",audit.is_file())
    reviewer='path "sys/control-group/*" { capabilities = ["update"] }'
    req("reviewer_policy","PUT","sys/policies/acl/cg-reviewer",{"policy":reviewer},expected=(204,),required=True)
    def stanza(path,ttl,factors):
        factorstr=""
        for name,group,count,selfyes in factors:
            factorstr+=' factor "'+name+'" { controlled_capabilities=["create","update"] identity { group_names=["'+group+'"] approvals='+str(count)+' self_authorization='+str(selfyes).lower()+' } }'
        return 'path "secret/data/'+path+'" { capabilities=["create","update","read"] control_group={ ttl="'+ttl+'"'+factorstr+' } }\n'
    policy=stanza("threshold","90s",[("ops","ops",2,False),("security","security",1,False)])
    policy+=stanza("self-no","90s",[("ops","ops",1,False)])
    policy+=stanza("self-yes","90s",[("ops","ops",1,True)])
    policy+=stanza("expired","2s",[("ops","ops",1,False)])
    policy+=stanza("reboot","90s",[("ops","ops",1,False)])
    policy+=stanza("read-capability","90s",[("ops","ops",1,False)])
    req("requester_policy","PUT","sys/policies/acl/cg-requester",{"policy":policy+reviewer},expected=(204,),required=True)
    users={};entities={}
    for name in ("requester","ops-one","ops-two","sec-one","outsider"):
        policies=["cg-requester"] if name=="requester" else ["cg-reviewer"]
        req(name+"_role","POST","auth/approle/role/"+name,{"token_policies":policies,"token_ttl":"10m","secret_id_ttl":"10m"},expected=(204,),required=True)
        _,r=req(name+"_roleid","GET","auth/approle/role/"+name+"/role-id",expected=(200,),required=True)
        _,s=req(name+"_sid","POST","auth/approle/role/"+name+"/secret-id",{},expected=(200,),required=True)
        _,a=req(name+"_login","POST","auth/approle/login",{"role_id":r["data"]["role_id"],"secret_id":s["data"]["secret_id"]},token="",expected=(200,),required=True)
        users[name]=a["auth"]["client_token"];entities[name]=a["auth"].get("entity_id","")
        check(name+"_entity",bool(entities[name]))
    req("ops_group","POST","identity/group",{"name":"ops","type":"internal","member_entity_ids":[entities[n] for n in ("requester","ops-one","ops-two")]},expected=(200,),required=True)
    req("security_group","POST","identity/group",{"name":"security","type":"internal","member_entity_ids":[entities["sec-one"],entities["ops-two"]]},expected=(200,),required=True)
    u=users["requester"];a1=users["ops-one"];a2=users["ops-two"];b1=users["sec-one"];out=users["outsider"]
    wt,ac=deferred("threshold_defer","threshold",u,"threshold-value")
    rootvalue("threshold_before_approval_absent","threshold",absent=True)
    review("threshold_initial_review",ac,a1,False,0)
    unwrap("threshold_unapproved_unwrap",wt,(400,403))
    rootvalue("threshold_after_unapproved_absent","threshold",absent=True)
    s,d=call(addr,ca,"POST","sys/control-group/authorize",out,{"accessor":ac})
    check("outsider_cannot_authorize",s>=400 or d.get("data",{}).get("approved") is False,s,{"approved":d.get("data",{}).get("approved")})
    review("outsider_does_not_count",ac,a1,False,0)
    approve("ops_one_approval",ac,a1,False)
    review("one_approval_threshold_unmet",ac,a1,False,1)
    s,d=req("duplicate_ops_one","POST","sys/control-group/authorize",{"accessor":ac},a1,(200,500))
    check("duplicate_ops_one_approved",(s==500 and not d.get("data")) or (s==200 and d.get("data",{}).get("approved") is False),observation={"approved":d.get("data",{}).get("approved")})
    review("duplicate_entity_not_counted",ac,a1,False,1)
    approve("security_one_approval",ac,b1,False)
    review("security_met_ops_unmet",ac,a1,False,2)
    approve("ops_two_overlap_approval",ac,a2,True)
    review("all_factors_met",ac,a1,True,3)
    rootvalue("approved_still_deferred_absent","threshold",absent=True)
    unwrap("threshold_execute",wt)
    rootvalue("threshold_after_execute_value","threshold","threshold-value")
    unwrap("threshold_one_use",wt,(400,403))
    _,d=call(addr,ca,"GET","secret/metadata/threshold",root)
    check("threshold_executed_exactly_once",d.get("data",{}).get("current_version")==1,observation={"current_version":d.get("data",{}).get("current_version")})
    wt,ac=deferred("self_no_defer","self-no",u,"self-no-value")
    s,d=call(addr,ca,"POST","sys/control-group/authorize",u,{"accessor":ac})
    check("self_authorization_false_denied",s>=400,s)
    review("self_no_review",ac,a1,False,0)
    approve("self_no_other_approval",ac,a1,True)
    unwrap("self_no_execute",wt);rootvalue("self_no_value","self-no","self-no-value")
    unwrap("self_no_one_use",wt,(400,403))
    _,d=call(addr,ca,"GET","secret/metadata/self-no",root)
    check("self_no_executed_exactly_once",d.get("data",{}).get("current_version")==1,observation={"current_version":d.get("data",{}).get("current_version")})
    wt,ac=deferred("self_yes_defer","self-yes",u,"self-yes-value")
    approve("self_authorization_true",ac,u,True)
    review("self_yes_review",ac,a1,True,1)
    unwrap("self_yes_execute",wt);rootvalue("self_yes_value","self-yes","self-yes-value")
    wt,ac=deferred("expired_defer","expired",u,"expired-value")
    time.sleep(3.1)
    s,d=call(addr,ca,"POST","sys/control-group/request",a1,{"accessor":ac});check("expired_review_denied",s>=400,s)
    s,d=call(addr,ca,"POST","sys/control-group/authorize",a1,{"accessor":ac});check("expired_approval_denied",s>=400,s)
    unwrap("expired_unwrap_denied",wt,(400,403))
    rootvalue("expired_never_executed","expired",absent=True)
    req("read_capability_seed","POST","secret/data/read-capability",{"data":{"value":"read-without-control"}},expected=(200,))
    s,d=req("uncontrolled_read","GET","secret/data/read-capability",token=u,expected=(200,))
    check("uncontrolled_read_returns_value",d.get("data",{}).get("data",{}).get("value")=="read-without-control" and not d.get("wrap_info"))
    wt,ac=deferred("reboot_defer","reboot",u,"reboot-value")
    approve("reboot_approved_before_restart",ac,a1,True)
    restart()
    check("owned_restart_completed",True,observation={"fault":"SIGKILL"})
    review("reboot_review_preserved",ac,a1,True,1)
    rootvalue("reboot_preexecution_absent","reboot",absent=True)
    unwrap("reboot_execute",wt);rootvalue("reboot_value","reboot","reboot-value")
    unwrap("reboot_one_use",wt,(400,403))
    s,d=req("namespace_create","POST","sys/namespaces/cg-other",{},expected=(200,),required=True)
    wt,ac=deferred("namespace_owner_defer","self-no",u,"namespace-value")
    s,d=call(addr,ca,"POST","sys/control-group/request",root,{"accessor":ac},"cg-other")
    check("foreign_namespace_review_denied",s>=400,s)
    s,d=call(addr,ca,"POST","sys/control-group/authorize",root,{"accessor":ac},"cg-other")
    check("foreign_namespace_approve_denied",s>=400,s)
    s,d=call(addr,ca,"POST","sys/wrapping/unwrap",wt,{},"cg-other")
    check("foreign_namespace_unwrap_denied",s>=400,s)
    review("foreign_namespace_no_approval_effect",ac,a1,False,0)
    approve("namespace_correct_approval",ac,a1,True)
    unwrap("namespace_correct_execute",wt)
    rootvalue("namespace_correct_value","self-no","namespace-value")
    audit_rows=[json.loads(line) for line in audit.read_text().splitlines()]
    for name,path in (("audit_deferred_operation","secret/data/threshold"),("audit_authorize","sys/control-group/authorize"),("audit_unwrap","sys/wrapping/unwrap")):
        if label=="official":
            observed=any(r.get("type")=="request" and r.get("request",{}).get("path")==path for r in audit_rows)
        else:
            key=(audit.parent/(audit.name+".hmac-key")).read_bytes()
            expected=set()
            for token in list(users.values())+wrappers+[root]:
                payload=b"heptabao.audit.request-fingerprint.v2"
                for field in ("POST","",path,token):
                    encoded=field.encode();payload+=len(encoded).to_bytes(8,"little")+encoded
                expected.add(base64.b64encode(hmac.new(key,payload,hashlib.sha256).digest()).decode())
            observed=any(r.get("event",{}).get("kind")=="request" and r.get("event",{}).get("path_digest") in expected for r in audit_rows)
        check(name,observed)
    audit_raw=audit.read_bytes()
    check("audit_client_tokens_redacted",all(v.encode() not in audit_raw for v in list(users.values())+wrappers+[root]))
    global_policy='path "secret/data/self-global" { capabilities=["create","update","read"] control_group={ ttl="90s" self_auth_allowed=true factor "ops" { controlled_capabilities=["create","update"] identity { group_names=["ops"] approvals=1 } } } }'
    gs,gd=req("global_self_auth_allowed_policy","PUT","sys/policies/acl/cg-global",{"policy":global_policy+reviewer},expected=(204,))
    if gs==204:
        req("global_requester_role_policy","POST","auth/approle/role/requester",{"token_policies":["cg-requester","cg-global"]},expected=(204,))
        _,rr=req("global_requester_roleid","GET","auth/approle/role/requester/role-id",expected=(200,))
        _,ss=req("global_requester_sid","POST","auth/approle/role/requester/secret-id",{},expected=(200,))
        _,aa=req("global_requester_login","POST","auth/approle/login",{"role_id":rr["data"]["role_id"],"secret_id":ss["data"]["secret_id"]},token="",expected=(200,))
        gu=aa["auth"]["client_token"];users["global-requester"]=gu;entities["global-requester"]=aa["auth"]["entity_id"]
        wt,ac=deferred("global_self_defer","self-global",gu,"global-self-value")
        approve("global_self_authorization_true",ac,gu,True)
        review("global_self_review",ac,a1,True,1)
        unwrap("global_self_execute",wt);rootvalue("global_self_value","self-global","global-self-value")
    check("complete",True)

def main():
    p=argparse.ArgumentParser();p.add_argument("--binary",type=Path,required=True);p.add_argument("--output",type=Path,required=True);p.add_argument("--private-work-root",type=Path,required=True);p.add_argument("--candidate-source",required=True);a=p.parse_args()
    os.umask(0o077)
    if not re.fullmatch(r"[0-9a-f]{40}",a.candidate_source):raise RuntimeError("candidate_source_requires_full_commit")
    if a.output.exists():raise RuntimeError("report_already_exists")
    a.private_work_root.mkdir(mode=0o700,parents=False,exist_ok=False)
    before=source_identity(ROOT,a.binary);verify_inputs(version="2.7.1")
    report={"schema":"heptabao.controlgroups271.differential.v2","runner_source":{k:v for k,v in before.items() if k!="binary_sha256"},"candidate_binary_sha256":before["binary_sha256"],"official":pinned_artifact(version="2.7.1"),"tls_verified":True,"synthetic_only":True,"scope":"fresh-root-namespace-single-node-controls","candidate_runtime_source_commit":a.candidate_source,"candidate_runtime_source_tree":owned_process.check_output(["git","rev-parse",a.candidate_source+"^{tree}"],cwd=ROOT,label="controlgroups271.runtime-tree").decode().strip(),"official_primary_source_controlgroup_sha256":"c7d0cc2d25d28f3b52a1601aef44cae1df87192b3ccae157c53566040dacaba1","production_authority":False,"replacement_authority":False,"observations":{},"failures":{}}
    os.environ["HB_ORACLE_WORK_ROOT"]=str(a.private_work_root)
    for label in ("official","candidate"):
        instance=None;oracle=None
        try:
            if label=="official":
                oracle=start_oracle(free_port(),version="2.7.1",audit_file=True);addr=oracle["address"];ca=Path(oracle["ca_file"]);raw_token=private_read(Path(oracle["token_file"]));root=(raw_token.decode() if isinstance(raw_token,bytes) else raw_token).strip();audit=Path(oracle["root"])/"audit.jsonl"
                def restart():
                    owned_process.stop(oracle["process"],action="KILL",timeout=5,expected_codes=(-9,))
                    oracle["log"].close();restart_oracle(oracle)
            else:
                instance=Instance(a.binary,a.private_work_root/"candidate");instance.start()
                s,d=instance.call("POST","sys/init",{"secret_shares":1,"secret_threshold":1})
                if s!=200:raise RuntimeError("candidate_init")
                root=d["root_token"];key=d["keys_base64"][0];instance.token=root
                if instance.call("POST","sys/unseal",{"key":key})[0]!=200:raise RuntimeError("candidate_unseal")
                addr=instance.address;ca=instance.root/"ca.crt";audit=instance.root/"audit.jsonl"
                def restart():
                    instance.stop();instance.start()
                    if instance.call("POST","sys/unseal",{"key":key})[0]!=200:raise RuntimeError("candidate_restart_unseal")
            report["observations"][label]=[]
            scenario(label,addr,ca,root,restart,report["observations"][label],audit)
        except BaseException as error:
            report["failures"][label]=str(error) if isinstance(error,RuntimeError) else type(error).__name__
            import traceback
            report.setdefault("failure_frames",{})[label]=[{"file":Path(f.filename).name,"line":f.lineno,"function":f.name} for f in traceback.extract_tb(error.__traceback__)]
        finally:
            try:
                if instance is not None:instance.stop()
                if oracle is not None:stop_oracle(oracle)
            except BaseException as error:report["failures"][label+"_cleanup"]=type(error).__name__
    after=source_identity(ROOT,a.binary);report["runner_source_and_candidate_binary_unchanged"]=before==after
    official={r["case"]:r for r in report["observations"].get("official",[])};candidate={r["case"]:r for r in report["observations"].get("candidate",[])}
    report["mismatches"]=[{"case":k,"official":official.get(k),"candidate":candidate.get(k)} for k in sorted(official.keys()|candidate.keys()) if official.get(k)!=candidate.get(k)]
    report["candidate_control_semantics_passed"]=(set(candidate)==REQUIRED_CASES and len(candidate)==132 and all(r["passed"] for r in candidate.values()) and not report["failures"] and before==after)
    report["strict_differential_passed"]=(not report["mismatches"] and set(official)==set(candidate)==REQUIRED_CASES and len(official)==len(candidate)==132 and all(r["passed"] for rows in report["observations"].values() for r in rows))
    report["status"]="passed" if report["candidate_control_semantics_passed"] and report["strict_differential_passed"] else "failed"
    private_write(a.output,report,replace=False)
    print(json.dumps({"status":report["status"],"failures":report["failures"],"counts":{k:{"total":len(v),"passed":sum(r["passed"] for r in v)} for k,v in report["observations"].items()},"mismatch_cases":[r["case"] for r in report["mismatches"]],"candidate_control_semantics_passed":report["candidate_control_semantics_passed"]}))
    return 0 if report["status"]=="passed" else 1
if __name__=="__main__":raise SystemExit(main())

