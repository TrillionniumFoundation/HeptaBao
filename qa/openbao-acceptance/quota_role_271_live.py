#!/usr/bin/env python3
"""Pinned 2.7.1 bounded root native-AppRole role-quota differential.
New private loopback TLS fixtures only; public results have no credentials."""
from pathlib import Path
import argparse, http.client, importlib.util, json, os, ssl, time
from urllib.parse import urlsplit,urlencode
def main():
    p=argparse.ArgumentParser();p.add_argument("--source-root",type=Path,required=True);p.add_argument("--binary",type=Path,required=True);p.add_argument("--output",type=Path,required=True);p.add_argument("--private-work-root",type=Path,required=True);p.add_argument("--official-only",action="store_true");a=p.parse_args()
    os.umask(0o077);a.private_work_root.mkdir(mode=0o700,parents=False,exist_ok=False)
    spec=importlib.util.spec_from_file_location("fixtures",a.source_root/"qa/openbao-acceptance/approle_271_security_live.py")
    f=importlib.util.module_from_spec(spec);spec.loader.exec_module(f)
    before=f.source_identity(a.source_root,a.binary);f.verify_inputs(version="2.7.1");os.environ["HB_ORACLE_WORK_ROOT"]=str(a.private_work_root)
    report={"schema":"heptabao.openbao271-bounded-approle-role-quota.v1",**before,"official":f.pinned_artifact(version="2.7.1"),"candidate_executed":not a.official_only,"tls_verified":True,"synthetic_only":True,"replacement_authority":False,"production_authority":False,"observations":{},"failures":{}}
    for label in (("official",) if a.official_only else ("official","candidate")):
        oracle=None;instance=None;rows=[];report["observations"][label]=rows
        try:
            if label=="official":
                oracle=f.start_oracle(f.free_port(),version="2.7.1");address=oracle["address"];ca=Path(oracle["ca_file"]);admin=f.private_read(Path(oracle["token_file"])).strip()
                def restart():f.stop_oracle(oracle);f.restart_oracle(oracle)
            else:
                instance=f.Instance(a.binary,a.private_work_root/"candidate");instance.start();status,init=instance.call("POST","sys/init",{"secret_shares":1,"secret_threshold":1})
                if status!=200:raise RuntimeError("initialize")
                admin=init["root_token"];key=init["keys_base64"][0];instance.token=admin
                if instance.call("POST","sys/unseal",{"key":key})[0]!=200:raise RuntimeError("unseal")
                address=instance.address;ca=instance.root/"ca.crt"
                def restart():
                    instance.stop();instance.start()
                    if instance.call("POST","sys/unseal",{"key":key})[0]!=200:raise RuntimeError("restart_unseal")
            def req(case,method,path,body=None,expected=204,token=None,form=False,auth=False,spoof=False):
                u=urlsplit(address);c=http.client.HTTPSConnection(u.hostname,u.port,context=ssl.create_default_context(cafile=str(ca)),timeout=15)
                h={"Connection":"close"};token=admin if token is None else token
                if token:h["X-Vault-Token"]=token
                raw=None
                if body is not None:h["Content-Type"]="application/x-www-form-urlencoded" if form else "application/json";raw=urlencode(body).encode() if form else json.dumps(body).encode()
                if spoof:h.update({"X-Forwarded-For":"203.0.113.99","X-Real-IP":"203.0.113.100"})
                try:
                    c.request(method,"/v1/"+path,body=raw,headers=h);r=c.getresponse();b=r.read(65537)
                    if len(b)>65536:raise RuntimeError("oversize_response")
                    status=r.status;data=json.loads(b) if b else {}
                except (OSError,http.client.HTTPException) as e:
                    rows.append({"case":case,"passed":False,"status":None,"transport_error":type(e).__name__});raise RuntimeError(case)
                finally:c.close()
                good=status==expected and (bool(data.get("auth",{}).get("client_token")) if auth else not data.get("auth") and not data.get("wrap_info"))
                rows.append({"case":case,"status":status,"passed":good})
                if not good:raise RuntimeError(case)
                return data
            def check(case,good):
                rows.append({"case":case,"passed":good is True})
                if good is not True:raise RuntimeError(case)
            cfg=req("config_read","GET","sys/quotas/config",expected=200)["data"]
            check("config_flags_default_false",cfg.get("enable_rate_limit_audit_logging") is False and cfg.get("enable_rate_limit_response_headers") is False)
            for mount in ("approle","custom-approle"):
                def named(case):return mount+"_"+case
                path="auth/"+mount+"/role/limited";login="auth/"+mount+"/login";q="sys/quotas/rate-limit/"+mount+"-limited"
                req(named("mount"),"POST","sys/auth/"+mount,{"type":"approle"})
                req(named("limited_role"),"POST",path,{"secret_id_num_uses":1,"token_ttl":60})
                rid=req(named("limited_id"),"GET",path+"/role-id",expected=200)["data"]["role_id"]
                def sid(case):
                    return req(named(case),"POST",path+"/secret-id",{},expected=200)["data"]["secret_id"]
                first={"role_id":rid,"secret_id":sid("first_sid")};held={"role_id":rid,"secret_id":sid("held_sid")}
                otherpath="auth/"+mount+"/role/other"
                req(named("other_role"),"POST",otherpath,{"secret_id_num_uses":0,"token_ttl":60})
                otherrid=req(named("other_id"),"GET",otherpath+"/role-id",expected=200)["data"]["role_id"]
                othersec=req(named("other_sid"),"POST",otherpath+"/secret-id",{},expected=200)["data"]["secret_id"]
                definition={"path":"auth/"+mount+"/","role":"limited","rate":1,"interval":"2s","block_interval":"2s"}
                req(named("quota_create"),"POST",q,definition)
                data=req(named("quota_read"),"GET",q,expected=200)["data"]
                check(named("quota_definition_roundtrip"),data.get("path")=="auth/"+mount+"/" and data.get("role")=="limited" and data.get("rate")==1 and data.get("interval")==2 and data.get("block_interval")==2)
                listed=req(named("quota_list"),"LIST","sys/quotas/rate-limit",expected=200)["data"].get("keys",[])
                check(named("quota_list_contains"),mount+"-limited" in listed)
                req(named("json_first_allowed"),"POST",login,first,200,token="",auth=True)
                req(named("other_role_form_isolated"),"POST",login,{"role_id":otherrid,"secret_id":othersec},200,token="",form=True,auth=True)
                req(named("form_held_denied"),"POST",login,held,429,token="",form=True)
                req(named("json_held_denied"),"POST",login,held,429,token="")
                req(named("spoof_peer_cannot_bypass"),"POST",login,held,429,token="",form=True,spoof=True)
                time.sleep(3.1)
                req(named("held_form_after_refill_block"),"POST",login,held,200,token="",form=True,auth=True)
                req(named("quota_delete"),"DELETE",q)
                req(named("held_consumed_once"),"POST",login,held,400,token="")
                # POSTing identical definition is a real update and resets its limiter.
                fresh={"role_id":rid,"secret_id":sid("update_first_sid")};updateheld={"role_id":rid,"secret_id":sid("update_held_sid")}
                req(named("update_quota_create"),"POST",q,definition)
                req(named("update_initial_json"),"POST",login,fresh,200,token="",auth=True)
                req(named("update_held_denied"),"POST",login,updateheld,429,token="",form=True)
                req(named("same_definition_update"),"POST",q,definition)
                req(named("same_update_resets_limiter"),"POST",login,updateheld,200,token="",form=True,auth=True)
                req(named("update_quota_delete"),"DELETE",q)
                # Durable definition survives cold restart; per-node RAM bucket resets.
                cold={"role_id":rid,"secret_id":sid("cold_first_sid")};coldheld={"role_id":rid,"secret_id":sid("cold_held_sid")}
                colddef={"path":"auth/"+mount+"/","role":"limited","rate":1,"interval":"1h","block_interval":"0s"}
                req(named("cold_quota_create"),"POST",q,colddef)
                req(named("cold_initial_json"),"POST",login,cold,200,token="",auth=True)
                req(named("cold_held_denied"),"POST",login,coldheld,429,token="",form=True)
                restart()
                data=req(named("quota_after_restart"),"GET",q,expected=200)["data"]
                check(named("definition_persisted_after_restart"),data.get("path")=="auth/"+mount+"/" and data.get("role")=="limited" and data.get("interval")==3600 and data.get("rate")==1)
                req(named("local_bucket_reset_after_restart"),"POST",login,coldheld,200,token="",form=True,auth=True)
                req(named("cold_quota_delete"),"DELETE",q)
                req(named("cold_secret_consumed_once"),"POST",login,coldheld,400,token="")
            rows.append({"case":"complete","passed":True})
        except BaseException as e:report["failures"][label]=str(e) if isinstance(e,RuntimeError) else type(e).__name__
        finally:
            if instance:instance.stop()
            if oracle:f.stop_oracle(oracle)
    after=f.source_identity(a.source_root,a.binary);report["source_and_binary_unchanged"]=before==after
    if a.official_only:report["mismatches"]=[]
    else:
        o={r["case"]:r for r in report["observations"].get("official",[])};c={r["case"]:r for r in report["observations"].get("candidate",[])}
        report["mismatches"]=[{"case":k,"official_status":o[k].get("status"),"candidate_status":c[k].get("status")} for k in sorted(o.keys()&c.keys()) if o[k].get("status")!=c[k].get("status") or o[k]["passed"]!=c[k]["passed"]]
        if o.keys()!=c.keys():report["mismatches"].append({"case":"coverage_keys_differ"})
    report["expected_cases_per_endpoint"]=81
    report["harness_sha256"]=__import__("hashlib").sha256(Path(__file__).read_bytes()).hexdigest()
    report["status"]="passed" if before==after and not before["source_dirty"] and not report["failures"] and not report["mismatches"] and all(len(rows)==81 and len({r["case"] for r in rows})==81 and rows[-1]["case"]=="complete" and all(r["passed"] for r in rows) for rows in report["observations"].values()) else "failed"
    f.private_write(a.output,report,replace=False)
    print(json.dumps({"status":report["status"],"candidate_executed":not a.official_only,"failures":report["failures"],"mismatches":report["mismatches"],"counts":{k:len(v) for k,v in report["observations"].items()}}))
    return 0 if report["status"]=="passed" else 1
if __name__=="__main__":raise SystemExit(main())
