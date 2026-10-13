#!/usr/bin/env python3
"""OpenBao 2.7.1 AppRole expiry and URL-encoded login observations.
Only newly allocated private loopback TLS fixtures. This runner records bounded
positive/negative behavior, never whole-surface or replacement admission.
"""
from __future__ import annotations
import argparse, hashlib, http.client, json, os, ssl, sys, tempfile, time
from pathlib import Path
from urllib.parse import urlencode
ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "qa/openbao-acceptance"))
sys.path.insert(0, str(ROOT / "qa/single-node"))
sys.path.insert(0, str(ROOT / "clients/python/src"))
from smoke import Instance
from bao_http import private_write, private_read
from official_openbao_launcher import start_oracle, stop_oracle, restart_oracle, verify_inputs, pinned_artifact
from oidc_renewal_live import free_port
from online_evidence import source_identity

def call(address, ca, method, path, token="", body=None, form=False):
    from urllib.parse import urlsplit
    u=urlsplit(address)
    c=http.client.HTTPSConnection(u.hostname,u.port,context=ssl.create_default_context(cafile=str(ca)),timeout=15)
    headers={"Connection":"close"}
    if token: headers["X-Vault-Token"]=token
    if body is not None:
        headers["Content-Type"]="application/x-www-form-urlencoded" if form else "application/json"
        raw=urlencode(body).encode() if form else json.dumps(body).encode()
    else: raw=None
    try:
        c.request(method,"/v1/"+path,body=raw,headers=headers)
        r=c.getresponse();b=r.read(65537)
        if len(b)>65536: raise RuntimeError("oversize_response")
        return r.status, json.loads(b) if b else {}
    finally:c.close()

def scenario(label,address,ca,root_token,restart, rows=None):
    rows=[] if rows is None else rows; sensitive=[]; started=time.monotonic()
    def check(case,condition,status=None):
        row={"case":case,"passed":condition is True}
        if status is not None:row["status"]=status
        rows.append(row)
        if condition is not True:raise RuntimeError(case)
    def req(case,method,path,body=None,expected=204,token=None,form=False):
        status,data=call(address,ca,method,path,root_token if token is None else token,body,form)
        check(case,status==expected,status);return data
    def denied(case,path,body,form=False):
        status,data=call(address,ca,"POST",path,"",body,form)
        check(case,status in (400,403) and not data.get("auth") and not data.get("wrap_info"),status)
    for mount in ("approle","custom-approle"):
        req(mount+"_mount","POST","sys/auth/"+mount,{"type":"approle"})
        req(mount+"_role","POST","auth/"+mount+"/role/live",{"secret_id_ttl":60,"token_ttl":60,"token_max_ttl":120,"secret_id_num_uses":0})
        role=req(mount+"_roleid","GET","auth/"+mount+"/role/live/role-id",expected=200)["data"]["role_id"]
        sec=req(mount+"_secret","POST","auth/"+mount+"/role/live/secret-id",{},200)["data"]
        sensitive.append(sec["secret_id"])
        for codec,form in (("json",False),("form",True)):
            try:
                status,data=call(address,ca,"POST","auth/"+mount+"/login","",{"role_id":role,"secret_id":sec["secret_id"]},form)
            except (OSError,http.client.HTTPException) as error:
                rows.append({"case":mount+"_login_"+codec,"status":None,"passed":False,"transport_error":type(error).__name__})
                continue
            rows.append({"case":mount+"_login_"+codec,"status":status,"passed":status==200 and bool(data.get("auth",{}).get("client_token"))})
            if data.get("auth",{}).get("client_token"):sensitive.append(data["auth"]["client_token"])
        denied(mount+"_invalid_secret_json","auth/"+mount+"/login",{"role_id":role,"secret_id":"synthetic-invalid"})
    req("expiry_role","POST","auth/approle/role/expires",{"secret_id_ttl":2,"token_ttl":60,"secret_id_num_uses":0})
    role=req("expiry_roleid","GET","auth/approle/role/expires/role-id",expected=200)["data"]["role_id"]
    sec=req("expiry_issue","POST","auth/approle/role/expires/secret-id",{},200)["data"]
    sensitive.append(sec["secret_id"])
    live=req("expiry_live_login","POST","auth/approle/login",{"role_id":role,"secret_id":sec["secret_id"]},200,token="")
    check("expiry_live_auth",bool(live.get("auth",{}).get("client_token")))
    issued=time.monotonic()
    time.sleep(3.1)
    check("expiry_before_periodic_tidy",3.0 <= time.monotonic()-issued < 60 and time.monotonic()-started < 55)
    denied("expired_json_before_tidy","auth/approle/login",{"role_id":role,"secret_id":sec["secret_id"]})
    denied("expired_form_before_tidy","auth/approle/login",{"role_id":role,"secret_id":sec["secret_id"]},True)
    restart()
    denied("expired_json_after_restart","auth/approle/login",{"role_id":role,"secret_id":sec["secret_id"]})
    denied("expired_form_after_restart","auth/approle/login",{"role_id":role,"secret_id":sec["secret_id"]},True)
    rows.append({"case":"complete","passed":True})
    return rows

def main():
    parser=argparse.ArgumentParser();parser.add_argument("--binary",type=Path,required=True);parser.add_argument("--output",type=Path,required=True);parser.add_argument("--private-work-root",type=Path,required=True)
    a=parser.parse_args();os.umask(0o077)
    if a.output.exists():raise RuntimeError("report_already_exists")
    a.private_work_root.mkdir(mode=0o700,parents=False,exist_ok=False)
    before=source_identity(ROOT,a.binary)
    official_binary=verify_inputs(version="2.7.1")
    report={"schema":"heptabao.openbao271-approle-security-observation.v1",**before,"official":pinned_artifact(version="2.7.1"),"official_version":"2.7.1","tls_verified":True,"synthetic_only":True,"independent_qualification":False,"compatibility_claim":False,"production_authority":False,"replacement_authority":False,"observations":{},"failures":{}}
    os.environ["HB_ORACLE_WORK_ROOT"]=str(a.private_work_root)
    for label in ("official","candidate"):
        instance=None;oracle=None
        try:
            if label=="official":
                oracle=start_oracle(free_port(),version="2.7.1")
                address=oracle["address"];ca=Path(oracle["ca_file"]);token=private_read(Path(oracle["token_file"])).strip()
                def restart():
                    stop_oracle(oracle);restart_oracle(oracle)
            else:
                instance=Instance(a.binary,a.private_work_root/"candidate");instance.start()
                status,init=instance.call("POST","sys/init",{"secret_shares":1,"secret_threshold":1})
                if status!=200:raise RuntimeError("candidate_initialize")
                token=init["root_token"];key=init["keys_base64"][0];instance.token=token
                if instance.call("POST","sys/unseal",{"key":key})[0]!=200:raise RuntimeError("candidate_unseal")
                address=instance.address;ca=instance.root/"ca.crt"
                def restart():
                    instance.stop();instance.start()
                    if instance.call("POST","sys/unseal",{"key":key})[0]!=200:raise RuntimeError("candidate_restart_unseal")
            report["observations"][label]=[]
            scenario(label,address,ca,token,restart,report["observations"][label])
        except BaseException as error:
            report["failures"][label]=type(error).__name__ if not isinstance(error,RuntimeError) else str(error)
        finally:
            if instance is not None:instance.stop()
            if oracle is not None:stop_oracle(oracle)
    after=source_identity(ROOT,a.binary);report["source_and_binary_unchanged"]=before==after
    official={r["case"]:r for r in report["observations"].get("official",[])}
    candidate={r["case"]:r for r in report["observations"].get("candidate",[])}
    report["mismatches"]=[{"case":k,"official_status":official[k].get("status"),"candidate_status":candidate[k].get("status")} for k in sorted(official.keys()&candidate.keys()) if official[k].get("status")!=candidate[k].get("status") or official[k]["passed"]!=candidate[k]["passed"]]
    report["status"]="passed" if not report["failures"] and not report["mismatches"] and before==after and all(r["passed"] for rows in report["observations"].values() for r in rows) and len(report["observations"])==2 and all(len(rows)==25 and len({r["case"] for r in rows})==25 and rows[-1]["case"]=="complete" for rows in report["observations"].values()) else "failed"
    private_write(a.output,report,replace=False)
    print(json.dumps({"status":report["status"],"failures":report["failures"],"mismatches":report["mismatches"],"source_commit":before["source_commit"],"binary_sha256":before["binary_sha256"]}))
    return 0 if report["status"]=="passed" else 1
if __name__=="__main__":raise SystemExit(main())
