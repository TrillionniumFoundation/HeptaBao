#!/usr/bin/env python3
"""New private TLS fixture; finite-use AppRole negative custody checks only."""
from pathlib import Path
import argparse, http.client, importlib.util, json, os, ssl, sys
from urllib.parse import urlsplit, urlencode
ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/"qa/openbao-acceptance"))
sys.path.insert(0,str(ROOT/"qa/single-node"))
from smoke import Instance
from bao_http import private_write
from online_evidence import source_identity
def main():
    p=argparse.ArgumentParser();p.add_argument("--binary",type=Path,required=True);p.add_argument("--output",type=Path,required=True);p.add_argument("--private-work-root",type=Path,required=True);a=p.parse_args()
    os.umask(0o077);a.private_work_root.mkdir(mode=0o700,parents=False,exist_ok=False)
    before=source_identity(ROOT,a.binary);rows=[];instance=Instance(a.binary,a.private_work_root/"candidate")
    report={"schema":"heptabao.approle-form-negative-custody.v1",**before,"tls_verified":True,"synthetic_only":True,"replacement_authority":False,"production_authority":False}
    def raw(method,path,payload=None,media="application/json",token="",headers=None):
        u=urlsplit(instance.address);c=http.client.HTTPSConnection(u.hostname,u.port,context=ssl.create_default_context(cafile=str(instance.root/"ca.crt")),timeout=15)
        h={"Connection":"close"}
        if token:h["X-Vault-Token"]=token
        if payload is not None:h["Content-Type"]=media
        h.update(headers or {})
        try:
            c.request(method,"/v1/"+path,body=payload,headers=h);r=c.getresponse();b=r.read(65537)
            if len(b)>65536:raise RuntimeError("oversize_response")
            return r.status,json.loads(b) if b else {}
        finally:c.close()
    def check(name,expected,method,path,payload=None,media="application/json",token="",headers=None,auth=False):
        try:
            status,data=raw(method,path,payload,media,token,headers)
            okay=status==expected and (bool(data.get("auth",{}).get("client_token")) if auth else not data.get("auth") and not data.get("wrap_info"))
            rows.append({"case":name,"status":status,"passed":okay})
            if not okay:raise RuntimeError(name)
            return data
        except (OSError,http.client.HTTPException) as e:
            rows.append({"case":name,"status":None,"passed":False,"transport_error":type(e).__name__});raise RuntimeError(name)
    try:
        instance.start();status,init=instance.call("POST","sys/init",{"secret_shares":1,"secret_threshold":1})
        if status!=200:raise RuntimeError("init")
        admin=init["root_token"];key=init["keys_base64"][0];instance.token=admin
        if instance.call("POST","sys/unseal",{"key":key})[0]!=200:raise RuntimeError("unseal")
        def admin_json(name,expected,method,path,body=None):
            return check(name,expected,method,path,json.dumps(body).encode() if body is not None else None,token=admin)
        admin_json("custom_mount",204,"POST","sys/auth/forms",{"type":"approle"})
        admin_json("finite_role",204,"POST","auth/forms/role/finite",{"secret_id_num_uses":1,"token_ttl":60})
        role=admin_json("role_id",200,"GET","auth/forms/role/finite/role-id")["data"]["role_id"]
        sid=admin_json("finite_secret",200,"POST","auth/forms/role/finite/secret-id",{})["data"]["secret_id"]
        form=urlencode({"role_id":role,"secret_id":sid}).encode()
        media="application/x-www-form-urlencoded"
        check("duplicate_fields",400,"POST","auth/forms/login",form+b"&role_id=other",media)
        check("malformed_percent",400,"POST","auth/forms/login",b"role_id=%GG&secret_id=synthetic",media)
        check("form_query_mixture",400,"POST","auth/forms/login?role_id=other",form,media)
        check("unknown_mount",400,"POST","auth/unknown/login",form,media)
        admin_json("userpass_mount",204,"POST","sys/auth/users",{"type":"userpass"})
        check("wrong_mount_kind",400,"POST","auth/users/login",form,media)
        check("finite_form_valid_after_all_rejections",200,"POST","auth/forms/login",form,media,auth=True)
        check("finite_form_reuse_denied",400,"POST","auth/forms/login",form,media)
        admin_json("kv_mount",204,"POST","sys/mounts/form-test",{"type":"kv","options":{"version":"2"}})
        marker={"X-HeptaBao-Internal-Auth-Form-Codec":"approle-form-v1"}
        check("fake_codec_header_json_kv",200,"POST","form-test/data/key",json.dumps({"data":{"value":"synthetic"}}).encode(),token=admin,headers=marker)
        read=check("fake_codec_header_json_read",200,"GET","form-test/data/key",token=admin,headers=marker)
        if read.get("data",{}).get("data",{}).get("value")!="synthetic":raise RuntimeError("kv_value")
        report["failure"]=None
    except BaseException as e:
        report["failure"]=str(e) if isinstance(e,RuntimeError) else type(e).__name__
    finally:instance.stop()
    after=source_identity(ROOT,a.binary);report["source_and_binary_unchanged"]=before==after;report["observations"]=rows
    report["status"]="passed" if report["failure"] is None and before==after and len(rows)==15 and all(r["passed"] for r in rows) else "failed"
    private_write(a.output,report,replace=False)
    print(json.dumps({"status":report["status"],"failure":report["failure"],"rows":len(rows),"passed":sum(r["passed"] for r in rows),"source_commit":before["source_commit"],"binary_sha256":before["binary_sha256"]}))
    return 0 if report["status"]=="passed" else 1
if __name__=="__main__":raise SystemExit(main())
