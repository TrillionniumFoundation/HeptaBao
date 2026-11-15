#!/usr/bin/env python3
"""Bounded real Service -> checksum-bound KMS provider qualification."""
from __future__ import annotations
import argparse, base64, hashlib, hmac, json, os, stat, sys, time
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "single-node"))
import smoke

KEY_ID="kms_fixture_key"
KEY_VERSION=7
AAD="7f"*32
PURPOSE="barrier_wrap"

def make_exec(path: Path, text: str) -> str:
    path.write_text(text, encoding="utf-8")
    path.chmod(stat.S_IRUSR|stat.S_IWUSR|stat.S_IXUSR)
    return hashlib.sha256(path.read_bytes()).hexdigest()

def configure(instance: smoke.Instance, root: Path):
    provider_key=root/"kms-provider-key.bin"
    provider_key.write_bytes(os.urandom(32)); provider_key.chmod(0o600)
    count=root/"kms-invocations.txt"
    wrapper=root/"kms-sandbox-wrapper.py"
    plugin=root/"kms-plugin.py"
    wrapper_sha=make_exec(wrapper, f"""#!{sys.executable}
import os,sys
a=sys.argv[1:]
def v(f): return a[a.index(f)+1]
if v("--heptabao-profile")!="kms_profile" or v("--heptabao-protocol")!="1" or v("--heptabao-operation")!="read":
    raise SystemExit(64)
os.execv(v("--heptabao-plugin"),[v("--heptabao-plugin")])
""")
    plugin_sha=make_exec(plugin, f"""#!{sys.executable}
import base64,hashlib,hmac,json,os,struct,sys,time
KEY=open({str(provider_key)!r},"rb").read()
COUNT={str(count)!r}
r=sys.stdin.buffer.read(1048588)
if len(r)<11 or r[:4]!=b"HBP1" or r[4:6]!=b"\\x00\\x01" or r[6]!=1: raise SystemExit(65)
n=struct.unpack(">I",r[7:11])[0]
if n==0 or len(r)!=11+n: raise SystemExit(65)
q=json.loads(r[11:].decode())
if q.get("key_id")!={KEY_ID!r} or q.get("key_version")!={KEY_VERSION}: raise SystemExit(66)
action=q.get("action"); aad=q.get("associated_data_digest"); purpose=q.get("purpose")
if not isinstance(aad,str) or len(aad)!=64 or not isinstance(purpose,str): raise SystemExit(66)
with open(COUNT,"a",encoding="utf-8") as f: f.write(action+"\\n")
if purpose=="timeout_case":
    time.sleep(2)
def wrap(raw):
    ctx=bytes.fromhex(aad)+purpose.encode()
    stream=hashlib.sha256(KEY+ctx).digest()
    enc=bytes(b^stream[i%len(stream)] for i,b in enumerate(raw))
    tag=hmac.new(KEY,ctx+enc,hashlib.sha256).digest()
    return base64.b64encode(enc+tag).decode()
def unwrap(token):
    blob=base64.b64decode(token,validate=True)
    if len(blob)<32: raise SystemExit(67)
    enc,tag=blob[:-32],blob[-32:]
    ctx=bytes.fromhex(aad)+purpose.encode()
    if not hmac.compare_digest(tag,hmac.new(KEY,ctx+enc,hashlib.sha256).digest()): raise SystemExit(67)
    stream=hashlib.sha256(KEY+ctx).digest()
    return bytes(b^stream[i%len(stream)] for i,b in enumerate(enc))
out={{"action":action,"key_id":{KEY_ID!r},"key_version":{KEY_VERSION}}}
if action=="wrap":
    out["ciphertext"]=wrap(base64.b64decode(q["plaintext"],validate=True))
elif action=="unwrap":
    out["plaintext"]=base64.b64encode(unwrap(q["ciphertext"])).decode()
elif action=="generate_data_key":
    size=q.get("bytes")
    if not isinstance(size,int) or not 1<=size<=65536: raise SystemExit(68)
    raw=os.urandom(size); out["plaintext"]=base64.b64encode(raw).decode(); out["ciphertext"]=wrap(raw)
else: raise SystemExit(68)
p=json.dumps(out,sort_keys=True,separators=(",",":")).encode()
sys.stdout.buffer.write(b"HBR1"+struct.pack(">I",len(p))+p)
""")
    p=instance.root/"server.json"; c=json.loads(p.read_text())
    base={"command":str(plugin),"command_sha256":plugin_sha,
          "sandbox_provider_id":"fixture_sandbox","sandbox_command":str(wrapper),
          "sandbox_command_sha256":wrapper_sha,"sandbox_profile_id":"kms_profile",
          "key_version":KEY_VERSION,"maximum_request_bytes":262144,
          "maximum_response_bytes":262144,"timeout_ms":300}
    c["plugin_kms"]=[
      dict(base,id="kms_fixture",key_id=KEY_ID,capabilities=["wrap","unwrap","generate_data_key"]),
      dict(base,id="kms_disabled",key_id="kms_disabled_key",key_version=1,
           capabilities=["wrap"],enabled=False),
    ]
    p.write_text(json.dumps(c)); p.chmod(0o600)
    return plugin,provider_key,count,plugin.read_bytes(),plugin_sha

def request(extra=None):
    value={"key_id":KEY_ID,"key_version":KEY_VERSION,"purpose":PURPOSE,
           "associated_data_digest":AAD}
    value.update(extra or {})
    return value

def run(binary: Path, root: Path):
    os.umask(0o077); root.mkdir(mode=0o700,parents=True,exist_ok=False)
    i=smoke.Instance(binary,root/"server")
    plugin,provider_key,count,original_plugin,plugin_sha=configure(i,root)
    passed=[]
    def ck(name,condition):
        if condition is not True: raise RuntimeError(name)
        passed.append(name)
    try:
        i.start(); st,b=i.call("POST","sys/init",{"secret_shares":1,"secret_threshold":1})
        ck("initialize",st==200); i.token=b["root_token"]; key=b["keys_base64"][0]
        ck("unseal",i.call("POST","sys/unseal",{"key":key})[0]==200)
        st,b=i.call("LIST","sys/plugins/catalog/kms")
        ck("catalog_lists_kms",st==200 and b.get("data",{}).get("keys")==["kms_disabled","kms_fixture"])
        st,b=i.call("GET","sys/plugins/catalog/kms/kms_fixture")
        ck("catalog_checksum_bound",st==200 and b["data"].get("type")=="kms"
           and b["data"].get("sha256")==plugin_sha and b["data"].get("state")=="active")

        before=count.read_text().count("\n") if count.exists() else 0
        bad=request({"plaintext":base64.b64encode(b"x").decode()}); bad["key_version"]=6
        ck("wrong_version_no_entry",i.call("POST","sys/plugins/kms/kms_fixture/wrap",bad)[0]==400
           and (count.read_text().count("\n") if count.exists() else 0)==before)
        disabled={"key_id":"kms_disabled_key","key_version":1,"purpose":PURPOSE,
                  "associated_data_digest":AAD,"plaintext":base64.b64encode(b"x").decode()}
        ck("disabled_key_no_entry",i.call("POST","sys/plugins/kms/kms_disabled/wrap",disabled)[0]==403)

        plain=b"heptabao-kms-roundtrip"
        st,b=i.call("POST","sys/plugins/kms/kms_fixture/wrap",
                    request({"plaintext":base64.b64encode(plain).decode()}))
        cipher=b.get("data",{}).get("ciphertext"); ck("wrap",st==200 and isinstance(cipher,str))
        st,b=i.call("POST","sys/plugins/kms/kms_fixture/unwrap",request({"ciphertext":cipher}))
        ck("unwrap",st==200 and base64.b64decode(b["data"]["plaintext"])==plain)
        st,b=i.call("POST","sys/plugins/kms/kms_fixture/generate-data-key",request({"bytes":32}))
        generated=b.get("data",{}); ck("generate_data_key",st==200
            and len(base64.b64decode(generated["plaintext"]))==32 and isinstance(generated["ciphertext"],str))

        i.stop(); i.start(); ck("restart_unseal",i.call("POST","sys/unseal",{"key":key})[0]==200)
        st,b=i.call("POST","sys/plugins/kms/kms_fixture/unwrap",request({"ciphertext":cipher}))
        ck("provider_custody_survives_service_restart",st==200 and base64.b64decode(b["data"]["plaintext"])==plain)
        ck("provider_key_outside_service_state",provider_key.exists()
           and provider_key.stat().st_mode & 0o077 == 0
           and provider_key.read_bytes() not in b"".join(path.read_bytes() for path in (i.root/"data").rglob("*") if path.is_file()))

        before=count.read_text().count("\n")
        with plugin.open("ab") as f: f.write(b"\n# mutated after admission\n")
        ck("changed_plugin_fails_before_entry",
           i.call("POST","sys/plugins/kms/kms_fixture/wrap",
                  request({"plaintext":base64.b64encode(b"mutate").decode()}))[0]==503
           and count.read_text().count("\n")==before)
        plugin.write_bytes(original_plugin); plugin.chmod(0o700)

        timeout=request({"plaintext":base64.b64encode(b"timeout").decode()})
        timeout["purpose"]="timeout_case"
        st,_=i.call("POST","sys/plugins/kms/kms_fixture/wrap",timeout)
        ck("post_entry_timeout_fences_host",st==503)
        st,b=i.call("GET","sys/plugins/catalog/kms/kms_fixture")
        ck("catalog_reports_reconciliation_required",
           st==200 and b.get("data",{}).get("state")=="reconciliation_required")
        st,_=i.call("POST","sys/plugins/kms/kms_fixture/wrap",
                    request({"plaintext":base64.b64encode(b"no-retry").decode()}))
        ck("fenced_host_rejects_blind_retry",st==503)
        i.stop(); i.start(); ck("restart_after_unknown_unseal",i.call("POST","sys/unseal",{"key":key})[0]==200)
        st,b=i.call("POST","sys/plugins/kms/kms_fixture/wrap",
                    request({"plaintext":base64.b64encode(b"fresh-after-restart").decode()}))
        ck("restart_readmits_without_replaying_unknown",st==200 and isinstance(b.get("data",{}).get("ciphertext"),str))

        print(json.dumps({"status":"passed","checks":passed,
            "provider_key_custody":"external_fixture_file",
            "key_version":KEY_VERSION,"full_openbao_kms_compatibility":False,
            "auto_unseal":False,"durable_unknown_effect_reconciliation":False,
            "independent_qualification":False,"production_authority":False}))
    finally:
        i.stop()

if __name__=="__main__":
    p=argparse.ArgumentParser(); p.add_argument("--binary",type=Path,required=True); p.add_argument("--work-dir",type=Path,required=True)
    a=p.parse_args()
    try: run(a.binary.resolve(),a.work_dir.resolve())
    except Exception as e:
        print("plugin kms live failed: "+type(e).__name__,file=sys.stderr); raise SystemExit(1)
