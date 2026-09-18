#!/usr/bin/env python3
"""Real server -> sealed sandbox wrapper -> read-only secret plugin."""
from __future__ import annotations
import argparse, hashlib, json, os, stat, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "single-node"))
import smoke

def make_exec(path: Path, text: str) -> str:
    path.write_text(text, encoding="utf-8")
    path.chmod(stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)
    return hashlib.sha256(path.read_bytes()).hexdigest()

def configure(instance: smoke.Instance, root: Path):
    count = root / "plugin-invocations.txt"
    wrapper = root / "sandbox-wrapper.py"
    plugin = root / "readonly-plugin.py"
    wrapper_sha = make_exec(wrapper, f"""#!{sys.executable}
import os,sys
a=sys.argv[1:]
def v(f): return a[a.index(f)+1]
if v("--heptabao-profile")!="readonly_profile" or v("--heptabao-protocol")!="1" or v("--heptabao-operation")!="read": raise SystemExit(64)
os.execv(v("--heptabao-plugin"),[v("--heptabao-plugin")])
""")
    plugin_sha = make_exec(plugin, f"""#!{sys.executable}
import json,struct,sys
r=sys.stdin.buffer.read(1048588)
if len(r)<11 or r[:4]!=b"HBP1" or r[4:6]!=b"\\x00\\x01" or r[6]!=1: raise SystemExit(65)
n=struct.unpack(">I",r[7:11])[0]
if n==0 or len(r)!=11+n: raise SystemExit(65)
q=json.loads(r[11:].decode())
with open({str(count)!r},"a",encoding="utf-8") as f: f.write("1\\n")
p=json.dumps({{"source":"sealed-readonly-plugin","path":q.get("path"),"method":q.get("method")}},sort_keys=True).encode()
sys.stdout.buffer.write(b"HBR1"+struct.pack(">I",len(p))+p)
""")
    p=instance.root/"server.json"; c=json.loads(p.read_text())
    c["plugin_secrets"]=[{"id":"readonly_fixture","command":str(plugin),"command_sha256":plugin_sha,"sandbox_provider_id":"fixture_sandbox","sandbox_command":str(wrapper),"sandbox_command_sha256":wrapper_sha,"sandbox_profile_id":"readonly_profile","maximum_request_bytes":262144,"maximum_response_bytes":262144,"timeout_ms":5000}]
    p.write_text(json.dumps(c)); p.chmod(0o600)
    return plugin,count

def run(binary: Path, root: Path):
    os.umask(0o077); root.mkdir(mode=0o700,parents=True,exist_ok=False)
    i=smoke.Instance(binary,root/"server"); plugin,count=configure(i,root); passed=[]
    def ck(n,x):
        if not x: raise RuntimeError(n)
        passed.append(n)
    try:
        i.start(); st,b=i.call("POST","sys/init",{"secret_shares":1,"secret_threshold":1}); ck("init",st==200)
        i.token=b["root_token"]; key=b["keys_base64"][0]; ck("unseal",i.call("POST","sys/unseal",{"key":key})[0]==200)
        ck("mount",i.call("POST","sys/mounts/external",{"type":"plugin","config":{"plugin_id":"readonly_fixture"}})[0]==204)
        ck("policy",i.call("POST","sys/policies/acl/plugin-reader",{"policy":'path "external/*" { capabilities = ["read", "list"] }'})[0]==204)
        st,b=i.call("POST","auth/token/create",{"policies":["plugin-reader"],"ttl":"1h"}); ck("token",st==200); t=b["auth"]["client_token"]
        st,b=i.call("GET","external/item",token=t); ck("read",st==200 and b.get("data",{}).get("source")=="sealed-readonly-plugin" and b["data"].get("path")=="item")
        before=count.read_text().count("\n"); ck("write_fenced",i.call("POST","external/item",{"x":1})[0]==501 and count.read_text().count("\n")==before)
        ck("unauthorized_no_entry",i.call("GET","external/item",token="invalid")[0]==403 and count.read_text().count("\n")==before)
        i.stop(); i.start(); ck("restart_unseal",i.call("POST","sys/unseal",{"key":key})[0]==200)
        st,b=i.call("GET","external/restart",token=t); ck("restart_binding",st==200 and b.get("data",{}).get("path")=="restart")
        before=count.read_text().count("\n")
        with plugin.open("a",encoding="utf-8") as f: f.write("\n#mutated\n")
        ck("digest_fence",i.call("GET","external/mutated",token=t)[0]==503 and count.read_text().count("\n")==before)
        print(json.dumps({"status":"passed","checks":passed,"read_only":True,"write_effects_admitted":False,"openbao_plugin_grpc_compatibility":False}))
    finally: i.stop()

if __name__=="__main__":
    p=argparse.ArgumentParser(); p.add_argument("--binary",type=Path,required=True); p.add_argument("--work-dir",type=Path,required=True); a=p.parse_args()
    try: run(a.binary.resolve(),a.work_dir.resolve())
    except Exception as e: print("plugin secret live failed: "+type(e).__name__,file=sys.stderr); raise SystemExit(1)
