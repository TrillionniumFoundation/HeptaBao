#!/usr/bin/env python3
"""Run the distributable Python CLI against an isolated real TLS service.

No mocked requests, production endpoints, secret command-line arguments or
client-generated compatibility admission. The full OpenBao CLI is not claimed.
"""
from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time

from bao_http import SafeArgumentParser, private_read, private_write
from core_isolation import ROOT, ScenarioFailure, file_hash


def main() -> int:
    parser=SafeArgumentParser(description=__doc__)
    parser.add_argument("--binary",required=True)
    parser.add_argument("--output",required=True)
    parser.add_argument("--client-python",help="Optional isolated interpreter with the reviewed client wheel installed")
    args=parser.parse_args()
    binary=Path(args.binary).resolve(strict=True)
    client_python = str(Path(args.client_python).absolute()) if args.client_python else sys.executable
    if not Path(client_python).is_file():
        parser.error("client interpreter must exist")
    output=Path(args.output).resolve()
    mode=output.parent.stat()
    if output.exists() or mode.st_uid != os.geteuid() or mode.st_mode & 0o077:
        parser.error("new output in private caller-owned directory required")
    root=Path(tempfile.mkdtemp(prefix="heptabao-client-live-"));root.chmod(0o700)
    instance=None; sensitive=[]
    report={"schema":"heptabao.client-live.v1","synthetic_only":True,"cases":[],
            "binary_sha256":file_hash(binary),"runner_sha256":file_hash(Path(__file__)),
            "source_commit":subprocess.check_output(["git","rev-parse","HEAD"],cwd=ROOT,text=True).strip(),
            "source_tree":subprocess.check_output(["git","rev-parse","HEAD^{tree}"],cwd=ROOT,text=True).strip(),
            "source_worktree_dirty":bool(subprocess.check_output(["git","status","--porcelain"],cwd=ROOT)),
            "started_at_unix":time.time(),"independent_qualification":False,
            "client_distribution":"installed-wheel" if args.client_python else "source-tree",
            "full_cli_compatibility":False,"production_authority":False}

    def check(name,condition):
        report["cases"].append({"case":name,"passed":bool(condition)})
        if not condition:raise ScenarioFailure(name)

    def save_token(name,value):
        path=root/name
        fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
        with os.fdopen(fd,"w") as handle:handle.write(value)
        sensitive.append(value)
        return str(path)

    def cli(name,arguments,*,root_auth=True,write=False,expected=0):
        destination=root/(name+".json")
        command=[client_python,"-m","heptabao","--address",instance.address,
                 "--ca-file",str(instance.root/"ca.crt"),"--output",str(destination)]
        if root_auth:command += ["--token-file",str(root/"root.token")]
        if write:command += ["--allow-write"]
        command+=arguments
        environment=os.environ.copy()
        if args.client_python:
            environment.pop("PYTHONPATH",None)
        else:
            environment["PYTHONPATH"]=str(ROOT/"clients/python")
        for key in ("BAO_TOKEN","VAULT_TOKEN","HB_CANDIDATE_TOKEN","HB_ORACLE_TOKEN"):
            environment.pop(key,None)
        completed=subprocess.run(command,cwd=root,env=environment,stdin=subprocess.DEVNULL,
                                 capture_output=True,timeout=30,check=False)
        check(name+".exit",completed.returncode==expected)
        diagnostic=(completed.stdout+completed.stderr).decode("utf-8",errors="replace")
        check(name+".no_secret_diagnostics",all(value not in diagnostic for value in sensitive))
        check(name+".private_response",destination.is_file() and destination.stat().st_mode&0o777==0o600)
        return json.loads(private_read(destination))

    try:
        spec=importlib.util.spec_from_file_location("client_live_smoke",ROOT/"qa/single-node/smoke.py")
        smoke=importlib.util.module_from_spec(spec);spec.loader.exec_module(smoke)
        instance=smoke.Instance(binary,root/"server");instance.start()
        status,init=instance.call("POST","sys/init",{"secret_shares":1,"secret_threshold":1})
        check("client.init",status==200)
        instance.token=init["root_token"];save_token("root.token",instance.token)
        check("client.unseal",instance.call("POST","sys/unseal",{"key":init["keys_base64"][0]})[0]==200)
        payload={"v":"private-synthetic-client-response"};sensitive.append(payload["v"])
        private_write(root/"kv-input.json",{"data":payload},replace=False)
        result=cli("client.write",["write","secret/data/cli-check","--input",str(root/"kv-input.json")],write=True)
        check("client.write_version",result.get("data",{}).get("version")==1)
        result=cli("client.read",["read","secret/data/cli-check"])
        check("client.read_value",result.get("data",{}).get("data")==payload)
        result=cli("client.list",["list","secret/metadata"])
        check("client.list_key",result.get("data",{}).get("keys")==["cli-check"])
        result=cli("client.capabilities",["capabilities","secret/data/cli-check"])
        check("client.capability_root",result.get("capabilities")==["root"])
        private_write(root/"wrap-input.json",payload,replace=False)
        result=cli("client.wrap",["wrap","--input",str(root/"wrap-input.json"),"--ttl","60s"],write=True)
        check("client.wrap_redacts",result.get("data") is None and bool(result.get("wrap_info",{}).get("token")))
        token_file=save_token("first.token",result["wrap_info"]["token"])
        result=cli("client.lookup",["wrapping-lookup","--wrapping-token-file",token_file],root_auth=False)
        check("client.lookup_only_metadata",set(result.get("data",{}))=={"creation_path","creation_time","creation_ttl"})
        result=cli("client.rewrap",["rewrap","--wrapping-token-file",token_file],write=True)
        replacement=save_token("second.token",result["wrap_info"]["token"])
        result=cli("client.unwrap",["unwrap","--wrapping-token-file",replacement],root_auth=False,write=True)
        check("client.unwrap_exact",result.get("data")==payload)
        result=cli("client.replay",["unwrap","--wrapping-token-file",replacement],root_auth=False,write=True,expected=1)
        check("client.replay_error_no_data",result.get("data") is None and bool(result.get("errors")))
        result=cli("client.delete",["delete","secret/data/cli-check"],write=True)
        check("client.delete_no_body",result=={})
        check("client.binary_unchanged",file_hash(binary)==report["binary_sha256"])
        report["status"]="passed"
    except Exception as error:
        report["status"]="failed"
        report["failure"]=str(error) if isinstance(error,ScenarioFailure) else type(error).__name__
    finally:
        if instance is not None:
            try:instance.stop()
            except Exception:report["status"],report["failure"]="failed","process_cleanup_failed"
        try:shutil.rmtree(root)
        except OSError:report["status"],report["failure"]="failed","private_fixture_cleanup_failed"
        report["finished_at_unix"]=time.time()
        private_write(output,report)
    print(json.dumps({"status":report["status"],"count":len(report["cases"]),"failure":report.get("failure")}))
    return 0 if report["status"]=="passed" else 1


if __name__=="__main__":raise SystemExit(main())
