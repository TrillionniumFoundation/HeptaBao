#!/usr/bin/env python3
"""Scoped real OpenBao 2.6.2 -> HeptaBao SSH OTP role migration rehearsal."""
from __future__ import annotations
import contextlib, importlib.util, io, json, os, shutil, socket, tempfile
from pathlib import Path
from bao_http import BaoError, Client, SafeArgumentParser, private_write
import migrate_ssh_roles as migration
from official_openbao_launcher import BINARY_SHA256, file_digest, start_oracle, stop_oracle
from heptabao.private_state import StateDirectory
ROOT=Path(__file__).resolve().parents[2]

def tool(args):
    out=io.StringIO()
    with contextlib.redirect_stdout(out): code=migration.main(args)
    result=json.loads(out.getvalue())
    if code: raise BaoError("ssh_role_live_cli_"+result.get("reason","failed"))
    return result

def run(binary, output):
    checks=[]
    def check(name, ok):
        if not ok: raise BaoError("ssh_role_live_"+name)
        checks.append(name)
    if not all(Path(os.environ.get(n,"/missing")).is_file() for n in ("HB_ORACLE_BINARY","HB_ORACLE_ARCHIVE")):
        raise FileNotFoundError("pinned oracle prerequisite missing")
    with tempfile.TemporaryDirectory(prefix="heptabao-ssh-role-migration-") as td:
        root=Path(td); root.chmod(0o700)
        spec=importlib.util.spec_from_file_location("smoke",ROOT/"qa/single-node/smoke.py")
        smoke=importlib.util.module_from_spec(spec); spec.loader.exec_module(smoke)
        oracle=instance=None
        mount="ssh-migrate"; name="deploy"
        role={"key_type":"otp","default_user":"deploy","allowed_users":"deploy,backup",
              "cidr_list":"127.0.0.0/8","exclude_cidr_list":"127.1.0.0/16","port":22}
        try:
            with socket.socket() as s: s.bind(("127.0.0.1",0)); port=s.getsockname()[1]
            oracle=start_oracle(port)
            source=Client(oracle["address"],oracle["ca_file"],Path(oracle["token_file"]).read_text().strip())
            check("source_mount",source.request("POST",f"/v1/sys/mounts/{mount}",{"type":"ssh"}).status==204)
            check("source_role",source.request("POST",f"/v1/{mount}/roles/{name}",role).status==204)
            src=migration.read_role(source,mount,name)
            issued=source.request("POST",f"/v1/{mount}/creds/{name}",{"ip":"127.0.0.1"})
            otp=issued.body.get("data",{}).get("key"); lease=issued.body.get("lease_id")
            check("source_otp",issued.status==200 and bool(otp) and bool(lease))
            instance=smoke.Instance(binary.resolve(),root/"candidate"); instance.start()
            status,init=instance.call("POST","sys/init",{"secret_shares":1,"secret_threshold":1})
            check("target_init",status==200); instance.token=init["root_token"]; key=init["keys_base64"][0]
            check("target_unseal",instance.call("POST","sys/unseal",{"key":key})[0]==200)
            target=Client(instance.address,str(instance.root/"ca.crt"),instance.token)
            check("target_mount",target.request("POST",f"/v1/sys/mounts/{mount}",{"type":"ssh"}).status==204)
            token_file=root/"target.token"; fd=os.open(token_file,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
            with os.fdopen(fd,"w") as f: f.write(instance.token)
            os.environ.update(HB_SOURCE_ADDR=oracle["address"],HB_SOURCE_CACERT=oracle["ca_file"],
                HB_SOURCE_TOKEN_FILE=oracle["token_file"],HB_TARGET_ADDR=instance.address,
                HB_TARGET_CACERT=str(instance.root/"ca.crt"),HB_TARGET_TOKEN_FILE=str(token_file))
            for n in ("HB_SOURCE_TOKEN","HB_TARGET_TOKEN","HB_SOURCE_NAMESPACE","HB_TARGET_NAMESPACE"): os.environ.pop(n,None)
            base=["--source-mount",mount,"--target-mount",mount]
            dry=tool(base)
            check("dry_run",dry["status"]=="dry_run_complete" and dry["objects_checked"]==1 and migration.read_role(target,mount,name,True) is None)
            cp=root/"ssh-role-checkpoint.json"; apply=base+["--checkpoint",str(cp),"--apply","--source-writes-frozen","--target-exclusive"]
            first=tool(apply)
            check("copied",first["objects_copied"]==1 and migration.read_role(target,mount,name)==src)
            check("source_unchanged",migration.read_role(source,mount,name)==src)
            check("otp_not_resurrected",target.request("POST",f"/v1/{mount}/verify",{"otp":otp},token="").status==400)
            check("authority_false",not any(first[k] for k in ("issued_credentials_transferred","lease_state_transferred","ca_authority_transferred","full_asset_migration","cutover_authority","rollback_authority")))
            check("repeat",tool(apply)["objects_already_verified"]==1)
            instance.stop(); instance.start(); check("restart_unseal",instance.call("POST","sys/unseal",{"key":key})[0]==200)
            check("restart_resume",tool(apply)["objects_already_verified"]==1 and migration.read_role(target,mount,name)==src)
            check("source_lease_owned",source.request("POST","/v1/sys/leases/lookup",{"lease_id":lease}).status==200)
            result={"schema":"heptabao.ssh-otp-role-migration-live.v1","status":"passed_scoped_ssh_role_transfer",
                "checks":checks,"count":len(checks),"candidate_binary_sha256":file_digest(binary),
                "oracle_binary_sha256":BINARY_SHA256,"official_openbao_version":source.health()["version"],
                "issued_credentials_transferred":False,"lease_state_transferred":False,"ca_authority_transferred":False,
                "full_asset_migration":False,"source_cutover":False,"cutover_authority":False,
                "rollback_authority":False,"independent_qualification":False}
            private_write(output,result,replace=False); return result
        finally:
            if instance is not None: instance.stop()
            if oracle is not None: stop_oracle(oracle); shutil.rmtree(oracle["root"],ignore_errors=True)

def main(argv=None):
    p=SafeArgumentParser(description=__doc__); p.add_argument("--binary",type=Path,required=True); p.add_argument("--output",type=Path,required=True); a=p.parse_args(argv)
    if os.path.lexists(a.output): raise BaoError("output_already_exists")
    with StateDirectory(a.output.absolute().parent): pass
    r=run(a.binary.resolve(),a.output); print(json.dumps({"status":r["status"],"count":r["count"],"full_asset_migration":False})); return 0
if __name__=="__main__":
    try: raise SystemExit(main())
    except FileNotFoundError: print(json.dumps({"status":"blocked_prerequisite","full_asset_migration":False})); raise SystemExit(77) from None
    except Exception as e:
        reason=str(e) if isinstance(e,BaoError) and str(e).startswith("ssh_role_live_") else "ssh_role_migration_live_failed"
        print(json.dumps({"status":"failed","reason":reason,"full_asset_migration":False})); raise SystemExit(2) from None
