#!/usr/bin/env python3
"""Bounded OpenBao 2.6.2 -> HeptaBao SSH OTP role transfer with durable resume.

Only explicitly supported OTP role configuration is transferred. Issued OTPs,
leases, CA issuers/keys, zero-address registration and live SSH authority are
never copied. Apply mode requires a private resumable checkpoint plus explicit
source-write freeze and exclusive ownership of selected target role names.
"""
from __future__ import annotations
import fcntl, json, os, stat
from pathlib import Path
from bao_http import BaoError, Client, SafeArgumentParser, digest, distinct_endpoints, key_path, private_json, private_write

SCHEMA="heptabao.ssh-otp-role-transfer.v1"
CHECKPOINT_SCHEMA="heptabao.ssh-otp-role-checkpoint.v1"
MAX_ROLES=1024
MAX_FIELD_BYTES=4096
SUPPORTED_FIELDS=("key_type","default_user","allowed_users","cidr_list","exclude_cidr_list","port")

def expect(response,statuses=(200,)):
    if response.status not in statuses: raise BaoError("unexpected_api_status_"+str(response.status))
    return response

def canonical_name(value):
    if not isinstance(value,str) or not value or "/" in value or key_path(value)!=value: raise BaoError("noncanonical_ssh_role_name")
    return value

def canonical_mount(value):
    if not isinstance(value,str): raise BaoError("invalid_ssh_mount")
    value=value.strip("/")
    if not value or len(value)>128 or any(p in ("",".","..") for p in value.split("/")): raise BaoError("invalid_ssh_mount")
    if any(key_path(p)!=p for p in value.split("/")): raise BaoError("invalid_ssh_mount")
    return value

def _default(v): return v in (None,False,"",0,{},[])

def normalize_role(data):
    if not isinstance(data,dict) or data.get("key_type")!="otp": raise BaoError("ssh_role_not_supported_otp")
    for field,value in data.items():
        if field not in SUPPORTED_FIELDS and not _default(value): raise BaoError("unsupported_ssh_role_semantics_"+field)
    default_user=data.get("default_user"); cidr=data.get("cidr_list")
    allowed=data.get("allowed_users",""); excluded=data.get("exclude_cidr_list",""); port=data.get("port",22)
    for label,value in (("default_user",default_user),("cidr_list",cidr),("allowed_users",allowed),("exclude_cidr_list",excluded)):
        if not isinstance(value,str) or len(value.encode())>MAX_FIELD_BYTES: raise BaoError("invalid_ssh_role_"+label)
    if not default_user or not cidr or type(port) is not int or not 1<=port<=65535: raise BaoError("invalid_ssh_role_required_fields")
    return {"key_type":"otp","default_user":default_user,"allowed_users":allowed,"cidr_list":cidr,"exclude_cidr_list":excluded,"port":port}

def list_roles(client,mount):
    r=client.request("LIST",f"/v1/{mount}/roles")
    if r.status==404: return []
    keys=expect(r).data().get("keys")
    if not isinstance(keys,list) or len(keys)>MAX_ROLES or len(keys)!=len(set(keys)): raise BaoError("invalid_or_unbounded_ssh_role_inventory")
    out=sorted(canonical_name(x) for x in keys)
    return out

def read_role(client,mount,name,absent_ok=False):
    canonical_name(name); r=client.request("GET",f"/v1/{mount}/roles/{name}")
    if absent_ok and r.status==404: return None
    return normalize_role(expect(r).data())

def snapshot_inventory(client,mount):
    before=list_roles(client,mount); records=[]
    for name in before:
        role=read_role(client,mount,name); records.append({"name":name,"role":role,"source_digest":digest(role)})
    if before!=list_roles(client,mount): raise BaoError("source_ssh_role_inventory_changed_during_snapshot")
    for record in records:
        if read_role(client,mount,record["name"])!=record["role"]: raise BaoError("source_ssh_role_changed_during_snapshot")
    manifest={"namespace":client.namespace,"mount":mount,"objects":[{"name":r["name"],"source_digest":r["source_digest"]} for r in records]}
    return records,digest(manifest)

def validate_record(record):
    if not isinstance(record,dict) or set(record)!={"name","role","source_digest"}: raise BaoError("invalid_ssh_role_record")
    canonical_name(record["name"]); role=normalize_role(record["role"])
    if role!=record["role"] or record["source_digest"]!=digest(role): raise BaoError("ssh_role_record_digest_mismatch")

class CheckpointLock:
    def __init__(self,filename): self.filename,self.fd=str(filename)+".lock",None
    def __enter__(self):
        try:
            self.fd=os.open(self.filename,os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW,0o600); info=os.fstat(self.fd)
            if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.geteuid() or info.st_mode&0o077: raise BaoError("checkpoint_lock_not_private_regular_file")
            fcntl.flock(self.fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except (OSError,BaoError):
            if self.fd is not None: os.close(self.fd); self.fd=None
            raise BaoError("checkpoint_locked_or_inaccessible") from None
        return self
    def __exit__(self,*_):
        if self.fd is not None: os.close(self.fd); self.fd=None

class Checkpoint:
    def __init__(self,filename,binding):
        self.filename=Path(filename); self.binding=digest(binding)
        if self.filename.exists() or self.filename.is_symlink():
            self.state=private_json(self.filename)
            if not isinstance(self.state,dict) or self.state.get("schema")!=CHECKPOINT_SCHEMA or self.state.get("binding")!=self.binding or not isinstance(self.state.get("objects"),dict): raise BaoError("checkpoint_context_mismatch")
        else:
            self.state={"schema":CHECKPOINT_SCHEMA,"binding":self.binding,"objects":{}}
            private_write(self.filename,self.state,replace=False)
    def save(self): private_write(self.filename,self.state)

def transfer_role(target,mount,record,checkpoint):
    validate_record(record); name,role=record["name"],record["role"]; oid=digest({"mount":mount,"name":name})
    entry=checkpoint.state["objects"].get(oid)
    if entry is None:
        if read_role(target,mount,name,absent_ok=True) is not None: raise BaoError("target_ssh_role_exists_without_owned_checkpoint")
        entry={"source_digest":record["source_digest"],"phase":"write_inflight"}; checkpoint.state["objects"][oid]=entry; checkpoint.save()
        expect(target.request("POST",f"/v1/{mount}/roles/{name}",role),(200,204))
        if read_role(target,mount,name)!=role: raise BaoError("target_ssh_role_readback_mismatch")
        entry["phase"]="complete"; checkpoint.save(); return "copied_and_verified"
    if not isinstance(entry,dict) or set(entry)!={"source_digest","phase"} or entry.get("source_digest")!=record["source_digest"] or entry.get("phase") not in ("write_inflight","complete"): raise BaoError("checkpoint_object_or_source_changed")
    observed=read_role(target,mount,name,absent_ok=True)
    if entry["phase"]=="write_inflight":
        if observed is None: raise BaoError("ambiguous_pending_write_requires_authoritative_reconciliation")
        if observed!=role: raise BaoError("target_ssh_role_conflicts_with_pending_write")
        entry["phase"]="complete"; checkpoint.save(); return "copied_and_verified"
    if observed!=role: raise BaoError("target_ssh_role_changed_after_checkpoint")
    return "already_verified"

def main(argv=None):
    p=SafeArgumentParser(description=__doc__); p.add_argument("--source-prefix",default="HB_SOURCE"); p.add_argument("--target-prefix",default="HB_TARGET")
    p.add_argument("--source-mount",default="ssh"); p.add_argument("--target-mount",default="ssh"); p.add_argument("--checkpoint")
    p.add_argument("--apply",action="store_true"); p.add_argument("--source-writes-frozen",action="store_true"); p.add_argument("--target-exclusive",action="store_true")
    a=p.parse_args(argv)
    result={"schema":SCHEMA,"status":"failed","mode":"apply" if a.apply else "dry_run","objects_checked":0,"objects_copied":0,"objects_already_verified":0,"target_existing_objects":0,"source_modified":False,"source_cutover":False,"issued_credentials_transferred":False,"lease_state_transferred":False,"ca_authority_transferred":False,"full_asset_migration":False,"cutover_authority":False,"rollback_authority":False,"scope":"single_namespace_supported_ssh_otp_role_configuration_only"}
    lock=None; code=2
    try:
        sm,tm=canonical_mount(a.source_mount),canonical_mount(a.target_mount); source,target=Client.from_env(a.source_prefix),Client.from_env(a.target_prefix)
        sh,th=source.health(),target.health()
        if sh["version"]!="2.6.2": raise BaoError("unsupported_source_version")
        distinct_endpoints(source,sh,target,th); records,inv=snapshot_inventory(source,sm); result["objects_checked"]=len(records)
        binding={"profile":SCHEMA,"source_identity":{"cluster_id":sh["cluster_id"],"version":sh["version"],"namespace":source.namespace,"mount":sm},"target_identity":{"cluster_id":th["cluster_id"],"version":th["version"],"namespace":target.namespace,"mount":tm},"inventory_digest":inv}
        checkpoint=None
        if a.apply:
            if not a.checkpoint or not a.source_writes_frozen or not a.target_exclusive: raise BaoError("apply_requires_checkpoint_freeze_and_exclusive_target")
            lock=CheckpointLock(a.checkpoint); lock.__enter__(); checkpoint=Checkpoint(a.checkpoint,binding)
        for record in records:
            if a.apply:
                outcome=transfer_role(target,tm,record,checkpoint); result["objects_already_verified" if outcome=="already_verified" else "objects_copied"]+=1
                if read_role(source,sm,record["name"])!=record["role"]: raise BaoError("source_ssh_role_changed_after_copy_target_not_cut_over")
            elif read_role(target,tm,record["name"],absent_ok=True) is not None: result["target_existing_objects"]+=1
        result.update(status="copied_and_verified" if a.apply else "dry_run_complete",inventory_digest=inv,source_mount=sm,target_mount=tm); code=0
    except BaoError as error: result["reason"]=str(error)
    finally:
        if lock is not None: lock.__exit__(None,None,None)
    print(json.dumps(result,sort_keys=True)); return code
if __name__=="__main__": raise SystemExit(main())
