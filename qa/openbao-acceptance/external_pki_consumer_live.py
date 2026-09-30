#!/usr/bin/env python3
"""Three fresh HTTPS processes verify direct external Ed25519 roots and CSRs.

The pinned official remote Transit owns every private key. Public certificates,
CSR bytes, signatures, tokens and provider configuration are never report data.
This bounded profile does not qualify leaf issuance, CRLs, non-Ed25519 issuers,
multi-issuer migration or production/release authority.
"""
from __future__ import annotations
import base64
import copy
import importlib.util
import json
import os
import re
from pathlib import Path
import subprocess
import tempfile
import time

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization
from bao_http import BaoError, Client, SafeArgumentParser, private_read, private_write
from official_openbao_launcher import file_digest, pinned_artifact, start_oracle, stop_oracle
import external_transit_consumer_live as shared

ROOT=Path(__file__).resolve().parents[2]
VERSION="2.7.0"
CONFIG="sys/external-keys/configs/provider"

def expected_cases():
    cases=["candidate.binary_before_hash","remote.health","official.health","candidate.health",
        "distinct_process_clusters","oracle.selected_backend","remote.mount","remote.key","remote.public_key"]
    for side in ("candidate","official"):
        cases += [f"{side}.{name}" for name in ("config","mapping")]
        for kind in ("root","csr"):
            cases += [f"{side}.{kind}.{name}" for name in ("mount","missing_grant","missing_grant_no_sign","grant",
                "generate","exact_response","actual_signature","spki_matches","private_key_absent")]
        cases += [f"{side}.{name}" for name in ("namespace","namespace_mount","namespace_root_ref_rejected",
            "namespace_config","namespace_mapping","namespace_grant","namespace_generate","namespace_signature",
            "root_readback","restart_health","restart_root_readback")]
    cases += ["remote.rotate"]
    for side in ("candidate","official"):
        cases += [f"{side}.rotated.{name}" for name in ("mount","grant","old_fixed_rejected","no_certificate","no_sign")]
    cases += ["candidate.audit_no_credentials","owned_processes_cleared","candidate.binary_after_hash"]
    return tuple(cases)

EXPECTED_CASES=expected_cases()

def trace_complete(rows):
    return isinstance(rows,list) and tuple(row.get("case") for row in rows)==EXPECTED_CASES and all(row.get("passed") is True for row in rows)

def scoped_client(client,namespace):
    scoped=copy.copy(client)
    scoped.namespace=namespace
    return scoped

def sign_entries(remote):
    count=0
    for line in (Path(remote["root"])/"audit.jsonl").read_text().splitlines():
        record=json.loads(line)
        if record.get("type")=="request" and record.get("request",{}).get("path","").startswith("transit/sign/"):
            count+=1
    return count

def validate_crypto(data,kind,public):
    if kind=="root":
        document=x509.load_pem_x509_certificate(data["certificate"].encode())
        verified=public.verify(document.signature,document.tbs_certificate_bytes)
        expected={"certificate","expiration","issuer_id","issuer_name","issuing_ca","key_id","key_name","serial_number"}
        exact=set(data)==expected and data["key_name"]==data["issuer_name"]=="" and data["certificate"]==data["issuing_ca"]
        exact &= tuple((extension.oid.dotted_string,extension.critical) for extension in document.extensions)==(
            ("2.5.29.15",True),("2.5.29.19",True),("2.5.29.14",False),("2.5.29.35",False),("2.5.29.17",False))
        constraints=document.extensions.get_extension_for_class(x509.BasicConstraints).value
        usage=document.extensions.get_extension_for_class(x509.KeyUsage).value
        ski=document.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value.digest
        aki=document.extensions.get_extension_for_class(x509.AuthorityKeyIdentifier).value.key_identifier
        exact &= constraints.ca is True and constraints.path_length is None and usage.key_cert_sign and usage.crl_sign
        exact &= not usage.digital_signature and not usage.key_encipherment
        exact &= ski==x509.SubjectKeyIdentifier.from_public_key(document.public_key()).digest and aki==ski
        exact &= int((document.not_valid_after-document.not_valid_before).total_seconds())==3630
        exact &= bool(re.fullmatch(r"[0-9a-f]{2}(?::[0-9a-f]{2}){19}",data["serial_number"]))
        exact &= int(data["serial_number"].replace(":",""),16)==document.serial_number
    else:
        document=x509.load_pem_x509_csr(data["csr"].encode())
        verified=public.verify(document.signature,document.tbs_certrequest_bytes)
        exact=set(data)=={"csr","key_id"} and tuple((extension.oid.dotted_string,extension.critical) for extension in document.extensions)==(("2.5.29.17",False),)
    common_name=document.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
    exact &= len(common_name)==1 and document.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName)==[common_name[0].value]
    actual=document.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw)
    expected_public=public.public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw)
    return bool(exact),actual==expected_public,verified is None

def run(binary,rows,*,oracle_contract=False,compare_official_csr=True,include_native_csr=True,observe_provider_signs=False):
    smoke_spec=importlib.util.spec_from_file_location("external_pki_native_smoke",ROOT/"qa/single-node/smoke.py")
    smoke=importlib.util.module_from_spec(smoke_spec);smoke_spec.loader.exec_module(smoke)
    private_root=Path(tempfile.mkdtemp(prefix="heptabao-external-pki270-"));private_root.chmod(0o700)
    instances=[];native=None;contract_consumer=None;t=shared.Trace(rows);result={}
    try:
        remote=start_oracle(shared.free_port(),version=VERSION,audit_file=True);instances.append(remote)
        official=start_oracle(shared.free_port(),version=VERSION);instances.append(official)
        r,o=shared.oracle_client(remote),shared.oracle_client(official)
        remote_token=private_read(remote["token_file"],8192).decode().strip()
        ca=Path(remote["ca_file"]).read_text()
        if oracle_contract:
            # Only the explicit QA preflight caller selects this branch. Every
            # request still reaches a fresh real official HTTPS process; no
            # init, cryptographic response or readback is synthesized.
            contract_consumer=start_oracle(shared.free_port(),version=VERSION,audit_file=True)
            instances.append(contract_consumer)
            c=shared.oracle_client(contract_consumer)
            audit_root=Path(contract_consumer["root"])
            candidate_token=private_read(contract_consumer["token_file"],8192).decode().strip()
            unseal=private_read(audit_root/"unseal.key",8192).decode().strip()
        else:
            native=smoke.Instance(binary,private_root/"candidate");shared.native_configuration(native,remote,ca);native.start()
            status,initialized=native.call("POST","sys/init",{"secret_shares":1,"secret_threshold":1})
            if status!=200:raise shared.Failure("candidate_init")
            native.token,unseal=initialized["root_token"],initialized["keys_base64"][0]
            if native.call("POST","sys/unseal",{"key":unseal})[0]!=200:raise shared.Failure("candidate_unseal")
            c=Client(native.address,str(native.root/"ca.crt"),native.token)
            audit_root=native.root;candidate_token=native.token
        clients={"candidate":c,"official":o};identities={}
        for side,client in (("remote",r),("official",o),("candidate",c)):
            health=client.health()
            t.check(side+".health",health.get("initialized") is True and health.get("sealed") is False
                and (side=="candidate" and not oracle_contract or health.get("version")==VERSION))
            identities[side]={key:health[key] for key in ("cluster_id","version")}
        t.check("distinct_process_clusters",len({identity["cluster_id"] for identity in identities.values()})==3)
        t.check("oracle.selected_backend",remote["storage_backend"]==official["storage_backend"]=="pebbledb"
            and (not oracle_contract or contract_consumer["storage_backend"]=="pebbledb"))
        t.call("remote.mount",r,"POST","sys/mounts/transit",204,{"type":"transit"})
        t.call("remote.key",r,"POST","transit/keys/ca",200,{"type":"ed25519"})
        descriptor=r.request("GET","/v1/transit/keys/ca")
        value=descriptor.body.get("data",{}).get("keys",{}).get("1",{}).get("public_key")
        raw=base64.b64decode(value,validate=True)
        t.check("remote.public_key",descriptor.status==200 and len(raw)==32 and base64.b64encode(raw).decode()==value,descriptor.status)
        public=ed25519.Ed25519PublicKey.from_public_bytes(raw)
        configurations={side:{"plugin":"transit","verify":side=="official" or oracle_contract,"address":remote["address"],"token":remote_token,"mount_path":"transit"}
            for side in clients}
        configurations["official"]["tls_ca_cert_bytes"]=ca
        if oracle_contract:configurations["candidate"]["tls_ca_cert_bytes"]=ca
        certificates={}
        for side,client in clients.items():
            t.call(side+".config",client,"POST",CONFIG,204,configurations[side])
            mapping={"name":"ca","version":1,"verify":side=="official" or oracle_contract}
            t.call(side+".mapping",client,"POST",CONFIG+"/keys/fixed",204,mapping)
            kinds=("root","csr") if (side=="candidate" and include_native_csr or side=="official" and compare_official_csr) else ("root",)
            for kind in kinds:
                mount="pki-"+kind;prefix=side+"."+kind+"."
                route="root/generate/kms" if kind=="root" else "intermediate/generate/kms"
                body={"external_key_ref":"provider:fixed","common_name":"synthetic-external-ca.example.test"}
                if kind=="root":body["ttl"]="1h"
                t.call(prefix+"mount",client,"POST","sys/mounts/"+mount,204,{"type":"pki"})
                before=sign_entries(remote)
                t.call(prefix+"missing_grant",client,"POST",mount+"/"+route,400,body)
                t.check(prefix+"missing_grant_no_sign",sign_entries(remote)==before)
                t.call(prefix+"grant",client,"POST",CONFIG+"/keys/fixed/grants/"+mount,204)
                before=sign_entries(remote)
                response=client.request("POST","/v1/"+mount+"/"+route,body)
                t.check(prefix+"generate",response.status==200,response.status)
                if observe_provider_signs:
                    observed=sign_entries(remote)-before
                    expected=3 if kind=="root" and (side=="official" or oracle_contract) else 1
                    try:t.check(prefix+"provider_sign_exact",observed==expected)
                    finally:rows[-1].update(observed_provider_sign_entries=observed,expected_provider_sign_entries=expected)
                data=response.body.get("data",{})
                exact,spki,verified=validate_crypto(data,kind,public)
                t.check(prefix+"exact_response",exact)
                t.check(prefix+"actual_signature",verified)
                t.check(prefix+"spki_matches",spki)
                t.check(prefix+"private_key_absent","private_key" not in data)
                if kind=="root":certificates[side]=data["certificate"]
            t.call(side+".namespace",client,"POST","sys/namespaces/team",200)
            t.call(side+".namespace_mount",client,"POST","sys/mounts/pki",204,{"type":"pki"},namespace="team")
            body={"external_key_ref":"provider:fixed","common_name":"synthetic-team-ca.example.test","ttl":"1h"}
            t.call(side+".namespace_root_ref_rejected",client,"POST","pki/root/generate/kms",400,body,namespace="team")
            t.call(side+".namespace_config",client,"POST",CONFIG,204,configurations[side],namespace="team")
            t.call(side+".namespace_mapping",client,"POST",CONFIG+"/keys/fixed",204,mapping,namespace="team")
            t.call(side+".namespace_grant",client,"POST",CONFIG+"/keys/fixed/grants/pki",204,namespace="team")
            before=sign_entries(remote)
            response=scoped_client(client,"team").request("POST","/v1/pki/root/generate/kms",body)
            t.check(side+".namespace_generate",response.status==200,response.status)
            if observe_provider_signs:
                observed=sign_entries(remote)-before
                expected=3 if side=="official" or oracle_contract else 1
                try:t.check(side+".namespace_provider_sign_exact",observed==expected)
                finally:rows[-1].update(observed_provider_sign_entries=observed,expected_provider_sign_entries=expected)
            exact,spki,verified=validate_crypto(response.body.get("data",{}),"root",public)
            t.check(side+".namespace_signature",exact and spki and verified)
            response=client.request("GET","/v1/pki-root/cert/ca")
            t.check(side+".root_readback",response.status==200 and response.body.get("data",{}).get("certificate")==certificates[side],response.status)
            if side=="candidate" and not oracle_contract:shared.restart_candidate(native,unseal,remote,ca)
            else:
                from official_openbao_launcher import restart_oracle
                selected=contract_consumer if side=="candidate" else official
                stop_oracle(selected);restart_oracle(selected)
            t.check(side+".restart_health",client.health()["cluster_id"]==identities[side]["cluster_id"])
            response=client.request("GET","/v1/pki-root/cert/ca")
            t.check(side+".restart_root_readback",response.status==200 and response.body.get("data",{}).get("certificate")==certificates[side],response.status)
        t.call("remote.rotate",r,"POST","transit/keys/ca/rotate",200)
        for side,client in clients.items():
            prefix=side+".rotated."
            t.call(prefix+"mount",client,"POST","sys/mounts/pki-rotated",204,{"type":"pki"})
            t.call(prefix+"grant",client,"POST",CONFIG+"/keys/fixed/grants/pki-rotated",204)
            before=sign_entries(remote)
            response=client.request("POST","/v1/pki-rotated/root/generate/kms",{"external_key_ref":"provider:fixed","common_name":"synthetic-old-ca.example.test","ttl":"1h"})
            t.check(prefix+"old_fixed_rejected",response.status==400,response.status)
            t.check(prefix+"no_certificate","certificate" not in response.body.get("data",{}))
            t.check(prefix+"no_sign",sign_entries(remote)==before)
        audit=(audit_root/"audit.jsonl").read_text()
        t.check("candidate.audit_no_credentials",all(secret not in audit for secret in (remote_token,candidate_token,unseal)))
        result.update(identities=identities,oracle_only_contract=oracle_contract,
            oracle_storage_backends={"remote":remote["storage_backend"],"official":official["storage_backend"]})
    finally:
        native_handle=None if native is None else native.process
        if native is not None:native.stop()
        for instance in reversed(instances):stop_oracle(instance)
        cleared=(native_handle is None or native_handle.poll() is not None) and all(instance["process"].poll() is not None for instance in instances)
        t.check("owned_processes_cleared",cleared)
    return result

def main():
    parser=SafeArgumentParser(description=__doc__)
    for name in ("binary","output","build-source-commit","build-source-tree","expected-binary-sha256"):parser.add_argument("--"+name,required=True)
    parser.add_argument("--oracle-version",choices=(VERSION,),default=VERSION)
    args=parser.parse_args();binary=Path(args.binary).resolve(strict=True);output=Path(args.output).resolve()
    if output.exists():parser.error("output already exists")
    stat=output.parent.stat()
    if stat.st_uid!=os.geteuid() or stat.st_mode&0o077:parser.error("output directory must be caller-owned mode 0700")
    for value,length in ((args.build_source_commit,40),(args.build_source_tree,40),(args.expected_binary_sha256,64)):
        if len(value)!=length or any(char not in "0123456789abcdef" for char in value):parser.error("source/binary identity malformed")
    pins=pinned_artifact(version=args.oracle_version);rows=[]
    result={"schema":"heptabao.external-pki-consumer270-comparison.v1","target_version":VERSION,"synthetic_only":True,
        "scope":"direct_ed25519_external_root_and_intermediate_csr","full_openbao_compatibility":False,"compatibility_claim":False,
        "independent_qualification":False,"production_authority":False,"migration_authority":False,"release_authority":False,
        "build_source_commit":args.build_source_commit,"build_source_tree":args.build_source_tree,"expected_binary_sha256":args.expected_binary_sha256,
        "actual_binary_sha256_before":file_digest(binary),"oracle_binary_sha256":pins["binary_sha256"],"oracle_artifact_sha256":pins["artifact_sha256"],
        "source_commit":subprocess.check_output(["git","rev-parse","HEAD"],cwd=ROOT,text=True).strip(),
        "source_worktree_dirty":bool(subprocess.check_output(["git","status","--porcelain"],cwd=ROOT)),
        "runner_sha256":file_digest(__file__),"cargo_lock_sha256":file_digest(ROOT/"Cargo.lock"),
        "source_binary_binding":"recorded_not_independently_attested","started_at_unix":time.time(),"required_case_count":len(EXPECTED_CASES),"cases":rows}
    try:
        shared.Trace(rows).check("candidate.binary_before_hash",result["actual_binary_sha256_before"]==args.expected_binary_sha256)
        result.update(run(binary,rows))
    except Exception as error:
        result["failure"]=str(error) if isinstance(error,shared.Failure) else type(error).__name__
    result["actual_binary_sha256_after"]=file_digest(binary)
    try:shared.Trace(rows).check("candidate.binary_after_hash",result["actual_binary_sha256_after"]==args.expected_binary_sha256)
    except shared.Failure as error:result["failure"]=str(error)
    result.update(passed=not result.get("failure") and trace_complete(rows),finished_at_unix=time.time())
    private_write(output,result)
    print(json.dumps({"passed":result["passed"],"case_count":len(rows),"required_case_count":len(EXPECTED_CASES),"failure":result.get("failure")}))
    return 0 if result["passed"] else 1

if __name__=="__main__":raise SystemExit(main())
