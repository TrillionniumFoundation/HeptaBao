#!/usr/bin/env python3
"""Fresh three-process external Ed25519 leaf/full/delta CRL comparison.

Only public TLS API observations and real cryptographic verification qualify a
row. A complete predeclared trace is required; CSR compatibility is excluded.
"""
from __future__ import annotations
import base64
from datetime import timezone
import importlib.util
import json
import math
import os
from pathlib import Path
import subprocess
import tempfile
import time
import urllib.error
import urllib.request

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from bao_http import BaoError, Client, SafeArgumentParser, private_read, private_write
from official_openbao_launcher import file_digest, pinned_artifact, start_oracle, stop_oracle, restart_oracle
import external_transit_consumer_live as shared

ROOT=Path(__file__).resolve().parents[2]
VERSION="2.7.0"
HTTP_TIMEOUT_SECONDS=2

def bounded_native_instance(smoke,binary,root):
    # This successor tightens the former native control 10s / Client 15s
    # defaults. Its runner digest and explicit scopes identify the new budget.
    class BoundedInstance(smoke.Instance):
        def call(self,method,path,body=None,*,token=None):
            selected=self.token if token is None else token
            client=Client(self.address,str(self.root/"ca.crt"),selected or "synthetic-uninitialized-client",timeout=HTTP_TIMEOUT_SECONDS)
            try:response=client.request(method,"/v1/"+path,body,token=selected)
            except BaoError as error:
                # The inherited startup poll distinguishes unavailable TLS
                # listeners from certificate rejection using the original
                # exception. Preserve that distinction for its health read.
                cause=error.__context__
                if method=="GET" and path=="sys/health" and str(error)=="transport_read_failed" and isinstance(cause,(OSError,urllib.error.URLError)):
                    raise cause
                raise
            return response.status,response.body
    return BoundedInstance(binary,root)

def expected_cases():
    cases=["candidate.binary_before_hash","remote.health","official.health","candidate.health","distinct_process_clusters",
        "oracle.selected_backend","remote.mount","remote.key","remote.public_key"]
    for side in ("candidate","official"):
        cases += [f"{side}.{name}" for name in ("mount","config","mapping","missing_grant","missing_grant_no_sign","grant",
            "root_generate","root_sign_exact","root_signature","root_spki","root_private_absent",
            "initial_full_read","initial_full_signature","initial_full_number","initial_full_revocations","initial_full_extensions",
            "initial_delta_read","initial_delta_signature","initial_delta_number","initial_delta_revocations","initial_delta_extensions",
            "cached_reads_no_sign","role","leaf_issue","leaf_sign_exact","leaf_exact_response","leaf_signature","leaf_private_binding",
            "leaf_usage","leaf_identifiers","leaf_san","leaf_lease","leaf_readback","leaf_readback_private_absent",
            "grant_delete","grant_denied_leaf","grant_denied_leaf_no_private","grant_denied_no_sign","grant_restore",
            "revoke","revoke_sign_exact","revoke_exact_response",
            "revoked_full_read","revoked_full_signature","revoked_full_number","revoked_full_revocations","revoked_full_extensions",
            "revoked_delta_read","revoked_delta_signature","revoked_delta_number","revoked_delta_revocations","revoked_delta_extensions",
            "rotate","rotate_sign_exact","rotated_full_read","rotated_full_signature","rotated_full_number","rotated_full_revocations","rotated_full_extensions",
            "rotated_delta_read","rotated_delta_signature","rotated_delta_number","rotated_delta_revocations","rotated_delta_extensions")]
    for side in ("candidate","official"):
        cases += [f"{side}.{name}" for name in ("restart_health","restart_leaf_readback","restart_full_read","restart_full_signature","restart_full_number","restart_full_revocations","restart_full_extensions","restart_delta_read","restart_delta_signature","restart_delta_number","restart_delta_revocations","restart_delta_extensions")]
    cases += ["candidate.audit_no_credentials","owned_processes_cleared","candidate.binary_after_hash"]
    return tuple(cases)

EXPECTED_CASES=expected_cases()

def trace_complete(rows):
    if not isinstance(rows,list) or tuple(row.get("case") for row in rows)!=EXPECTED_CASES or not all(row.get("passed") is True for row in rows):return False
    for row in rows:
        if row["case"].endswith("sign_exact"):
            count=3 if row["case"].endswith("root_sign_exact") else 1 if row["case"].endswith("leaf_sign_exact") else 2
            if row.get("observed_provider_sign_entries")!=count or row.get("expected_provider_sign_entries")!=count:return False
        if row["case"].endswith("leaf_lease") and not lease_metadata_complete(row):return False
    return True

def lease_metadata_complete(row):
    before=row.get("request_before_unix");after=row.get("request_after_unix")
    expires=row.get("certificate_not_after_unix");not_before=row.get("certificate_not_before_unix")
    duration=row.get("observed_lease_duration")
    if (type(before) not in (int,float) or type(after) not in (int,float)
            or not math.isfinite(before) or not math.isfinite(after) or before>after
            or type(expires) is not int or type(not_before) is not int or type(duration) is not int):return False
    lower=max(0,math.floor(expires-after+0.5));upper=max(0,math.floor(expires-before+0.5))
    return (row.get("lease_id_present") is True and row.get("observed_renewable") is False
        and expires-not_before==630 and math.floor(before)+600<=expires<=math.floor(after)+600
        and row.get("certificate_requested_ttl_matches") is True
        and row.get("lease_duration_expected_min")==lower and row.get("lease_duration_expected_max")==upper
        and lower<=duration<=upper)

def sign_entries(remote):
    entries=0
    for line in (Path(remote["root"])/"audit.jsonl").read_text().splitlines():
        record=json.loads(line)
        entries += record.get("type")=="request" and record.get("request",{}).get("path")=="transit/sign/ca"
    return entries

def sign_count(trace,case,remote,before,expected):
    count=sign_entries(remote)-before
    try:trace.check(case,count==expected)
    finally:
        if trace.rows and trace.rows[-1].get("case")==case:
            trace.rows[-1].update(observed_provider_sign_entries=count,expected_provider_sign_entries=expected)

def check_leaf_lease(trace,case,body,*,request_before=None,request_after=None,certificate=None):
    # These scalars are safe diagnostics even when the contract rejects a row.
    # Never retain the lease identifier or certificate/private-key response.
    duration=body.get("lease_duration")
    renewable=body.get("renewable")
    present=bool(body.get("lease_id"))
    diagnostics={}
    matched=False
    if (certificate is not None and type(request_before) in (int,float)
            and type(request_after) in (int,float) and math.isfinite(request_before)
            and math.isfinite(request_after) and request_before<=request_after):
        after=getattr(certificate,"not_valid_after_utc",None) or certificate.not_valid_after.replace(tzinfo=timezone.utc)
        before=getattr(certificate,"not_valid_before_utc",None) or certificate.not_valid_before.replace(tzinfo=timezone.utc)
        expires=int(after.timestamp());not_before=int(before.timestamp())
        # The successful endpoint reports its remaining certificate validity,
        # rounded to the nearest second at a time inside this request window.
        # A window wholly below/above a half-second has one exact permitted value.
        lower=max(0,math.floor(expires-request_after+0.5))
        upper=max(0,math.floor(expires-request_before+0.5))
        data=body.get("data",{})
        window=(expires-not_before==630 and math.floor(request_before)+600<=expires<=math.floor(request_after)+600
            and data.get("expiration")==expires and data.get("not_before")==not_before)
        matched=(present and type(duration) is int and renewable is False and window and lower<=duration<=upper)
        diagnostics.update(certificate_not_after_unix=expires,certificate_not_before_unix=not_before,
            request_before_unix=request_before,request_after_unix=request_after,
            lease_duration_expected_min=lower,lease_duration_expected_max=upper,certificate_requested_ttl_matches=window)
    try:trace.check(case,matched)
    finally:
        if trace.rows and trace.rows[-1].get("case")==case:
            trace.rows[-1].update(lease_id_present=present,
                observed_lease_duration=duration if type(duration) is int else None,
                observed_renewable=renewable if type(renewable) is bool else None)
            trace.rows[-1].update(diagnostics)

def raw_crl(client,delta):
    path="/v1/pki/crl"+("/delta" if delta else "")
    opener=client._opener
    request=urllib.request.Request(client.address+path,headers={"X-Vault-Token":client._token})
    try:response=opener.open(request,timeout=2)
    except urllib.error.HTTPError as error:response=error
    with response:
        payload=response.read(512*1024+1)
        if len(payload)>512*1024:raise shared.Failure("bounded_public_crl")
        return response.status,payload

def check_crl(t,client,public,prefix,number,revoked,delta,serial):
    status,der=raw_crl(client,delta);t.check(prefix+"read",status==200,status)
    crl=x509.load_der_x509_crl(der)
    public.verify(crl.signature,crl.tbs_certlist_bytes);t.check(prefix+"signature",True)
    t.check(prefix+"number",crl.extensions.get_extension_for_class(x509.CRLNumber).value.crl_number==number)
    entries=list(crl);t.check(prefix+"revocations",len(entries)==revoked and (not revoked or entries[0].serial_number==serial))
    expected=["2.5.29.35","2.5.29.20"]+(["2.5.29.27"] if delta else [])
    matched=[extension.oid.dotted_string for extension in crl.extensions]==expected and int((crl.next_update-crl.last_update).total_seconds())==72*3600
    if delta:matched=matched and crl.extensions.get_extension_for_class(x509.DeltaCRLIndicator).value.crl_number==number-1
    t.check(prefix+"extensions",matched)
    return der

def run(binary,rows,*,oracle_contract=False):
    spec=importlib.util.spec_from_file_location("external_pki_leaf_smoke",ROOT/"qa/single-node/smoke.py")
    smoke=importlib.util.module_from_spec(spec);spec.loader.exec_module(smoke)
    private_root=Path(tempfile.mkdtemp(prefix="heptabao-external-pki-leaf270-"));private_root.chmod(0o700)
    instances=[];native=None;contract_consumer=None;t=shared.Trace(rows);result={}
    try:
        remote=start_oracle(shared.free_port(),version=VERSION,audit_file=True);instances.append(remote)
        official=start_oracle(shared.free_port(),version=VERSION);instances.append(official)
        r=shared.oracle_client(remote);o=shared.oracle_client(official)
        remote_token=private_read(remote["token_file"],8192).decode().strip();ca=Path(remote["ca_file"]).read_text()
        if oracle_contract:
            contract_consumer=start_oracle(shared.free_port(),version=VERSION,audit_file=True);instances.append(contract_consumer)
            c=shared.oracle_client(contract_consumer);audit_root=Path(contract_consumer["root"])
            native_token=private_read(contract_consumer["token_file"],8192).decode().strip()
        else:
            native=bounded_native_instance(smoke,binary,private_root/"candidate");shared.native_configuration(native,remote,ca);native.start()
            status,initialized=native.call("POST","sys/init",{"secret_shares":1,"secret_threshold":1})
            if status!=200:raise shared.Failure("candidate_init")
            native.token,unseal=initialized["root_token"],initialized["keys_base64"][0]
            if native.call("POST","sys/unseal",{"key":unseal})[0]!=200:raise shared.Failure("candidate_unseal")
            c=Client(native.address,str(native.root/"ca.crt"),native.token,timeout=HTTP_TIMEOUT_SECONDS);audit_root=native.root;native_token=native.token
        clients={"candidate":c,"official":o};identities={}
        for side,client in (("remote",r),("official",o),("candidate",c)):
            health=client.health();t.check(side+".health",health.get("initialized") is True and health.get("sealed") is False and (side=="candidate" and not oracle_contract or health.get("version")==VERSION))
            identities[side]={key:health[key] for key in ("cluster_id","version")}
        t.check("distinct_process_clusters",len({health["cluster_id"] for health in identities.values()})==3)
        t.check("oracle.selected_backend",remote["storage_backend"]==official["storage_backend"]=="pebbledb" and (not oracle_contract or contract_consumer["storage_backend"]=="pebbledb"))
        t.call("remote.mount",r,"POST","sys/mounts/transit",204,{"type":"transit"});t.call("remote.key",r,"POST","transit/keys/ca",200,{"type":"ed25519"})
        descriptor=r.request("GET","/v1/transit/keys/ca");raw=base64.b64decode(descriptor.body["data"]["keys"]["1"]["public_key"],validate=True)
        t.check("remote.public_key",descriptor.status==200 and len(raw)==32)
        public=ed25519.Ed25519PublicKey.from_public_bytes(raw);documents={};crls={}
        for side,client in clients.items():
            config={"plugin":"transit","address":remote["address"],"token":remote_token,"mount_path":"transit","verify":side=="official" or oracle_contract}
            if side=="official" or oracle_contract:config["tls_ca_cert_bytes"]=ca
            prefix=side+".";cfg="sys/external-keys/configs/provider"
            t.call(prefix+"mount",client,"POST","sys/mounts/pki",204,{"type":"pki"})
            t.call(prefix+"config",client,"POST",cfg,204,config);t.call(prefix+"mapping",client,"POST",cfg+"/keys/fixed",204,{"name":"ca","version":1,"verify":side=="official" or oracle_contract})
            before=sign_entries(remote);root_body={"external_key_ref":"provider:fixed","common_name":"synthetic-ca.example.test","ttl":"1h"}
            t.call(prefix+"missing_grant",client,"POST","pki/root/generate/kms",400,root_body);t.check(prefix+"missing_grant_no_sign",sign_entries(remote)==before)
            t.call(prefix+"grant",client,"POST",cfg+"/keys/fixed/grants/pki",204,{})
            before=sign_entries(remote);response=client.request("POST","/v1/pki/root/generate/kms",root_body)
            t.check(prefix+"root_generate",response.status==200,response.status);sign_count(t,prefix+"root_sign_exact",remote,before,3)
            data=response.body["data"];root_pem=data["certificate"];root_cert=x509.load_pem_x509_certificate(data["certificate"].encode());public.verify(root_cert.signature,root_cert.tbs_certificate_bytes)
            t.check(prefix+"root_signature",True);t.check(prefix+"root_spki",root_cert.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw)==raw)
            t.check(prefix+"root_private_absent","private_key" not in data)
            before=sign_entries(remote)
            check_crl(t,client,public,prefix+"initial_full_",1,0,False,None);check_crl(t,client,public,prefix+"initial_delta_",2,0,True,None)
            t.check(prefix+"cached_reads_no_sign",sign_entries(remote)==before)
            t.call(prefix+"role",client,"POST","pki/roles/leaf",200,{"allowed_domains":["example.test"],"allow_subdomains":True,"max_ttl":"30m","generate_lease":True,"key_type":"ed25519"})
            before=sign_entries(remote);leaf_request_before=time.time()
            response=client.request("POST","/v1/pki/issue/leaf",{"common_name":"leaf.example.test","ttl":"10m"})
            leaf_request_after=time.time()
            t.check(prefix+"leaf_issue",response.status==200,response.status);sign_count(t,prefix+"leaf_sign_exact",remote,before,1)
            data=response.body["data"];fields={"certificate","issuing_ca","ca_chain","private_key","private_key_type","serial_number","expiration","not_before"}
            t.check(prefix+"leaf_exact_response",set(data)==fields and data["private_key_type"]=="ed25519" and data["ca_chain"]==[data["issuing_ca"]] and data["issuing_ca"]==root_pem)
            leaf=x509.load_pem_x509_certificate(data["certificate"].encode());public.verify(leaf.signature,leaf.tbs_certificate_bytes);t.check(prefix+"leaf_signature",True)
            private=serialization.load_pem_private_key(data["private_key"].encode(),password=None)
            leaf_public=leaf.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw)
            t.check(prefix+"leaf_private_binding",private.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw)==leaf_public)
            usage=leaf.extensions.get_extension_for_class(x509.KeyUsage).value;eku=leaf.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
            t.check(prefix+"leaf_usage",usage.digital_signature and usage.key_encipherment and usage.key_agreement and [oid.dotted_string for oid in eku]==["1.3.6.1.5.5.7.3.1","1.3.6.1.5.5.7.3.2"] and [extension.oid.dotted_string for extension in leaf.extensions]==["2.5.29.15","2.5.29.37","2.5.29.14","2.5.29.35","2.5.29.17"])
            t.check(prefix+"leaf_identifiers",leaf.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value==x509.SubjectKeyIdentifier.from_public_key(leaf.public_key()) and leaf.extensions.get_extension_for_class(x509.AuthorityKeyIdentifier).value.key_identifier==x509.SubjectKeyIdentifier.from_public_key(public).digest)
            t.check(prefix+"leaf_san",leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName)==["leaf.example.test"])
            check_leaf_lease(t,prefix+"leaf_lease",response.body,request_before=leaf_request_before,
                request_after=leaf_request_after,certificate=leaf)
            read=client.request("GET","/v1/pki/cert/"+data["serial_number"]);t.check(prefix+"leaf_readback",read.status==200 and read.body["data"]["certificate"]==data["certificate"],read.status)
            t.check(prefix+"leaf_readback_private_absent","private_key" not in read.body["data"])
            documents[side]={"certificate":data["certificate"],"serial_number":data["serial_number"],"serial":leaf.serial_number}
            t.call(prefix+"grant_delete",client,"DELETE",cfg+"/keys/fixed/grants/pki",204,{})
            before=sign_entries(remote);denied=client.request("POST","/v1/pki/issue/leaf",{"common_name":"leaf.example.test","ttl":"10m"})
            t.check(prefix+"grant_denied_leaf",denied.status==500,denied.status);t.check(prefix+"grant_denied_leaf_no_private","private_key" not in denied.body.get("data",{}))
            t.check(prefix+"grant_denied_no_sign",sign_entries(remote)==before);t.call(prefix+"grant_restore",client,"POST",cfg+"/keys/fixed/grants/pki",204,{})
            before=sign_entries(remote);response=client.request("POST","/v1/pki/revoke",{"serial_number":data["serial_number"]})
            t.check(prefix+"revoke",response.status==200,response.status);sign_count(t,prefix+"revoke_sign_exact",remote,before,2)
            t.check(prefix+"revoke_exact_response",set(response.body["data"])=={"revocation_time","revocation_time_rfc3339","state"} and response.body["data"]["state"]=="revoked")
            check_crl(t,client,public,prefix+"revoked_full_",3,1,False,leaf.serial_number);check_crl(t,client,public,prefix+"revoked_delta_",4,0,True,None)
            before=sign_entries(remote);response=client.request("GET","/v1/pki/crl/rotate")
            t.check(prefix+"rotate",response.status==200 and response.body.get("data")=={"success":True},response.status);sign_count(t,prefix+"rotate_sign_exact",remote,before,2)
            crls[side]=(check_crl(t,client,public,prefix+"rotated_full_",5,1,False,leaf.serial_number),check_crl(t,client,public,prefix+"rotated_delta_",6,0,True,None))
        for side in clients:
            if side=="official":stop_oracle(official);restart_oracle(official);client=shared.oracle_client(official)
            elif oracle_contract:stop_oracle(contract_consumer);restart_oracle(contract_consumer);client=shared.oracle_client(contract_consumer)
            else:
                native.stop();native.start()
                if native.call("POST","sys/unseal",{"key":unseal})[0]!=200:raise shared.Failure("candidate_restart_unseal")
                client=Client(native.address,str(native.root/"ca.crt"),native.token,timeout=HTTP_TIMEOUT_SECONDS)
            prefix=side+".";t.check(prefix+"restart_health",client.health()["cluster_id"]==identities[side]["cluster_id"])
            read=client.request("GET","/v1/pki/cert/"+documents[side]["serial_number"])
            t.check(prefix+"restart_leaf_readback",read.status==200 and read.body["data"]["certificate"]==documents[side]["certificate"] and "private_key" not in read.body["data"],read.status)
            full=check_crl(t,client,public,prefix+"restart_full_",5,1,False,documents[side]["serial"])
            delta=check_crl(t,client,public,prefix+"restart_delta_",6,0,True,None)
            if (full,delta)!=crls[side]:raise shared.Failure("signed_crl_restart_identity")
        audit=(audit_root/"audit.jsonl").read_text();t.check("candidate.audit_no_credentials",remote_token not in audit and native_token not in audit)
        result["identities"]=identities
    finally:
        native_handle=None if native is None else native.process
        if native:native.stop()
        for instance in reversed(instances):stop_oracle(instance)
        t.check("owned_processes_cleared",all(instance["process"].poll() is not None for instance in instances) and (native_handle is None or native_handle.poll() is not None))
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
    pins=pinned_artifact(version=VERSION);rows=[]
    report={"schema":"heptabao.external-pki-leaf-crl270-comparison.v1","target_version":VERSION,"synthetic_only":True,
        "scope":"external_ed25519_leaf_full_delta_crl_revoke_readback_restart","full_openbao_compatibility":False,"compatibility_claim":False,
        "independent_qualification":False,"production_authority":False,"migration_authority":False,"release_authority":False,
        "official_csr_remote_binding_compared":False,"build_source_commit":args.build_source_commit,"build_source_tree":args.build_source_tree,
        "expected_binary_sha256":args.expected_binary_sha256,"actual_binary_sha256_before":file_digest(binary),
        "oracle_binary_sha256":pins["binary_sha256"],"oracle_artifact_sha256":pins["artifact_sha256"],
        "source_commit":subprocess.check_output(["git","rev-parse","HEAD"],cwd=ROOT,text=True).strip(),
        "source_worktree_dirty":bool(subprocess.check_output(["git","status","--porcelain"],cwd=ROOT)),
        "runner_sha256":file_digest(__file__),"cargo_lock_sha256":file_digest(ROOT/"Cargo.lock"),
        "http_timeout_seconds":HTTP_TIMEOUT_SECONDS,"native_fixture_control_timeout_seconds":HTTP_TIMEOUT_SECONDS,
        "budget_revision":"successor_tightens_native_client_15s_and_control_10s_to_2s",
        "source_binary_binding":"recorded_not_independently_attested","started_at_unix":time.time(),"required_case_count":len(EXPECTED_CASES),"cases":rows}
    try:
        shared.Trace(rows).check("candidate.binary_before_hash",report["actual_binary_sha256_before"]==args.expected_binary_sha256)
        report.update(run(binary,rows))
    except Exception as error:report["failure"]=str(error) if isinstance(error,shared.Failure) else type(error).__name__
    report["actual_binary_sha256_after"]=file_digest(binary)
    try:shared.Trace(rows).check("candidate.binary_after_hash",report["actual_binary_sha256_after"]==args.expected_binary_sha256)
    except shared.Failure as error:report["failure"]=str(error)
    report.update(passed=not report.get("failure") and trace_complete(rows),finished_at_unix=time.time())
    private_write(output,report);print(json.dumps({"passed":report["passed"],"case_count":len(rows),"required_case_count":len(EXPECTED_CASES),"failure":report.get("failure")}))
    return 0 if report["passed"] else 1

if __name__=="__main__":raise SystemExit(main())
