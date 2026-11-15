#!/usr/bin/env python3
"""Compare external roots and the native OpenBao 2.7 locally owned KMS CSR.

Root signatures use the real remote provider. Standard KMS CSRs use their
actual local Ed25519 public key selected from the provider type, its own
self-signature, and zero remote sign entries.
The original failed remote-bound standard-CSR profile remains separate.
"""
from __future__ import annotations
import json
import os
from pathlib import Path
import subprocess
import time

from bao_http import SafeArgumentParser, private_write
from official_openbao_launcher import file_digest, pinned_artifact
import external_pki_consumer_live as pki

ROOT=pki.ROOT
VERSION=pki.VERSION

def expected_cases():
    cases=["candidate.binary_before_hash","remote.health","official.health","candidate.health",
        "distinct_process_clusters","oracle.selected_backend","remote.mount","remote.key","remote.public_key"]
    for side in ("candidate","official"):
        cases += [f"{side}.{name}" for name in ("config","mapping")]
        for kind in ("root","csr"):
            signature=("actual_self_signature","local_spki_distinct") if kind=="csr" else ("actual_signature","spki_matches")
            cases += [f"{side}.{kind}.{name}" for name in ("mount","missing_grant","missing_grant_no_sign","grant",
                "generate","provider_sign_exact","exact_response",*signature,"private_key_absent")]
        cases += [f"{side}.{name}" for name in ("namespace","namespace_mount","namespace_root_ref_rejected",
            "namespace_config","namespace_mapping","namespace_grant","namespace_generate","namespace_provider_sign_exact",
            "namespace_signature","root_readback","restart_health","restart_root_readback")]
    cases += ["remote.rotate"]
    for side in ("candidate","official"):
        cases += [f"{side}.rotated.{name}" for name in ("mount","grant","old_fixed_rejected","no_certificate","no_sign")]
    cases += ["candidate.audit_no_credentials","owned_processes_cleared","candidate.binary_after_hash"]
    return tuple(cases)

EXPECTED_CASES=expected_cases()
NATIVE_CSR_CASES=tuple(case for case in EXPECTED_CASES if ".csr." in case)
ROOT_COMPARISON_CASES=tuple(case for case in EXPECTED_CASES if case not in NATIVE_CSR_CASES)

def trace_complete(rows,expected=EXPECTED_CASES,*,oracle_contract=False):
    if not isinstance(rows,list) or tuple(row.get("case") for row in rows)!=expected or not all(row.get("passed") is True for row in rows):return False
    for row in rows:
        if row["case"].endswith("provider_sign_exact"):
            count=0 if ".csr." in row["case"] else 3
            if row.get("observed_provider_sign_entries")!=count or row.get("expected_provider_sign_entries")!=count:return False
    return True

def scope_results(rows):
    root=[row for row in rows if row.get("case") in ROOT_COMPARISON_CASES]
    csr=[row for row in rows if row.get("case") in NATIVE_CSR_CASES]
    return trace_complete(root,ROOT_COMPARISON_CASES),trace_complete(csr,NATIVE_CSR_CASES)

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
    result={"schema":"heptabao.external-pki-root270-native-local-csr.v2","target_version":VERSION,"synthetic_only":True,
        "scope":"external_ed25519_roots_and_native_local_kms_csrs_compared","full_openbao_compatibility":False,"compatibility_claim":False,
        "independent_qualification":False,"production_authority":False,"migration_authority":False,"release_authority":False,
        "official_native_local_csr_compared":True,"remote_bound_csr_extension_compared":False,
        "build_source_commit":args.build_source_commit,"build_source_tree":args.build_source_tree,"expected_binary_sha256":args.expected_binary_sha256,
        "actual_binary_sha256_before":file_digest(binary),"oracle_binary_sha256":pins["binary_sha256"],"oracle_artifact_sha256":pins["artifact_sha256"],
        "source_commit":subprocess.check_output(["git","rev-parse","HEAD"],cwd=ROOT,text=True).strip(),
        "source_worktree_dirty":bool(subprocess.check_output(["git","status","--porcelain"],cwd=ROOT)),
        "runner_sha256":file_digest(__file__),"shared_runner_sha256":file_digest(pki.__file__),"cargo_lock_sha256":file_digest(ROOT/"Cargo.lock"),
        "source_binary_binding":"recorded_not_independently_attested","started_at_unix":time.time(),"required_case_count":len(EXPECTED_CASES),"cases":rows}
    try:
        pki.shared.Trace(rows).check("candidate.binary_before_hash",result["actual_binary_sha256_before"]==args.expected_binary_sha256)
        result.update(pki.run(binary,rows,compare_official_csr=True,observe_provider_signs=True,local_csr=True))
    except Exception as error:
        result["failure"]=str(error) if isinstance(error,pki.shared.Failure) else type(error).__name__
    result["actual_binary_sha256_after"]=file_digest(binary)
    try:pki.shared.Trace(rows).check("candidate.binary_after_hash",result["actual_binary_sha256_after"]==args.expected_binary_sha256)
    except pki.shared.Failure as error:result["failure"]=str(error)
    root,csr=scope_results(rows)
    result.update(root_comparison_passed=root,native_local_csr_comparison_passed=csr,
        passed=not result.get("failure") and trace_complete(rows) and root and csr,finished_at_unix=time.time())
    private_write(output,result)
    print(json.dumps({"passed":result["passed"],"root_comparison_passed":root,"native_local_csr_comparison_passed":csr,
        "case_count":len(rows),"required_case_count":len(EXPECTED_CASES),"failure":result.get("failure")}))
    return 0 if result["passed"] else 1

if __name__=="__main__":raise SystemExit(main())
