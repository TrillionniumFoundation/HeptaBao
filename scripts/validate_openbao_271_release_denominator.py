#!/usr/bin/env python3
"""Fail-closed OpenBao 2.7.0+2.7.1 release denominator completeness.

This is a structural validator, NOT an executable compatibility attestation.
"""
from __future__ import annotations
import json
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
MANIFEST=ROOT/'planning/OPENBAO_271_ADMISSION_SUPERSET_V1.json'
BASELINE_COMMIT='a5db72cef75c24b920ade02065b18dd8eb666bac'
SECURITY=frozenset({
 'sanitized_acme_eab_mac_key',
 'root_generation_and_rekey_audit_fail_closed',
 'approle_secret_id_expiry_before_tidy',
 'approle_form_encoded_login',
 'certificate_quota_tls_identity',
 'kubernetes_renewal_post_revocation',
 'agent_proxy_quit_request_header',
 'canonical_resolve_path_operation',
 'plugin_command_path_confinement',
 'plugins_root_namespace_only',
 'unauthorized_workflow_policy_denial',
 'cross_namespace_policy_cache_isolation',
 'sdk_malformed_audit_redaction',
 'pki_acme_unvalidated_san_rejection',
 'oidc_ui_prompt_none_disabled',
})
EXTRA_CHANGES=frozenset({
 'barrier_rotation_disabled_field_persistence',
 'linux_package_default_pebbledb',
})
GATES=frozenset({
 'exact_head_native', 'prospective_main_merge', 'module_evidence_integrity',
 'scalable_state_storage', 'replay_identity_lifecycle',
 'complete_surface_admission', 'external_provider_semantics',
 'full_asset_migration', 'multi_host_fault_upgrade',
 'openbao_2_7_1_oracle', 'security_release_supply_chain',
})

def audit_rows(rows, category, required):
    errors=[]
    if not isinstance(rows,list):
        return [f'{category} must be an array']
    ids=[]
    for row in rows:
        if not isinstance(row,dict) or not isinstance(row.get('id'),str):
            errors.append(f'{category}: malformed item')
            continue
        key=row['id']
        ids.append(key)
        if row.get('status') not in ('OPEN','ADMITTED'):
            errors.append(f'{category}.{key}: unsupported status')
        if row.get('status')=='ADMITTED' and not row.get('receipt'):
            errors.append(f'{category}.{key}: admitted without evidence receipt')
        if not isinstance(row.get('scenario') if category!='required_gates' else row.get('id'),str):
            errors.append(f'{category}.{key}: missing scenario/id')
    duplicates=sorted(k for k in set(ids) if ids.count(k)>1)
    if duplicates:
        errors.append(f'{category}: duplicate ids {duplicates}')
    missing=sorted(required-set(ids))
    if missing:
        errors.append(f'{category}: missing required ids {missing}')
    return errors

def validate(doc):
    if not isinstance(doc,dict):
        return ['admission document must be an object']
    errors=[]
    if doc.get('schema')!='heptabao.openbao-2.7.1-complete-replacement-admission.v1':
        errors.append('wrong 2.7.1 admission schema')
    baseline=doc.get('baseline')
    if not isinstance(baseline,dict) or baseline.get('product')!='OpenBao' or baseline.get('version')!='2.7.1' or baseline.get('commit')!=BASELINE_COMMIT:
        errors.append('pinned official 2.7.1 baseline mismatch')
    for name,ids in [('security_delta',SECURITY),('feature_and_correctness_delta',EXTRA_CHANGES)]:
        errors.extend(audit_rows(doc.get(name),name,ids))
    gate_rows=doc.get('required_gates')
    if not isinstance(gate_rows,list):
        errors.append('required_gates must be an array')
    else:
        seen=[]
        for gate in gate_rows:
            if not isinstance(gate,dict) or not isinstance(gate.get('id'),str):
                errors.append('malformed required gate')
                continue
            seen.append(gate['id'])
            if gate.get('status') not in ('OPEN','ADMITTED'):
                errors.append(f"required_gates.{gate['id']}: bad status")
            if gate.get('status')=='ADMITTED' and not gate.get('exact_candidate_receipt'):
                errors.append(f"required_gates.{gate['id']}: admitted without exact candidate receipt")
        if len(seen)!=len(set(seen)):
            errors.append('duplicate required gate')
        if not GATES.issubset(set(seen)):
            errors.append('required gate denominator missing: '+repr(sorted(GATES-set(seen))))
    # No amount of coverage metadata can issue production authority.
    if doc.get('replacement_authority') is not False or doc.get('authority')!='NOT_ADMITTED':
        errors.append('structural coverage validation cannot authorize replacement')
    return errors

def main():
    try:
        errors=validate(json.loads(MANIFEST.read_text()))
    except (OSError,json.JSONDecodeError) as exc:
        print('FAIL: cannot read 2.7.1 release denominator:',str(exc))
        return 1
    if errors:
        for err in errors:print('FAIL:',err)
        return 1
    print('PASS: OpenBao 2.7.0+2.7.1 release delta structurally complete; security=15, supplemental changes=2, gates=11, release authority=false')
    return 0

if __name__=='__main__':
    raise SystemExit(main())
