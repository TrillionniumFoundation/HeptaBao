#!/usr/bin/env python3
"""Document the immutable R1 source; no Rust execution or host observation."""
from pathlib import Path
import hashlib,json
P=Path(__file__).resolve().parent
def pin(p):
 b=p.read_bytes(); return {'blob':hashlib.sha1(b'blob '+str(len(b)).encode()+b'\0'+b).hexdigest(),'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest()}
def emit(name,value):
 (P/name).write_text(json.dumps(value,indent=2,ensure_ascii=False)+'\n')
result=json.loads((P/'VERIFY.result.public.json').read_text())
changed=json.loads((P/'SOURCE.splice-inputs.json').read_text())
table=[]
for name,v in sorted(changed.items()):
 table.append({'path':'crates/heptabao-server/src/'+name,'before':v['before'],'after':v['after'],'diff':pin(P/'diffs'/(name+'.diff')),'change':'new' if v['before'] is None else 'modified'})
emit('FILES.public.json',{'base_commit':'4e808d0ecb1bcded22870a7ec960dfb2491cf6ec','base_tree':'eba5e650bd080b8ad41ea52a2bc68867f541d255','seven_modified_two_new':table})
claims=[
 ('service_native_auth.rs','dispatch_native_auth_request','Select Userpass first, then JWT. R1 Token API composition gaps are explicit in CROSS-REVIEW.md.'),
 ('service_native_auth.rs','dispatch_native_owner_request_with_pki','Capture original source proof; fresh jwt_lifetime=None; pass private output only for JWT login.'),
 ('service.rs','dispatch_native_authorized_subrequest','Forward the request-local optional output; ordinary wrapper passes None.'),
 ('service.rs','dispatch_authorized_subrequest_inner','Fresh authenticated_jwt_lifetime=None; actual Auth then finish_identity_response_observed; export only after successful finalization/candidate installation.'),
 ('auth.rs','handle_with_connection_clock_and_native_jwt_lifetime_for_cluster','Reject prefilled optional output; forward to actual JWT route.'),
 ('auth.rs','jwt_route_with_native_lifetime','Select exactly one verifier branch. All original role/key/body/claim/token candidate processing remains in actual handler.'),
 ('federated_native_jwt.rs','verify_native_with_user_claim_and_lifetime','One self.verified_claims call; return private lifetime with identity only after original predicates succeed.'),
 ('federated_auth.rs','verified_claims','Existing PEM-key search may try multiple cryptographic keys; no second verifier invocation was added.'),
 ('auth_native_jwt.rs','bind_successful_login','Consume private lifetime once; bind actual issued token/root/role/accessor/entity/source; never reverify assertion.'),
 ('service_native_auth.rs','dispatch_native_owner_request_with_pki','Bind original status/body before plan; retain source gate, Identity-only engine delta, real commit and terminal custody.'),
 ('service_native_auth.rs','complete_native_auth_delivery','Require mandatory actual audit and retained original publication proof; do not roll back a known durable root on later denial.')]
emit('CALLGRAPH.public.json',{'source_only':True,'edges':[{'file':f,'pin':pin(P/'candidate'/f),'function':n,'contract':c} for f,n,c in claims],'verification_claim':'One existing verifier invocation; PEM primitive may iterate matching keys. No second authentication pass.','no_durable_witness_schema':True,'zero_runtime_and_compile':True})
coverage=[
 ('real local service login, same assertion twice, one entity, cold value, expired-assertion renewal after key rotation, revoke/unmount','Missing Token API child/batch/mixed-origin cases are separately flagged.'),
 ('remote JWT/batch JWT/bad signature fail closed; complete relevant Auth/Identity projection unchanged','Does not test Token API batch issuance by a JWT actor.'),
 ('current legacy role collection GET/list and named DELETE/update+sudo; no-sudo denial','Not an OpenBao ACL oracle result.'),
 ('disabled actual Identity after verification; no returned witness/token; later fresh success','No synthetic Identity grant/witness.'),
 ('original assertion expires after real authentication before plan; logical root unchanged and cold check','No claim that every lower-level unknown I/O writes zero bytes.'),
 ('real owner-capacity gate 507 after authentication; root fits but candidate does not','Known prepublication capacity veto, not unknown I/O injection.'),
 ('real committed root; assertion expiry during actual audit vetoes delivery','Committed root remains, no rollback.'),
 ('actual mandatory audit capacity failure; complete root retained/recovery required','No automatic retry or token reissue.'),
 ('audited status tamper plus original deadline expiry','No replacement deadline/proof.'),
 ('actual owner/proof held across separately authorized real revoke; stale delivery rejected','Actual original proof reused only for rejection; cold revoked token denied.')]
emit('REGRESSIONS.public.json',{'file':pin(P/'candidate/service_native_jwt_tests.rs'),'count':10,'executed':0,'compile':False,'tests':[{'name':n,'required_observation':c,'limit':l,'execution':'NOT_RUN'} for n,(c,l) in zip(result['new_test_names'],coverage,strict=True)],'existing_userpass_test_update':'Only unsupported-provider example jwt -> oidc; all original assertions/test name preserved.','existing_qualified_denominators_changed':False,'uncovered_r1':['JWT-origin Token API service child','JWT-origin Token API batch grant','mixed Userpass/JWT targets','official OpenBao 2.7.1 role ACL oracle','durable/HA UNKNOWN fault harness']})
emit('EXECUTION.public.json',{'kind':'recorded_local_completion_observation_not_original_SDK','command':'python3 ha_native_jwt_source_r1/verify_source.py','local_session_id':12095,'observed_exit_code':0,'result':pin(P/'VERIFY.result.public.json'),'source_only_checks':799,'unchanged_existing_functions':641,'Rust_compiled':False,'Rust_tests_run':0,'rustfmt_run':False,'Runtime_calls':0,'old_local_session_73135_terminal_sdk_unobserved':True})
files=[]
for p in sorted(P.rglob('*')):
 if not p.is_file() or p.name in {'FREEZE.input.public.json','MANIFEST.public.json','PACKET.public.json'}: continue
 # One preserved copy for each checker failure, not the live duplicate path.
 if p.name=='VERIFY.failure.public.json': continue
 files.append({'path':str(p.relative_to(P)),**pin(p)})
emit('FREEZE.input.public.json',{'status':'FROZEN_R1_WITH_TWO_FUNCTIONAL_BLOCKERS','base_commit':'4e808d0ecb1bcded22870a7ec960dfb2491cf6ec','files':files,'total_bytes':sum(f['bytes'] for f in files)})
print(json.dumps({'files':len(files),'bytes':sum(f['bytes'] for f in files),'Runtime':0,'Rust_compile':False}))
