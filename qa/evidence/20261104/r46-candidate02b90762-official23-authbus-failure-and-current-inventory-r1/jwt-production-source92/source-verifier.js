
/* Pure V8 source/evidence verifier. Never evaluates Rust or calls Runtime. */
function verifyJwtPolicyCandidate(texts, H) {
  const checks=[];
  const ok=(value,label,detail=null)=>{checks.push({label,pass:!!value,detail});if(!value)throw Error(label);};
  const eq=(a,b,label)=>ok(JSON.stringify(a)===JSON.stringify(b),label);
  const mapping=JSON.parse(texts["SOURCE-MAP.public.json"]);
  ok(mapping.files.length===12,"twelve exact source leaves");
  ok(mapping.files.filter(r=>r.kind==="modify").length===10,"ten existing leaves");
  ok(mapping.files.filter(r=>r.kind==="new").length===2,"two new leaves");
  ok(mapping.candidateCommit===null&&mapping.execution.rustCompiled===false&&mapping.execution.nativeCalls===0,"uncommitted SOURCE-only");
  const by={};
  for(const r of mapping.files){
    const before=r.beforeFile?texts[r.beforeFile]:"",after=texts[r.afterFile];
    ok(typeof after==="string"&&(!r.beforeFile||typeof before==="string"),"whole source present "+r.index);
    if(r.before)eq(H.meta(before),r.before,"whole actual before "+r.index);
    eq(H.meta(after),r.after,"whole after "+r.index);
    eq(H.meta(texts[r.forwardFile]),r.forward,"whole forward diff "+r.index);
    eq(H.meta(texts[r.reverseFile]),r.reverse,"whole reverse diff "+r.index);
    ok(H.apply(before,texts[r.forwardFile])===after,"strict forward "+r.index);
    ok(H.apply(after,texts[r.forwardFile],true)===before,"strict forward reversal "+r.index);
    ok(H.apply(after,texts[r.reverseFile])===before,"strict reverse "+r.index);
    ok(H.apply(before,texts[r.reverseFile],true)===after,"strict reverse reversal "+r.index);
    ok(jwtBalanced(after),"lexical delimiter balance only "+r.index);
    by[r.path.split("/").pop()]={before,after,row:r};
  }
  ok(mapping.files.reduce((s,r)=>s+r.after.bytes,0)===1404403,"total candidate bytes");
  ok(mapping.files.reduce((s,r)=>s+r.hunks,0)===39,"thirty-nine strict hunks including two additions");

  const auth=by["auth.rs"],native=by["auth_native_jwt.rs"];
  const stage=texts["auth.draft2.intermediate.rs"];
  eq(H.meta(stage),mapping.authChain.intermediate,"whole prior draft2 auth");
  ok(H.apply(auth.before,texts["auth.actual-to-draft2.forward.diff"])===stage,"actual c407 to draft2");
  ok(H.apply(stage,texts["auth.actual-to-draft2.forward.diff"],true)===auth.before,"draft2 reverse to c407");
  ok(H.apply(stage,texts["auth.draft2-to-final.forward.diff"])===auth.after,"draft2 to candidate");
  ok(H.apply(auth.after,texts["auth.draft2-to-final.forward.diff"],true)===stage,"candidate reverse to draft2");

  function fns(raw){const n={},o={};for(const f of jwtFunctions(raw)){const id=f.name+"#"+(n[f.name]=(n[f.name]||0)+1);o[id]=f.raw;}return o;}
  const allowed={
    "auth_native_jwt.rs":{changed:["capture_native_v6_jwt_owner#1"],added:[],removed:[]},
    "auth.rs":{changed:["jwt_route_with_native_lifetime#1","parse_jwt_config#1","jwt_role_route#1"],added:["jwt_role_write_capability#1"],removed:[]},
    "service.rs":{changed:["supported_reader_schema#1","handle_inner_control_group_with_quota#1"],added:[],removed:[]},
    "service_identity.rs":{changed:["writer_schema#1","validate_publication_schema#1","validate_format#1"],added:[],removed:[]},
    "service_backup_restore.rs":{changed:["validate_snapshot_protected_floor#1"],added:[],removed:[]},
    "service_jwt_user_claim_tests.rs":{changed:["jwt_user_claim_schema68_is_conditional_sticky_and_snapshot_protected#1"],added:[],removed:[]},
    "service_jwt_pem_tests.rs":{changed:["jwt_pem_namespace_reopen_renew_and_sticky_retirement_keep_existing_authority#1","jwt_pem_state_requires69_and_revalidates_public_key_binding_without_changing_legacy_bytes#1","jwt_pem_authenticated_snapshot_prepare_and_final_commit_reject_active_retired_downgrade#1"],added:["historical_setup#1"],removed:[]},
    "service_jwt_renewal_tests.rs":{changed:["fixture#1","historical_fixture#1","fixture_with_bootstrap#1","restore_v18_jwt_config#1"],added:[],removed:[]},
    "auth_tests.rs":{changed:["jwt_config_and_role_readback_preserve_openbao_aliases#1"],added:[],removed:[]}
  };
  let unchangedFunctions=0;
  for(const [name,rule]of Object.entries(allowed)){
    const b=fns(by[name].before),a=fns(by[name].after);
    const changed=Object.keys(b).filter(k=>a[k]!==b[k]),added=Object.keys(a).filter(k=>!(k in b)),removed=Object.keys(b).filter(k=>!(k in a));
    eq(changed,rule.changed,"only expected changed functions "+name);
    eq(added,rule.added,"only expected added functions "+name);
    eq(removed,rule.removed,"only expected removed functions "+name);
    unchangedFunctions+=Object.keys(b).filter(k=>a[k]===b[k]).length;
  }
  for(const name of ["policies","validate_assignment"]){
    const b=jwtFunctions(auth.before).filter(f=>f.name===name).map(f=>f.raw);
    const a=jwtFunctions(auth.after).filter(f=>f.name===name).map(f=>f.raw);
    ok(b.length>0,"global helper exists "+name);eq(a,b,"all global helper occurrences unchanged "+name);
  }
  for(const name of ["authorize_reply","bind_response","bind_successful_login","admit_candidate","native_v6_jwt_state_supported"]){
    ok(jwtOneFunction(native.before,name)===jwtOneFunction(native.after,name),"Native original authority/delivery unchanged "+name);
  }
  for(const r of mapping.unchangedReferences){
    eq(H.meta(texts[r.file]),r.pin,"whole preserved reference "+r.file);
    ok(!mapping.files.some(f=>f.path===r.path),"preserved reference is not modified "+r.file);
  }
  const role=jwtOneFunction(auth.after,"jwt_role_route"),login=jwtOneFunction(auth.after,"jwt_route_with_native_lifetime");
  ok(role.includes('let capability = self.jwt_role_write_capability(scope, name);')&&role.includes('self.permission(principal, namespace, &path, capability, now)?;'),"role source capability required");
  ok(!role.includes("validate_assignment("),"only JWT role no actor subset call");
  ok((auth.before.match(/self\.validate_assignment\(/g)||[]).length===(auth.after.match(/self\.validate_assignment\(/g)||[]).length+1,"exactly one local assignment call removed");
  ok(role.includes('\"token_no_default_policy\": role.token_no_default_policy.unwrap_or(false)')&&role.includes("token_no_default_policy,"),"role flag read/write linked");
  ok(!role.includes('policies.contains("root")'),"root configuration not prematurely denied");
  ok(login.includes('role.policies.contains("root")')&&login.indexOf('role.policies.contains("root")')<login.indexOf("let identity = ExternalIdentity"),"root denied before identity/token construction");
  ok(login.indexOf("let issued_policies = jwt_policies::issued_policies(&role);")<login.indexOf("batch_issuance::PendingBatchGrant::response"),"defaults before both issuance branches");
  ok(login.includes("policies: issued_policies.clone(),")&&login.includes("policies: issued_policies,"),"service and batch share issued policies");
  ok(auth.after.includes('#[serde(default, skip_serializing_if = "Option::is_none")]\n    token_no_default_policy: Option<bool>'),"historical None encoding preserved");
  const helper=by["auth_jwt_policies.rs"].after;
  ok(helper.includes("pub(crate) const STATE_SCHEMA: u32 = 147;"),"local schema147 constant");
  ok(helper.includes('token_policies::weak_boolean(Some(value), "token_no_default_policy")'),"reuse unchanged HTTP weak boolean");
  ok(helper.includes(".or_else(|| previous.and_then(|role| role.token_no_default_policy))"),"omitted update retains prior flag");
  ok(helper.includes('body.get("token_policies").is_some()')&&helper.includes('body.get("policies").is_some()')&&helper.includes("Ok(Some(flag.unwrap_or(false)))"),"new semantics tagged even raw empty/false");
  const issued=jwtOneFunction(helper,"issued_policies");
  ok(issued.includes("let mut policies = role.policies.clone();")&&issued.includes('policies.insert("default".into());')&&!issued.includes("remove("),"default injection never erases explicit default");
  ok(issued.includes("if !role.token_no_default_policy.unwrap_or(false)"),"suppression applied only at issuance");
  const detection=jwtOneFunction(helper,"has_jwt_policy_state");
  ok(detection.includes(".flat_map(|mounts| mounts.values())")&&detection.includes(".any(|role| role.token_no_default_policy.is_some())"),"all namespace roles Some(false/true) require new reader");
  ok(detection.includes("Some(TokenAuthProvenance::Jwt { .. })")&&detection.includes('!token.policies.contains("default")'),"retained JWT grant also fences absent-default origin");
  const service=by["service.rs"].after,identity=by["service_identity.rs"].after,backup=by["service_backup_restore.rs"].after;
  ok(service.includes("const MAX_SUPPORTED_STATE_SCHEMA: u32 = JWT_POLICY_STATE_SCHEMA;"),"reader maximum147");
  ok(jwtOneFunction(service,"supported_reader_schema").includes("| JWT_POLICY_STATE_SCHEMA"),"reader accepts147");
  ok(jwtOneFunction(service,"handle_inner_control_group_with_quota").includes("admitted.auth.has_jwt_policy_state()"),"admitted publication uses writer floor");
  const writer=jwtOneFunction(identity,"writer_schema");
  ok(writer.includes("required.max(JWT_POLICY_STATE_SCHEMA)")&&writer.includes("self.schema.max(required)"),"writer floor remains sticky");
  const publish=jwtOneFunction(identity,"validate_publication_schema"),validate=jwtOneFunction(identity,"validate_format");
  ok(publish.includes("old.schema >= JWT_POLICY_STATE_SCHEMA")&&publish.includes("self.auth.has_jwt_policy_state()"),"publication rejects inherited or active downgrade");
  ok(validate.includes("self.schema < JWT_POLICY_STATE_SCHEMA && self.auth.has_jwt_policy_state()"),"loader rejects active147 under lower label");
  ok(validate.includes("| JWT_POLICY_STATE_SCHEMA"),"format accepts147 explicitly");
  const floor=jwtOneFunction(backup,"validate_snapshot_protected_floor");
  ok(floor.includes("current.schema >= JWT_POLICY_STATE_SCHEMA")&&floor.includes("incoming.auth.has_jwt_policy_state()")&&floor.includes("incoming.schema < JWT_POLICY_STATE_SCHEMA"),"snapshot floor handles active and retired semantic owner");
  ok(floor.includes('400,\n                "snapshot would downgrade JWT role policy semantics"'),"snapshot downgrade preserves400 guard type");
  ok(service.includes('#[path = "service_jwt_policy_tests.rs"]\nmod jwt_policy_tests;'),"new tests module connected");

  const nt=by["service_native_jwt_tests.rs"],oldNames=jwtTestNames(nt.before),newNames=jwtTestNames(nt.after);
  const removed=oldNames.filter(n=>!newNames.includes(n)),added=newNames.filter(n=>!oldNames.includes(n));
  eq(removed,["native_jwt_role_operations_keep_the_existing_legacy_acl_contract"],"only incompatible old Native ACL test replaced");
  ok(oldNames.length===15&&newNames.length===20&&added.length===6,"Native test15 to20 exact");
  for(const n of oldNames.filter(n=>!removed.includes(n)))ok(jwtOneFunction(nt.before,n)===jwtOneFunction(nt.after,n),"retained Native test exact "+n);
  ok(jwtOneFunction(nt.after,"native_jwt_rejects_remote_batch_and_bad_signature_without_candidate_delta").includes("501"),"Native batch501 remains an unsupported boundary");
  const actor=jwtOneFunction(nt.after,"acl_token");
  ok(actor.includes("let token_policies = vec![name];")&&actor.includes('"no_default_policy":true')&&!actor.includes('vec!["default"'),"real no-default path-only ACL actor");
  ok(actor.includes('\"auth/token/lookup\"')&&actor.includes('looked.body["data"]["policies"]'),"actor grant independently looked up");
  const policyTest=jwtOneFunction(nt.after,"native_jwt_empty_role_policies_and_no_default_flag_survive_real_cold_reopen");
  ok(policyTest.includes('["token_policies", "policies"]')&&policyTest.includes('body[field] = json!([])')&&policyTest.includes("f.restart()?")&&policyTest.includes('assert_native_jwt_policy_grant(&mut f, &[])?'),"real Native raw-policy/cold/defaultless issuance regression");
  const nativeRoot=jwtOneFunction(nt.after,"native_jwt_root_role_configuration_is_stored_but_never_issued_or_retroactively_renewed");
  ok(nativeRoot.includes('\"jwt-root-role-writer\", ROLE, &[\"update\"]')&&nativeRoot.includes('body[field] = json!(["root"])')&&nativeRoot.includes("status(&denied, 400)"),"actual update-only writer can save root while login denied");
  ok(nativeRoot.includes('\"auth/token/renew\"')&&nativeRoot.includes('json!(["default", "native-jwt"])'),"renewal keeps previously issued grant");
  const legacy=by["service_jwt_policy_tests.rs"].after;
  ok(jwtTestNames(legacy).length===4,"four new legacy/schema regressions");
  ok(legacy.includes('for token_type in ["service", "batch"]')&&legacy.includes('RequestExecution::Complete(response)')&&legacy.includes("service.native_root.is_none()"),"legacy real Service issuance distinguished from Native");
  ok(legacy.includes('before_tokens + usize::from(token_type == "service")'),"batch issuance checks token-storage separation");
  ok(legacy.includes('\"auth/token/lookup\"')&&legacy.includes("f.restart()?"),"legacy issuance verified by lookup and cold reopen");
  const schema=jwtOneFunction(legacy,"jwt_policy_schema147_covers_false_true_all_namespaces_and_sticky_restore_floor");
  ok(schema.includes("for flag in [false, true]")&&schema.includes('\"token_policies\":[]'),"schema regression covers rawemptySome(false) and true");
  ok(schema.includes("policy-namespace-fixture")&&schema.includes("never published as a valid tenant"),"namespace scan projection honestly bounded");
  ok(schema.includes('f.admin("DELETE", ROLE')&&schema.includes("retired.schema, JWT_POLICY_STATE_SCHEMA"),"real deletion/cold sticky floor checked");
  const hist=jwtOneFunction(legacy,"historical_role");
  ok(hist.includes("source.schema >= JWT_POLICY_STATE_SCHEMA")&&hist.includes("source.auth.has_jwt_policy_state()"),"historical factory refuses new predecessor");
  ok(hist.includes('get(name).is_some()')&&hist.includes("candidate.auth.handle(")&&hist.includes("!response.mutated"),"historical factory only validates never-published new role");
  ok(hist.indexOf('role.remove("token_no_default_policy")')<hist.indexOf("service.commit_state(&mut candidate)"),"marker removal only before initial candidate publication");
  ok(!hist.includes("service.state =")&&!hist.includes("candidate.schema = 146"),"historical helper cannot relabel published owner");
  ok(hist.includes("candidate.validate_publication_schema(service.state.as_ref())")&&hist.includes("service.install_committed_namespace_view(candidate)"),"historical first commit retains real schema and install gates");
  for(const name of ["service_jwt_user_claim_tests.rs","service_jwt_pem_tests.rs","service_jwt_renewal_tests.rs","auth_tests.rs"]){
    eq(jwtTestNames(by[name].before),jwtTestNames(by[name].after),"all old test names retained "+name);
  }
  const authTests=by["auth_tests.rs"];
  ok(jwtOneFunction(authTests.before,"jwt_configuration_rejects_bad_keys_namespace_and_privilege_escalation")===jwtOneFunction(authTests.after,"jwt_configuration_rejects_bad_keys_namespace_and_privilege_escalation"),"old missing-create JWT negative remains exact, not subset evidence");
  ok(jwtOneFunction(authTests.before,"token_creation_cannot_escalate_policies_or_skip_parent_without_sudo")===jwtOneFunction(authTests.after,"token_creation_cannot_escalate_policies_or_skip_parent_without_sudo"),"global token escalation negative unchanged");
  const readback=jwtOneFunction(authTests.after,"jwt_config_and_role_readback_preserve_openbao_aliases");
  ok(readback.includes('json!(["reader"])')&&readback.includes('["token_no_default_policy"], false'),"role readback raw reader and false");

  const oldGroups=JSON.parse(texts["groups149.original.json"]),groups=JSON.parse(texts["groups158.proposed.json"]);
  const inventory=JSON.parse(texts["TEST-INVENTORY.public.json"]);
  const entries=gs=>gs.reduce((s,g)=>s+g.tests.length,0),unique=gs=>new Set(gs.flatMap(g=>g.tests)).size;
  eq([unique(oldGroups),entries(oldGroups)],[149,166],"whole original149/166");
  eq([unique(groups),entries(groups)],[158,180],"proposed158/180 source");
  eq([unique(groups)-unique(oldGroups),entries(groups)-entries(oldGroups)],[9,14],"exact unique/profile delta");
  const oldSet=new Set(oldGroups.flatMap(g=>g.tests)),newSet=new Set(groups.flatMap(g=>g.tests));
  eq([...oldSet].filter(n=>!newSet.has(n)),inventory.exactDelta.removed.map(r=>r.fullname),"inventory removed name exact");
  eq([...newSet].filter(n=>!oldSet.has(n)).sort(),inventory.exactDelta.added.map(r=>r.fullname).sort(),"inventory added names exact");
  for(const g of groups){ok(g.runtime_seconds===600,"unchanged family deadline "+g.label);ok(new Set(g.tests).size===g.tests.length,"no within-profile duplicates "+g.label);}
  eq(groups[3],oldGroups[3],"entire Native auth/Identity group unchanged");
  ok(groups[2].tests.slice(0,oldGroups[2].tests.length).join("\n")===oldGroups[2].tests.join("\n"),"old legacy63 kept in original order");
  for(const g of groups.slice(0,2)){
    eq(g.tests.filter(n=>n.startsWith("service::native_auth::jwt_tests::")),newNames.map(n=>"service::native_auth::jwt_tests::"+n),"exact Native declared names "+g.libtest_profile);
    eq(g.tests.filter(n=>!n.startsWith("service::native_auth::jwt_tests::")),oldGroups.find(old=>old.libtest_profile===g.libtest_profile&&old.label.startsWith("native-jwt-pki")).tests.filter(n=>!n.startsWith("service::native_auth::jwt_tests::")),"PKI two unchanged "+g.libtest_profile);
  }

  const cg0=JSON.parse(texts["combined237.groups.original.json"]),cg1=JSON.parse(texts["combined246.groups.proposed.json"]);
  const ce0=JSON.parse(texts["combined254.entries.original.json"]),ce1=JSON.parse(texts["combined268.entries.proposed.json"]);
  const cp0=JSON.parse(texts["profiles.original.json"]),cp1=JSON.parse(texts["profiles.proposed.json"]);
  const pc=Object.fromEntries(cp0.map(x=>[x.profile,x.package]));
  const ids=rows=>rows.map(x=>[x.crate,x.libtest_profile,x.name]);
  const fromGroups=gs=>gs.flatMap(g=>g.tests.map(n=>[pc[g.libtest_profile],g.libtest_profile,n]));
  eq(ids(ce0),fromGroups(cg0),"prior combined ordered crate/profile/fullname exact");
  eq(ids(ce1),fromGroups(cg1),"proposed combined ordered crate/profile/fullname exact");
  const cu=rows=>new Set(rows.map(x=>x.crate+"\0"+x.name)).size;
  eq([ce0.length,cu(ce0)],[254,237],"whole frozen prior combined254/237");
  eq([ce1.length,cu(ce1)],[268,246],"exact combined268/246");
  eq(cg1.slice(4),cg0.slice(4),"fourteen later groups unchanged");
  eq(ce1.slice(180),ce0.slice(166),"eighty-eight later inventory rows including provenance unchanged");
  eq(cg1.slice(0,4),groups,"combined first four are proposed groups158");
  eq(cp1,cp0.map(x=>({...x,entries:ce1.filter(e=>e.libtest_profile===x.profile).length})),"profiles change counts only");
  eq(cp1.map(x=>x.entries),[22,229,17],"file22 default229 HA17");
  ok(cg1.length===18&&cg1.every(g=>g.runtime_seconds===600),"eighteen original600s families");
  eq(H.meta(texts["combined237.groups.original.json"]),inventory.combinedReference.priorGroups,"whole original combined groups pin");
  eq(H.meta(texts["combined254.entries.original.json"]),inventory.combinedReference.priorInventory,"whole original combined entries pin");
  eq(H.meta(texts["combined246.groups.proposed.json"]),inventory.combinedReference.newGroups,"whole proposed combined groups pin");
  eq(H.meta(texts["combined268.entries.proposed.json"]),inventory.combinedReference.newInventory,"whole proposed combined entries pin");

  return {schema:"heptabao.jwt-policy.source-verification.r1",pass:true,checkCount:checks.length,checks,unchangedFunctionBodies:unchangedFunctions,files:12,hunks:39,sourceBytes:1404403,priorUnique:149,priorProfileEntries:166,proposedUnique:158,proposedProfileEntries:180,deltaUnique:9,deltaProfileEntries:14,combinedUnique:246,combinedProfileEntries:268,lexicalNotRustAst:true,rustCompiled:false,rustTestsExecuted:0,NativeCalls:0,candidateCommit:null,fullReplacement:false};
}
