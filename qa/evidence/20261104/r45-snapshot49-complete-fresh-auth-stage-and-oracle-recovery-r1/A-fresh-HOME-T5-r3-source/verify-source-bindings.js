/* Pure source/carrier verifier. Requires pure_helpers + strict-diff. No module or SDK execution. */
function verifyFreshHomeR3(files) {
 const K={
  "beforeSourcePins": {
    "blob": "ef82837632272a8c9d071d2279828cf9f8010679",
    "bytes": 4384,
    "sha256": "72dfa9baf1ca978e380392e030d14174f5cb6b43039fe333ebe00a0aa2e74e2d"
  },
  "beforeDocumentPins": {
    "blob": "bc69a9d75a5d5453129848836e75f0d356be0311",
    "bytes": 1693,
    "sha256": "a5a973e9b6705c7d5827184a2add577ea9355ff8d90e824d4dd0cb0850d4ac8c"
  },
  "beforeRequest": {
    "blob": "2cbe610fa2f2264d1eb137d46421069db38655a5",
    "bytes": 875394,
    "sha256": "cbb10074d91b254d2205f037e976f4dbbb377c0c4e37a36dd930432bd8a65314"
  },
  "beforePublisher": {
    "blob": "ea84d70d3c434a33d0f216de8b0b002633650a0a",
    "bytes": 36514,
    "sha256": "19b91f34d98b8056a4921e400dc3e87200581043ce7df7531db81be6a0982a69"
  },
  "beforeJournal": {
    "blob": "52c2735d9eae38cf4745f89802fcf25c3b5738c1",
    "bytes": 19050,
    "sha256": "70254ca18f378f03ce6abe2788d1cfbf512989671a26ee83fbe33c60ca814b9f"
  },
  "beforeDeriver": {
    "blob": "47c30a8833171ecc52679a25a913c71ca7a35eac",
    "bytes": 7131,
    "sha256": "67b551c147ccfd0fa42d3e37da1c547a94308e03da3a03d3f4fce9565b9a4dbe"
  },
  "beforeRuntimeInputs": {
    "blob": "d52b0300ed877fa7d1608cd126cf56a1ebaf0c1b",
    "bytes": 15274,
    "sha256": "0d60aa2f27f309f021de9d641e2c020e1c02ce0d1f5c9ffefbc08867e27aa78b"
  },
  "approvedParser": {
    "blob": "3f259a4b085394fba0658359575aa0d74b9757e2",
    "bytes": 58584,
    "sha256": "1d69a93a3111238424f90b02ffe44f6f3e9c3eb704aa8044625de7c17978f78f"
  },
  "beforeCandidate": {
    "blob": "268c8540cc67174bcf5f94b4d4fafc8dff4adf75",
    "bytes": 7499,
    "sha256": "4194d61794ec066d23ca17863d2323674a918779f9524cf20fb2109e334d1e56"
  },
  "approvedParserDiff": {
    "blob": "079ffb29a11030f878045a599d717df2eda42a84",
    "bytes": 549,
    "sha256": "7b43b6cb1720eb11615de4b882686dcf2d0a7b8c43d3605f5107ba513186f7fd"
  },
  "oldT5": "/Volumes/T5/hepta-vnext-recovery-20261013/mac-authbus-4e808-current-home-launch-r2",
  "oldHome": "/Users/qianqi/heptabao-mac-authbus-4e808-home-launch-20261106-r2",
  "newT5": "/Volumes/T5/hepta-vnext-recovery-20261013/mac-authbus-4e808-current-home-launch-r3",
  "newHome": "/Users/qianqi/heptabao-mac-authbus-4e808-home-launch-20261106-r3"
};
 const checks=[];const check=(name,pass,detail)=>{checks.push({name,pass:!!pass,...(detail===undefined?{}:{detail})});return!!pass;};
 const same=(a,b)=>JSON.stringify(a)===JSON.stringify(b);
 const pin=raw=>gitBlobMeta(raw),j=name=>JSON.parse(files[name]);
 const eq=(raw,p)=>same(pin(raw),p);
 try {
 const contract=j('CONTRACT.public.json'),changes=j('strict-change-map.public.json');
 const bp=j('before--source-pins.public.json'),np=j('source-pins.public.json');
 const bd=j('before--document-pins.public.json'),nd=j('document-pins.public.json');
 const oldReq=j('dispatch--before.exact-request.public.json'),req=j('dispatch--inert.exact-request.public.json');
 const oldPayload=JSON.parse(oldReq.stdin),payload=j('dispatch--public-stdin.original.json');
 const bCand=j('before--candidate.public.json'),cand=j('after--candidate.public.json');
 const ns=[[K.oldT5,K.newT5],[K.oldHome,K.newHome],
 ['mac-authbus-4e808-current-home-launch-r2','mac-authbus-4e808-current-home-launch-r3'],
 ['org.heptabao.qa.mac-authbus-4e808-home-r2.server','org.heptabao.qa.mac-authbus-4e808-home-r3.server'],
 ['org.heptabao.qa.mac-authbus-4e808-home-r2.consumer','org.heptabao.qa.mac-authbus-4e808-home-r3.consumer']];
 const forward=s=>ns.reduce((v,[a,b])=>v.split(a).join(b),s);
 const reverse=s=>ns.slice().reverse().reduce((v,[a,b])=>v.split(b).join(a),s);
 const sourceNames=Object.keys(bp);
 check('baseline_source_pin_table',eq(files['before--source-pins.public.json'],K.beforeSourcePins));
 check('baseline_document_pin_table',eq(files['before--document-pins.public.json'],K.beforeDocumentPins));
 check('source_names_exact_22',sourceNames.length===22&&same(sourceNames,Object.keys(np)));
 check('approved_parser_after_exact',eq(files['reference--approved-parser-after.py'],K.approvedParser));
 check('approved_parser_original_diff',eq(files['reference--approved-parser.diff'],K.approvedParserDiff));
 const changed=[];let oldBytes=0,newBytes=0;
 for(const name of sourceNames){
  const after=files['source--'+name],before=files['before--'+name]===undefined?after:files['before--'+name];
  check(name+':before_whole',eq(before,bp[name]));
  check(name+':after_whole',eq(after,np[name]));
  oldBytes+=pin(before).bytes;newBytes+=pin(after).bytes;
  const normalized=reverse(after),expected=name==='mac_owned_launchd_r3.py'?files['reference--approved-parser-after.py']:before;
  check(name+':only_namespace_plus_one_approved_parser',normalized===expected);
  if(after!==before){
   changed.push(name);
   const d=files['diff--'+name+'.diff'],iv=files['inverse--'+name+'.diff'];
   check(name+':strict_forward',strictApplySource(before,d).raw===after);
   check(name+':strict_inverse',strictApplySource(after,iv).raw===before);
   const row=changes.sources.find(x=>x.name===name);
   check(name+':diff_counts_and_pins',!!row&&same(row.before,bp[name])&&same(row.after,np[name])&&
    row.forwardHunks===(d.match(/^@@ /gm)||[]).length&&row.inverseHunks===(iv.match(/^@@ /gm)||[]).length);
  }
 }
 check('changed_11_unchanged_11',changed.length===11&&sourceNames.length-changed.length===11);
 check('change_map_exact_names',same(changed,changes.sources.map(x=>x.name))&&changes.changed===11&&changes.unchanged===11);
 check('semantic_added_bytes_only_132',newBytes-oldBytes===132);
 for(const target of changed){
  check(target+':no_stale_literal_hash_reference',sourceNames.every(n=>!files['source--'+n].includes(bp[target].sha256)));
 }
 check('parser_three_line_diff_forward',strictApplySource(files['before--mac_owned_launchd_r3.py'],files['reference--approved-parser.diff']).raw===files['reference--approved-parser-after.py']);
 check('parser_three_line_diff_inverse',strictApplySource(files['reference--approved-parser-after.py'],files['reference--approved-parser.inverse.diff']).raw===files['before--mac_owned_launchd_r3.py']);
 const manager=files['source--mac_owned_launchd_r3.py'];
 check('consumer_success_stays_strict_zero',manager.includes("need(state.get('last exit code')==0,'actual_launchd_phase_exit_zero')"));
 check('exact_never_exit_None_only_once',manager.split("if name=='last exit code' and typed_value=='(never exited)':").length===2&&manager.includes("fields[name]=None\n                continue"));
 check('strict_integer_and_existing_EX_CONFIG_rule',manager.includes("if name=='last exit code' and typed_value=='78: EX_CONFIG':")&&manager.includes("'typed_launchctl_integer'"));
 check('home_control_exact_normalized',reverse(files['home-control.py'])===files['before--home-control.py']);
 check('home_control_same_manager_publisher',manager.includes(files['home-control.py'])&&files['after--publisher.py'].includes(files['home-control.py']));
 check('old_candidate_whole',eq(files['before--candidate.public.json'],K.beforeCandidate));
 const expectedCand=JSON.parse(files['before--candidate.public.json']);
 expectedCand.sourcePins=Object.fromEntries(sourceNames.map(n=>[n,np[n].sha256]));expectedCand.homeControl.root=K.newHome;
 check('candidate_only_pins_and_HOME_root',JSON.stringify(expectedCand,null,2)+'\n'===files['after--candidate.public.json']);
 check('candidate_embedded_document_exact',files['document--candidate-current-manager-wal-r1.public.json']===files['after--candidate.public.json']);
 check('source_hash_map_exact',same(j('source-hashes.public.json'),expectedCand.sourcePins));
 check('document_names_8_same',Object.keys(bd).length===8&&same(Object.keys(bd),Object.keys(nd)));
 for(const name of Object.keys(nd)){
  const raw=files['document--'+name.replaceAll('/','--')];
  check(name+':new_document_whole',eq(raw,nd[name]));
  check(name+':payload_document_exact',utf8Text(unb64(payload.documents[name]))===raw);
  if(name!=='candidate-current-manager-wal-r1.public.json')
   check(name+':unchanged_original_proof',eq(raw,bd[name])&&payload.documents[name]===oldPayload.documents[name]);
 }
 for(const name of sourceNames)check(name+':public_carrier_exact',utf8Text(unb64(payload.files[name]))===files['source--'+name]);
 check('carrier_shape_schema_anchor_unchanged',same(Object.keys(payload),Object.keys(oldPayload))&&payload.schema===oldPayload.schema&&payload.anchorBase64===oldPayload.anchorBase64&&same(Object.keys(payload.files),sourceNames)&&same(Object.keys(payload.documents),Object.keys(nd)));
 check('old_request_whole',eq(files['dispatch--before.exact-request.public.json'],K.beforeRequest));
 check('old_publisher_whole',eq(files['before--publisher.py'],K.beforePublisher));
 check('old_journal_whole',eq(files['before--journal.js'],K.beforeJournal));
 check('old_runtime_deriver_whole',eq(files['before--runtime-deriver.js'],K.beforeDeriver));
 check('old_runtime_inputs_whole',eq(files['before--runtime-binding-inputs.public.json'],K.beforeRuntimeInputs));
 const table=pins=>JSON.stringify(Object.fromEntries(Object.entries(pins).map(([n,p])=>[n,[p.bytes,p.sha256]])),null,4);
 let pub=reverse(files['after--publisher.py']);
 pub=pub.replace('\nPINS='+table(np)+'\nDOCUMENT_PINS=','\nPINS='+table(bp)+'\nDOCUMENT_PINS=');
 pub=pub.replace('\nDOCUMENT_PINS='+table(nd)+'\nPAYLOAD_BYTES=','\nDOCUMENT_PINS='+table(bd)+'\nPAYLOAD_BYTES=');
 pub=pub.replace('\nPAYLOAD_BYTES='+pin(files['dispatch--public-stdin.original.json']).bytes+'\n','\nPAYLOAD_BYTES='+pin(oldReq.stdin).bytes+'\n');
 pub=pub.replace('\nPAYLOAD_SHA="'+pin(files['dispatch--public-stdin.original.json']).sha256+'"\n','\nPAYLOAD_SHA="'+pin(oldReq.stdin).sha256+'"\n');
 check('publisher_inverse_only_exact_bindings',pub===files['before--publisher.py']);
 for(const name of ['publisher.py','journal.js','runtime-deriver.js','candidate.public.json']){
  const before=files['before--'+name],after=files['after--'+name];
  check(name+':strict_binding_forward',strictApplySource(before,files['diff--'+name+'.diff']).raw===after);
  check(name+':strict_binding_inverse',strictApplySource(after,files['inverse--'+name+'.diff']).raw===before);
 }
 const expectedReq=JSON.parse(files['dispatch--before.exact-request.public.json']);
 expectedReq.args[4]=files['after--publisher.py'];expectedReq.stdin=files['dispatch--public-stdin.original.json'];
 const pubPin=pin(files['after--publisher.py']);
 expectedReq.idempotency_key='heptabao-mac-current-home-launch-inert-'+pubPin.sha256.slice(0,8)+'-20261106-r3';
 check('exact_request_only_three_fields',JSON.stringify(expectedReq,null,2)+'\n'===files['dispatch--inert.exact-request.public.json']);
 check('correct_stdin_schema_not_stdin_text',typeof req.stdin==='string'&&!Object.hasOwn(req,'stdin_text'));
 check('request_regular_interpreter_and_original_limits',req.host==='mac'&&req.executable===oldReq.executable&&req.cwd===oldReq.cwd&&req.timeout_seconds===60&&same(req.args.slice(0,4),['-I','-S','-B','-c']));
 const rp=pin(files['dispatch--inert.exact-request.public.json']),op=pin(files['dispatch--before.exact-request.public.json']);
 const requestLiteral=p=>'const GF_REQUEST = {blob:"'+p.blob+'",\n bytes:'+p.bytes+',sha256:"'+p.sha256+'"};';
 let journal=files['after--journal.js'].replace('const GF_SLOT = "owner_authbus_current_home_inert_gitfirst_r3";','const GF_SLOT = "owner_authbus_current_home_inert_gitfirst_r2";');
 journal=journal.replace(requestLiteral(rp),requestLiteral(op));
 journal=journal.replace('heptabao-mac-current-home-launch-inert-'+pubPin.sha256.slice(0,8)+'-','heptabao-mac-current-home-launch-inert-'+K.beforePublisher.sha256.slice(0,8)+'-');
 check('journal_only_slot_request_and_prefix',journal===files['before--journal.js']);
 check('runtime_deriver_only_unique_r3_key_suffix',files['after--runtime-deriver.js'].replace("+'-20261106-r3';","+'-20261106-r2';")===files['before--runtime-deriver.js']);
 const ri=j('runtime-binding-inputs.public.json'),oldri=j('before--runtime-binding-inputs.public.json'),expectedRi=JSON.parse(files['before--runtime-binding-inputs.public.json']);
 expectedRi.newRoot=K.newT5;expectedRi.homeRoot=K.newHome;expectedRi.publisherPayload=pin(files['dispatch--public-stdin.original.json']);
 expectedRi.sourcePins=np;expectedRi.documentPins=nd;expectedRi.sourcePinsRaw=files['source-hashes.public.json'];
 expectedRi.candidate=nd['candidate-current-manager-wal-r1.public.json'];expectedRi.outer=np['mac_current_outer_wal_r1.py'];
 check('runtime_binding_input_exact_mechanical',JSON.stringify(expectedRi,null,2)+'\n'===files['runtime-binding-inputs.public.json']);
 check('original_runtime_template_exact',ri.originalRuntimeRequestRaw===oldri.originalRuntimeRequestRaw&&JSON.parse(ri.originalRuntimeRequestRaw).timeout_seconds===1080);
 const state=j('future-runtime-state.public.json');
 check('actual_slots_null_and_unready',state.actualHomeBinding===null&&state.runtimeExactRequest===null&&state.actualPort===null&&state.readyForRuntime===false&&state.NativeCalls===0);
 check('all_original_candidate_budgets_preserved',same(cand.budgets,bCand.budgets)&&same(contract.preserved.budgets,bCand.budgets)&&contract.preserved.outerRuntimeNativeTimeoutSeconds===1080);
 const outer=files['source--mac_current_outer_wal_r1.py'];
 check('fresh_actual_ephemeral_loopback_bind_retained',outer.includes("sock.bind(('127.0.0.1',0));port=sock.getsockname()[1]")&&contract.actualPort.value===null&&!contract.actualPort.oldPortReused);
 check('renew_empty_JSON_retained',outer.includes("'POST','auth/token/renew-self',{}")&&contract.preserved.renewIncrementAdded===false);
 check('strict_expiry_extension_after_closure_retained',outer.indexOf("manager_terminal=manager.finish()")<outer.indexOf("check('both_actual_renewal_expiries_increased'")&&outer.includes("token_lifecycle_before(client,guard,'initial'")&&outer.includes("token_lifecycle_before(client,guard,'cold-new-process'"));
 check('source_commit_and_tree_not_future_product',cand.sourceCommit==='4e808d0ecb1bcded22870a7ec960dfb2491cf6ec'&&cand.sourceTree==='eba5e650bd080b8ad41ea52a2bc68867f541d255');
 check('source_only_contract',contract.status==='SOURCE_ONLY_NO_NATIVE_ADMISSION'&&contract.NativeCalls===0&&contract.effectsAuthorizedByThisSource===false);
 check('readback_future_null_and_finite',contract.futureRuntime.readbackTargets[2].bytes===null&&contract.futureRuntime.readbackTargets[2].sha256===null&&contract.futureRuntime.readbackBodyMaximumIfSeparatelyAuthorized===73918+7499+65536&&contract.futureRuntime.readyForRuntime===false);
 const current=j('reference--current-independent-observation.stdout.original.json');
 check('historical_unknown_not_upgraded',current.observationComplete===true&&current.ok===false&&current.outcomeUnknown===true&&current.currentManagedScopeStillUnknown===true&&contract.namespaceEvidence.historicalClosureClaim===false);
 return {schema:'heptabao.fresh-home-r3.pure-source-binding-checks.v1',status:checks.every(x=>x.pass)?'PASS':'FAIL',passed:checks.every(x=>x.pass),checkCount:checks.length,checks,scope:'Pure source/carrier binding only; no candidate, Python, SDK or Runtime execution.',NativeCalls:0};
 }catch(e){
  return {schema:'heptabao.fresh-home-r3.pure-source-binding-checks.v1',status:'VERIFIER_ERROR',passed:false,checkCount:checks.length,checks,error:{type:e.name,message:String(e.message)},NativeCalls:0};
 }
}
