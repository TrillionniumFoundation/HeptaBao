/* Pure offline binding verifier. Input: the complete flat SOURCE packet path->UTF8 text map.
 * Required globals: gitBlobMeta, utf8Text, unb64, strictApplySource.
 * No Python/JS candidate modules, SDK, OS, filesystem or Native calls are invoked. */
function verifyHomeLaunchR2(files) {
 const checks=[];const check=(name,value)=>checks.push({name,passed:value===true});
 const j=path=>JSON.parse(files[path]),equal=(a,b)=>JSON.stringify(a)===JSON.stringify(b);
 const names=j('source-pins.public.json'),changes=j('CHANGES.public.json'),ns=changes.namespaces;
 const rebind=t=>ns.reduce((s,[a,b])=>s.split(a).join(b),t);
 const unbind=t=>ns.reduce((s,[a,b])=>s.split(b).join(a),t);
 const beforeHome=files['home.before.py'],afterHome=files['home.after.py'],fixedHome=files['component.home.first5.py'];
 const beforePub=files['publisher.before.py'],afterPub=files['publisher.after.py'],fixedPub=files['component.publisher.first5.py'];
 const beforeManager=files['before.mac_owned_launchd_r3.py'],afterManager=files['after.mac_owned_launchd_r3.py'],fixedManager=files['component.manager.first5.py'];
 const oldQ=j('reference.inert-r1.exact-request.public.json'),q=j('dispatch.inert.exact-request.public.json');
 const oldP=JSON.parse(oldQ.stdin),p=JSON.parse(q.stdin),candidate=j('doc.candidate-current-manager-wal-r1.public.json'),oldCandidate=j('candidate.before.public.json');
 check('exact22_source_names',Object.keys(names).length===22&&equal(Object.keys(names),changes.sources.map(x=>x.name)));
 check('11_whole_10_namespace_1_reviewed_component',changes.sources.filter(x=>x.category==='whole_unchanged').length===11&&changes.sources.filter(x=>x.category==='namespace_only').length===10&&changes.sources.filter(x=>x.category==='reviewed_first5_component_plus_namespace').length===1);
 for(const row of changes.sources){
  const b=files['before.'+row.name],a=files['after.'+row.name];
  check(row.name+'.before_pin',equal(gitBlobMeta(b),row.before));
  check(row.name+'.after_pin',equal(gitBlobMeta(a),row.after)&&names[row.name]===gitBlobMeta(a).sha256);
  check(row.name+'.limited_transform',a===rebind(row.name==='mac_owned_launchd_r3.py'?fixedManager:b));
  if(row.changed){
   check(row.name+'.strict_forward',strictApplySource(b,files['diff.'+row.name+'.diff']).raw===a);
   check(row.name+'.strict_reverse',strictApplySource(a,files['reverse.'+row.name+'.diff']).raw===b);
  } else check(row.name+'.whole_equal',a===b);
 }
 check('component_manager_only_home_replacement',beforeManager.split(beforeHome).length===2&&fixedManager===beforeManager.replace(beforeHome,fixedHome));
 check('component_publisher_only_home_replacement',beforePub.split(beforeHome).length===2&&fixedPub===beforePub.replace(beforeHome,fixedHome));
 check('new_home_only_namespace_after_reviewed_fix',afterHome===rebind(fixedHome));
 check('same_home_instance_definition_in_manager_publisher',afterManager.split(afterHome).length===2&&afterPub.split(afterHome).length===2);
 for(const [name,b,a]of [['home',beforeHome,afterHome],['publisher',beforePub,afterPub],['journal',files['journal.before.js'],files['journal.after.js']],['runtime-deriver',files['derive-runtime.before.js'],files['derive-runtime.after.js']],['candidate',files['candidate.before.public.json'],files['doc.candidate-current-manager-wal-r1.public.json']]]){
  check(name+'.strict_forward',strictApplySource(b,files[name+'.forward.diff']).raw===a);
  check(name+'.strict_reverse',strictApplySource(a,files[name+'.reverse.diff']).raw===b);
 }
 for(const [name,b,a]of [['home',beforeHome,fixedHome],['manager',beforeManager,fixedManager],['publisher',beforePub,fixedPub]]){
  check('reviewed_component_'+name+'.strict_forward',strictApplySource(b,files['component.'+name+'.forward.diff']).raw===a);
  check('reviewed_component_'+name+'.strict_reverse',strictApplySource(a,files['component.'+name+'.reverse.diff']).raw===b);
 }
 check('candidate_source_pins_exact22',equal(candidate.sourcePins,names));
 const revertedCandidate=JSON.parse(JSON.stringify(candidate));revertedCandidate.sourcePins=oldCandidate.sourcePins;revertedCandidate.homeControl.root=oldCandidate.homeControl.root;
 check('candidate_only_pins_and_home_root',equal(revertedCandidate,oldCandidate));
 check('candidate_new_HOME_exact',candidate.homeControl.root===changes.newHome);
 check('source_commit_tree_budgets_unchanged',equal(candidate.budgets,oldCandidate.budgets)&&candidate.sourceCommit===oldCandidate.sourceCommit&&candidate.sourceTree===oldCandidate.sourceTree);
 check('payload_envelope_anchor_schema_original',p.schema===oldP.schema&&p.anchorBase64===oldP.anchorBase64&&equal(Object.keys(p).sort(),Object.keys(oldP).sort()));
 check('payload_22_source_inventory_original',equal(Object.keys(p.files),Object.keys(oldP.files))&&Object.keys(p.files).length===22);
 for(const[n,b64]of Object.entries(p.files))check(n+'.payload_exact',utf8Text(unb64(b64))===files['after.'+n]);
 check('payload_8_document_inventory_original',equal(Object.keys(p.documents),Object.keys(oldP.documents))&&Object.keys(p.documents).length===8);
 for(const[n,b64]of Object.entries(p.documents)){
  const path='doc.'+n.replaceAll('/','__'),body=utf8Text(unb64(b64));
  check(n+'.payload_exact',body===files[path]);
  if(n!=='candidate-current-manager-wal-r1.public.json')check(n+'.whole_original_proof',b64===oldP.documents[n]);
 }
 check('request_stdin_exact_standalone',q.stdin===files['dispatch.inert.stdin.public.json']);
 check('request_publisher_exact',q.args.length===oldQ.args.length&&q.args.at(-1)===afterPub);
 const oldOther=JSON.parse(JSON.stringify(oldQ)),newOther=JSON.parse(JSON.stringify(q));
 for(const v of [oldOther,newOther]){delete v.stdin;delete v.idempotency_key;v.args=v.args.slice(0,-1);}
 check('request_other_fields_all_original',equal(oldOther,newOther)&&q.timeout_seconds===60&&!Object.hasOwn(q,'stdin_text'));
 const pubPin=gitBlobMeta(afterPub),oldPubPin=gitBlobMeta(beforePub),rq=gitBlobMeta(files['dispatch.inert.exact-request.public.json']),oldRq=gitBlobMeta(files['reference.inert-r1.exact-request.public.json']);
 check('request_new_dedicated_generation_key',q.idempotency_key==='heptabao-mac-current-home-launch-inert-'+pubPin.sha256.slice(0,8)+'-20261106-r2');
 function section(src,start,end){const a=src.indexOf(start),b=src.indexOf(end,a);if(a<0||b<=a)throw Error('fixed_pin_section');return src.slice(a,b);}
 const pubPins=JSON.parse(section(afterPub,'PINS=','\nDOCUMENT_PINS=').slice(5));
 const docsPins=JSON.parse(section(afterPub,'DOCUMENT_PINS=','\nPAYLOAD_BYTES=').slice(14));
 check('publisher22_exact_pins',Object.keys(pubPins).length===22&&Object.entries(pubPins).every(([n,x])=>equal(x,[gitBlobMeta(files['after.'+n]).bytes,gitBlobMeta(files['after.'+n]).sha256])));
 check('publisher8_exact_document_pins',Object.keys(docsPins).length===8&&Object.entries(docsPins).every(([n,x])=>equal(x,[gitBlobMeta(files['doc.'+n.replaceAll('/','__')]).bytes,gitBlobMeta(files['doc.'+n.replaceAll('/','__')]).sha256])));
 check('publisher_payload_length_hash_exact',afterPub.includes('PAYLOAD_BYTES='+gitBlobMeta(q.stdin).bytes+'\n')&&afterPub.includes('PAYLOAD_SHA='+JSON.stringify(gitBlobMeta(q.stdin).sha256)+'\n'));
 let restoredPub=unbind(afterPub);
 for(const[a,b]of [['PINS=','\nDOCUMENT_PINS='],['DOCUMENT_PINS=','\nPAYLOAD_BYTES=']])restoredPub=restoredPub.replace(section(restoredPub,a,b),section(fixedPub,a,b));
 restoredPub=restoredPub.replace('PAYLOAD_BYTES='+gitBlobMeta(q.stdin).bytes,'PAYLOAD_BYTES='+gitBlobMeta(oldQ.stdin).bytes)
  .replace('PAYLOAD_SHA='+JSON.stringify(gitBlobMeta(q.stdin).sha256),'PAYLOAD_SHA='+JSON.stringify(gitBlobMeta(oldQ.stdin).sha256));
 check('publisher_only_reviewed_component_namespaces_derived_pins',restoredPub===fixedPub);
 const literal=pin=>'const GF_REQUEST = {blob:"'+pin.blob+'",\n bytes:'+pin.bytes+',sha256:"'+pin.sha256+'"};';
 const restoredJournal=files['journal.after.js'].replace('owner_authbus_current_home_inert_gitfirst_r2','owner_authbus_current_home_inert_gitfirst_r1')
  .replace(literal(rq),literal(oldRq))
  .replace('/^heptabao-mac-current-home-launch-inert-'+pubPin.sha256.slice(0,8)+'-/','/^heptabao-mac-current-home-launch-inert-'+oldPubPin.sha256.slice(0,8)+'-/');
 check('journal_only_slot_request_prefix',restoredJournal===files['journal.before.js']);
 check('future_deriver_only_r2_key_suffix',files['derive-runtime.after.js'].replace("+'-20261106-r2';","+'-20261106-r1';")===files['derive-runtime.before.js']);
 const ri=j('derive-runtime.inputs.public.json'),oldRi=j('derive-runtime.inputs.before.public.json');
 check('future_runtime_inputs_no_new_old_request',ri.originalRuntimeRequestRaw===oldRi.originalRuntimeRequestRaw&&ri.oldRoot===oldRi.oldRoot&&ri.regularPython===oldRi.regularPython);
 check('future_runtime_inputs_current_pins_paths',ri.newRoot===changes.newT5&&ri.homeRoot===changes.newHome&&equal(ri.publisherPayload,gitBlobMeta(q.stdin))&&ri.sourcePinsRaw===files['source-pins.public.json']&&equal(ri.candidate,gitBlobMeta(files['doc.candidate-current-manager-wal-r1.public.json']))&&equal(ri.outer,gitBlobMeta(files['after.mac_current_outer_wal_r1.py'])));
 check('future_runtime22_source_pins_whole',Object.entries(ri.sourcePins).every(([n,pin])=>equal(pin,gitBlobMeta(files['after.'+n])))&&Object.keys(ri.sourcePins).length===22);
 check('future_runtime8_document_pins_whole',Object.entries(ri.documentPins).every(([n,pin])=>equal(pin,gitBlobMeta(files['doc.'+n.replaceAll('/','__')])))&&Object.keys(ri.documentPins).length===8);
 check('no_old_active_namespaces_in_new_code',[...Object.keys(names).map(n=>files['after.'+n]),afterHome,afterPub].every(t=>ns.every(([old])=>!t.includes(old))));
 const contract=j('CONTRACT.public.json');
 check('unobserved_actual_binding_and_runtime_slots',contract.runtime.actualHomeBinding===null&&contract.runtime.exactRequest===null&&contract.runtime.readyForRuntime===false&&contract.inert.slotInitialized===false);
 check('all_old_budget_values_preserved',equal(contract.preservedCaps,j('reference.r1.CONTRACT.public.json').preservedCaps));
 return {schema:'heptabao.home-launch-r2.pure-binding-verification.r1',passed:checks.every(x=>x.passed),checkCount:checks.length,checks,NativeCalls:0,PythonModulesExecuted:0,SDKExecuted:0,productTests:0,scope:'Mechanical source and payload binding only; original failures and actual HOME/T5 absence remain outside this SOURCE result.'};
}