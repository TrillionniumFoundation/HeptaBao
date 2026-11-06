function verifyReadyControlsSource(files){
 const checks=[];const eq=(a,b)=>JSON.stringify(a)===JSON.stringify(b);
 function ck(ok,code){checks.push({code,pass:!!ok});if(!ok)throw Error(code);}
 const plan=JSON.parse(files["PLAN.public.json"]),pins=JSON.parse(files["PINS.public.json"]);
 const prePlan=JSON.parse(files["PREBOUND.original.PLAN.public.json"]),stage=parseLosslessIntegers(files["actual-stage.public.json"]);
 const qualification=JSON.parse(files["root-stage-qualification.public.json"]),info=JSON.parse(files["actual-stage-info.public.json"]);
 ck(qualification.passed===true&&qualification.completeActualStage===true&&qualification.readyControlsMayBeBound===true&&qualification.normalBuildQualified===false,"separate_actual_stage_qualified_not_build");
 ck(eq(gitBlobMeta(files["root-stage-qualification.public.json"]),plan.actualStage.rootQualification),"exact_root_qualification_pin");
 ck(stage.source_commit===plan.product.commit&&stage.source_tree===plan.product.tree&&stage.sole_parent===plan.product.soleParent&&stage.status==="prepared","exact_candidate_stage_and_parent");
 ck(eq(gitBlobMeta(files["actual-stage.public.json"]),plan.actualStage.body)&&info.sha256===plan.actualStage.body.sha256&&info.size===28125&&info.version===plan.actualStage.info.version,"actual_whole_stage_metadata_binding");
 let definitionCount=0;
 for(const name of ["runner","launcher","publisher"]){const before=files[name+".before.py"],after=files[name+".ready.py"],diff=files[name+".strict.diff"];
  ck(applyStrictUnified(before,diff,false).text===after&&applyStrictUnified(after,diff,true).text===before,name+":strict_both_directions");
  ck(before.split("BINDING_READY = False").length===2&&after.split("BINDING_READY = True").length===2,name+":one_ready_flag");
  let reverted=after.replace("BINDING_READY = True","BINDING_READY = False");
  if(name==="publisher"){const oldPins=before.match(/PINS = \{[\s\S]*?\n\}/)[0],newPins=after.match(/PINS = \{[\s\S]*?\n\}/)[0];reverted=reverted.replace(newPins,oldPins);}
  ck(reverted===before,name+":all_other_bytes_and_definitions_unchanged");
  definitionCount+=(before.match(/^[ \t]*(?:async )?def [A-Za-z_][A-Za-z_0-9]*\(/gm)||[]).length;
 }
 ck(definitionCount===25,"original_25_definitions_preserved");
 const contents={"native_jwt_build.py":files["runner.ready.py"],"launch_native_jwt_build.py":files["launcher.ready.py"],"jwt-test-groups.public.json":files["jwt-test-groups.public.json"]};
 const ptable=JSON.parse(files["publisher.ready.py"].match(/PINS = (\{[\s\S]*?\n\})/)[1]),carrier=JSON.parse(files["payload.ready.json"]),originalCarrier=JSON.parse(files["payload.before.json"]);
 ck(carrier.schema===originalCarrier.schema&&Object.keys(carrier.files).join(",")===Object.keys(contents).join(","),"original_carrier_schema_and_three_names");
 for(const[name,raw]of Object.entries(contents)){const pin=gitBlobMeta(raw);
  ck(eq(pin,pins.components[name])&&eq(ptable[name],[pin.bytes,pin.sha256]),name+":publisher_full_pin");
  ck(utf8Text(unb64(carrier.files[name]))===raw,name+":carrier_exact_content");
 }
 ck(gitBlobMeta(files["jwt-test-groups.public.json"]).sha256==="35153ff5e90b582f83e4fbbb66ff5c9fb295e95153f08df152cefedecdb50869"&&carrier.files["jwt-test-groups.public.json"]===originalCarrier.files["jwt-test-groups.public.json"],"frozen_groups_and_contents_unchanged");
 ck(files["runner.ready.py"].includes("35153ff5e90b582f83e4fbbb66ff5c9fb295e95153f08df152cefedecdb50869")&&files["launcher.ready.py"].includes("35153ff5e90b582f83e4fbbb66ff5c9fb295e95153f08df152cefedecdb50869"),"four_way_groups_digest");
 const q=JSON.parse(files["INERT.REVIEW-ONLY.public.json"]),oldq=JSON.parse(files["request.before.json"]);
 ck(q.host==="rog"&&q.executable==="/usr/bin/python3"&&q.cwd==="/home/qian-qi"&&q.timeout_seconds===60&&q.args.length===5&&eq(q.args.slice(0,4),["-I","-S","-B","-c"]),"unchanged_inert_interface_60");
 ck(q.args[4]===files["publisher.ready.py"]&&q.stdin===files["payload.ready.json"],"whole_inline_source_and_payload");
 const norm=JSON.parse(JSON.stringify(q));norm.args[4]=oldq.args[4];norm.stdin=oldq.stdin;norm.idempotency_key=oldq.idempotency_key;
 ck(eq(norm,oldq),"only_source_payload_key_request_changes");
 ck(eq(gitBlobMeta(files["INERT.REVIEW-ONLY.public.json"]),plan.exactRequest)&&eq(gitBlobMeta(files["payload.ready.json"]),pins.components.carrier)&&pins.components.carrier.bytes===plan.budgets.publisherPayloadActual&&pins.components.carrier.bytes<=262144,"actual_payload_budget_and_request_pins");
 const binding=processStartBinding(q);
 ck(binding.sha256===plan.typedBinding.sha256&&binding.native_fingerprint===plan.typedBinding.native_fingerprint&&gitBlobMeta(binding.canonical).bytes===plan.typedBinding.canonicalBytes,"correct_typed_stdin_binding");
 ck(applyStrictUnified(files["journal.before.js"],files["journal.strict.diff"],false).text===files["journal.ready.js"]&&applyStrictUnified(files["journal.ready.js"],files["journal.strict.diff"],true).text===files["journal.before.js"],"journal_strict_both_directions");
 let inverse=files["journal.ready.js"];
 inverse=inverse.replace(plan.journal.slot,"jwt_pki_33b814c7_build_controls_inert_gitfirst_r1");
 inverse=inverse.replace('{blob:"'+plan.exactRequest.blob+'",\n bytes:'+plan.exactRequest.bytes+',sha256:"'+plan.exactRequest.sha256+'"}','{blob:"b304be2ede7fccc0c7013e7b2974d2637a7f7667",\n bytes:124154,sha256:"b3982988fe15b71e804524b13c1d5e5ac5b462930446ef492e3f65585dac9e03"}');
 inverse=inverse.replace(plan.journal.observerPrefix,"heptabao-native-jwt-pki-33b814c7-controls-observe-r1-");
 ck(inverse===files["journal.before.js"],"journal_only_three_literal_bindings");
 ck(eq(gitBlobMeta(files["journal.ready.js"]),plan.journal.source)&&eq(gitBlobMeta(files["journal.before.js"]),plan.journal.before),"journal_source_pins");
 ck(plan.newRoot.endsWith("-r2")&&plan.oldAttemptRoot.endsWith("-r1")&&plan.oldAttemptPreserved===true&&plan.rootMustBeAbsent===true,"fresh_create_only_root_and_failed_attempt_preserved");
 ck(plan.denominators.existingUnique+plan.denominators.newUnique===149&&plan.denominators.newJwtUnique+plan.denominators.newPkiUnique===17&&plan.denominators.existingUnique+plan.denominators.newJwtProfiles+plan.denominators.newPkiProfiles===166,"original_149_unique_166_profiles");
 ck(plan.budgets.outer===12000&&plan.budgets.release===1800&&plan.budgets.sharedCompile===3600&&plan.budgets.families4x600===true&&plan.budgets.listing===30&&plan.budgets.term===5&&plan.budgets.kill===5,"all_original_build_budgets");
 ck(plan.target===prePlan.target&&plan.lockPath===prePlan.lockPath&&plan.probeClosedBeforeRunner&&plan.probeNotHeldForWholeCargo&&plan.rootMustCoordinateCargo,"fresh_NB_probe_scope_not_lifetime_lock");
 ck(plan.actualPublication===null&&plan.actualIndependentFourFiles===null&&plan.actualBuild===null&&plan.Runtime===false&&plan.journal.initializePermittedNow===false,"unobserved_publication_build_not_authorized");
 return {schema:"heptabao.025b.ready-controls-source-verification.r1",status:"PASS",checks:checks.length,results:checks,Native:0,Python:0,Cargo:0,scope:"literal binding and exact bytes only",definitionCount,typedBinding:plan.typedBinding};
}
