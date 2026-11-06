function verifyMac576BundleBindingPreparation(input) {
 const {template,baseJournal,binder,originalBinder,beforeLF,diff,bindings}=input,checks=[];
 function check(name,value){checks.push({name,pass:value===true});if(value!==true)throw Error(name);}
 check("immutable_stage_template_79c2",gitBlobMeta(template).blob==="79c2bae6e400b385a5efa8c57a23c6e5f0ea72ed");
 check("immutable_previous_journal_0bcb",gitBlobMeta(baseJournal).blob==="0bcb0ae541da1865f788a26cdb4a884425c50cbd");
 check("immutable_previous_binder_43a1",gitBlobMeta(originalBinder).blob==="43a1e30af8d02223e00237c2ed91318604597537");
 check("explicit_single_LF_before_view",!originalBinder.endsWith("\n")&&beforeLF===originalBinder+"\n");
 check("strict_delta_forward",applyStrict(beforeLF,diff)===binder);
 check("strict_delta_reverse",applyStrict(binder,diff,true)===beforeLF);
 check("template_both_actual_constants_unbound",template.includes("CANONICAL_BUNDLE_BYTES = None\n")&&template.includes("CANONICAL_BUNDLE_SHA256 = None\n"));
 check("exact576_candidate",bindings.candidate.commit==="5767739cd25e458ac052dc8d384019bab8688ae0"&&bindings.candidate.tree==="42477d622dcf96e1e2b0929fe9ecc6b7ba484740"&&bindings.candidate.parent==="02b90762b3d6cc8699cc88bffb6f76cb1f07e270");
 check("all_unobserved_bundle_fields_null",bindings.ready===false&&Object.values(bindings.bundle).every(v=>v===null)&&bindings.producer.report===null&&bindings.producer.rootQualification===null&&["infoNative","infoOperation","bodyOperations","transport","transportRootQualification","base64"].every(k=>bindings[k]===null));
 check("fixed_producer_path",bindings.producer.host==="rog"&&bindings.producer.path==="/home/qian-qi/hb-5767739c-src-20261106-r1/control/canonical-hb-5767739c-from02b.bundle");
 check("only_two_source_literal_replacements",(binder.match(/\n oneSource\(/g)||[]).length===2);
 check("only_three_journal_literal_replacements",(binder.match(/\n oneJournal\(/g)||[]).length===3);
 check("no_tool_or_storage_calls",!/\b(?:tools|store|load|fetch|process|subprocess)\s*[.(]/.test(binder));
 check("whole_carrier262144_and_outer360",binder.includes('need(carrierPin.bytes<=262144,"original_complete_carrier_cap")')&&binder.includes("timeout_seconds:360"));
 let code=null;
 try { bindMac576SourceOnlyStage({sourceTemplate:template,baseJournal,bindings,canonicalBase64Text:null,transportRaw:null}); }
 catch(error){code=String(error.message);}
 check("actual_binding_unresolved_rejects_before_output",code==="actual_bundle_binding_unresolved");
 check("native_and_GO_flags_never_granted",binder.includes("NativeExecuted:false,MacStageGO:null"));
 return {schema:"heptabao.mac576.bundle-binding-preparation.source-check.v1",pass:true,check_count:checks.length,checks,
   valid_actual_bundle_binding_executed:false,original_stage27_repeated:false,Native_calls:0,Python_calls:0,Git_calls:0};
}
