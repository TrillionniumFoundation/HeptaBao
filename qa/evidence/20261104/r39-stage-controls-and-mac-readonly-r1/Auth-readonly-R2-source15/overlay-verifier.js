function verifyReadonlyHashOverlay(old,neo) {
 const results=[];
 function ck(name,value){results.push({name,passed:!!value});if(!value)throw new Error("overlay:"+name);}
 const q1=JSON.parse(old.request),q2=JSON.parse(neo.request),c1=JSON.parse(old.contract),c2=JSON.parse(neo.contract);
 const sp=gitBlobMeta(neo.source),rp=gitBlobMeta(neo.request),jp=gitBlobMeta(neo.journal);
 ck("preserved_r1_source",gitBlobMeta(old.source).blob==="467393a64a2a5e7eb92a89df0981b9849217eb87");
 ck("two_source_hunks",neo.sourceDiff.hunks===2&&neo.sourceReverse.hunks===2);
 ck("source_forward_exact",strictApplySource(old.source,neo.sourceDiff.raw).raw===neo.source);
 ck("source_reverse_exact",strictApplySource(neo.source,neo.sourceReverse.raw).raw===old.source);
 const expected=old.source.replace("'full9':held,'bytes':len(raw),'sha256':sha(raw),'markerFull9':marker,","'full9':held,'bytes':len(raw),'markerFull9':marker,").replace("result['terminal'].update(qualified=True,public=projected,sha256=sha(raw))","result['terminal'].update(qualified=True,public=projected)");
 ck("only_two_dynamic_hash_fields_removed",neo.source===expected);
 const rest1={...q1},rest2={...q2};delete rest1.stdin;delete rest1.idempotency_key;delete rest2.stdin;delete rest2.idempotency_key;
 ck("all_nonpayload_request_fields_unchanged",JSON.stringify(rest1)===JSON.stringify(rest2));
 ck("request_exact_new_source",q2.stdin===neo.source);
 ck("source_bound_fresh_key",q2.idempotency_key==="heptabao-mac-owned-home-t5-readonly-"+sp.sha256.slice(0,8)+"-20261106-r2");
 ck("journal_forward_exact",strictApplySource(old.journal,neo.journalDiff.raw).raw===neo.journal);
 ck("journal_reverse_exact",strictApplySource(neo.journal,neo.journalReverse.raw).raw===old.journal);
 const p1=gitBlobMeta(old.request),s1=gitBlobMeta(old.source);
 const jExpected=old.journal.replace("owner_launchd_home_t5_existing_readonly_gitfirst_r1","owner_launchd_home_t5_existing_readonly_gitfirst_r2")
 .replace(p1.blob,rp.blob).replace("bytes:"+p1.bytes+',sha256:"'+p1.sha256+'"',"bytes:"+rp.bytes+',sha256:"'+rp.sha256+'"')
 .replace("home-t5-readonly-"+s1.sha256.slice(0,8)+"-","home-t5-readonly-"+sp.sha256.slice(0,8)+"-");
 ck("only_journal_identity_binding_changed",neo.journal===jExpected);
 ck("same_original_budgets",JSON.stringify(c1.budgets)===JSON.stringify(c2.budgets));
 ck("same_pinned_inputs",JSON.stringify(c1.pinnedInputs)===JSON.stringify(c2.pinnedInputs));
 ck("same_original_parser",JSON.stringify(c1.originalParser)===JSON.stringify(c2.originalParser));
 ck("same_no_managed_effect_scope",JSON.stringify(c1.ownership)===JSON.stringify(c2.ownership)&&JSON.stringify(c1.forbidden)===JSON.stringify(c2.forbidden));
 ck("contract_three_wholepins",JSON.stringify(c2.source)===JSON.stringify(sp)&&JSON.stringify(c2.request)===JSON.stringify(rp)&&JSON.stringify(c2.journal)===JSON.stringify(jp));
 ck("fresh_dynamic_hashes_explicitly_absent",c2.freshDynamicBodyHashesExported===false);
 ck("still_source_only",c2.status==="SOURCE_ONLY_NO_NATIVE_GO"&&c2.slotInitialized===false);
 return {ok:true,checkCount:results.length,checks:results,scope:"pure source overlay; original 78 not rerun; no Python or Native",source:sp,request:rp,journal:jp};
}