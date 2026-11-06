function verify576CanonicalBodySource(input) {
 const {before,infoSource,after,diff,infoDiff,edits,requestRaw,infoNativeRaw,infoStateRaw,plan}=input,checks=[];
 const check=(name,value)=>{checks.push({name,pass:value===true});if(value!==true)throw Error(name);};
 const pinEq=(raw,p)=>{const a=gitBlobMeta(raw);return a.blob===p.blob&&a.bytes===p.bytes&&a.sha256===p.sha256;};
 check("qualified_three_range_BODY_baseline",gitBlobMeta(before).blob==="dff9afae455ce293963433771ceb4901081d7967");
 check("actual_current_INFO_source",gitBlobMeta(infoSource).blob==="a0f43f0aa0789d7405f7ac1b00379a4b0ece8749");
 check("candidate_source45b5",gitBlobMeta(after).blob==="45b5e9adc11936acae8b594cd09b525b5a8973b7");
 check("old_BODY_diff_forward",applyStrict(before,diff)===after);
 check("old_BODY_diff_reverse",applyStrict(after,diff,true)===before);
 check("current_INFO_diff_forward",applyStrict(infoSource,infoDiff)===after);
 check("current_INFO_diff_reverse",applyStrict(after,infoDiff,true)===infoSource);
 check("5_and8_hunks",(diff.match(/^@@ /gm)||[]).length===5&&(infoDiff.match(/^@@ /gm)||[]).length===8);
 let rebuilt=before;for(const e of edits){check("unique_literal_"+edits.indexOf(e),rebuilt.split(e.before).length===2);rebuilt=rebuilt.replace(e.before,e.after);}
 check("twelve_exact_literal_edits_only",edits.length===12&&rebuilt===after);
 const bodies=s=>Array.from(s.matchAll(/^(?:async )?function (\w+)[^\n]*\n[\s\S]*?(?=^(?:async )?function |\n\/\*|$(?![\s\S]))/gm),m=>({name:m[1],body:m[0]}));
 const a=bodies(before),b=bodies(after),changed=a.filter((x,i)=>x.body!==b[i]?.body).map(x=>x.name);
 check("fourteen_definitions_only_two_literal_bodies",a.length===14&&b.length===14&&JSON.stringify(a.map(x=>x.name))===JSON.stringify(b.map(x=>x.name))&&JSON.stringify(changed)===JSON.stringify(["gfAuthorizeCanonicalBundleBodyOnly","gfCloseOriginalObserver"]));
 const meta=parseLosslessIntegers(infoNativeRaw),state=JSON.parse(infoStateRaw),expected=plan.expected;
 check("exact_whole_original_INFO_native_state",pinEq(infoNativeRaw,plan.actual_info.native)&&pinEq(infoStateRaw,plan.actual_info.state)&&plan.actual_info.native.blob==="b40eebebed4155bff74279c2b1d06cb8e2dd181e"&&plan.actual_info.state.blob==="a416295e4d2cfdc04472dce2de46e88f26b9afcb");
 check("INFO_original_three_calls_closed",Object.keys(state.calls).length===3&&state.completedObservers.length===1&&state.completedObservers[0].id===expected.infoOperation&&state.completedObservers[0].completedInactive===true&&state.activeObserver===null&&state.pending===null&&state.paused===false&&state.nativeCallInFlight===false);
 check("actual_version_size_SHA",expected.bytes===5766&&expected.path===meta.path&&expected.bytes===meta.size&&expected.sha256===meta.sha256&&expected.version===meta.version&&JSON.stringify(expected.full9)===JSON.stringify(state.bundleInfo.derivedFull9));
 const q=JSON.parse(requestRaw),r=plan.ranges;
 check("one_exact_range_whole_request",r.length===1&&r[0].offset===0&&r[0].limit===5766&&pinEq(requestRaw,r[0].request)&&q.operation.tool==="binary_read"&&q.operation.arguments.host==="rog"&&q.operation.arguments.path===meta.path&&q.operation.arguments.expected_version===meta.version&&q.operation.arguments.offset===0&&q.operation.arguments.limit===5766);
 check("separate_whole_BODY_authority_exact_one",after.includes('g.maximum_binary_read_starts===1')&&after.includes('g.exact_requests.length===1')&&after.includes('maximumBinaryReadStarts:1')&&after.includes('goPin.blob!==s.goPin.blob')&&after.includes('rootGo:s.bundleBodyGO?.pin??s.goPin'));
 check("prior_INFO_state_whole_before_attach",after.includes('gfMetaEquals(JSON.stringify(s,null,2)+"\\n",GF_BUNDLE_INFO_STATE)')&&after.includes('gfMetaEquals(load(GF_SLOT+":closed_native:"+need.infoOperation),need.infoNative)'));
 check("new_archive_keys_only",after.includes('"successor576-canonical-bundle-chunk-"')&&after.includes('"successor576-canonical-source-bundle-whole-r1"')&&!after.includes('"final02b-canonical-bundle-chunk-"')&&!after.includes('"final02b-canonical-source-bundle-whole-r1"'));
 check("original_body_and_INFO_limits",plan.limits.body_page_bytes===16384&&plan.limits.existing_INFO_page_bytes===8192&&plan.limits.status_calls_per_body===8&&plan.limits.pages_per_body===128&&plan.limits.payload_bytes_per_body===1048576&&plan.limits.binary_range_cap===65536&&plan.limits.carrier_bytes_for_later_Mac_stage===262144);
 check("no_newinitialization_or_runtime",plan.initialize===false&&plan.action==="authorize_bundle_body"&&plan.boundaries.body_submitted===false&&plan.boundaries.Native_GO===null&&plan.boundaries.process_start===0&&plan.boundaries.new_file_info===0);
 return {schema:"heptabao.canonical576-body-source-verification.v1",pass:true,check_count:checks.length,checks,Native_calls:0,Python_calls:0,journal_executed:false};
}
