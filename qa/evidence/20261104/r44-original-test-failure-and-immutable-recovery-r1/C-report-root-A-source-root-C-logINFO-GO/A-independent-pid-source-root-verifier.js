function rootIndependentPidSource(f,author,prior){
 const rows=[],ck=(name,v)=>{rows.push({name,passed:v===true});if(v!==true)throw Error(name);};
 const c=JSON.parse(f["CONTRACT.public.json"]),q=JSON.parse(f["exact-request.proposed.json"]),oldQ=JSON.parse(f["before-request.original.json"]),b=f["before-identity-r1.py"],a=f["after-pid-observation-r2.py"];
 ck("author62_exact",author.exact&&author.value.passed&&author.value.checkCount===62);
 ck("before_exact_reviewed_source",gitBlobMeta(b).blob==="a938ba9fd034a6ba4b66300fd88e61383ab1be32");
 ck("after_source_exact",gitBlobMeta(a).blob===c.source.blob&&gitBlobMeta(a).sha256===c.source.sha256);
 const fw=strictApply(b,f["source-forward.diff"]),rv=strictApply(a,f["source-reverse.diff"]);ck("seven_strict_hunks_both",fw.text===a&&rv.text===b&&fw.hunks===7&&rv.hunks===7);
 ck("journal_two_strict_hunks",strictApply(f["before-journal.original.js"],f["journal-forward.diff"]).text===f["after-journal.proposed.js"]&&strictApply(f["after-journal.proposed.js"],f["journal-reverse.diff"]).text===f["before-journal.original.js"]);
 ck("request_exact_source_and_pin",q.stdin===a&&gitBlobMeta(f["exact-request.proposed.json"]).blob===c.request.blob);
 ck("request_only_stdin_key_changed",JSON.stringify({...q,stdin:null,idempotency_key:null})===JSON.stringify({...oldQ,stdin:null,idempotency_key:null}));
 ck("Mac_absolute_interpreter_deadline60",q.host==="mac"&&q.timeout_seconds===60&&q.executable===oldQ.executable&&JSON.stringify(q.args)==='["-I","-S","-B","-"]');
 ck("runtime_trigger_original_whole",f["reference-original-failed-stdout.txt"]===load("r34_packet_Auth-PID32527-identity-actual-full70").raw["actual--stdout.original.txt"]&&prior.value.passed&&prior.value.nativeObservationLaneReleased);
 ck("no_cleanup_or_private_expansion",c.target.signalAuthorized===false&&c.target.bootoutAuthorized===false&&c.cleanupCore.dispatchable===false);
 ck("seven_path_prefix_original",a.slice(0,a.indexOf("class ProbeRefused"))===b.slice(0,b.indexOf("class ProbeRefused")));
 ck("original_final_cleanup_exact",a.slice(a.indexOf("    finally:",a.indexOf("def main(")))===b.slice(b.indexOf("    finally:",b.indexOf("def main("))));
 ck("no_ESRCH_historical_exit_claim",a.includes("'pidExitOrHistoricalReapClaimed':False")&&a.includes("'currentManagedScopeStillUnknown':True"));
 ck("new_pair_guard_shortcircuits_null",a.includes("pair['sameLifetimeWithinPair']\n            and pair['pathResult'] == pair['childCountResult'] == 'complete'")&&a.includes("identity_first['sameLifetimeWithinPair'] and identity_second['sameLifetimeWithinPair']"));
 ck("two_registration_mappings_before_eligibility",a.includes("result['currentLabelMappingSameFixedPidBoth'] and result['currentIdentityKernelMetadataComplete']"));
 const binding=processStartBinding(q);
 return {schema:"heptabao.root-independent-label-pid-source.r2",passed:true,checks:rows.length,rows,source:c.source,request:c.request,journal:c.journal,binding:{sha256:binding.sha256,native_fingerprint:binding.native_fingerprint,canonicalBytes:utf8Bytes(binding.canonical).length},sourceOnly:true,NativeCalls:0,managedScopeQualified:false};
 }