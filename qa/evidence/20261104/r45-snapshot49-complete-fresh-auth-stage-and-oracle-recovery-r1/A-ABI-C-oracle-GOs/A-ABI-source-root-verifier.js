function rootPIDGuardR3(f,author,layout){
 const rows=[],ck=(name,v)=>{rows.push({name,passed:v===true});if(v!==true)throw Error(name);},b=f["source-before.r2.py"],a=f["source-after.r3.py"],q=JSON.parse(f["request-after.r3.json"]),old=JSON.parse(f["request-before.r2.json"]);
 ck("author41_exact",author.exact&&author.value.passed&&author.value.checkCount===41);
 ck("exact_prior_source",b===load("r34_packet_Auth-independent-label-PID-R2-SOURCE21").raw["after-pid-observation-r2.py"]);
 ck("only_wrong_guard_corrected",a===b.replace("BsdInfo.pgid.offset == 108","BsdInfo.pgid.offset == 100"));
 ck("strict_one_hunk",strictApply(b,f["source-forward.diff"]).text===a&&strictApply(a,f["source-inverse.diff"]).text===b&&strictApply(b,f["source-forward.diff"]).hunks===1);
 ck("independent_declared_layout",layout.value.fields.length===22&&layout.value.size===136&&layout.value.expectedPGID===100&&layout.value.ttydevOffset===108);
 ck("primary_header_exact",gitBlobMeta(f["primary-Apple-proc_info.h"]).blob==="718a69fcf5340f547893ed8dc85908f253c1ce81");
 ck("request_source_and_unchanged_runtime",q.stdin===a&&JSON.stringify({...q,stdin:null,idempotency_key:null})===JSON.stringify({...old,stdin:null,idempotency_key:null}));
 ck("journal_only_two_binding_hunks",strictApply(f["journal-before.r2.js"],f["journal-forward.diff"]).text===f["journal-after.r3.js"]&&strictApply(f["journal-after.r3.js"],f["journal-inverse.diff"]).text===f["journal-before.r2.js"]&&strictApply(f["journal-before.r2.js"],f["journal-forward.diff"]).hunks===2);
 const bind=processStartBinding(q);
 return {schema:"heptabao.root-PID-declared-ABI-guard-source.r3",passed:true,checks:rows.length,rows,tree:"d6715818ee514bdbe1cd4ad5e0866cc5c723069f",source:gitBlobMeta(a),request:gitBlobMeta(f["request-after.r3.json"]),journal:gitBlobMeta(f["journal-after.r3.js"]),binding:{sha256:bind.sha256,native_fingerprint:bind.native_fingerprint,canonicalBytes:utf8Bytes(bind.canonical).length},sourceOnly:true,NativeABIObserved:false,NativeCalls:0};
 }