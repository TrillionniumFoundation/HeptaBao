function verifyStreamHelpSource(files) {
 const checks=[];
 const eq=(name,a,b)=>checks.push({name,passed:JSON.stringify(a)===JSON.stringify(b)});
 const yes=(name,value)=>checks.push({name,passed:value===true});
 const before=files["source.before.py"],after=files["source.py"],oldJournal=files["journal.before.js"],journal=files["journal.js"];
 const contract=JSON.parse(files["CONTRACT.public.json"]),request=JSON.parse(files["request.exact.json"]);
 eq("before/source-pin",gitBlobMeta(before),{"blob":"5bbd852c3b8c49a3cc18a0dc716fe123f33c3726","bytes":44719,"sha256":"aed2df85d5e22ef9933fe342e981426e2fc5817d81212ee4b17987a0b563ae35"});
 eq("after/source-pin",gitBlobMeta(after),{"blob":"84a2d90a6b32adf39495ea8f238e933907df365f","bytes":44702,"sha256":"0753ca3587f8e090081cce1292918037790bc083d0db272cfbe70889c88cb6b8"});
 eq("source/forward-strict",strictApplySource(before,files["source.forward.diff"]),{raw:after,hunks:5});
 eq("source/inverse-strict",strictApplySource(after,files["source.inverse.diff"]),{raw:before,hunks:5});
 eq("journal/forward-strict",strictApplySource(oldJournal,files["journal.forward.diff"]),{raw:journal,hunks:2});
 eq("journal/inverse-strict",strictApplySource(journal,files["journal.inverse.diff"]),{raw:oldJournal,hunks:2});
 let restored=after;
 for(const edit of contract.mechanical.sourceEdits) {
  eq("source/edit-once/"+edit.old,restored.split(edit.next).length-1,1);
  restored=restored.replace(edit.next,edit.old);
 }
 eq("source/only-declared-edits",restored,before);
 const moduleLine=s=>s.split("\n").find(x=>x.startsWith("MODULES = "));
 eq("modules/whole-encoded-two-helpers",moduleLine(after),moduleLine(before));
 const definition=(s,name)=>{const a=s.indexOf("\ndef "+name+"(");if(a<0)return null;const next=s.indexOf("\ndef ",a+1);return s.slice(a+1,next<0?undefined:next+1);};
 for(const name of ["need","sha","identity","remaining","public_error","load_helpers","metadata","admit_binding","open_fixed","verify_all","hash_tool","command_public","close_rows"])
  eq("unchanged-definition/"+name,definition(after,name),definition(before,name));
 eq("finally/whole",after.slice(after.indexOf("    finally:\n",after.indexOf("\ndef main("))),before.slice(before.indexOf("    finally:\n",before.indexOf("\ndef main("))));
 eq("request/source",request.stdin,after);
 eq("request/pin",gitBlobMeta(files["request.exact.json"]),contract.exactRequest);
 eq("request/fixed-inputs",[request.host,request.executable,request.args,request.cwd,request.timeout_seconds],
 ["mac","/opt/homebrew/Cellar/python@3.14/3.14.3_1/Frameworks/Python.framework/Versions/3.14/bin/python3.14",["-I","-S","-B","-"],"/Users/qianqi",60]);
 eq("request/key",request.idempotency_key,"heptabao-mac-public-log-stream-help-0753ca35-20261106-r1");
 yes("request/stdin-only",Object.hasOwn(request,"stdin")&&!Object.hasOwn(request,"stdin_text"));
 eq("journal/pin",gitBlobMeta(journal),contract.journal);
 let normalized=journal.replace("owner_authbus_public_log_stream_help_gitfirst_r1","owner_launchd_log_help_protocol_gitfirst_r2")
  .replace(/const GF_REQUEST = \{[\s\S]*?\};/,oldJournal.match(/const GF_REQUEST = \{[\s\S]*?\};/)[0])
  .replace("heptabao-mac-public-log-stream-help-0753ca35-","heptabao-mac-owned-launchd-log-help-protocol-aed2df85-");
 eq("journal/only-three-bindings",normalized,oldJournal);
 yes("help/stream-only",after.includes("HELP_ARGV = [LOG_PATH, 'help', 'stream']"));
 yes("help/exact-two-options",after.includes("for name in ('--predicate', '--style')"));
 yes("help/original-exit-protocol",after.includes("if row['exitCode'] == 0 and not err:")&&after.includes("elif row['exitCode'] == 64 and not out:"));
 eq("contract/budgets",[contract.budgets.sharedSeconds,contract.budgets.helpChildSeconds,contract.budgets.processStartSeconds,contract.codeAndMetadataScope.applicationFDs,contract.budgets.immutablePageBytes],[45,10,60,4,8192]);
 eq("contract/zero-native",[contract.NativeSubmitted,contract.GO,contract.pendingLiveDiagnostic.notAuthorized],[0,null,true]);
 return {schema:"heptabao.fixed-stream-help-mechanical-source-checks.r1",passed:checks.every(x=>x.passed),checkCount:checks.length,checks,executedPython:false,NativeCalls:0,scope:"Exact mechanical changes and preserved owner/resource contract only"};
}
