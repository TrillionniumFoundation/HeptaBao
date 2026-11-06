function verifyX230TwoBundleStageSource(input){
 const checks=[];function ok(n,x){if(!x)throw Error(n);checks.push(n);}
 const H=new Function(input.pure+"\n"+input.correct+"\n"+input.strict+"\nreturn{gitBlobMeta,strictDiff,applyStrict,processStartBinding};")();
 function def(text,name){const lines=text.split("\n"),at=lines.findIndex(x=>x.startsWith("def "+name+"("));if(at<0)return null;let end=at+1;while(end<lines.length&&(lines[end]===""||/^[ \t]/.test(lines[end])))end++;return lines.slice(at,end).join("\n").trimEnd()+"\n";}
 const names=["on_signal","digest","identity","remaining","stable","fsync_dir","create","public","process_snapshot","group_members","stop_active","stop_owned","persist_command","owned_argv","owned","git","freeze","read_file","prove_canonical","recheck_artifacts"];
 ok("strict source forward",H.applyStrict(input.before,input.diff,false)===input.after);
 ok("strict source reverse",H.applyStrict(input.after,input.diff,true)===input.before);
 for(const name of names)ok("unchanged original helper "+name,def(input.before,name)!==null&&def(input.before,name)===def(input.after,name));
 ok("original final child cleanup retained",input.after.includes(input.originalFinally));
 ok("explicit removed product receipt qualifications",!input.after.includes("def verify_normal61(")&&!input.after.includes("def verify_receipts(")&&!input.after.includes("normal61-result.public.json")&&!input.after.includes("native-build.public.json"));
 ok("fixed original time ceilings",input.after.includes("UNTIL=START+300")&&input.after.includes("def owned(label,path,*command,allowed=(0,),limit=60):")&&input.after.includes("str(OLD_SOURCE),str(SOURCE),limit=90)"));
 ok("original network prohibition retained",input.after.includes("'protocol.allow=never'")&&input.after.includes("'protocol.file.allow=always'")&&input.after.includes("'GIT_NO_LAZY_FETCH':'1'")&&input.after.includes("'GIT_OPTIONAL_LOCKS':'0'"));
 ok("local base has no invented origin requirement",!def(input.after,"freeze").includes("origin")&&input.after.includes("assert origin==str(OLD_SOURCE)")&&input.after.includes("'remove-new-local-origin'"));
 const main=input.after.slice(input.after.indexOf("\ntry:\n",input.after.indexOf("def recheck_artifacts")));
 ok("base and ancestor before fresh root writes",main.indexOf("base_before=freeze(")<main.indexOf("ROOT.mkdir(")&&main.indexOf("'base-has-first-prerequisite'")<main.indexOf("ROOT.mkdir("));
 ok("two verified sequential imports before checkout",main.indexOf("for ordinal,item in enumerate(FILES):")<main.indexOf("owned('canonical-checkout'")&&main.includes("'bundle%d-verify'")&&main.includes("'bundle%d-import'")&&main.includes("assert fetched==item['head']"));
 ok("base before and after no fallback",main.includes("assert base_after==base_before")&&!main.includes("reset")&&!main.includes("pull")&&!main.includes("https://"));
 const receive=def(input.after,"receive_files"),read=def(input.after,"read_carrier");
 ok("bounded exact carrier and whole binary binding",read.includes("count<=MAX_CARRIER")&&read.includes("digest(raw)==BINDING['carrier']['sha256']")&&read.includes("base64.b64decode(encoded,validate=True)")&&read.includes("digest(body)==item['sha256']"));
 ok("new input FD ledger precedes acquisition",receive.indexOf("result['input_descriptors'].append(ledger)")<receive.indexOf("fd=os.open(")&&receive.indexOf("try:\n            protected+=1")<receive.indexOf("fd=os.open("));
 ok("new input close once critical",receive.split("os.close(fd)").length===2&&receive.includes("finally:\n            if fd is not None:\n                protected+=1")&&receive.includes("os.close(fd);ledger['closed']=True"));
 ok("bounded writes and same FD whole readback",receive.includes("os.write(fd,view[:65536])")&&receive.includes("read_file(fd,item['bytes'],item['sha256'])")&&receive.includes("identity(before)==identity(os.fstat(fd))==identity(path.lstat())"));
 ok("failure retains partial scope and conservative closure",input.after.includes("'partial_root_retained_on_failure':True")&&input.after.includes("result['base_after_error_type']")&&input.after.includes("if not result['input_descriptors_closed'] or result.get('old_source_unchanged') is not True:"));
 ok("current full materialized index and bytes gate",input.after.includes("assert total==BINDING['candidate']['tracked_bytes']")&&input.after.includes("assert proof.hexdigest()==BINDING['candidate']['full_index_sha256']")&&input.after.includes("total<=128*1024*1024"));
 const bind=new Function("input",input.pure+"\n"+input.correct+"\n"+input.binder+"\nreturn bindX230TwoBundleSource(input);");
 const bound=bind(input.bindingInput);
 ok("mechanical template binding exact",bound.source===input.after&&bound.requestRaw===input.requestRaw&&JSON.stringify(bound.typed)===JSON.stringify(input.typed));
 const req=JSON.parse(input.requestRaw);
 ok("only fixed x230 process proposal",req.host==="x230"&&req.executable==="/usr/bin/python3"&&req.cwd==="/home/qian"&&req.timeout_seconds===360&&req.args[4]===input.after&&req.args[5]===H.gitBlobMeta(input.after).sha256);
 ok("whole stdin distinct from request size",H.gitBlobMeta(req.stdin).bytes===235828&&H.gitBlobMeta(req.stdin).bytes<=262144&&H.gitBlobMeta(input.requestRaw).bytes===267126);
 ok("candidate frozen current576 no actual qualification",bound.candidate.commit==="5767739cd25e458ac052dc8d384019bab8688ae0"&&bound.candidate.tree==="42477d622dcf96e1e2b0929fe9ecc6b7ba484740"&&bound.NativeGO===null&&bound.NativeExecuted===false);
 for(const name of ["carrier_bytes","root","first_prerequisite","second_binary_SHA","candidate"]){
  const x=JSON.parse(JSON.stringify(input.bindingInput));
  if(name==="carrier_bytes")x.carrier+=" ";
  if(name==="root")x.binding.fresh_root+="-other";
  if(name==="first_prerequisite")x.binding.bundles[0].prerequisite="0".repeat(40);
  if(name==="second_binary_SHA")x.binding.bundles[1].sha256="0".repeat(64);
  if(name==="candidate")x.binding.candidate.tree="0".repeat(40);
  let refused=false;try{bind(x);}catch(e){refused=true;}
  ok("pure binder refuses "+name,refused);
 }
 return {schema:"heptabao.x230-two-bundle-source-static-verification.v1",pass:true,check_count:checks.length,checks,unchangedOriginalHelpers:names.length,originalFunctions:27,currentFunctions:25,removedFunctions:["need","verify_normal61","verify_receipts"],newFunction:"read_carrier",sourceHunks:(input.diff.match(/^@@ /gm)||[]).length,source:H.gitBlobMeta(input.after),request:H.gitBlobMeta(input.requestRaw),carrier:H.gitBlobMeta(req.stdin),NativeCalls:0,PythonCompiled:false,PythonExecuted:false,actualBasePresence:null,X230StageQualified:false,full34Qualified:false,scope:"Pure V8 bindings, strict diff, full retained helper comparison and static control flow checks only; no Python/runtime safety proof or host observation."};
}