function verifyFixedCrashR5Source(files, publicProbeSource) {
 const checks=[],norm=x=>Array.isArray(x)?x.map(norm):x&&typeof x==="object"?Object.fromEntries(Object.keys(x).sort().map(k=>[k,norm(x[k])])):x;
 const eq=(name,a,b)=>checks.push({name,passed:JSON.stringify(norm(a))===JSON.stringify(norm(b))});
 const yes=(name,x)=>checks.push({name,passed:x===true});
 const meta=gitBlobMeta,json=JSON.parse,before=files["source.before.original.py"],after=files["source.py"];
 const jb=files["journal.before.original.js"],ja=files["journal.js"],q=json(files["request.exact.json"]),c=json(files["CONTRACT.public.json"]);
 const mf=json(files["source-core.manifest.original.json"]);
 for(const e of mf.entries)eq("core-whole/"+e.path,meta(files[e.path]),{blob:e.blob,bytes:e.bytes,sha256:e.sha256});
 eq("base/R4-source",meta(before),{blob:"6813e19bf3d6fed77d6f0705d8c10b22104af2cb",bytes:37634,sha256:"9e758b73a9a487e7ffa19f2815583761e44d545f8e8a40467fb160de8871b612"});
 for(const [name,input,diff,expected,hunks] of [
  ["source-forward",before,files["source.forward.diff"],after,4],
  ["source-inverse",after,files["source.inverse.diff"],before,4],
  ["journal-forward",jb,files["journal.forward.diff"],ja,2],
  ["journal-inverse",ja,files["journal.inverse.diff"],jb,2]]) {
  const applied=strictApplySource(input,diff);eq("patch/"+name,applied.raw,expected);eq("patch/"+name+"/hunks",applied.hunks,hunks);
 }
 const block=(s,name)=>{const re=new RegExp("^def "+name+"\\([^\\n]*\\):","m"),m=re.exec(s);if(!m)return null;const rest=s.slice(m.index+m[0].length),next=/^(?:def|class) /m.exec(rest);return s.slice(m.index,next?m.index+m[0].length+next.index:s.length);};
 const defs=s=>[...s.matchAll(/^def ([a-zA-Z_][a-zA-Z0-9_]*)\(/gm)].map(x=>x[1]);
 const oldDefs=defs(before),added=defs(after).filter(n=>!oldDefs.includes(n));
 eq("source/three-new-projection-functions",added,["public_frame_image","public_frame_symbol","faulting_thread_projection"]);
 for(const name of oldDefs.filter(n=>!["namespace_field","crash_projection","main"].includes(n)))
  eq("unchanged-function/"+name,block(after,name),block(before,name));
 eq("unchanged/constants-signals",after.slice(0,after.indexOf("def namespace_field(")),before.slice(0,before.indexOf("def namespace_field(")));
 const restoredCrash=block(after,"crash_projection")
   .replace("       'faultingThreadPublicProjection':faulting_thread_projection(crash),\n","")
   .replace("'rawThreadsEnvironmentOrUsedImagesExported':False","'threadsEnvironmentOrUsedImagesExported':False");
 eq("unchanged/seven-plus-path-gates-and-body-parser",restoredCrash,block(before,"crash_projection"));
 eq("unchanged/main-custody-and-fallback",block(after,"main").replaceAll("fixed-file-projection.r5","fixed-file-projection.r4"),block(before,"main"));
 eq("request/source",q.stdin,after);
 eq("request/contract-pin",meta(files["request.exact.json"]),c.request);
 eq("source/contract-pin",meta(after),c.source);
 eq("journal/contract-pin",meta(ja),c.journal);
 eq("request/fixed-fields",{host:q.host,executable:q.executable,args:q.args,cwd:q.cwd,timeout_seconds:q.timeout_seconds},
  {host:"mac",executable:"/opt/homebrew/Cellar/python@3.14/3.14.3_1/Frameworks/Python.framework/Versions/3.14/bin/python3.14",args:["-I","-S","-B","-"],cwd:"/Users/qianqi",timeout_seconds:60});
 eq("request/stable-key",q.idempotency_key,"heptabao-mac-public-node-crash-"+meta(after).sha256.slice(0,8)+"-20261106-r5");
 const gp=/const GF_REQUEST = \{blob:"([0-9a-f]{40})",\n bytes:([0-9]+),sha256:"([0-9a-f]{64})"\};/;
 const oldpin=gp.exec(jb),newpin=gp.exec(ja);yes("journal/request-pin-literal",!!oldpin&&!!newpin);
 eq("journal/request-pins",{blob:newpin[1],bytes:Number(newpin[2]),sha256:newpin[3]},meta(files["request.exact.json"]));
 eq("journal/only-three-bound-literals",ja.replace(c.freshSlot,"owner_authbus_public_node_crash_fixed_file_gitfirst_r4")
  .replace(newpin[0],oldpin[0]).replace(c.prefix,"heptabao-mac-public-node-crash-9e758b73-"),jb);
 const ns=block(after,"namespace_field"),st=block(after,"faulting_thread_projection"),im=block(after,"public_frame_image"),sy=block(after,"public_frame_symbol");
 yes("namespace/256-utf8-no-control",ns.includes("utf8_length<=256")&&ns.includes("value.isprintable()")&&ns.includes("except UnicodeEncodeError:pass"));
 yes("namespace/type-length-ascii-trim",["'characterLength'","'utf8Bytes'","'asciiOnly'","'trimClass'","'value':value if accepted else None"].every(x=>ns.includes(x)));
 yes("namespace/no-new-closed-enum-gate",!ns.includes("re.fullmatch")&&ns.includes("'semanticMeaningClaimed':False"));
 yes("stack/direct-typed-index",st.includes("type(fault) is int and 0<=fault<len(threads)")&&st.includes("thread=threads[selected]"));
 yes("stack/sole-thread-only-fallback",st.includes("'faultingThread' not in crash and len(threads)==1")&&st.includes("only.get('triggered') is not True"));
 yes("stack/triggered-conflict-refuses",st.includes("if 'triggered' in thread and triggered is not True:")&&st.includes("'selected-triggered-conflicts';return row"));
 yes("stack/32-prefix-honesty",st.includes("range(min(len(frames),32))")&&st.includes("max(0,len(frames)-32)")&&st.includes("row['selectedThreadAllFramesVisited']=len(frames)<=32"));
 yes("stack/shared-deadline",st.split("remaining()").length-1===3);
 yes("stack/no-other-thread-or-image-loop",!/\bfor\s+\w+\s+in\s+(?:threads|images)\b/.test(st)&&st.includes("images[index] if valid else None"));
 yes("stack/no-address-register-fields",![".get('threadState')",".get('queue')",".get('imageOffset')",".get('symbolLocation')",".get('base')",".get('uuid')"].some(x=>(st+im+sy).includes(x)));
 yes("stack/no-new-IO",!/\b(?:open|pread|readlink|scandir|Popen|execv|kill|waitpid)\s*\(/.test(st+im+sy));
 yes("image/fixed-dyld-path",im.includes("'dyld'")&&im.includes("path=='/usr/lib/'+basename"));
 yes("image/name-crosscheck",im.includes("name!=basename"));
 yes("image/no-content-qualification",im.includes("'fileContentOrExecutableIdentityQualified':False"));
 yes("symbol/mapped-image-required",sy.includes("not image['publicMapQualified']:return row"));
 yes("symbol/address-token-rejected",sy.includes("r'0x[0-9a-fA-F]+'"));
 yes("symbol/bounded-public-families",sy.includes("{1,256}")&&sy.includes("dyld[234]?")&&sy.includes("node|v8|uv|std"));
 eq("contract/unchanged-IO",[
  c.budgets.workSeconds,c.budgets.afterClosureSeconds,c.budgets.NativeOuterSeconds,
  c.budgets.returnedExplicitFdAttempts,c.budgets.readCalls,c.budgets.metadataCalls,
  c.budgets.maximumOpenedBodies,c.budgets.bodyBytesMaximum,c.budgets.returnedBytesMaximum,
  c.budgets.scandirIteratorAttempts,c.budgets.applicationWrites,c.budgets.directChildren],
  [5,8,60,8,36,256,1,6809,6810,0,0,0]);
 eq("contract/original-observation-bounds",c.budgets.observation,{processStatusMaximum:8,processReadObserverMaximum:8,processReadBytes:16384,perObserverStatusMaximum:8,immutablePageBytes:8192,perObserverPagesMaximum:128,perObserverPayloadMaximum:1048576});
 const proof=json(files["PUBLIC_INPUTS_BINDING.public.json"]),actual=json(files["public-probe.actual.stdout.original.json"]);
 eq("public-input/original-source",meta(publicProbeSource),proof.source);
 eq("public-input/original-actual",meta(files["public-probe.actual.stdout.original.json"]),proof.actualStdout);
 eq("public-input/explicit-env-cwd-argv",[proof.explicitEnvironment,proof.cwd,proof.argv],[actual.environment,actual.cwd,actual.argv]);
 eq("public-input/environment-seven",Object.keys(proof.explicitEnvironment).sort(),["HOME","OPENCLAW_CONFIG_PATH","OPENCLAW_HOME","OPENCLAW_OAUTH_DIR","OPENCLAW_STATE_DIR","PATH","TMPDIR"].sort());
 yes("public-input/env-not-inherited",publicProbeSource.includes("child_env=dict(env)")&&publicProbeSource.includes("env=child_env,cwd=str(cwd),start_new_session=True")&&!publicProbeSource.includes("child_env=dict(os.environ)"));
 const m=publicProbeSource.match(/^PUBLIC_FILES=json\.loads\(base64\.b64decode\('([A-Za-z0-9+/=]+)'\)\)$/m);
 yes("public-input/fixed-literal-found",!!m);
 const packed=json(utf8Text(unb64(m[1]))),marker=utf8Text(unb64(packed.marker));
 eq("public-input/marker-original",marker,files["public-node-startup.original.mjs"]);
 eq("public-input/marker-pin",meta(marker),proof.markerSource);
 for(const [key,path] of [["marker","startup-imports.mjs"],["rows","mac_auth_rows_cas_r1.mjs"],["cache","mac_authbus_cache_cas_r1.mjs"]]){
  const raw=utf8Text(unb64(packed[key])),pin=meta(raw),a=actual.createdPublicFiles.find(x=>x.path.endsWith("/"+path));
  yes("public-input/actual-file/"+key,!!a);eq("public-input/bytes-sha/"+key,[pin.bytes,pin.sha256],[a.bytes,a.sha256]);
 }
 const prior=json(files["prior-R4.stdout.original.json"]);
 eq("prior/R4-whole",meta(files["prior-R4.stdout.original.json"]),c.evidence.priorReaderActual.stdout);
 eq("prior/R4-original-limit-fact",prior.candidates[0].projection.termination.namespace,{knownInPreviousEnum:false,present:true,publicSyntaxQualified:false,semanticMeaningClaimed:false,type:"string",value:null});
 yes("prior/no-host-cause-presumed",c.projectionAdmission.causalConclusionClaimed===false&&c.projectionAdmission.causeClaim===false&&c.NativeCalls===0&&c.status==="SOURCE_ONLY_NO_NATIVE_GO");
 return {schema:"heptabao.fixed-crash-r5-source-mechanical-checks.r1",passed:checks.every(x=>x.passed),checkCount:checks.length,checks,execution:"pure V8 whole/strict diff/source text/provenance comparison only; not Python or projector execution",NativeCallsAdded:0,privateIPSRead:false,freshSlotInitialized:false};
}
