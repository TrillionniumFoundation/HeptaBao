function verify(d,meta){
 const result=[];function c(n,v){result.push({name:n,passed:!!v});if(!v)throw Error(n);}
 let t=d.before;for(const[a,b]of d.replacements){c("replacement unique "+a.slice(0,45),t.split(a).length===2);t=t.replace(a,b);}
 c("five replacements",d.replacements.length===5);c("candidate entire forward exact",t===d.after);
 for(const[a,b]of [...d.replacements].reverse()){c("inverse unique "+b.slice(0,45),t.split(b).length===2);t=t.replace(b,a);}c("entire inverse original",t===d.before);
 function apply(s,diff,inverse){let a=s.split("\n");c("base terminal LF",a.pop()==="");let o=[],pos=0,hunks=0,p=diff.split("\n");
  for(let i=2;i<p.length;){if(!p[i]){i++;continue;}let m=/^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@/.exec(p[i++]);if(!m)throw Error("hunk");let at=+m[inverse?3:1]-1,need=+(m[inverse?4:2]??1),used=0;if(at<pos)throw Error("overlap");o.push(...a.slice(pos,at));pos=at;
   while(i<p.length&&!p[i].startsWith("@@ ")){let x=p[i++];if(!x)continue;let k=x[0],line=x.slice(1);if(inverse)k=k==="+"?"-":k==="-"?"+":k;if(k===" "||k==="-"){if(a[pos++]!==line)throw Error("context");used++;}if(k===" "||k==="+")o.push(line);if(!" +-".includes(k))throw Error("bad sign");}
   if(used!==need)throw Error("count");hunks++;}
  return {text:o.concat(a.slice(pos)).join("\n")+"\n",hunks};}
 const fw=apply(d.before,d.diff,false),rv=apply(d.after,d.diff,true);
 c("strict three hunks",fw.hunks===3&&rv.hunks===3);c("strict diff forward",fw.text===d.after);c("strict diff reverse",rv.text===d.before);
 const defs=s=>{const m=[...s.matchAll(/^(?:async )?function ([A-Za-z]+)\(/gm)];return m.map((x,i)=>({name:x[1],text:s.slice(x.index,m[i+1]?.index??s.length)}));};
 const old=defs(d.before),now=defs(d.after);c("ordered thirteen definitions",old.length===13&&JSON.stringify(old.map(x=>x.name))===JSON.stringify(now.map(x=>x.name)));
 for(let i=0;i<old.length;i++)if(!["gfValidateRequest","gfAcceptArchivedSDK"].includes(old[i].name))c("whole definition "+old[i].name,old[i].text===now[i].text);
 c("archive original whole pin",meta(d.archive).blob==="b093fdbf655511f7db94be2d95555606141bbb42");
 c("pure original whole pin",meta(d.pure).blob==="b6890e8b7217c546bec073dcb04988fc37652721");
 c("exact stage request whole",meta(d.request).blob==="c1429991e9c597d1639f02a68f791043e6c8b9e5"&&meta(d.request).bytes===111605&&meta(d.request).sha256==="aebf043cfcb5d60611dd67f3ed93c0caee8098091a70c8b61c8306de05fc5b65");
 const q=JSON.parse(d.request);c("original rog retained",q.host==="rog");c("unchanged 360 outer",q.timeout_seconds===360);
 c("exact inline stager",meta(q.args[4]).blob==="40cdd07ec0e87656c2ea2e65c13a0734ffde6c51");
 c("unique GF slot",d.after.includes('const GF_SLOT = "jwt_e3af_rog_source_gitfirst_r1";'));
 c("observer host rog exact",d.after.includes('a && a.host==="rog" && a.job_id===s.job'));
 c("ACK host rog exact",d.after.includes('v.job?.host==="rog" && v.job.execution_mode==="operator"'));
 c("new observer prefix",d.after.includes('/^heptabao-native-jwt-e3afc157-rog-source-observe-r1-/'));
 c("only original closed native tool set",d.after.includes('else throw new Error("closed_native_tool_set")')&&!d.after.includes('op.tool==="file_info"')&&!d.after.includes('op.tool==="binary_read"'));
 c("original page cap 8192",d.after.includes("q.limit===8192")&&d.after.includes("b.length<=8192"));
 c("original streams cap 16384",d.after.includes("a.limit===16384")&&d.after.includes("b.length<=16384"));
 c("single original future",d.after.includes("s.job!==null && s.activeObserver===null")&&d.after.includes('!s.paused && !s.nativeCallInFlight && s.pending===null'));
 c("closed before result",d.after.includes("s.activeObserver?.futureClosed===true")&&d.after.includes("v.owned_future_active===false && v.result_state==="));
 c("SDK first statement before parse",d.after.indexOf('store(GF_SLOT+":original_sdk:"+callKey,sdk)')<d.after.indexOf('const raw=JSON.stringify(sdk,null,2)'));
 c("SDK whole before isError",d.after.indexOf('c.sdkArchive=await archiveFlatPublicTextsOnce')<d.after.indexOf('gfNeed(sdk.isError!==true')&&d.after.includes('"SDK_whole_before_isError"'));
 c("invoke once marker no await gap",d.after.includes('c.called=true;c.phase="native_call_entered";s.nativeCallInFlight=true;')&&d.after.includes('if(c.kind==="process_start")s.startCalled=true;'));
 c("Git UNKNOWN blocks",d.after.includes('s.paused=true;c.phase="sdk_git_archive_unresolved"'));
 c("new normal-return gfRun whole",old.find(x=>x.name==="gfRun").text===now.find(x=>x.name==="gfRun").text);
 c("old wrong process binding unused",!d.after.includes("processStartBinding("));
 c("no init without separately reviewed root GO",d.after.includes("goWholeReadback===true && gfMetaEquals(goRaw,goPin)")&&d.after.includes('load(GF_SLOT)===undefined'));
 c("no automatic retry of transport",d.after.includes('c.phase="transport_unknown"')&&d.after.includes("replayAllowed:false"));
 c("SDK immutable history retained",d.archive.includes("original-sdk-by-blob:")&&d.archive.includes('history.push(event)'));
 c("one Git create admission",d.archive.match(/await tools\.mcp__codex_apps__github_create_tree\(/g)?.length===1&&d.archive.includes("archive_already_admitted_no_mutation_retry"));
 c("allsettled batch evidence before aggregate error",d.archive.includes("Promise.allSettled")&&d.archive.indexOf('store(prefix+":whole_batch:"+start')<d.archive.indexOf('throw new Error("whole_read_incomplete_no_mutation_retry")'));
 return {schema:"heptabao.native-jwt.gitfirst-stage-source-checks.v1",passed:true,checks:result.length,results:result,scope:"pure V8 source and identity checks only; no GF or Native function invoked",Runtime:0};
}