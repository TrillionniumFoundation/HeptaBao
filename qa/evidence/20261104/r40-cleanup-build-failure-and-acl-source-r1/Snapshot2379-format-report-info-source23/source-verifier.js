function verifyFormatter49InfoSource(input){
 const checks=[];function ck(n,v){checks.push({name:n,pass:!!v});if(!v)throw new Error(n);}
 const {before,after,edits,diff,baseBefore,baseDiff,request,requestPin,prerequisites,path,cap,actualTexts}=input;
 let rebuilt=before;
 for(const e of edits){ck(e.label+":declared-count",rebuilt.split(e.before).length-1===e.occurrences);rebuilt=rebuilt.split(e.before).join(e.after);}
 ck("exact-declared-source-delta",rebuilt===after);
 ck("old-info-forward",snapshotApply(before,diff)===after);
 ck("old-info-reverse",snapshotApply(after,diff,true)===before);
 ck("formatter-forward",snapshotApply(baseBefore,baseDiff)===after);
 ck("formatter-reverse",snapshotApply(after,baseDiff,true)===baseBefore);
 ck("six-localized-hunks",(baseDiff.match(/^@@ /gm)||[]).length===6);
 const mp=gitBlobMeta(request);ck("request-whole",mp.blob===requestPin.blob&&mp.bytes===requestPin.bytes&&mp.sha256===requestPin.sha256);
 const q=JSON.parse(request);ck("single-fixed-file-info",Object.keys(q).sort().join(",")==="idempotency_key,operation"&&Object.keys(q.operation).sort().join(",")==="arguments,tool"&&q.operation.tool==="file_info"&&Object.keys(q.operation.arguments).sort().join(",")==="host,path"&&q.operation.arguments.host==="rog"&&q.operation.arguments.path===path);
 ck("exact-formatter-path",path==="/home/qian-qi/heptabao-native-snapshot-forward-2379d02b-format-20261106-r1/result.public.json"&&cap===131072);
 ck("only-existing-slot",after.includes('const GF_SLOT = "snapshot_2379_rog_formatter_gitfirst_r1";'));
 ck("scope-exact",after.includes('g.scope==="format_result_file_info_only"')&&after.includes('g.maximum_file_info_starts===1')&&after.includes('g.binary_read_authorized===false'));
 ck("three-original-prerequisites",prerequisites.length===3&&prerequisites.map(p=>p.tool).join(",")==="process_status,process_read,process_read");
 prerequisites.forEach((p,i)=>{const m=gitBlobMeta(actualTexts[i]);ck("actual-native-"+i,m.blob===p.nativeText.blob&&m.bytes===p.nativeText.bytes&&m.sha256===p.nativeText.sha256);});
 ck("whole-stdout-precedes-summary-parse",after.indexOf("actual_whole_formatter_stdout")<after.indexOf("const terminal=JSON.parse(stdoutRaw)"));
 ck("two-stream-geometry",after.includes("first.stdout.next_offset===16384")&&after.includes("last.stdout.offset===16384")&&after.includes("last.stdout.next_offset===17780")&&after.includes("s.nextStdout===17780"));
 ck("terminal-passed-fenced",after.includes('terminal.status==="passed"')&&after.includes("terminal.allOwnedStopped===true")&&after.includes("terminal.files.length===49")&&after.includes("terminal.publicationError===null"));
 ck("file-info-guard",after.includes("v.size<=GF_FORMAT_RESULT_MAX_BYTES")&&after.includes("v.mode===384")&&after.includes("md.uid===1000 && md.gid===1000 && md.link_count===1"));
 ck("lossless-version-full9",after.includes('parts.every(x=>/^[0-9]+$/.test(x))')&&after.includes('parts[2]===String(v.size)')&&after.includes('"1",String(v.size),parts[3],parts[4]'));
 ck("once-marker-before-native",after.indexOf('s.formatResultInfoStarted=true;')<after.indexOf("sdk=await tools."));
 ck("no-binary-read-dispatch",!after.includes('op.tool==="binary_read"')&&!after.includes('a.tool==="binary_read"')&&!after.includes("controller_binary_read"));
 ck("same-page-and-payload-caps",after.includes("q.limit===8192")&&after.includes("b.length<=8192")&&after.includes("v.total_bytes<=1048576"));
 ck("source-only-syntax",typeof new Function(after)==="function");
 function functions(raw){const matches=[...raw.matchAll(/^(?:async )?function ([A-Za-z0-9_]+)\(/gm)],m={};for(let i=0;i<matches.length;i++)m[matches[i][1]]=raw.slice(matches[i].index,i+1<matches.length?matches[i+1].index:raw.length);return m;}
 const b=functions(baseBefore),a=functions(after);
 for(const n of ["gfNeed","gfMetaEquals","gfState","gfSave","gfIntegerText","gfInitializeOnlyAfterRootGO","gfAcceptArchivedSDK","gfReconcileSameGitArchiveReadOnly"])ck(n+":unchanged-whole",b[n]===a[n]);
 return{schema:"heptabao.snapshot2379.format49.info-source-checks.r1",pass:true,count:checks.length,checks,noNative:true,noCandidateFunctionInvoked:true,reportBodyNotAuthorized:true};
}