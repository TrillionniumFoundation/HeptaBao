function verifySnapshot2379StageInfoSource(input) {
 const checks=[];function check(name,v){checks.push({name,pass:!!v});if(!v)throw new Error(name);}
 const {before,after,edits,diff,stageBefore,stageDiff,request,requestPin,prerequisites}=input;
 let transformed=before;
 check("exactly-seven-literals",edits.length===7);
 for(let i=0;i<edits.length;i++){const e=edits[i];check("literal-"+i+"-unique",transformed.split(e.before).length===2);transformed=transformed.replace(e.before,e.after);}
 check("exact-literal-only-whole",transformed===after);
 check("old-info-forward-strict",snapshotApply(before,diff)===after);
 check("old-info-reverse-strict",snapshotApply(after,diff,true)===before);
 check("stage-forward-strict",snapshotApply(stageBefore,stageDiff)===after);
 check("stage-reverse-strict",snapshotApply(after,stageDiff,true)===stageBefore);
 check("stage-six-hunks",(stageDiff.match(/^@@ /gm)||[]).length===6);
 check("old-info-two-hunks",(diff.match(/^@@ /gm)||[]).length===2);
 const p=gitBlobMeta(request),q=JSON.parse(request);
 check("exact-request-whole",p.blob===requestPin.blob&&p.bytes===requestPin.bytes&&p.sha256===requestPin.sha256);
 check("fixed-request-shape",Object.keys(q).sort().join(",")==="idempotency_key,operation"&&Object.keys(q.operation).sort().join(",")==="arguments,tool"&&Object.keys(q.operation.arguments).sort().join(",")==="host,path");
 check("fixed-file-info",q.operation.tool==="file_info"&&q.operation.arguments.host==="rog"&&q.operation.arguments.path==="/home/qian-qi/heptabao-native-snapshot-forward-source-2379d02b-20261106-r1/control/stage-result.public.json");
 check("fixed-key",q.idempotency_key==="heptabao-native-snapshot-23799024-rog-source-observe-r1-report-info");
 check("same-slot",after.includes('const GF_SLOT = "snapshot_2379_rog_source_gitfirst_r1";'));
 check("separate-go",after.includes('g.scope==="stage_result_file_info_only"')&&after.includes('goPin.blob!==s.goPin.blob'));
 check("no-body-authorization",after.includes('g.binary_read_authorized===false')&&!after.includes('op.tool==="binary_read"'));
 check("existing-job",after.includes('s.job==="1a1b008fa4a-fc05-6d9a"'));
 check("original-closed-prerequisites",prerequisites.length===2&&prerequisites[0].id==="1dd76fec9350714727e292af3868878ae220edbfb88ee10c35c204f874f2873b"&&prerequisites[1].id==="af4c0d7dfb5c3eb8da7afe7476a042c2feb85b02839021f7b258e58252084681");
 check("closed-lane-required",after.includes('s.activeObserver===null && s.startCalled===true')&&after.includes('s.stageResultInfoStarted!==true'));
 check("one-file-info-marker",after.includes('if(c.kind==="operation_start" && q.operation.tool==="file_info")s.stageResultInfoStarted=true;'));
 check("summary383-0",after.includes('s.nextStdout===383 && s.nextStderr===0'));
 check("cap65536",after.includes("const GF_STAGE_RESULT_MAX_BYTES = 65536;"));
 check("pages8192",after.includes("q.limit===8192"));
 check("payload1MiB",after.includes("1048576"));
 check("decimal-lossless",after.includes("gfIntegerText")&&after.includes("parseLosslessIntegers"));
 check("scope-no-execution",input.nativeCalls===0&&input.candidateFunctionCalls===0);
 return{schema:"heptabao.snapshot-2379-info-only-source-checks.v1",pass:true,count:checks.length,checks,newNativeCalls:0,candidateFunctionCalls:0};
}
