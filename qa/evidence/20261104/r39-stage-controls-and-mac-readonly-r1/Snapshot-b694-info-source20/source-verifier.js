function verifySnapshotB694StageInfoSource(input) {
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
 check("fixed-file-info",q.operation.tool==="file_info"&&q.operation.arguments.host==="rog"&&q.operation.arguments.path==="/home/qian-qi/heptabao-native-snapshot-forward-source-b6949024-20261106-r1/control/stage-result.public.json");
 check("fixed-key",q.idempotency_key==="heptabao-native-snapshot-b6949024-rog-source-observe-r1-report-info");
 check("same-slot",after.includes('const GF_SLOT = "snapshot_b694_rog_source_gitfirst_r1";'));
 check("separate-go",after.includes('g.scope==="stage_result_file_info_only"')&&after.includes('goPin.blob!==s.goPin.blob'));
 check("no-body-authorization",after.includes('g.binary_read_authorized===false')&&!after.includes('op.tool==="binary_read"'));
 check("existing-job",after.includes('s.job==="1a1afe9f4f5-fc05-6cb6"'));
 check("original-closed-prerequisites",prerequisites.length===2&&prerequisites[0].id==="63eb11ba6363fa901c8e79ab4418ea9f6ce240e82757391fa6c83c4ed696d4b1"&&prerequisites[1].id==="502549e6c265343e2d5d8239a65515d474546b02b4dcc8cea72581b114394c1c");
 check("closed-lane-required",after.includes('s.activeObserver===null && s.startCalled===true')&&after.includes('s.stageResultInfoStarted!==true'));
 check("one-file-info-marker",after.includes('if(c.kind==="operation_start" && q.operation.tool==="file_info")s.stageResultInfoStarted=true;'));
 check("summary383-0",after.includes('s.nextStdout===383 && s.nextStderr===0'));
 check("cap65536",after.includes("const GF_STAGE_RESULT_MAX_BYTES = 65536;"));
 check("pages8192",after.includes("q.limit===8192"));
 check("payload1MiB",after.includes("1048576"));
 check("decimal-lossless",after.includes("gfIntegerText")&&after.includes("parseLosslessIntegers"));
 check("scope-no-execution",input.nativeCalls===0&&input.candidateFunctionCalls===0);
 return{schema:"heptabao.snapshot-b694-info-only-source-checks.v1",pass:true,count:checks.length,checks,newNativeCalls:0,candidateFunctionCalls:0};
}
