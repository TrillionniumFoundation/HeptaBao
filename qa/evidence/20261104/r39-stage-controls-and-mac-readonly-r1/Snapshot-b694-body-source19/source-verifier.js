function verifySnapshotB694BodySource(input) {
 const checks=[];function check(name,v){checks.push({name,pass:!!v});if(!v)throw new Error(name);}
 const {before,after,edits,diff,infoBefore,infoDiff,request,requestPin,expected,infoRaw}=input;
 let rebuilt=before;
 check("10-logical-bindings",edits.length===10);
 check("11-exact-occurrences",edits.reduce((n,e)=>n+e.count,0)===11);
 for(let i=0;i<edits.length;i++){const e=edits[i];check("binding-"+i+"-count",rebuilt.split(e.before).length-1===e.count);rebuilt=rebuilt.split(e.before).join(e.after);}
 check("literal-only-whole",rebuilt===after);
 check("old-body-forward",snapshotApply(before,diff)===after);
 check("old-body-reverse",snapshotApply(after,diff,true)===before);
 check("info-forward",snapshotApply(infoBefore,infoDiff)===after);
 check("info-reverse",snapshotApply(after,infoDiff,true)===infoBefore);
 check("3-plus-6-hunks",(diff.match(/^@@ /gm)||[]).length===3&&(infoDiff.match(/^@@ /gm)||[]).length===6);
 const q=JSON.parse(request),m=gitBlobMeta(request),a=q.operation.arguments,info=parseLosslessIntegers(infoRaw),ip=gitBlobMeta(infoRaw);
 check("request-whole",m.blob===requestPin.blob&&m.bytes===requestPin.bytes&&m.sha256===requestPin.sha256);
 check("request-binary-read",q.operation.tool==="binary_read"&&Object.keys(a).sort().join(",")==="expected_version,host,limit,offset,path");
 check("fixed-host-path",a.host==="rog"&&a.path===expected.path&&expected.path==="/home/qian-qi/heptabao-native-snapshot-forward-source-b6949024-20261106-r1/control/stage-result.public.json");
 check("fixed-key",q.idempotency_key==="heptabao-native-snapshot-b6949024-rog-source-observe-r1-report-body");
 check("one-actual-range",a.offset===0&&a.limit===28206&&a.limit===expected.bytes&&a.limit<=65536);
 check("exact-version",a.expected_version===expected.version&&expected.version===info.version);
 check("actual-info-whole",ip.blob===expected.infoNative.blob&&ip.bytes===expected.infoNative.bytes&&ip.sha256===expected.infoNative.sha256);
 check("actual-info-binding",info.path===expected.path&&info.size===expected.bytes&&info.sha256===expected.sha256);
 check("actual-safe-metadata",info.mode===384&&info.metadata.mode===384&&info.metadata.uid===1000&&info.metadata.gid===1000&&info.metadata.link_count===1&&info.metadata.metadata_platform==="linux");
 const parts=info.version.split(":");check("lossless-full9-source",parts.length===5&&parts.every(v=>/^[0-9]+$/.test(v))&&parts[2]===String(expected.bytes)&&parts[3]==="1793952723578666336"&&parts[4]===parts[3]);
 check("actual-closed-info",expected.infoOperation==="353762d80b5cec5728d101a73623b74ffe60fd1333f03c5982fb73325450a336");
 check("separate-root-scope",after.includes('g.scope==="stage_result_binary_read_only"')&&after.includes("g.maximum_binary_read_starts===1"));
 check("closed-existing-context",after.includes('s.stageResultInfoGO?.whole===true && s.stageResultInfoStarted===true')&&after.includes('s.stageResultBodyGO===undefined && s.stageResultBodyStarted!==true'));
 check("once-before-dispatch-marker",after.includes('if(c.kind==="operation_start" && q.operation.tool==="binary_read")s.stageResultBodyStarted=true;'));
 check("original-8192-pages",after.includes("q.limit===8192"));
 check("original-1MiB-payload",after.includes("1048576"));
 check("no-new-scope-execution",input.nativeCalls===0&&input.candidateFunctionCalls===0);
 return{schema:"heptabao.snapshot-b694-stage-report-body-source-checks.v1",pass:true,count:checks.length,checks,newNativeCalls:0,candidateFunctionCalls:0};
}
