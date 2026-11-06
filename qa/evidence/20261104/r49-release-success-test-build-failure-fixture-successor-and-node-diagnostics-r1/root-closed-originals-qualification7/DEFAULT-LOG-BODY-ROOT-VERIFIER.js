function verifyDefaultLogBodyRoot(input) {
 const {files,rangePayloads,goRaw,originalInfoState,buildReport}=input;
 const checks=[];const check=(name,pass)=>{checks.push({name,passed:!!pass});if(!pass)throw Error(name);};
 const eq=(a,b)=>JSON.stringify(a)===JSON.stringify(b);
 const rel=parseLosslessIntegers(files["RELEASE.public.json"]),st=parseLosslessIntegers(files["STATE.original.json"]),go=JSON.parse(goRaw);
 check("exact original BODY GO bytes",files["LOG-GO.original.json"]===goRaw);
 check("release STATE pin",eq(gitBlobMeta(files["STATE.original.json"]),rel.originalState));
 const calls=Object.values(st.calls),observers=Object.values(st.completedObservers);
 check("112 accepted original calls",calls.length===112&&calls.every(x=>x.called===true&&x.phase==="accepted"));
 check("25 closed original observers",observers.length===25&&observers.every(x=>x.completedInactive===true)&&observers.reduce((n,x)=>n+x.pages,0)===61);
 check("no current call future or pending",rel.NativeCall===0&&rel.NativeFuture===0&&rel.ownerRelease&&st.pending===null&&st.activeObserver===null&&!st.nativeCallInFlight&&!st.paused);
 check("no rerun",rel.businessReplay===false&&rel.newProcess===false&&rel.cargoRepeated===false);
 check("exact 7 new ranges completed",st.buildLogBodyNext===7&&st.buildLogBodyCalled===7&&rel.newCalls===50&&rel.newObservers===7&&rel.newPages===36);
 check("old unknown preserved",rel.oldGitUNKNOWNPreserved.oldUnknownRetained&&rel.oldGitUNKNOWNPreserved.originalNativeCallNotRepeated&&eq(st.outerFailure,originalInfoState.outerFailure));
 check("old INFO calls preserved",Object.entries(originalInfoState.calls).every(([k,v])=>eq(st.calls[k],v)));
 const joined={stderr:[],stdout:[]};
 for(let i=0;i<7;i++){
  const spec=go.orderedRanges[i],statusRow=rel.statuses[i],payloadRaw=rangePayloads[i];
  const payload=parseLosslessIntegers(payloadRaw);
  check("range "+i+" original payload pin",eq(gitBlobMeta(payloadRaw),statusRow.range.payload));
  check("range "+i+" payload text shape",payload.isError===false&&payload.content.length===1&&payload.content[0].type==="text");
  const nativeRaw=payload.content[0].text,native=parseLosslessIntegers(nativeRaw);
  check("range "+i+" native text pin",eq(gitBlobMeta(nativeRaw),statusRow.range.nativeText));
  const bytes=unb64(native.data_base64);
  check("range "+i+" actual fixed path version",native.path===spec.path&&native.version===spec.version);
  check("range "+i+" offset length next EOF",native.offset===spec.offset&&bytes.length===spec.limit&&native.next_offset===spec.offset+spec.limit&&native.eof===spec.eof&&native.size===spec.bytes);
  check("range "+i+" chunk SHA",sha256Latin1(byteString(bytes))===native.chunk_sha256);
  const part=st.buildLogParts[spec.stream].find(x=>x.offset===spec.offset);
  check("range "+i+" state admitted same bytes",part&&part.base64===native.data_base64&&part.bytes===bytes.length&&part.originalOperation===statusRow.range.id&&part.chunkSHA256===native.chunk_sha256);
  check("range "+i+" accepted exact once start",calls.filter(c=>c.kind==="operation_start"&&c.requestPin.blob===spec.request.blob).length===1);
  const sdkRaw=files["range"+i+".status.SDK.original.json"],nativeStatusRaw=files["range"+i+".status.native.original.json"],requestRaw=files["range"+i+".status.request.original.json"];
  const sdk=JSON.parse(sdkRaw),status=JSON.parse(nativeStatusRaw),request=JSON.parse(requestRaw);
  check("range "+i+" original status pins",eq(gitBlobMeta(sdkRaw),statusRow.sdk)&&eq(gitBlobMeta(nativeStatusRaw),statusRow.native)&&eq(gitBlobMeta(requestRaw),statusRow.request));
  const sdkText=sdk.content.find(x=>x.type==="text")?.text;
  check("range "+i+" original SDK status matches",typeof sdkText==="string"&&eq(JSON.parse(sdkText),status));
  check("range "+i+" original observer inactive",status.operation_id===statusRow.range.id&&request.operation_id===status.operation_id&&status.async_state==="completed"&&status.owned_future_active===false&&status.payload_available&&status.automatic_retry===false);
  check("range "+i+" sequential stream bytes",joined[spec.stream].length===spec.offset);
  joined[spec.stream]=joined[spec.stream].concat(bytes);
 }
 const expected=buildReport.compile_shared.commands.find(x=>x.label==="default-libtest-build");
 for(const stream of ["stderr","stdout"]){
  const body=rel.bodies.find(x=>x.stream===stream),raw=files[stream==="stderr"?"STDERR.original.txt":"STDOUT.original.jsonl"];
  check(stream+" whole decoded exact original",utf8Text(joined[stream])===raw);
  check(stream+" whole SHA matches actual report",sha256Latin1(byteString(joined[stream]))===expected[stream+"_sha256"]);
  check(stream+" final archive exact meta",eq(gitBlobMeta(raw),body.body)&&body.wholeReadback===true);
 }
 check("failure terminal actual",buildReport.status==="failed"&&buildReport.runtime_tests_started===false&&buildReport.group_results.length===0&&expected.exit_code===101);
 return {schema:"heptabao.root.default-libtest-original-two-logs-body.r1",passed:true,checkCount:checks.length,checks,originalCounts:{calls:112,observers:25,pages:61},newCounts:{calls:50,observers:7,pages:36},allSevenOriginalPayloadsAndStatusSDKWhole:true,allNewCallSDKIndependentlyRead:false,sourceJournalAndStateAccepted:true,laneReleased:true,oldUnknownPreserved:true,NativeCallsAdded:0};
}