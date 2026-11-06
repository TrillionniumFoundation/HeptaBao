async function collectOneFixedFile(fi) {
 const slot="snapshot_2379_formatted23_readonly_gitfirst_r1",P=load("snapshot_stage23_source:packet-texts");
 const G=eval(P["pure-helper.original.js"]+"\n"+P["archive-helper.original.js"]+"\n"+load("formatted23_plan:candidate").after+";({run:gfRun})");
 async function action(kind,args){const r=await G.run(kind,args);if(!r.ok){text(r);return null;}return r;}
 let initial=load(slot);
 if(initial.paused||initial.pending!==null||initial.activeObserver!==null||initial.nativeCallInFlight||initial.outputFiles.length!==fi){text({stopped:"expected_clean_fixed_file_boundary",fi});return false;}
 for(let ob=0;ob<9&&load(slot).outputFiles.length===fi;ob++){
  const nextResult=await action("next_request");if(!nextResult)return false;
  const nr=nextResult.value;if(nr.fileIndex!==fi){text({stopped:"unexpected_file_index",expected:fi,actual:nr.fileIndex});return false;}
  const label="sf23-r1-f"+String(fi).padStart(2,"0")+"-"+(nr.tool==="file_info"?"info":"b"+String(nr.rangeIndex).padStart(2,"0"));
  const key=label+"-admit";
  for(const [a,v] of [["prepare",{callKey:key,kind:"operation_start",requestRaw:nr.raw}],["invoke",{callKey:key}],["accept",{callKey:key}]])
   if(!(await action(a,v)))return false;
  notify({phase:"original_ack",fileIndex:fi,tool:nr.tool,rangeIndex:nr.rangeIndex,operation:load(slot).activeObserver?.id});
  for(let n=0;n<8;n++){
   const a=load(slot).activeObserver;if(a.futureClosed)break;
   const k=label+"-s"+a.statusCalled;
   for(const [a1,v] of [["prepare",{callKey:k,kind:"operation_status",requestRaw:JSON.stringify({operation_id:a.id},null,2)+"\n"}],["invoke",{callKey:k}],["accept",{callKey:k}]])
    if(!(await action(a1,v)))return false;
  }
  if(!load(slot).activeObserver.futureClosed){text({stopped:"original_future_not_closed_after_allowed_statuses",fileIndex:fi});return false;}
  const width=nr.tool==="binary_read"?16384:8192,cap=nr.tool==="binary_read"?64:128;
  for(let n=0;n<cap;n++){
   const a=load(slot).activeObserver;if(a.eof)break;
   const k=label+"-p"+a.pageCalled;
   for(const [a1,v] of [["prepare",{callKey:k,kind:"operation_result",requestRaw:JSON.stringify({operation_id:a.id,offset:a.nextPageOffset,limit:width},null,2)+"\n"}],["invoke",{callKey:k}],["accept",{callKey:k}]])
    if(!(await action(a1,v)))return false;
  }
  if(!(await action("close_observer")))return false;
  notify({phase:"observer_closed",fileIndex:fi,tool:nr.tool,rangeIndex:nr.rangeIndex,completedObservers:load(slot).completedObservers.length,bodyBytes:load(slot).bodyBytes});
 }
 const s=load(slot);
 if(s.outputFiles.length!==fi+1||s.pending!==null||s.activeObserver!==null||s.nativeCallInFlight){text({stopped:"file_not_complete",fileIndex:fi});return false;}
 text({phase:"file_whole",file:s.outputFiles[fi],completedFiles:s.outputFiles.length,completedObservers:s.completedObservers.length,bodyBytes:s.bodyBytes});
 return true;
}