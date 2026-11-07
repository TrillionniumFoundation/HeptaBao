async function verifyBundleArchiveR2(files) {
 const checks=[];function ok(v,label){checks.push({label,pass:!!v});if(!v)throw Error(label);}
 const plan=JSON.parse(files["PLAN.public.json"]);
 for(const b of plan.bindings){
  let derived=files[b.tag+".before.js"];for(const e of b.changes){ok(derived.split(e.before).length===2,b.tag+" unique archive literal");derived=derived.replace(e.before,e.after);}
  const after=files[b.tag+".after.js"];
  ok(derived===after&&b.changes.length===2,b.tag+" only two key literals");
  ok(applyStrict(files[b.tag+".before.js"],files[b.tag+".forward.diff"])===after&&applyStrict(after,files[b.tag+".reverse.diff"])===files[b.tag+".before.js"],b.tag+" strict forward reverse");
  ok((files[b.tag+".forward.diff"].match(/^@@ /gm)||[]).length===2,b.tag+" two bounded hunks");
  ok(JSON.stringify(gitBlobMeta(files[b.tag+".request.unchanged.json"]))===JSON.stringify(b.request),b.tag+" original request unchanged");
  const start=after.indexOf("async function gfCloseOriginalObserver"),end=after.indexOf("\n/* Recovery rule",start);
  const before=files[b.tag+".before.js"],bs=before.indexOf("async function gfCloseOriginalObserver"),be=before.indexOf("\n/* Recovery rule",bs);
  ok(after.slice(0,start)===before.slice(0,bs)&&after.slice(end)===before.slice(be),b.tag+" everything outside close unchanged");
 }
 const slot="successor4a_mac_canonical_bundle_info_gitfirst_r1",history=JSON.parse(files["original-error-history.json"]);
 const m=new Map([[slot,JSON.parse(files["paused-state.original.json"])],[slot+":outer_failures",history]]);
 const before=JSON.stringify(m.get(slot),null,2)+"\n",realCalls=m.get(slot).calls;
 const archiveRequests=[];
 const archive=async q=>{
  archiveRequests.push(q);
  const entries=Object.keys(q.texts).sort().map(path=>({path,...gitBlobMeta(q.texts[path]),whole:true}));
  const b=[];for(const e of entries){b.push(...utf8Bytes("100644 "+e.path+"\0"));for(let i=0;i<40;i+=2)b.push(parseInt(e.blob.slice(i,i+2),16));}
  return {tree:sha1Bytes(utf8Bytes("tree "+b.length+"\0").concat(b)),entries,count:entries.length,bytes:entries.reduce((n,e)=>n+e.bytes,0),whole:true,localDurableJournal:false,runtimeAuthorized:false};
 };
 const noTools=new Proxy({}, {get(){throw Error("pure review has no tools");}});
 const api=new Function("store","load","tools","archiveFlatPublicTextsOnce",files["pure_helpers.original.js"]+"\n"+files["mac.original-payload-closure.source.js"]+"\nreturn {prepareMac4aOriginalPayloadClosure,applyMac4aOriginalPayloadClosure};")
  ((k,v)=>m.set(k,v),k=>m.get(k),noTools,archive);
 const g={authorization:"GO",scope:plan.MacRecovery.scope,original_operation:plan.MacRecovery.originalOperation,
  paused_state:plan.MacRecovery.pausedState,original_payload:plan.MacRecovery.payload,corrected_mac_journal:plan.bindings[0].after,
  maximum_native_calls:0,maximum_new_git_archives:3,new_output_archive_keys:plan.MacRecovery.newOutputKeys,
  proof_archive_key:plan.MacRecovery.proofKey,apply_only_after_whole_proof:true,pureReviewOnly:true};
 const goRaw=JSON.stringify(g,null,2)+"\n",goPin=gitBlobMeta(goRaw),go={goRaw,goPin,goWholeReadback:true};
 const prepared=await api.prepareMac4aOriginalPayloadClosure({...go,pureRaw:files["pure_helpers.original.js"],journalRaw:files["mac.after.js"],payloadRaw:files["payload.original.json"],payloadArchive:JSON.parse(files["payload-archive-whole.public.json"])});
 ok(prepared.ok,"pure original-payload closure preparation succeeds");
 ok(JSON.stringify(m.get(slot),null,2)+"\n"===before,"real reviewed paused slot unchanged before apply");
 ok(archiveRequests.length===3&&archiveRequests.map(x=>x.key).join(",")===plan.MacRecovery.newOutputKeys.concat(plan.MacRecovery.proofKey).join(","),"only two output and proof archives; original payload never recreated");
 ok(archiveRequests.every(x=>!x.key.startsWith("successor576")&&!x.key.startsWith("gfc-")),"no historical archive key reused");
 const applied=api.applyMac4aOriginalPayloadClosure(go);
 ok(applied.ok&&applied.NativeCalls===0&&applied.GitCalls===0,"pure apply only after whole proof");
 const after=m.get(slot);
 ok(after.activeObserver===null&&!after.paused&&after.pending===null&&!after.nativeCallInFlight&&after.completedObservers.length===2,"one original completed observer closed");
 ok(after.bundleBodyStarted===1&&after.bundleBodyRanges.length===1,"original body budget not reset");
 ok(JSON.stringify(after.calls)===JSON.stringify(realCalls),"all six original calls unchanged");
 ok(JSON.stringify(after.outerFailure)===JSON.stringify(JSON.parse(before).outerFailure)&&JSON.stringify(m.get(slot+":outer_failures"))===JSON.stringify(history),"original error and history retained exactly");
 ok(after.bundleBody.binaryBytes===1253&&after.bundleBody.binarySHA256==="0bdbb69aed82e8cb5d5536ef8b782ac761ceca73d03e45af4d3073f890f18851","whole original body identity");
 ok(!api.applyMac4aOriginalPayloadClosure(go).ok,"second apply rejected");
 return {schema:"heptabao.bundle-archive-r2.pure-source-review.v1",pass:true,check_count:checks.length,checks,realNativeCalls:0,realGitCalls:0,realOriginalStateMutated:false};
}
