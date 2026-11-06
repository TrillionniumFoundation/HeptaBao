const H=eval(load("owner_pure_source")+"\n"+load("owner_source_unified_helpers")+";({pin:gitBlobMeta,utf8:utf8Bytes,b64:encodeBase64Bytes,hash:sha256Latin1,byteString,apply:strictApplySource})");
const deriver=load("authbus_home_r2_readback_deriver"),journal=load("authbus_home_r2_readback_journal"),before=load("authbus_home_r2_readback_journal_before"),plan=load("authbus_home_r2_readback_plan");
const checks=[];const ck=(name,pass)=>{checks.push({name,passed:pass===true});if(pass!==true)throw Error(name);};
try{
 new Function(journal);ck("journal parses without invocation",true);
 new Function(deriver);ck("pure deriver parses without invocation",true);
 ck("exact 3 forward hunks strict",load("authbus_home_r2_readback_journal_diff").hunks===3&&H.apply(before,load("authbus_home_r2_readback_journal_diff").raw).raw===journal);
 ck("exact 3 reverse hunks strict",load("authbus_home_r2_readback_journal_reverse").hunks===3&&H.apply(journal,load("authbus_home_r2_readback_journal_reverse").raw).raw===before);
 function definitions(x){const hits=[...x.matchAll(/^(?:async )?function ([A-Za-z0-9_]+)\(/gm)];return Object.fromEntries(hits.map((m,i)=>[m[1],x.slice(m.index,hits[i+1]?.index??x.length).trim()]));}
 const bf=definitions(before),af=definitions(journal),changed=["gfInitializeOnlyAfterRootGO","gfValidateRequest","gfCloseOriginalObserver"];
 const unchanged=Object.keys(bf).filter(n=>!changed.includes(n));
 ck("13 old journal definitions 10 exact unchanged",Object.keys(bf).length===13&&unchanged.length===10&&unchanged.every(n=>bf[n]===af[n]));
 ck("only 3 finite pure functions added",Object.keys(af).filter(n=>!Object.hasOwn(bf,n)).sort().join(",")==="deriveFixedReadbackBodies,validateFixedReadbackBody,validateFixedReadbackInfo");
 ck("new slot remains uninitialized",load(plan.newSlot)===undefined);
 ck("old final context exact byte unchanged",H.pin(JSON.stringify(load(plan.oldSlot),null,2)+"\n").blob===plan.originalState.blob);
 ck("actual root qualification bound",plan.actualRootQualification.blob==="00900615411da59bc3d0997bb579a007f832822a");
 ck("actual receipt only final stdout pin",plan.targets[2].sha256===load("authbus_home_r2_report").candidateReceipt.sha256&&plan.targets[2].bytes===15237);
 ck("3 exact metadata closed tool args only",plan.metadataRequests.every((raw,i)=>{const q=JSON.parse(raw);return q.operation.tool==="file_info"&&q.operation.arguments.host==="mac"&&q.operation.arguments.path===plan.targets[i].path&&Object.keys(q.operation.arguments).sort().join(",")==="host,path";}));
 ck("exact total and chunks",plan.targets.reduce((n,t)=>n+t.bytes,0)===96654&&plan.targets.flatMap(t=>t.bodyChunks).join(",")==="65536,8382,7499,15237");
 const P=eval(load("owner_pure_source")+"\n"+deriver+";({info:validateFixedReadbackInfo,derive:deriveFixedReadbackBodies,body:validateFixedReadbackBody})");
 const fixtures=plan.targets.map(t=>({path:t.path,size:t.bytes,sha256:t.sha256,version:[t.stageFull9[0],t.stageFull9[1],t.stageFull9[6],t.stageFull9[7],t.stageFull9[8]].join(":"),mode:384,metadata:{mode:384,uid:501,gid:20,link_count:1,metadata_platform:"darwin"}}));
 const derived=P.derive(plan,fixtures);
 ck("synthetic metadata derives exactly 4 fixed bodies",derived.requests.length===4&&derived.totalBytes===96654);
 ck("body versions come exactly from supplied metadata",derived.requests.every(e=>JSON.parse(e.requestRaw).operation.arguments.expected_version===fixtures[e.targetOrdinal-1].version));
 const expectRefusal=(label,fn)=>{let rejected=false;try{fn();}catch(e){rejected=true;}ck(label,rejected);};
 const wrongHash=JSON.parse(JSON.stringify(fixtures));wrongHash[0].sha256="0".repeat(64);expectRefusal("synthetic drift SHA refuses",()=>P.derive(plan,wrongHash));
 const wrongVersion=JSON.parse(JSON.stringify(fixtures));wrongVersion[1].version=wrongVersion[1].version.replace(/[^:]+$/,"1");expectRefusal("synthetic drift full9 version refuses",()=>P.derive(plan,wrongVersion));
 const wrongLink=JSON.parse(JSON.stringify(fixtures));wrongLink[2].metadata.link_count=2;expectRefusal("synthetic receipt multi-link refuses",()=>P.derive(plan,wrongLink));
 const candidate=load("authbus_home_r2_candidate"),sourceBytes=H.utf8(candidate.sources["mac_current_outer_wal_r1.py"]);
 const parts=[];let outerWhole=null;
 for(let i=0;i<2;i++){const q=JSON.parse(derived.requests[i].requestRaw),a=q.operation.arguments,b=sourceBytes.slice(a.offset,a.offset+a.limit);const v={path:a.path,size:sourceBytes.length,version:a.expected_version,offset:a.offset,next_offset:a.offset+b.length,eof:a.offset+b.length===sourceBytes.length,data_base64:H.b64(b),chunk_sha256:H.hash(H.byteString(b))};const result=P.body(plan,fixtures,i,q,v,parts);parts.push(result.part);if(result.whole)outerWhole=result.whole;if(i===0){expectRefusal("synthetic body stale version refuses",()=>P.body(plan,fixtures,i,q,{...v,version:"stale"},[]));}}
 ck("synthetic chunks reconstruct exact frozen outer",outerWhole?.pin.blob===candidate.sourcePins["mac_current_outer_wal_r1.py"].blob);
 ck("unchanged original runtime deriver",H.pin(candidate.runtimeDeriver).blob==="47c30a8833171ecc52679a25a913c71ca7a35eac");
 const result={schema:"heptabao.home-r2-fixed-readback-source-checks.v1",passed:true,checkCount:checks.length,checks,unchangedOldFunctions:unchanged,changedOldFunctions:changed,addedPureFunctions:Object.keys(af).filter(n=>!Object.hasOwn(bf,n)),sourceOnly:true,fixtureMetadataNotHostObservation:true,NativeCalls:0,SDKExecuted:false,newSlotInitialized:false,runtimeGO:false};
 store("authbus_home_r2_readback_source_checks",result);
 store("authbus_home_r2_readback_fixture_inputs",{syntheticOnly:true,infos:fixtures,nativeNotSubmitted:true});
 text({passed:true,count:checks.length,unchanged:unchanged,sourceOnly:true});
}catch(e){store("authbus_home_r2_readback_check_error",{error:String(e),checks,NativeCalls:0});text({error:String(e),checks});}