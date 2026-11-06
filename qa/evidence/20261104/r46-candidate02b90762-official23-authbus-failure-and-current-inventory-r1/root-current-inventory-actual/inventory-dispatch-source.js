
async function rootInventoryDispatch(spec){
 const stateKey="r46_root_inventory_state",s=load(stateKey);
 if(s.pending||s.nativeCallInFlight||s.paused||s.calls.some(x=>x.key===spec.key))throw Error("inventory duplicate/pending/paused dispatch");
 if(s.calls.length>=27)throw Error("inventory total budget");
 if(spec.kind==="start" && (s.activeSearch||s.calls.filter(x=>x.kind==="start").length>=3))throw Error("inventory start budget/active search");
 if(spec.kind==="page" && (!s.activeSearch||spec.request.search_id!==s.activeSearch.id||spec.request.limit!==32||spec.scope!==s.activeSearch.scope))throw Error("inventory page ownership");
 const requestRaw=JSON.stringify(spec.request,null,2)+"\n";
 const intent={schema:"heptabao.original-call-intent.v1",call:spec.key,tool:spec.kind==="start"?"search_start":"search_results",request:gitBlobMeta(requestRaw),go:s.rootGo,originalCallOrdinal:s.calls.length+1,dispatchCount:0,automaticRetry:false};
 const arm=await saveGitFirstPublicBatch("r46_root_inventory_"+spec.key+"_arm_archive",[{name:"ROOT-GO.original.json",text:load("r46_root_inventory_GO").text},{name:"request.original.json",text:requestRaw},{name:"intent.original.json",text:JSON.stringify(intent,null,2)+"\n"}]);
 s.pending={...spec,requestRaw,intent,arm:arm.tree};s.nativeCallInFlight=true;
 const rec={key:spec.key,kind:spec.kind,scope:spec.scope,requestRaw,intentRaw:JSON.stringify(intent,null,2)+"\n",arm:arm.tree,phase:"dispatched-once",dispatchCount:1};s.calls.push(rec);store(stateKey,s);
 let sdk;
 try{sdk=await tools[spec.kind==="start"?"mcp__codex_apps__heptaruntime_mac_controller_search_start":"mcp__codex_apps__heptaruntime_mac_controller_search_results"](spec.request);}
 catch(e){s.nativeCallInFlight=false;s.paused=true;s.transportFailure={key:spec.key,error:String(e),outcome:"UNKNOWN",automaticRetry:false};store(stateKey,s);throw Error("inventory original outcome UNKNOWN; no replay");}
 const raw=JSON.stringify(sdk,null,2)+"\n";store("r46_root_inventory_"+spec.key+"_SDK_raw",raw);s.nativeCallInFlight=false;rec.phase="SDK-returned-unarchived";store(stateKey,s);
 const archive=await saveGitFirstPublicBatch("r46_root_inventory_"+spec.key+"_SDK_archive",[{name:"SDK.original.json",text:raw}]);
 rec.sdk=gitBlobMeta(raw);rec.sdkArchive=archive.tree;rec.phase="SDK-whole-uninterpreted";store(stateKey,s);
 return {key:spec.key,sdk:rec.sdk,archive:archive.tree,isError:sdk.isError??false};
}