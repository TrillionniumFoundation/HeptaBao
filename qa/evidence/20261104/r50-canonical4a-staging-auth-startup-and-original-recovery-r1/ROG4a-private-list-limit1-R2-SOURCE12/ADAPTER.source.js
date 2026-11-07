/* SOURCE ONLY. One bounded read-only registry page. No tool runs on load.
 * Requires exact pure_helpers.js plus git_archive_once.js. Raw registry SDK and
 * Pages SDKs stay private; only request, code, digests and safe projection may
 * be public. The old failed BUILD context is never written or reinitialized.
 */
const B4P_SLOT="combined_4a49405b_unknown_start_private_list_r2";
const B4P_OLD_SLOT="combined_4a49405b_fresh_build_gitfirst_r1";
const B4P_OLD={blob:"2d512764d26256fabaaaf7deb3eae41120d92d3e",bytes:181122,sha256:"196a33b53ea752d27a5226e06f90e75383b1f621a44791e0e240ded17f0bac82"};
const B4P_Q={"blob":"828019befe1e6529fead23a24db811c15db7a462","bytes":34,"sha256":"e31531bed4ff4a89122bd1f8bb56fe4076390fd1f48352353597d46a096d481d"};
const B4P_TITLE="HeptaBao 4a build original job discovery evidence";
const B4P_PAGE_KEY="heptabao-4a49405b-start-list-private-sdk-r2";
const B4P_KEY="heptabao-combined-4a49405b-fresh-build-20261106-r1-a4d59953";
const B4P_DIGEST="33dcdfaa308ff7e6669737a1326ec90e9f6275038ee7f27d896aeb95981f2d50";
const B4P_FP="3737107712862844902";
const B4P_MAX_RAW=131072, B4P_PART=8192;
function b4pNeed(v,c){if(!v)throw new Error(c);}
function b4pJ(x){return JSON.stringify(x,null,2)+"\n";}
function b4pEq(raw,p){const q=gitBlobMeta(raw);return q.blob===p.blob&&q.bytes===p.bytes&&q.sha256===p.sha256;}
function b4pOld(){
 const s=load(B4P_OLD_SLOT);
 b4pNeed(s&&b4pEq(b4pJ(s),B4P_OLD),"old_failed_state_exact");
 b4pNeed(s.paused===true&&s.job===null&&s.startCalled===true
  &&s.pending==="c4a-build-r1-start"&&s.nativeCallInFlight===false
  &&s.activeObserver===null,"old_unknown_boundary");
 return s;
}
function b4pPrivateRecord(label,sdk){
 const raw=b4pJ(sdk),pin=gitBlobMeta(raw),key=B4P_SLOT+":private-sdk:"+pin.blob;
 const old=load(key);b4pNeed(old===undefined||old===raw,"private_sdk_hash_collision");
 store(key,raw);store(B4P_SLOT+":private-alias:"+label,{pin,key});
 return {raw,pin,key};
}
function b4pPack(raw){
 const pin=gitBlobMeta(raw);b4pNeed(pin.bytes<=B4P_MAX_RAW,"private_sdk_representation_cap");
 const all=encodeBase64Bytes(utf8Bytes(raw)),parts=[];
 for(let offset=0;offset<all.length;offset+=B4P_PART)parts.push(all.slice(offset,offset+B4P_PART));
 b4pNeed(parts.length>0&&parts.length<=22,"bounded_base64_blocks");
 const manifest={schema:"heptabao.private.original-native-sdk.r1",
  encoding:"UTF-8 JSON.stringify two-space indent plus LF encoded as base64",
  sdk:pin,request:B4P_Q,originalUnknownState:B4P_OLD,nativeTool:"process_list_page",
  partChars:B4P_PART,partCount:parts.length,
  parts:parts.map((p,i)=>({ordinal:i,chars:p.length,sha256:gitBlobMeta(p).sha256}))};
 const f=String.fromCharCode(96).repeat(3);
 const blocks=[
  "This private evidence record preserves the complete original response used to locate the existing HeptaBao 4a build. The original startup timeout remains recorded; this record does not start or replay a build.",
  "# Original response manifest",f+"json\n"+JSON.stringify(manifest,null,2)+"\n"+f,
  "# Original response bytes",
  ...parts.map((p,i)=>f+"text\nHEPTABAO_SDK_PART "+i+" OF "+parts.length+"\n"+p+"\n"+f)
 ];
 return {manifest,parts,request:{title:B4P_TITLE,idempotency_key:B4P_PAGE_KEY,initial_blocks:blocks}};
}
function b4pRequireFullOwner(a,pageId){
 b4pNeed(a.scope==="page_and_backing_library_folder"&&a.sharing_available===true,"full_roster_scope");
 b4pNeed(a.page_id===pageId&&a.backing_type==="drive","same_private_drive_page");
 b4pNeed(a.workspace_id===null&&a.space_id===null&&a.next_cursor===null,"no_workspace_space_or_roster_continuation");
 b4pNeed(a.owner?.principal_type==="user"&&typeof a.owner.principal_id==="string"
  &&a.owner.principal_id.length>0&&a.owner.principal_id===a.page_owner?.principal_id,"canonical_owner_only_identity");
 b4pNeed(Array.isArray(a.shares)&&a.shares.length===0,"zero_direct_nonowner_grants");
 for(const k of ["inherited_access","inherited_access_summary","inherited_workspace_link_access"]){
  b4pNeed(a[k]?.complete===true&&Array.isArray(a[k].sources)&&a[k].sources.length===0,"complete_zero_inherited_grants");
 }
 return {ownerOnly:true,basis:"complete_full_roster",originalLiteralOwnerOnlyFieldAbsent:!Object.prototype.hasOwnProperty.call(a,"owner_only")};
}

function b4pDecode(readSDK,sharingSDK,pageId,expectedRaw,packed){
 b4pNeed(readSDK.isError!==true&&sharingSDK.isError!==true,"private_read_or_sharing_tool_error");
 const r=readSDK.structuredContent,a=sharingSDK.structuredContent;
 b4pNeed(r&&!r.error&&a&&!a.error,"private_structured_read_and_sharing");
 if(!(a.owner_only===true&&["page_owner","page_and_backing_library_folder"].includes(a.scope))){
  b4pNeed(!Object.prototype.hasOwnProperty.call(a,"owner_only"),"literal_owner_only_false_or_unknown");
  b4pRequireFullOwner(a,pageId);
 }
 if(a.complete!==undefined)b4pNeed(a.complete===true,"sharing_snapshot_not_partial");
 b4pNeed(r.metadata?.page_id===pageId&&r.content?.page_id===pageId
  &&r.content.title===B4P_TITLE
  &&r.metadata.drive_scope==="personal"&&r.metadata.owner_workspace_id==null
  &&Array.isArray(r.content.blocks),"exact_private_page_full_read");
 if(r.selection)b4pNeed(r.selection.whole_page_complete===true,"whole_page_required");
 const chunks=new Map();let manifest=null,fences=0;
 const f=String.fromCharCode(96).repeat(3);
 for(const block of r.content.blocks){
  b4pNeed(block.kind==="markdown"&&typeof block.markdown==="string","only_created_markdown_blocks");
  const matches=[...block.markdown.matchAll(new RegExp(f+"(json|text)\\n([\\s\\S]*?)\\n"+f,"g"))];
  for(const m of matches){
   fences++;
   if(m[1]==="json"){
    b4pNeed(manifest===null&&m[2]===JSON.stringify(packed.manifest,null,2),"one_exact_private_manifest");
    manifest=JSON.parse(m[2]);
   }else{
    const p=/^HEPTABAO_SDK_PART ([0-9]+) OF ([0-9]+)\n([A-Za-z0-9+/=]+)$/.exec(m[2]);
    b4pNeed(p&&Number(p[2])===packed.parts.length,"exact_chunk_marker");
    const i=Number(p[1]);b4pNeed(i<packed.parts.length&&!chunks.has(i),"unique_contiguous_chunk");
    b4pNeed(p[3]===packed.parts[i],"private_chunk_exact");chunks.set(i,p[3]);
   }
  }
 }
 b4pNeed(manifest&&chunks.size===packed.parts.length&&fences===packed.parts.length+1,"all_private_blocks");
 const bytes=unb64(packed.parts.map((_,i)=>chunks.get(i)).join("")),raw=utf8Text(bytes);
 b4pNeed(raw===expectedRaw&&b4pEq(raw,manifest.sdk)
  &&byteString(utf8Bytes(raw))===byteString(bytes),"private_original_all_bytes_and_hashes");
 return {sdk:manifest.sdk,ownerOnly:true,whole:true,raw};
}
function b4pInteger(v){
 if(typeof v==="string"&&/^[0-9]{1,20}$/.test(v))return v;
 if(Number.isSafeInteger(v)&&v>=0)return String(v);
 if(v&&Object.keys(v).join(",")==="$exactInteger"&&/^[0-9]{1,20}$/.test(v.$exactInteger))return v.$exactInteger;
 throw new Error("exact_public_identity_integer");
}
function b4pProject(raw,originalRequest){
 const sdk=JSON.parse(raw);
 b4pNeed(sdk.isError!==true,"native_list_tool_error_private_raw_preserved");
 b4pNeed(sdk.content?.length===1&&sdk.content[0].type==="text","one_native_list_text");
 const v=parseLosslessIntegers(sdk.content[0].text);
 b4pNeed(Array.isArray(v.jobs)&&v.jobs.length<=1,"actual_list_schema_jobs_required");
 b4pNeed(typeof v.inventory_complete==="boolean"&&(v.next_cursor===null||typeof v.next_cursor==="string"),
  "actual_list_page_coverage_fields");
 const rows=v.jobs.filter(x=>x&&x.host==="rog"&&x.idempotency_key===B4P_KEY);
 b4pNeed(rows.length<=1,"ambiguous_key_on_page_stop");
 const out={schema:"heptabao.original-job-discovery.safe-projection.r1",
  sdk:gitBlobMeta(raw),privateWholeVerified:true,privateOwnerOnly:true,
  rowsOnPage:v.jobs.length,inventoryComplete:v.inventory_complete,
  hasNextCursor:typeof v.next_cursor==="string",match:null,oldTimeoutPreserved:true,
  authoritativeLiveStatus:false,originalBuildStateChanged:false};
 if(rows.length===0)return out;
 const r=rows[0];
 b4pNeed(r.execution_mode==="operator"&&r.executable===originalRequest.executable
  &&r.cwd===originalRequest.cwd&&JSON.stringify(r.args)===JSON.stringify(originalRequest.args)
  &&r.request_digest===B4P_DIGEST&&b4pInteger(r.request_fingerprint)===B4P_FP,
  "target_row_exact_key_typed_exec_args_cwd");
 b4pNeed(typeof r.id==="string"&&/^[a-z0-9-]{1,100}$/.test(r.id),"exact_job_id_format");
 const created=b4pInteger(r.created_unix_ms);
 b4pNeed(BigInt(created)>=BigInt(Date.parse("2026-11-06T23:57:27Z")),"created_after_original_go");
 out.match={id:r.id,host:"rog",idempotencyKey:B4P_KEY,requestDigest:B4P_DIGEST,
  fingerprint:B4P_FP,executable:originalRequest.executable,cwd:originalRequest.cwd,
  argsExactMatch:true,createdUnixMs:created};
 return out;
}
async function b4pPrepare({goRaw,goPin,goWholeReadback}){
 b4pOld();b4pNeed(load(B4P_SLOT)===undefined,"fresh_discovery_context_once");
 b4pNeed(goWholeReadback===true&&b4pEq(goRaw,goPin),"root_go_external_whole");
 const g=JSON.parse(goRaw);
 b4pNeed(g.scope==="combined4a_unknown_start_private_list_page_limit1_only"
  &&g.maximumNativeCalls===1&&g.onlyReadOnlyNative===true&&g.host==="rog"
  &&JSON.stringify(g.request)===JSON.stringify(B4P_Q)
  &&JSON.stringify(g.originalUnknownState)===JSON.stringify(B4P_OLD)
  &&g.privatePage?.title===B4P_TITLE&&g.privatePage.idempotency_key===B4P_PAGE_KEY
  &&g.privatePage.omitSpaceAndParent===true&&g.privatePage.maximumCreates===1,
  "exact_private_page_discovery_go");
 const requestRaw=b4pJ({host:"rog",limit:1});
 const intent={schema:"heptabao.original-job-private-discovery-intent.r1",
  tool:"process_list_page",request:B4P_Q,originalUnknownState:B4P_OLD,rootGo:goPin,
  maximumNativeCalls:1,maximumPrivatePageCreates:1,
  rawSdkPublicGitAllowed:false,noStart:true,noStatus:true,noProcessRead:true,
  noCursorContinuation:true,nativeNotYetCalled:true};
 const armed={...intent,schema:"heptabao.original-job-private-discovery-armed.r1",
  mayHaveDispatchedAfterCheckpoint:true};
 const s={phase:"arming",called:false,inflight:false,paused:false,requestRaw,goPin,goRaw};
 store(B4P_SLOT,s);
 try{
  s.arm=await archiveFlatPublicTextsOnce({key:"c4a-private-list-arm-r2",
   repository:"TrillionniumFoundation/HeptaBao",texts:{"request.json":requestRaw,
   "intent.json":b4pJ(intent),"armed.json":b4pJ(armed)}});
  s.phase="armed_whole";store(B4P_SLOT,s);
  return {arm:s.arm,requiresModelBoundary:true,nativeCalled:false};
 }catch(e){s.paused=true;s.failure=String(e);store(B4P_SLOT,s);throw e;}
}
async function b4pInvokeAndArchivePrivate(){
 b4pOld();const s=load(B4P_SLOT);
 b4pNeed(s&&!s.paused&&!s.called&&!s.inflight&&s.phase==="armed_whole"
  &&s.arm?.whole===true&&b4pEq(s.requestRaw,B4P_Q),"one_armed_discovery_page");
 s.called=true;s.inflight=true;s.phase="native_call_entered";store(B4P_SLOT,s);
 try{
  const sdk=await tools.mcp__codex_apps__heptaruntime_mac_controller_process_list_page(JSON.parse(s.requestRaw));
  store(B4P_SLOT+":private-original-native-object",sdk);
  const raw=b4pJ(sdk);store(B4P_SLOT+":private-original-native-raw",raw);
  const pin=gitBlobMeta(raw);
  s.inflight=false;s.nativeSdkPin=pin;s.phase="private_sdk_stored_uninterpreted";store(B4P_SLOT,s);
  const packed=b4pPack(raw);store(B4P_SLOT+":private-page-create-request",packed.request);
  s.pageCreateCalled=true;s.phase="private_page_create_entered";store(B4P_SLOT,s);
  const created=await tools.mcp__codex_apps__chatgpt_space_create_page(packed.request);
  b4pPrivateRecord("create_page",created);
  b4pNeed(created.isError!==true&&!created.structuredContent?.error,"private_create_unknown_or_error_stop");
  const pageId=created.structuredContent?.metadata?.page_id??created.structuredContent?.page_id;
  b4pNeed(typeof pageId==="string"&&/^page_[A-Za-z0-9_-]{1,200}$/.test(pageId),"returned_exact_private_page_id");
  s.pageId=pageId;s.phase="private_page_verifying";store(B4P_SLOT,s);
  const reads=await Promise.allSettled([
   tools.mcp__codex_apps__chatgpt_space_read_page({page_id:pageId,view:"full"}),
   tools.mcp__codex_apps__chatgpt_space_get_page_sharing({page_id:pageId})
  ]);
  for(let i=0;i<reads.length;i++){
   const r=reads[i],label=i===0?"read_page_full":"get_page_sharing";
   if(r.status==="fulfilled")b4pPrivateRecord(label,r.value);
   else store(B4P_SLOT+":private-read-exception:"+label,{name:r.reason?.name,message:String(r.reason?.message)});
  }
  b4pNeed(reads.every(r=>r.status==="fulfilled"),"private_read_transport_unknown_stop");
  const verified=b4pDecode(reads[0].value,reads[1].value,pageId,raw,packed);
  s.privateWhole={sdk:verified.sdk,pageId,ownerOnly:true,whole:true};
  s.phase="private_sdk_whole_uninterpreted";store(B4P_SLOT,s);b4pOld();
  return {phase:s.phase,sdk:pin,privateWhole:true,ownerOnly:true,semanticParsed:false};
 }catch(e){s.inflight=false;s.paused=true;s.failure=String(e);store(B4P_SLOT,s);throw e;}
}
function b4pAcceptSafeProjection(){
 const old=b4pOld(),s=load(B4P_SLOT),raw=load(B4P_SLOT+":private-original-native-raw");
 b4pNeed(s&&!s.paused&&!s.inflight&&s.phase==="private_sdk_whole_uninterpreted"
  &&s.privateWhole?.whole===true&&s.privateWhole.ownerOnly===true
  &&b4pEq(raw,s.nativeSdkPin),"private_original_whole_before_native_parse");
 try{
  const request=JSON.parse(old.calls["c4a-build-r1-start"].requestRaw);
  const projection=b4pProject(raw,request);store(B4P_SLOT+":safe-projection",projection);
  s.phase="safe_projection_no_job_binding";store(B4P_SLOT,s);b4pOld();return projection;
 }catch(e){s.paused=true;s.failure=String(e);store(B4P_SLOT,s);throw e;}
}

/* The only public entry. No exception-derived text or stack is returned. */
async function b4pRun(action,input){
 try{
  if(action==="prepare")return {ok:true,value:await b4pPrepare(input)};
  if(action==="invoke")return {ok:true,value:await b4pInvokeAndArchivePrivate()};
  if(action==="accept")return {ok:true,value:b4pAcceptSafeProjection()};
  throw new Error("closed_private_action_set");
 }catch(error){
  store(B4P_SLOT+":private-entry-exception",{
   name:String(error?.name),message:String(error?.message),stack:String(error?.stack)});
  return {ok:false,stopped:true,code:"private_adapter_stopped"};
 }
}
