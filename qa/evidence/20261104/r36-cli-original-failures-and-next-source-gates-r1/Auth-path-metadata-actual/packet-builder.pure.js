function buildPathMetadataActualPacket(){
 const pin=gitBlobMeta, enc=x=>JSON.stringify(x,null,2)+'\n';
 const slot='owner_launchd_path_metadata_gitfirst_r1',s=load(slot),texts={...load('owner_path_metadata_actual_min_texts')},calls=[];
 if(s.pending!==null||s.activeObserver!==null||s.nativeCallInFlight!==false||s.paused)throw Error('live_state_not_closed');
 for(const [key,c] of Object.entries(s.calls)){
  if(c.phase!=='accepted'||c.called!==true)throw Error('call_not_accepted:'+key);
  const prepared=load('pure_git_once:gfa-'+key),sdkRaw=load(slot+':original_sdk_raw:'+key),nativeRaw=load(slot+':native_raw:'+key);
  const sdk=JSON.parse(sdkRaw);
  if(sdk.isError!==false||sdk.content.filter(x=>x.type==='text').map(x=>x.text).join('\n')!==nativeRaw)throw Error('original_sdk_native_mismatch:'+key);
  if(pin(c.requestRaw).blob!==c.requestPin.blob||pin(sdkRaw).blob!==c.sdkPin.blob||pin(nativeRaw).blob!==c.nativePin.blob)throw Error('original_pin_mismatch:'+key);
  const prefix='call-'+key+'--';
  for(const [name,raw] of Object.entries(prepared.texts))texts[prefix+name]=raw;
  texts[prefix+'original.sdk.json']=sdkRaw;texts[prefix+'native.original.json']=nativeRaw;
  calls.push({key,kind:c.kind,phase:c.phase,called:c.called,request:c.requestPin,preparedTree:c.armed.tree??prepared.expectedTree,sdk:c.sdkPin,sdkTree:c.sdkArchive.tree,native:c.nativePin,prefix});
 }
 for(const o of s.completedObservers){
  const p=load('pure_git_once:gfc-'+o.id).texts['payload.original.json'];
  if(pin(p).blob!==o.payload.blob)throw Error('closed_payload_mismatch:'+o.id);
  texts['observer-'+o.id+'--payload.original.json']=p;
 }
 texts['CALLS.public.json']=enc({schema:'heptabao.public-native-original-call-index.r1',slot,callCount:calls.length,calls,observers:s.completedObservers});
 texts['final-state.original.json']=enc(s);
 texts['diagnostic.source.py']=load('owner_cause_metadata_source').raw;
 texts['journal.native.source.js']=load('owner_cause_metadata_journal_source');
 texts['journal.archive.source.js']=load('owner_pure_git_archive_helper_r2');
 texts['journal.pure.source.js']=load('owner_pure_source');
 texts['SOURCE_BINDING.public.json']=enc({source:load('owner_cause_metadata_source').pin,sourceTree:'d361caf1f759deaad5b9a85ad9e04369dd0f1248',journalTree:'17fba4e4d6e0183a2e4fd9d982bc6327c8b88e25',go:load('owner_path_metadata_root_go').pin,sourceOnlyProvenanceIsNotCurrentRuntimeStatus:true});
 texts['REVIEW.md']='# Exact path metadata diagnostic — actual closure\n\nThis packet preserves one exact process_start and two original observers (authority and process_read), seven immutable pages, all original SDK/native texts, each external request/intent/armed checkpoint, and the final diagnostic stdout. No observer was re-admitted and there was no Native recovery/error in this diagnostic. The archive is Git-first under the exact root GO; local durable journaling was unavailable and is not claimed.\n\nThe new diagnostic succeeded and all 22 returned application descriptors closed. The original Python alias resolved to the known regular interpreter full nine-field identity; all fixed paths were stable and all requested current-observer access checks allowed. Original server stdout/stderr remain zero bytes. These current facts do not identify launchd EX_CONFIG, do not establish launchd/TCC access, do not hash current code, and do not close the original service registration or historical lineage. No file bodies, child process, service mutation, SDK/provider, or credential call occurred.\n\nThe original worker failure, original label, prior Git 8916 mutation UNKNOWN, and historical 11754 uncertainty remain separate and unchanged. Lane A is released; subsequent work is SOURCE only unless separately authorized.\n';
 return {texts,calls};
}
