/* Pure mechanical R2 -> fresh R3 binding. No Runtime, SDK, filesystem or credential access. */
function makeFreshHomeR3(before, approvedParserAfter) {
 const need=(v,c)=>{if(!v)throw Error(c);};
 const same=(a,b)=>JSON.stringify(a)===JSON.stringify(b);
 const meta=gitBlobMeta;
 const oldT5='/Volumes/T5/hepta-vnext-recovery-20261013/mac-authbus-4e808-current-home-launch-r2';
 const oldHome='/Users/qianqi/heptabao-mac-authbus-4e808-home-launch-20261106-r2';
 const newT5='/Volumes/T5/hepta-vnext-recovery-20261013/mac-authbus-4e808-current-home-launch-r3';
 const newHome='/Users/qianqi/heptabao-mac-authbus-4e808-home-launch-20261106-r3';
 const namespaces=[
  [oldT5,newT5],[oldHome,newHome],
  ['mac-authbus-4e808-current-home-launch-r2','mac-authbus-4e808-current-home-launch-r3'],
  ['org.heptabao.qa.mac-authbus-4e808-home-r2.server','org.heptabao.qa.mac-authbus-4e808-home-r3.server'],
  ['org.heptabao.qa.mac-authbus-4e808-home-r2.consumer','org.heptabao.qa.mac-authbus-4e808-home-r3.consumer']
 ];
 const rewrite=raw=>namespaces.reduce((s,[a,b])=>s.split(a).join(b),raw);
 const once=(raw,a,b)=>{need(raw.split(a).length===2,'exact_one_binding_literal');return raw.replace(a,b);};
 need(before.NEW_T5===oldT5&&before.NEW_HOME===oldHome,'exact_R2_roots');
 need(Object.keys(before.sources).length===22,'exact_22_sources');
 need(meta(approvedParserAfter).blob==='3f259a4b085394fba0658359575aa0d74b9757e2','exact_approved_three_line_parser');
 const out={OLD_T5:oldT5,OLD_HOME:oldHome,NEW_T5:newT5,NEW_HOME:newHome,namespaces,sources:{},sourcePins:{},pins:{}};
 for(const [name,raw] of Object.entries(before.sources)){
  need(same(meta(raw),before.sourcePins[name]),'exact_before_source_pin');
  const base=name==='mac_owned_launchd_r3.py'?approvedParserAfter:raw;
  const next=rewrite(base);
  out.sources[name]=next;out.sourcePins[name]=meta(next);out.pins[name]=out.sourcePins[name].sha256;
 }
 out.homeSource=rewrite(before.homeSource);
 need(out.sources['mac_owned_launchd_r3.py'].includes(out.homeSource),'same_embedded_HomeControl');
 out.candidate=JSON.parse(before.candidateRaw);
 need(same(out.candidate.sourcePins,before.pins),'exact_before_candidate_pins');
 out.candidate.sourcePins=out.pins;
 out.candidate.homeControl.root=newHome;
 out.candidateRaw=JSON.stringify(out.candidate,null,2)+'\n';
 out.documents={...before.documents,'candidate-current-manager-wal-r1.public.json':out.candidateRaw};
 out.documentPins=Object.fromEntries(Object.entries(out.documents).map(([n,s])=>[n,meta(s)]));
 const payload=JSON.parse(before.payloadRaw);
 need(Object.keys(payload.files).length===22&&Object.keys(payload.documents).length===8,'original_carrier_counts');
 payload.files=Object.fromEntries(Object.entries(out.sources).map(([n,s])=>[n,encodeBase64Bytes(utf8Bytes(s))]));
 payload.documents=Object.fromEntries(Object.entries(out.documents).map(([n,s])=>[n,encodeBase64Bytes(utf8Bytes(s))]));
 out.payloadRaw=JSON.stringify(payload,null,2)+'\n';out.payloadPin=meta(out.payloadRaw);
 const table=pins=>JSON.stringify(Object.fromEntries(Object.entries(pins).map(([n,p])=>[n,[p.bytes,p.sha256]])),null,4);
 let publisher=rewrite(before.publisher);
 publisher=once(publisher,'\nPINS='+table(before.sourcePins)+'\nDOCUMENT_PINS=','\nPINS='+table(out.sourcePins)+'\nDOCUMENT_PINS=');
 publisher=once(publisher,'\nDOCUMENT_PINS='+table(before.documentPins)+'\nPAYLOAD_BYTES=','\nDOCUMENT_PINS='+table(out.documentPins)+'\nPAYLOAD_BYTES=');
 publisher=once(publisher,'\nPAYLOAD_BYTES='+before.payloadPin.bytes+'\n','\nPAYLOAD_BYTES='+out.payloadPin.bytes+'\n');
 publisher=once(publisher,'\nPAYLOAD_SHA="'+before.payloadPin.sha256+'"\n','\nPAYLOAD_SHA="'+out.payloadPin.sha256+'"\n');
 need(publisher.includes(out.homeSource),'same_HomeControl_publisher');
 out.publisher=publisher;out.publisherPin=meta(publisher);
 out.request=JSON.parse(before.requestRaw);
 need(out.request.args.length===5&&out.request.args[4]===before.publisher&&out.request.stdin===before.payloadRaw,'exact_original_carrier');
 out.request.args[4]=publisher;out.request.stdin=out.payloadRaw;
 out.request.idempotency_key='heptabao-mac-current-home-launch-inert-'+out.publisherPin.sha256.slice(0,8)+'-20261106-r3';
 out.requestRaw=JSON.stringify(out.request,null,2)+'\n';out.requestPin=meta(out.requestRaw);
 out.slot='owner_authbus_current_home_inert_gitfirst_r3';
 out.prefix='heptabao-mac-current-home-launch-inert-'+out.publisherPin.sha256.slice(0,8)+'-';
 const oldRequestLiteral='const GF_REQUEST = {blob:"'+before.requestPin.blob+'",\n bytes:'+before.requestPin.bytes+',sha256:"'+before.requestPin.sha256+'"};';
 const newRequestLiteral='const GF_REQUEST = {blob:"'+out.requestPin.blob+'",\n bytes:'+out.requestPin.bytes+',sha256:"'+out.requestPin.sha256+'"};';
 let journal=once(before.journal,'const GF_SLOT = "owner_authbus_current_home_inert_gitfirst_r2";','const GF_SLOT = "'+out.slot+'";');
 journal=once(journal,oldRequestLiteral,newRequestLiteral);
 journal=once(journal,'heptabao-mac-current-home-launch-inert-'+before.publisherPin.sha256.slice(0,8)+'-',out.prefix);
 out.journal=journal;out.journalPin=meta(journal);
 out.runtimeDeriver=once(before.runtimeDeriver,"+'-20261106-r2';","+'-20261106-r3';");
 out.runtimeDeriverPin=meta(out.runtimeDeriver);
 out.runtimeInput=JSON.parse(before.runtimeInputRaw);
 out.runtimeInput.newRoot=newT5;out.runtimeInput.homeRoot=newHome;
 out.runtimeInput.publisherPayload=out.payloadPin;out.runtimeInput.sourcePins=out.sourcePins;
 out.runtimeInput.documentPins=out.documentPins;out.runtimeInput.sourcePinsRaw=JSON.stringify(out.pins,null,2)+'\n';
 out.runtimeInput.candidate=out.documentPins['candidate-current-manager-wal-r1.public.json'];
 out.runtimeInput.outer=out.sourcePins['mac_current_outer_wal_r1.py'];
 out.runtimeInputRaw=JSON.stringify(out.runtimeInput,null,2)+'\n';
 out.actualHomeBinding=null;out.runtimeExactRequest=null;out.actualPort=null;
 out.readyForRuntime=false;out.NativeCalls=0;
 return out;
}
