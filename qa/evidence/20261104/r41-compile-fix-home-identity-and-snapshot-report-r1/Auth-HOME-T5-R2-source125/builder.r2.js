/* Pure mechanical R2 successor construction; no Native, filesystem, SDK or child execution. */
function buildHomeLaunchR2(previous, first5, oldJournal, oldRuntimeDeriver, oldRuntimeInput) {
 const need=(v,c)=>{if(!v)throw Error(c);};
 const pin=gitBlobMeta, encode=s=>encodeBase64Bytes(utf8Bytes(s));
 const OLD_T5=previous.sources.NEW_ROOT,OLD_HOME=previous.sources.HOME;
 const NEW_T5='/Volumes/T5/hepta-vnext-recovery-20261013/mac-authbus-4e808-current-home-launch-r2';
 const NEW_HOME='/Users/qianqi/heptabao-mac-authbus-4e808-home-launch-20261106-r2';
 const namespaces=[
  [OLD_T5,NEW_T5],
  [OLD_HOME,NEW_HOME],
  ['mac-authbus-4e808-current-home-launch-r1','mac-authbus-4e808-current-home-launch-r2'],
  ['org.heptabao.qa.mac-authbus-4e808-home-r1.server','org.heptabao.qa.mac-authbus-4e808-home-r2.server'],
  ['org.heptabao.qa.mac-authbus-4e808-home-r1.consumer','org.heptabao.qa.mac-authbus-4e808-home-r2.consumer']
 ];
 function rebind(s){for(const[a,b]of namespaces)s=s.split(a).join(b);return s;}
 function one(s,a,b,code){need(s.split(a).length===2,code);return s.replace(a,b);}
 need(first5.components.manager.before===previous.sources.sources['mac_owned_launchd_r3.py'],'exact_manager_baseline');
 need(first5.components.publisher.before===previous.dispatch.source,'exact_publisher_baseline');
 need(first5.before===previous.homeSource,'exact_HomeControl_baseline');
 const sources={};
 for(const[n,t]of Object.entries(previous.sources.sources))
  sources[n]=rebind(n==='mac_owned_launchd_r3.py'?first5.components.manager.after:t);
 const homeSource=rebind(first5.after);
 need(sources['mac_owned_launchd_r3.py'].split(homeSource).length===2,'one_exact_home_helper_in_manager');
 const pins=Object.fromEntries(Object.entries(sources).map(([n,t])=>[n,pin(t).sha256]));
 const candidate=JSON.parse(previous.dispatch.candidateRaw);
 candidate.sourcePins=pins;candidate.homeControl.root=NEW_HOME;
 const candidateRaw=JSON.stringify(candidate,null,2)+'\n';
 const documents={...previous.dispatch.documents,'candidate-current-manager-wal-r1.public.json':candidateRaw};
 const payload=JSON.parse(previous.dispatch.payloadRaw);
 for(const n of Object.keys(payload.files))payload.files[n]=encode(sources[n]);
 for(const n of Object.keys(payload.documents))payload.documents[n]=encode(documents[n]);
 const payloadRaw=JSON.stringify(payload,null,2)+'\n';
 const sourcePins=Object.fromEntries(Object.entries(sources).map(([n,t])=>[n,pin(t)]));
 const documentPins=Object.fromEntries(Object.entries(documents).map(([n,t])=>[n,pin(t)]));
 const compactSources=Object.fromEntries(Object.entries(sourcePins).map(([n,p])=>[n,[p.bytes,p.sha256]]));
 const compactDocuments=Object.fromEntries(Object.entries(documentPins).map(([n,p])=>[n,[p.bytes,p.sha256]]));
 let publisher=rebind(first5.components.publisher.after);
 let begin=publisher.indexOf('PINS='),end=publisher.indexOf('\nDOCUMENT_PINS=',begin);
 need(begin>=0&&end>begin,'exact_publisher_source_pin_boundaries');
 publisher=publisher.slice(0,begin)+'PINS='+JSON.stringify(compactSources,null,4)+publisher.slice(end);
 begin=publisher.indexOf('DOCUMENT_PINS=');end=publisher.indexOf('\nPAYLOAD_BYTES=',begin);
 need(begin>=0&&end>begin,'exact_publisher_document_pin_boundaries');
 publisher=publisher.slice(0,begin)+'DOCUMENT_PINS='+JSON.stringify(compactDocuments,null,4)+publisher.slice(end);
 publisher=one(publisher,'PAYLOAD_BYTES='+previous.dispatch.payloadPin.bytes,'PAYLOAD_BYTES='+pin(payloadRaw).bytes,'single_payload_byte_pin');
 publisher=one(publisher,'PAYLOAD_SHA='+JSON.stringify(previous.dispatch.payloadPin.sha256),
               'PAYLOAD_SHA='+JSON.stringify(pin(payloadRaw).sha256),'single_payload_hash_pin');
 need(publisher.split(homeSource).length===2,'one_exact_home_helper_in_publisher');
 const publisherPin=pin(publisher),request=JSON.parse(previous.dispatch.requestRaw);
 request.args[request.args.length-1]=publisher;request.stdin=payloadRaw;
 request.idempotency_key='heptabao-mac-current-home-launch-inert-'+publisherPin.sha256.slice(0,8)+'-20261106-r2';
 const requestRaw=JSON.stringify(request,null,2)+'\n',requestPin=pin(requestRaw);
 const oldRequest=previous.dispatch.requestPin;
 let journal=one(oldJournal,'owner_authbus_current_home_inert_gitfirst_r1',
                 'owner_authbus_current_home_inert_gitfirst_r2','single_fresh_journal_slot');
 const oldPinLiteral='const GF_REQUEST = {blob:"'+oldRequest.blob+'",\n bytes:'+oldRequest.bytes+',sha256:"'+oldRequest.sha256+'"};';
 const newPinLiteral='const GF_REQUEST = {blob:"'+requestPin.blob+'",\n bytes:'+requestPin.bytes+',sha256:"'+requestPin.sha256+'"};';
 journal=one(journal,oldPinLiteral,newPinLiteral,'exact_journal_request_binding');
 journal=one(journal,'/^heptabao-mac-current-home-launch-inert-'+previous.dispatch.sourcePin.sha256.slice(0,8)+'-/',
                     '/^heptabao-mac-current-home-launch-inert-'+publisherPin.sha256.slice(0,8)+'-/','fixed_observer_prefix');
 const runtimeDeriver=one(oldRuntimeDeriver,"+'-20261106-r1';","+'-20261106-r2';",'future_only_runtime_key_generation');
 const runtimeInput=JSON.parse(oldRuntimeInput);
 runtimeInput.newRoot=NEW_T5;runtimeInput.homeRoot=NEW_HOME;
 runtimeInput.publisherPayload=pin(payloadRaw);runtimeInput.sourcePins=sourcePins;
 runtimeInput.documentPins=documentPins;runtimeInput.sourcePinsRaw=JSON.stringify(pins,null,2)+'\n';
 runtimeInput.candidate=pin(candidateRaw);runtimeInput.outer=sourcePins['mac_current_outer_wal_r1.py'];
 return {OLD_T5,OLD_HOME,NEW_T5,NEW_HOME,namespaces,sources,sourcePins,pins,homeSource,candidate,candidateRaw,
  documents,documentPins,payloadRaw,payloadPin:pin(payloadRaw),publisher,publisherPin,request,requestRaw,requestPin,
  journal,journalPin:pin(journal),runtimeDeriver,runtimeDeriverPin:pin(runtimeDeriver),
  runtimeInput,runtimeInputRaw:JSON.stringify(runtimeInput,null,2)+'\n',
  actualHomeBinding:null,runtimeExactRequest:null,readyForRuntime:false,NativeCalls:0};
}