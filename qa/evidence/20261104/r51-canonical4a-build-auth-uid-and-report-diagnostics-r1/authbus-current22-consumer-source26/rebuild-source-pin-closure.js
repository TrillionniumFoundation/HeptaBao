function rebuildAuthBusR3SourcePinClosure(before,newSources,expectedSourcePins){
 const need=(v,c)=>{if(!v)throw Error(c);};
 const same=(a,b)=>JSON.stringify(a)===JSON.stringify(b);
 const meta=gitBlobMeta;
 const once=(raw,a,b)=>{need(raw.split(a).length===2,"one_mechanical_binding_literal");return raw.replace(a,b);};
 const oldPayload=JSON.parse(before.payloadRaw),oldPins=JSON.parse(before.sourcePinsRaw);
 need(meta(before.payloadRaw).blob==="aff137a45af0d8f529f94cf2d93ba2a754eac527","fixed_public_carrier");
 need(meta(before.publisher).blob==="77f84c87e203714bc8e809df51aa0900653b6260","fixed_publisher");
 need(Object.keys(newSources).length===22&&same(Object.keys(newSources).sort(),Object.keys(oldPins).sort()),"exact_22_source_names");
 const nextPins={},shaPins={},originalSources={};
 for(const name of Object.keys(oldPins)){
  const old=utf8Text(unb64(oldPayload.files[name]));
  need(same(meta(old),oldPins[name]),"before_carrier_source_pin");
  originalSources[name]=old;
  const current=meta(newSources[name]);
  need(same(current,expectedSourcePins[name]),"current_22_source_pin");
  nextPins[name]=current;shaPins[name]=current.sha256;
 }
 need(nextPins["mac_owned_launchd_r3.py"].blob==="92a1293db9792644b378da07eb9650951979358a","exact_signed_uid_manager");
 const documents=Object.fromEntries(Object.entries(oldPayload.documents).map(([name,b64])=>[name,utf8Text(unb64(b64))]));
 need(Object.keys(documents).length===8,"eight_public_documents");
 const candidateName="candidate-current-manager-wal-r1.public.json",candidateBefore=documents[candidateName];
 const candidate=JSON.parse(candidateBefore);
 need(same(candidate.sourcePins,Object.fromEntries(Object.entries(oldPins).map(([n,p])=>[n,p.sha256]))),"original_candidate_pin_map");
 candidate.sourcePins=shaPins;
 documents[candidateName]=JSON.stringify(candidate,null,2)+"\n";
 const oldDocumentPins=Object.fromEntries(Object.entries(oldPayload.documents).map(([n,b])=>[n,meta(utf8Text(unb64(b)))]));
 const documentPins=Object.fromEntries(Object.entries(documents).map(([n,s])=>[n,meta(s)]));
 const payload=JSON.parse(before.payloadRaw);
 payload.files=Object.fromEntries(Object.keys(oldPins).map(n=>[n,encodeBase64Bytes(utf8Bytes(newSources[n]))]));
 payload.documents=Object.fromEntries(Object.entries(documents).map(([n,s])=>[n,encodeBase64Bytes(utf8Bytes(s))]));
 const payloadRaw=JSON.stringify(payload,null,2)+"\n",payloadPin=meta(payloadRaw);
 const table=pins=>JSON.stringify(Object.fromEntries(Object.entries(pins).map(([n,p])=>[n,[p.bytes,p.sha256]])),null,4);
 let publisher=before.publisher;
 publisher=once(publisher,"\nPINS="+table(oldPins)+"\nDOCUMENT_PINS=","\nPINS="+table(nextPins)+"\nDOCUMENT_PINS=");
 publisher=once(publisher,"\nDOCUMENT_PINS="+table(oldDocumentPins)+"\nPAYLOAD_BYTES=","\nDOCUMENT_PINS="+table(documentPins)+"\nPAYLOAD_BYTES=");
 publisher=once(publisher,"\nPAYLOAD_BYTES="+meta(before.payloadRaw).bytes+"\n","\nPAYLOAD_BYTES="+payloadPin.bytes+"\n");
 publisher=once(publisher,'\nPAYLOAD_SHA="'+meta(before.payloadRaw).sha256+'"\n','\nPAYLOAD_SHA="'+payloadPin.sha256+'"\n');
 const compiledSourceNames=Object.keys(nextPins).filter(n=>n.endsWith(".py")).sort();
 need(compiledSourceNames.length===18,"same_eighteen_compile_only_sources");
 const definitionNames=["mac_owned_unreaped_r1.py","mac_owned_commands_r1.py","mac_t5_volume_guard_r1.py"];
 const loadedDefinitions=Object.fromEntries(definitionNames.map(n=>[n,nextPins[n]]));
 const shaPinsRaw=JSON.stringify(shaPins,null,2)+"\n";
 return {
  schema:"heptabao.authbus-r3-source-pin-closure.SOURCE",
  sourcePins:nextPins,shaPins,shaPinsRaw,candidateBeforeRaw:candidateBefore,candidateTemplateRaw:documents[candidateName],
  documentPins,payloadTemplateRaw:payloadRaw,payloadPin,publisherTemplate:publisher,publisherPin:meta(publisher),
  changedSourceNames:Object.keys(nextPins).filter(n=>!same(nextPins[n],oldPins[n])),
  unchangedProofNames:Object.keys(documents).filter(n=>n!==candidateName&&documents[n]===utf8Text(unb64(oldPayload.documents[n]))),
  compiledSourceNames,loadedDefinitions,
  runtimeBindingTemplate:{
   schema:"heptabao.authbus-runtime-binding-UNBOUND.SOURCE",
   sourcePins:nextPins,sourcePinsRaw:shaPinsRaw,documentPins,
   candidate:documentPins[candidateName],outer:nextPins["mac_current_outer_wal_r1.py"],publisherPayload:payloadPin,
   newRoot:null,homeRoot:null,actualHomeBinding:null,actualPort:null,
   originalRuntimeRequestRaw:null,inertExactRequest:null,runtimeExactRequest:null,readyForRuntime:false,
   currentMacBinary:null,currentMacBinaryFull9:null,currentMacBinaryVersion:null,currentMacBuildQualification:null,
   trustedIssuer:null,privateCredentialGeneration:null,actualSelectedOwner:null
  },
  oldNamespaceDispatchAuthorized:false,publisherTemplateDispatchable:false,
  historicalCandidateProductFieldsAreReferenceOnly:true,
  existingNamespaceAndBinaryLiteralsStillRequireFreshActualBinding:true,
  NativeCalls:0,PythonModulesExecuted:false,compiledPythonExecuted:false
 };
}
