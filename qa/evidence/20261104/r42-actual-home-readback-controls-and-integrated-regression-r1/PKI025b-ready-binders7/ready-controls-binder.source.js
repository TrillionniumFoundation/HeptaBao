function bind025bReadyControls(input){
 const {prebound,stageBodyRaw,stageBodyPin,stageInfo,stageQualification,oldPublisherRequestRaw}=input;
 if(!stageQualification||!stageQualification.whole||!/^[0-9a-f]{40}$/.test(stageQualification.pin?.blob||""))throw Error("root_stage_qualification_required");
 const actual=gitBlobMeta(stageBodyRaw);
 if(JSON.stringify(actual)!==JSON.stringify(stageBodyPin)||actual.bytes!==stageInfo.size||actual.sha256!==stageInfo.sha256||!stageInfo.version)throw Error("actual_whole_stage_identity");
 if(prebound.proposal.commit!=="025b05a340de841b8161c1120344e86eae30eb97"||prebound.proposal.tree!=="1d8160c9385f8053b9a683cc1834da0f912e2d37"||prebound.proposal.selectedUnique149!==149||prebound.proposal.selectedProfiles166!==166)throw Error("frozen_candidate_and_denominators");
 function ready(src){if(src.split("BINDING_READY = False").length!==2)throw Error("one_ready_literal");return src.replace("BINDING_READY = False","BINDING_READY = True");}
 const runner=ready(prebound.runner),launcher=ready(prebound.launcher),groups=prebound.groups;
 const newPins={"native_jwt_build.py":gitBlobMeta(runner),"launch_native_jwt_build.py":gitBlobMeta(launcher),"jwt-test-groups.public.json":gitBlobMeta(groups)};
 let publisher=ready(prebound.publisher);
 const m=publisher.match(/PINS = \{[\s\S]*?\n\}/);if(!m)throw Error("one_PINS_block");
 const table=Object.fromEntries(Object.entries(newPins).map(([name,pin])=>[name,[pin.bytes,pin.sha256]]));
 publisher=publisher.replace(m[0],"PINS = "+JSON.stringify(table,null,4));
 const carrierObject=JSON.parse(prebound.carrier),names=Object.keys(carrierObject.files);
 if(names.join(",")!=="native_jwt_build.py,launch_native_jwt_build.py,jwt-test-groups.public.json")throw Error("original_three_payload_names");
 for(const [name,raw]of Object.entries({"native_jwt_build.py":runner,"launch_native_jwt_build.py":launcher,"jwt-test-groups.public.json":groups}))carrierObject.files[name]=encodeBase64Bytes(utf8Bytes(raw));
 const carrier=JSON.stringify(carrierObject,null,2)+"\n";
 if(gitBlobMeta(carrier).bytes>262144)throw Error("original_publisher_stdin_cap");
 const q=JSON.parse(oldPublisherRequestRaw);q.args[4]=publisher;q.stdin=carrier;
 q.idempotency_key="heptabao-native-jwt-pki-025b05a3-controls-inert-r2-"+gitBlobMeta(publisher).sha256.slice(0,8);
 if(q.host!=="rog"||q.timeout_seconds!==60||q.args.length!==5||q.args.slice(0,4).join(",")!=="-I,-S,-B,-c")throw Error("unchanged_publisher_interface");
 const requestRaw=JSON.stringify(q,null,2)+"\n";
 return {runner,launcher,groups,publisher,carrier,requestRaw,pins:{...newPins,publisher:gitBlobMeta(publisher),carrier:gitBlobMeta(carrier),request:gitBlobMeta(requestRaw)},actualStage:{body:actual,info:stageInfo,rootQualification:stageQualification.pin},actualPublication:null,actualBuild:null,Runtime:false,authorization:"SOURCE_ONLY_PENDING_EXACT_ROOT_INERT_GO"};
}
