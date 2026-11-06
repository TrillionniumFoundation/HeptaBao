function bind025bStageBody(input){
 const {oldBodyJournal,oldRequestRaw,infoBindings,info,infoRaw,closedObserver,job}=input;
 if(job!=="1a1b07b7e0b-fc05-70ca"||!info||!closedObserver?.completedInactive||closedObserver.tool!=="file_info"||closedObserver.id!==info.originalOperation)throw Error("actual_closed_info_required");
 if(info.path!=="/home/qian-qi/heptabao-native-jwt-pki-source-025b05a3-20261106-r1/control/stage-result.public.json"||!Number.isSafeInteger(info.size)||info.size<=0||info.size>65536||info.size>150000)throw Error("bounded_actual_report");
 if(!/^[0-9a-f]{64}$/.test(info.sha256)||typeof info.version!=="string"||info.version.split(":").length!==5||info.version.split(":")[2]!==String(info.size))throw Error("actual_content_identity");
 if(JSON.stringify(gitBlobMeta(infoRaw))!==JSON.stringify(info.nativeText)||closedObserver.nativeText.blob!==info.nativeText.blob)throw Error("actual_info_original_pin");
 const q=JSON.parse(oldRequestRaw);
 q.idempotency_key="heptabao-native-jwt-pki-025b05a3-rog-source-observe-r1-stage-result-body0";
 q.operation.arguments.path=info.path;q.operation.arguments.limit=info.size;q.operation.arguments.expected_version=info.version;
 const requestRaw=JSON.stringify(q,null,2)+"\n",requestPin=gitBlobMeta(requestRaw);
 let source=oldBodyJournal;const changes=[];
 for(const r of infoBindings){const expected=r.why==="actual new original process identity"?2:1,actual=source.split(r.old).length-1;if(actual!==expected)throw Error("info_literal_count:"+r.why);source=source.split(r.old).join(r.next);changes.push({...r,count:actual});}
 const expected={path:info.path,bytes:info.size,sha256:info.sha256,version:info.version,infoOperation:info.originalOperation,infoNative:info.nativeText};
 for(const [tag,next]of [["GF_STAGE_BODY_REQUEST",requestPin],["GF_STAGE_BODY_EXPECTED",expected]]){const re=new RegExp("const "+tag+" = .*;\\n"),m=source.match(re);if(!m)throw Error("missing_body_constant:"+tag);const replacement="const "+tag+" = "+JSON.stringify(next)+";\n";source=source.replace(m[0],replacement);changes.push({why:tag,old:m[0],next:replacement,count:1});}
 const comment="Only this 27931-byte range is admitted;";if(source.split(comment).length!==2)throw Error("body_comment_count");source=source.replace(comment,"Only this "+info.size+"-byte range is admitted;");
 changes.push({why:"actual range comment",old:comment,next:"Only this "+info.size+"-byte range is admitted;",count:1});
 return {source,sourcePin:gitBlobMeta(source),requestRaw,requestPin,expected,changes,Runtime:false,authorization:"SOURCE_ONLY_REQUIRES_SEPARATE_ROOT_BODY_GO"};
}
