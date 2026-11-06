function bindFinalStageBodyAfterActualInfo({oldBodyJournal,oldBodyRequestRaw,infoReplacements,expectedResultPath,infoNativeRaw,infoOperation,infoNativePin,bodyKey},h) {
 function need(x,c){if(!x)throw Error(c);}
 need(h.gitBlobMeta(oldBodyJournal).blob==="703a403a43fbd8ce8db9d0e30c21b77d13982900","exact_successful_body_baseline");
 need(h.gitBlobMeta(oldBodyRequestRaw).blob==="53891d75942f028f9511f61724474fc58d3343e6","exact_original_single_body_request");
 need(h.gitBlobMeta(infoNativeRaw).blob===infoNativePin.blob&&h.gitBlobMeta(infoNativeRaw).sha256===infoNativePin.sha256,"whole_actual_info_native");
 const v=h.parseLosslessIntegers(infoNativeRaw),parts=v.version?.split(":");
 need(v.path===expectedResultPath&&Number.isSafeInteger(v.size)&&v.size>0&&v.size<=65536&&v.size<=150000,"actual_fixed_report_single_chunk");
 need(/^[0-9a-f]{64}$/.test(v.sha256)&&v.mode===384&&v.metadata?.metadata_platform==="linux"&&v.metadata.mode===384&&v.metadata.uid===1000&&v.metadata.gid===1000&&v.metadata.link_count===1,"actual_linux_content_identity");
 need(parts?.length===5&&parts.every(x=>/^[0-9]+$/.test(x))&&parts[2]===String(v.size)&&/^[0-9a-f]{64}$/.test(infoOperation),"actual_lossless_version_and_original_info_ID");
 const q=JSON.parse(oldBodyRequestRaw);q.idempotency_key=bodyKey;q.operation.arguments.path=v.path;q.operation.arguments.limit=v.size;q.operation.arguments.expected_version=v.version;
 need(q.operation.tool==="binary_read"&&q.operation.arguments.host==="rog"&&q.operation.arguments.offset===0&&bodyKey.length<=128,"one_original_shape");
 const requestRaw=JSON.stringify(q,null,2)+"\n",requestPin=h.gitBlobMeta(requestRaw);
 const expected={path:v.path,bytes:v.size,sha256:v.sha256,version:v.version,infoOperation,infoNative:infoNativePin};
 const oldRequest=/^const GF_STAGE_BODY_REQUEST = (.*);$/m.exec(oldBodyJournal)[0],oldExpected=/^const GF_STAGE_BODY_EXPECTED = (.*);$/m.exec(oldBodyJournal)[0];
 const replacements=[[oldRequest,"const GF_STAGE_BODY_REQUEST = "+JSON.stringify(requestPin)+";",1],[oldExpected,"const GF_STAGE_BODY_EXPECTED = "+JSON.stringify(expected)+";",1],["Only this 27581-byte range is admitted","Only this "+v.size+"-byte range is admitted",1]];
 for(const[a,b]of infoReplacements)replacements.push(a.startsWith("/home/")?['const GF_STAGE_RESULT_PATH = "'+a+'";','const GF_STAGE_RESULT_PATH = "'+b+'";',1]:[a,b,a.startsWith("s.job===")?2:1]);
 let source=oldBodyJournal;for(const[a,b,n]of replacements){need(source.split(a).length===n+1,"exact_literal_count:"+a.slice(0,60));source=source.split(a).join(b);}
 let inverse=source;for(const[a,b,n]of replacements.slice().reverse()){need(inverse.split(b).length===n+1,"exact_inverse_count:"+b.slice(0,60));inverse=inverse.split(b).join(a);}need(inverse===oldBodyJournal,"whole_inverse_baseline");
 return {source,pin:h.gitBlobMeta(source),requestRaw,requestPin,expected,replacements,Runtime:false,requiresSeparateExactBodyGO:true};
}
