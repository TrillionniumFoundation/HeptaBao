function bindPublishedControlsBodies({before,infos,closedObservers,nativeTexts},h,d) {
 function need(v,k){if(!v)throw Error(k);}
 need(h.gitBlobMeta(before).blob==="80e33a52cc2b2d5a4c781de1521432c0eb56d6de","exact_info4_journal");
 need(Array.isArray(infos)&&infos.length===4&&Array.isArray(closedObservers),"four_actual_closed_infos");
 const expectedPaths=[
 "/home/qian-qi/heptabao-native-jwt-pki-controls-20261106-r1/native_jwt_build.py",
 "/home/qian-qi/heptabao-native-jwt-pki-controls-20261106-r1/launch_native_jwt_build.py",
 "/home/qian-qi/heptabao-native-jwt-pki-controls-20261106-r1/jwt-test-groups.public.json",
 "/home/qian-qi/heptabao-native-jwt-pki-controls-20261106-r1/inert-stage.result.public.json"];
 const sizes=[30397,38565,19789,1854],hashes=[
 "023f6f3ad71b8909a46da632767044de44ec2ea6fcb11692a2160e2cec518add",
 "5d639fbde4aa09663be694d9322bc4f598f4cd9594f9a3c09c61c21013b98056",
 "35153ff5e90b582f83e4fbbb66ff5c9fb295e95153f08df152cefedecdb50869",
 "f1e1f3a2576fcb2ecd05cdb9b8f4fbebd6bb849eddb48536eb5c66ed5be109e2"];
 const expected=infos.map((v,i)=>{
  const prior=closedObservers.find(o=>o.id===v.originalOperation);
  need(v.index===i&&v.path===expectedPaths[i]&&v.size===sizes[i]&&v.sha256===hashes[i]
   &&typeof v.version==="string"&&v.version.split(":").length===5
   &&v.full9Strings?.length===9&&v.full9Strings[4]==="33152"&&v.full9Strings[5]==="1"
   &&v.size<=65536&&prior?.tool==="file_info"&&prior.completedInactive===true
   &&prior.nativeText.blob===v.nativeText.blob
   &&h.gitBlobMeta(nativeTexts[v.originalOperation]).blob===v.nativeText.blob,
   "actual_independent_info:"+i);
  return {index:i,path:v.path,bytes:v.size,sha256:v.sha256,version:v.version,
   full9Strings:v.full9Strings,infoOperation:v.originalOperation,infoNative:v.nativeText};
 });
 const requests=expected.map(v=>JSON.stringify({idempotency_key:"heptabao-native-jwt-pki-33b814c7-controls-observe-r1-published-body"+v.index,
  operation:{tool:"binary_read",arguments:{host:"rog",path:v.path,expected_version:v.version,offset:0,limit:v.bytes}}},null,2)+"\n");
 const requestPins=requests.map(raw=>h.gitBlobMeta(raw));
 const block=`
/* Four actual-version-bound whole public bodies. New body pages are16KiB;
 * all original status/stream/file-info observers retain their8KiB pages.
 */
const GF_CONTROLS_BODY_REQUESTS = ${JSON.stringify(requestPins)};
const GF_CONTROLS_BODY_EXPECTED = ${JSON.stringify(expected)};

function gfAuthorizePublishedControlsBodiesOnly({goRaw,goPin,goWholeReadback}) {
 const s=gfState();
 gfNeed(!s.paused && !s.nativeCallInFlight && s.pending===null && s.activeObserver===null
   && s.job==="1a1b001e788-fc05-6d66" && s.controlsInfoGO?.whole===true
   && s.publishedInfos?.length===4 && s.publishedInfoStarted?.every(x=>x===true)
   && s.controlsBodyGO===undefined && s.publishedBodyStarted===undefined
   && s.publishedBodies===undefined,"closed_all4_infos_before_body_GO");
 gfNeed(goWholeReadback===true && gfMetaEquals(goRaw,goPin)
   && goPin.blob!==s.goPin.blob && goPin.blob!==s.controlsInfoGO.pin.blob,
   "separate_whole_fixed4_body_GO");
 const g=JSON.parse(goRaw);
 gfNeed(g.authorization==="GO" && g.scope==="build_controls_fixed_four_binary_reads_only"
   && g.original_job===s.job && g.maximum_binary_read_starts===4
   && g.immutable_page_bytes===16384 && g.maximum_total_body_bytes===90605
   && Array.isArray(g.exact_requests) && g.exact_requests.length===4
   && g.exact_requests.every((p,i)=>p.blob===GF_CONTROLS_BODY_REQUESTS[i].blob
     && p.bytes===GF_CONTROLS_BODY_REQUESTS[i].bytes
     && p.sha256===GF_CONTROLS_BODY_REQUESTS[i].sha256),"exact_new_root_fixed4_body_scope");
 for(const need of GF_CONTROLS_BODY_EXPECTED) {
  const info=s.publishedInfos[need.index],prior=s.completedObservers.find(o=>o.id===need.infoOperation);
  gfNeed(prior?.completedInactive===true && prior.tool==="file_info"
    && prior.nativeText.blob===need.infoNative.blob
    && gfMetaEquals(load(GF_SLOT+":closed_native:"+need.infoOperation),need.infoNative)
    && info.path===need.path && info.size===need.bytes && info.sha256===need.sha256
    && info.version===need.version && info.originalOperation===need.infoOperation
    && JSON.stringify(info.full9Strings)===JSON.stringify(need.full9Strings),
    "exact_actual_closed_info_before_body");
 }
 s.controlsBodyGO={pin:goPin,raw:goRaw,whole:true};
 s.publishedBodyStarted=[false,false,false,false];s.publishedBodies=[];
 gfSave(s);
 return {originalJob:s.job,exactRequests:GF_CONTROLS_BODY_REQUESTS,
   maximumBinaryStarts:4,maximumWholeBodyBytes:90605,immutableBodyPageBytes:16384};
}

`;
 const reps=[
 ["function gfNeed(value, code) {",block+"function gfNeed(value, code) {"],
 ['  if(op.tool==="file_info") {',`  if(op.tool==="binary_read") {
   const i=s.publishedBodies?.length;
   gfNeed(s.controlsBodyGO?.whole===true && Number.isSafeInteger(i) && i>=0 && i<4
     && s.publishedBodyStarted[i]===false && gfMetaEquals(raw,GF_CONTROLS_BODY_REQUESTS[i])
     && Object.keys(a).sort().join(",")==="expected_version,host,limit,offset,path"
     && a.path===GF_CONTROLS_BODY_EXPECTED[i].path && a.offset===0
     && a.limit===GF_CONTROLS_BODY_EXPECTED[i].bytes && a.limit<=65536
     && a.expected_version===GF_CONTROLS_BODY_EXPECTED[i].version,
     "one_fixed_ordered_actual_version_body");
  } else if(op.tool==="file_info") {`],
 ['   && q.operation_id===s.activeObserver.id && q.limit===8192',
  '   && q.operation_id===s.activeObserver.id && q.limit===(s.activeObserver.tool==="binary_read"?16384:8192)'],
 [`  rootGo:((kind==="operation_start" && q.operation.tool==="file_info")
    || s.activeObserver?.tool==="file_info") ? s.controlsInfoGO.pin : s.goPin,`,
  `  rootGo:((kind==="operation_start" && q.operation.tool==="binary_read")
    || s.activeObserver?.tool==="binary_read") ? s.controlsBodyGO.pin
    : ((kind==="operation_start" && q.operation.tool==="file_info")
      || s.activeObserver?.tool==="file_info") ? s.controlsInfoGO.pin : s.goPin,`],
 [` if(c.kind==="operation_start" && q.operation.tool==="file_info")
  s.publishedInfoStarted[s.publishedInfos.length]=true;`,
  ` if(c.kind==="operation_start" && q.operation.tool==="file_info")
  s.publishedInfoStarted[s.publishedInfos.length]=true;
 if(c.kind==="operation_start" && q.operation.tool==="binary_read")
  s.publishedBodyStarted[s.publishedBodies.length]=true;`],
 ['   gfNeed(b.length<=8192 && v.next_offset===q.offset+b.length',
  '   gfNeed(b.length<=(a.tool==="binary_read"?16384:8192) && v.next_offset===q.offset+b.length'],
 ['  if(a.tool==="file_info") {',`  if(a.tool==="binary_read") {
   const i=s.publishedBodies.length,need=GF_CONTROLS_BODY_EXPECTED[i];
   gfNeed(i<4 && s.publishedBodyStarted[i]===true
     && a.request.operation.arguments.path===need.path
     && v.path===need.path && v.version===need.version && v.size===need.bytes
     && v.offset===0 && v.next_offset===need.bytes && v.eof===true
     && typeof v.data_base64==="string" && v.chunk_sha256===need.sha256,
     "exact_published_body_original_extent");
   const bodyBytes=unb64(v.data_base64),bodyRaw=utf8Text(bodyBytes),bodyPin=gitBlobMeta(bodyRaw);
   gfNeed(bodyBytes.length===need.bytes && bodyPin.bytes===need.bytes
     && bodyPin.sha256===need.sha256,"exact_published_body_actual_whole_SHA");
   store(GF_SLOT+":published_body_original:"+i,bodyRaw);
   s.publishedBodies.push({index:i,path:need.path,version:need.version,body:bodyPin,
     originalOperation:a.id,metadataOperation:need.infoOperation,originalPayload:pin,
     semanticQualification:false});
  } else if(a.tool==="file_info") {`],
 ['  else if(action==="authorize_published_controls_info")value=gfAuthorizePublishedControlsInfoOnly(args);',
  '  else if(action==="authorize_published_controls_info")value=gfAuthorizePublishedControlsInfoOnly(args);\n  else if(action==="authorize_published_controls_bodies")value=gfAuthorizePublishedControlsBodiesOnly(args);']
 ];
 let source=before;
 for(const[a,b]of reps){need(source.split(a).length===2,"single_body_insertion");source=source.replace(a,b);}
 let reverse=source;for(const[a,b]of reps.slice().reverse()){need(reverse.split(b).length===2,"single_reverse");reverse=reverse.replace(b,a);}
 need(reverse===before,"whole_reverse");
 const diff=d.makeStrictUnified(before,source,"journal.info4.before.js","journal.body4.after.js"),forward=d.applyStrictUnified(before,diff);
 need(forward.text===source&&d.applyStrictUnified(source,diff,true).text===before,"strict_body_diff");
 return {source,pin:h.gitBlobMeta(source),before,diff,diffPin:h.gitBlobMeta(diff),replacements:reps,hunks:forward.hunks,requests,requestPins,expected,totalBodyBytes:90605,Runtime:0,requiresSeparateExactBodyGO:true};
}
