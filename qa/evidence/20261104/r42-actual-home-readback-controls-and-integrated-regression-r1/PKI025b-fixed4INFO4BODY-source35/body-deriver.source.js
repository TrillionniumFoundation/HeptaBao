/* Pure SOURCE deriver. No tools/store/dispatch; unknown identities stay null until four closed original infos. */
const D_CFG = {"slot":"jwt_pki_025b05a3_build_controls_inert_gitfirst_r2","job":"1a1b0ade81d-fc05-7220","infoSource":{"blob":"576f37e9856f99e5de88e49dbad848abd8ccf5d4","bytes":26589,"sha256":"51a5df5ec49318e8f7e0b8c5496332142bef4d4ed5e656c62510099c82a011b3"},"infoRequests":[{"blob":"78c9767df0ed826a7bab3d868787f33281960da6","bytes":284,"sha256":"b3c0790bc7e3a4df7715e3e6fc2f1c8519e4c76b89d2dcf88ca2960b8a7f61a3"},{"blob":"0f0487c4d2e64d6474f0c321a4f56fc4c800d00d","bytes":291,"sha256":"33f596d548fcab8f1c1eae1c855f04cbe38e45eb6f6ff8febbb0bee57a3b3779"},{"blob":"3cedb52ffcacd7820b98d9c80a022bfcb0e2aff5","bytes":292,"sha256":"81da20525aa4e777753bc5c4b0ad5a72f1efde628787d4cc55b3905e705c3905"},{"blob":"55b50cccf3fa7c3948a04ae310bd9107639c56b6","bytes":295,"sha256":"d494099f252df35e1daf90e03505095d9e1a2cdf7aed1fcd957b584b5faf6751"}],"expected":[{"index":0,"name":"native_jwt_build.py","path":"/home/qian-qi/heptabao-native-jwt-pki-controls-20261106-r2/native_jwt_build.py","bytes":30397,"sha256":"d76b3d392c20bf4a7bbb7e8d8ea69abdfe3bb11f71a35075ba26ab948e778a50","publisherFull9":["66306","33212340","1000","1000","33152","1","30397","1793965550402189411","1793965550403278461"]},{"index":1,"name":"launch_native_jwt_build.py","path":"/home/qian-qi/heptabao-native-jwt-pki-controls-20261106-r2/launch_native_jwt_build.py","bytes":38565,"sha256":"efec176c08804a91adfd0160cdc092fad879d64ff594debe2fffe8008488d00c","publisherFull9":["66306","33212341","1000","1000","33152","1","38565","1793965550403677310","1793965550405279309"]},{"index":2,"name":"jwt-test-groups.public.json","path":"/home/qian-qi/heptabao-native-jwt-pki-controls-20261106-r2/jwt-test-groups.public.json","bytes":19789,"sha256":"35153ff5e90b582f83e4fbbb66ff5c9fb295e95153f08df152cefedecdb50869","publisherFull9":["66306","33212342","1000","1000","33152","1","19789","1793965550406347359","1793965550407346912"]},{"index":3,"name":"inert-stage.result.public.json","path":"/home/qian-qi/heptabao-native-jwt-pki-controls-20261106-r2/inert-stage.result.public.json","bytes":1854,"sha256":"30cd7315341a685f3bf0b95b3938dd12e717d880ded7161d462f14e75c0eac61","publisherFull9":null}],"bodyTemplates":[{"blob":"80a2bb969a1e900632b0c353f1f25d51ac185da6","bytes":359,"sha256":"d5e2d625af69662c7bd4821c87271fd3e8ae559c7118aee90da3d6142ab48d4a"},{"blob":"be6adb2545856ef4d79815398997f851ec6753f2","bytes":366,"sha256":"6da8004c00f48beb173f5820b19642c3d551ed5ca8bb4066e51464efc43c16b1"},{"blob":"64128cff9cbf613bf3c974119e583c22531327c9","bytes":367,"sha256":"bf39e9259fdc787d1f6f4215255a6e7317d072a97ec5a42e3c69d47291494ee0"},{"blob":"108256126445a7a0a384c611f4b1871fd8a11fc0","bytes":369,"sha256":"d3204a7a76ad55e140b906233036cb4515883748627ac859ac2847071477194b"}],"totalBodyBytes":90605,"metadataMustBeIndependentlyObserved":true,"unobserved":[{"index":0,"version":null,"full9":null,"infoOperation":null,"infoNative":null,"bodyOperation":null,"bodyNative":null},{"index":1,"version":null,"full9":null,"infoOperation":null,"infoNative":null,"bodyOperation":null,"bodyNative":null},{"index":2,"version":null,"full9":null,"infoOperation":null,"infoNative":null,"bodyOperation":null,"bodyNative":null},{"index":3,"version":null,"full9":null,"infoOperation":null,"infoNative":null,"bodyOperation":null,"bodyNative":null}]};

function derive025bPublishedBodies(input,h) {
 const {templateSource,deriverSource,goRaw,goPin,goWholeReadback,closedState,nativeTexts,requestTemplates}=input;
 const need=(v,k)=>{if(!v)throw Error(k);},meta=(raw,p)=>{const a=h.gitBlobMeta(raw);return a.blob===p?.blob&&a.bytes===p?.bytes&&a.sha256===p?.sha256;};
 need(goWholeReadback===true&&meta(goRaw,goPin),"whole_conditional_root_GO");
 const s=closedState,g=JSON.parse(goRaw),c=g.conditional_body_authorization;
 need(s && s.job===D_CFG.job && s.startCalled===true && !s.paused
   && !s.nativeCallInFlight && s.pending===null && s.activeObserver===null
   && s.controlsInfoGO?.whole===true && meta(goRaw,s.controlsInfoGO.pin)
   && s.controlsInfoGO.raw===goRaw && s.publishedInfos?.length===4
   && s.publishedInfoStarted?.length===4 && s.publishedInfoStarted.every(x=>x===true)
   && s.controlsBodyGO===undefined && s.publishedBodyStarted===undefined
   && s.publishedBodies===undefined,"all_four_original_infos_closed_before_derivation");
 need(g.authorization==="GO" && g.scope==="build_controls_fixed_four_file_info_only"
   && g.original_job===D_CFG.job && g.maximum_file_info_starts===4
   && g.binary_read_authorized===false && JSON.stringify(g.exact_requests)===JSON.stringify(D_CFG.infoRequests),
   "same_exact_four_info_root_GO");
 need(c?.authorization==="GO" && c.scope==="build_controls_fixed_four_binary_reads_only"
   && c.maximum_binary_read_starts===4 && c.immutable_page_bytes===16384
   && c.maximum_total_body_bytes===90605
   && meta(templateSource,c.journal_template) && meta(deriverSource,c.deriver)
   && JSON.stringify(c.exact_templates)===JSON.stringify(D_CFG.bodyTemplates)
   && Array.isArray(requestTemplates) && requestTemplates.length===4
   && requestTemplates.every((raw,i)=>meta(raw,D_CFG.bodyTemplates[i])),
   "exact_root_pinned_conditional_body_template_and_deriver");
 const ids=new Set();
 const expected=s.publishedInfos.map((info,i)=>{
  const known=D_CFG.expected[i],o=s.completedObservers.find(x=>x.id===info.originalOperation);
  need(/^[a-f0-9]{64}$/.test(info.originalOperation)&&!ids.has(info.originalOperation)
    &&o?.tool==="file_info"&&o.completedInactive===true
    &&meta(nativeTexts[info.originalOperation],o.nativeText)
    &&JSON.stringify(o.nativeText)===JSON.stringify(info.nativeText),"distinct_closed_info_native:"+i);
  ids.add(info.originalOperation);
  const v=h.parseLosslessIntegers(nativeTexts[info.originalOperation]),md=v.metadata,parts=typeof v.version==="string"?v.version.split(":"):[];
  need(v.path===known.path && v.size===known.bytes && v.sha256===known.sha256
    && v.mode===384 && md?.metadata_platform==="linux" && md.mode===384
    && md.uid===1000 && md.gid===1000 && md.link_count===1
    && parts.length===5 && parts.every(x=>/^[0-9]+$/.test(x))
    && parts[2]===String(v.size),"independent_exact_content_identity:"+i);
  const full9=[parts[0],parts[1],"1000","1000",String(32768|v.mode),"1",String(v.size),parts[3],parts[4]];
  need(known.publisherFull9===null||JSON.stringify(known.publisherFull9)===JSON.stringify(full9),
    "independent_publisher_full9_match:"+i);
  need(info.index===i && info.path===v.path && info.size===v.size && info.sha256===v.sha256
    &&info.version===v.version&&JSON.stringify(info.full9Strings)===JSON.stringify(full9),
    "closed_info_projection_matches_native:"+i);
  return {index:i,path:v.path,bytes:v.size,sha256:v.sha256,version:v.version,
    full9Strings:full9,infoOperation:info.originalOperation,infoNative:o.nativeText};
 });
 const requests=requestTemplates.map((raw,i)=>{const q=JSON.parse(raw);
  need(q.operation.arguments.expected_version===null,"unobserved_template_version_only");
  q.operation.arguments.expected_version=expected[i].version;
  return JSON.stringify(q,null,2)+"\n";
 });
 const requestPins=requests.map(h.gitBlobMeta);
 let source=templateSource;
 for(const[name,value]of [["GF_CONTROLS_BODY_REQUESTS",requestPins],["GF_CONTROLS_BODY_EXPECTED",expected]]) {
  const marker="const "+name+" = null;";
  need(source.split(marker).length===2,"one_literal_body_binding:"+name);
  source=source.replace(marker,"const "+name+" = "+JSON.stringify(value)+";");
 }
 need(expected.reduce((n,x)=>n+x.bytes,0)===90605&&expected.every(x=>x.bytes<=65536),
   "fixed_four_whole_ranges_only");
 return {schema:"heptabao.025b-controls-four-body-literal-binding.v1",source,sourcePin:h.gitBlobMeta(source),
   templatePin:h.gitBlobMeta(templateSource),deriverPin:h.gitBlobMeta(deriverSource),rootGO:goPin,
   requests,requestPins,expected,totalBodyBytes:90605,actualOriginalInfosClosed:true,
   actualBodyObserved:false,NativeCalls:0,sourceChangesOnly:["GF_CONTROLS_BODY_REQUESTS","GF_CONTROLS_BODY_EXPECTED"]};
}
