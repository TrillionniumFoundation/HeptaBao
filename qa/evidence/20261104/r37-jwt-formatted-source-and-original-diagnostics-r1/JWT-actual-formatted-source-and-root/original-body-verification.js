
function verifyJwtReportBodyOriginal(){
 const p=load("r34_packet_JWT-fixed38-report-three-ranges-full-actual"),g=load("r37_jwt_report_body_GO"),go=g.value,s=JSON.parse(p.raw["recovery.state.public.json"]),ix=JSON.parse(p.raw["CALL-INDEX.public.json"]),release=JSON.parse(p.raw["LANE-RELEASE.public.json"]),checks=[];
 const ck=(name,ok)=>{checks.push({name,passed:!!ok});if(!ok)throw Error(name);};
 const eq=(a,b)=>JSON.stringify(a)===JSON.stringify(b),matches=(t,x)=>{const m=gitBlobMeta(t);return m.blob===x.blob&&m.bytes===x.bytes&&m.sha256===x.sha256;},blobs=Object.fromEntries(p.pins.map(x=>[x.blob,p.raw[x.path]]));
 ck("whole121_all1792424_bytes",p.audit.whole===true&&p.audit.files===121&&p.audit.bytes===1792424);
 ck("exact_GO_journal_and_original_release",matches(p.raw["GO.original.json"],g)&&matches(p.raw["journal.source.js"],go.candidate)&&p.raw["LANE-RELEASE.public.json"]===load("r34_packet_JWT-fixed38-report-body-minimal").raw["LANE-RELEASE.public.json"]);
 const ids=release.observations.map(x=>x.operation_id),obs=s.completedObservers.filter(o=>ids.includes(o.id));
 const calls=ix.map(x=>({key:x.call_key,kind:x.kind,phase:x.phase,requestPin:x.request,sdkPin:x.sdk,nativePin:x.native,requestText:p.raw[x.files_prefix+"-request.json"],sdkText:p.raw[x.files_prefix+"-original.sdk.json"],nativeText:p.raw[x.files_prefix+"-native.original.json"],armedText:p.raw[x.files_prefix+"-armed.json"],intentText:p.raw[x.files_prefix+"-intent.json"],armedTree:x.arm_tree}));
 const cs=verifyOriginalJournal({label:"JWT_report_body",calls,observers:obs,blob:sha=>blobs[sha],goPins:[g],pageLimit:()=>16384,ck});
 ck("twentyone_calls_three_observers_fifteen_pages_no_process",cs.length===21&&obs.length===3&&cs.every(x=>x.c.kind!=="process_start")&&obs.reduce((n,x)=>n+x.pages,0)===15&&release.original_calls===21&&release.returned_observers===3&&release.immutable_pages===15);
 const starts=cs.filter(x=>x.c.kind==="operation_start");
 ck("three_original_operation_ids_and_page_counts",eq(starts.map(x=>x.n.operation_id),ids)&&eq(obs.map(x=>x.pages),[6,6,3])&&starts.every(x=>x.q.operation.tool==="binary_read"));
 let body=[],at=0;
 const ranges=[];
 for(let i=0;i<3;i++){
  const start=starts[i],expect=go.exact_ranges[i],q=start.q.operation.arguments,n=JSON.parse(p.raw["observer-"+i+"-native.original.json"]),data=unb64(n.data_base64),ob=obs[i],rel=release.observations[i];
  ck("exact_range_request_"+i,matches(start.c.requestText,expect.request)&&q.host==="rog"&&q.path===go.fixed_report.path&&q.expected_version===go.fixed_report.version&&q.offset===expect.offset&&q.limit===expect.limit&&start.a.originalJob===go.original_job);
  ck("fixed_range_bytes_EOF_SHA_"+i,n.offset===at&&n.offset===expect.offset&&data.length===expect.limit&&n.next_offset===at+data.length&&n.size===go.fixed_report.bytes&&n.path===go.fixed_report.path&&n.version===go.fixed_report.version&&n.eof===(i===2)&&n.chunk_sha256===sha256Latin1(byteString(data)));
  ck("original_payload_release_identity_"+i,matches(p.raw["observer-"+i+"-native.original.json"],ob.nativeText)&&eq(ob.nativeText,rel.native)&&eq(ob.payload,rel.payload)&&ob.payload.bytes<=go.maximum_original_payload_bytes&&ob.id===rel.operation_id);
  const first=cs.findIndex(x=>x.n.operation_id===ob.id&&x.c.kind==="operation_start"),last=cs.findIndex(x=>x.c.kind==="operation_result"&&x.q.operation_id===ob.id&&x.n.eof===true);
  ck("original_observer_fully_closed_before_next_"+i,first===[0,8,16][i]&&last===[7,15,20][i]&&(i===2||last<cs.indexOf(starts[i+1]))&&cs.slice(first,last+1).every(x=>x.c.kind==="operation_start"?x.n.operation_id===ob.id:x.q.operation_id===ob.id));
  for(const byte of data)body.push(byte);at+=data.length;
  ranges.push({operation_id:ob.id,offset:n.offset,bytes:data.length,next_offset:n.next_offset,eof:n.eof,chunk_sha256:n.chunk_sha256,payload:ob.payload,native:ob.nativeText,pages:ob.pages});
 }
 const raw=utf8Text(body),rp=load("r37_jwt_fixed38_actual_report");
 ck("exact_167436_whole_UTF8_sha_blob",at===167436&&at===go.fixed_report.bytes&&sha256Latin1(byteString(body))===go.fixed_report.sha256&&eq(utf8Bytes(raw),body)&&raw===p.raw["observation.public.json"]&&raw===rp.text&&matches(raw,rp)&&eq(release.whole_report.body,{blob:rp.blob,bytes:rp.bytes,sha256:rp.sha256}));
 ck("original_file_info_version_and_full9_retained",s.collectorReportInfo.originalOperation===go.info_operation&&s.collectorReportInfo.path===go.fixed_report.path&&s.collectorReportInfo.size===go.fixed_report.bytes&&s.collectorReportInfo.sha256===go.fixed_report.sha256&&s.collectorReportInfo.version===go.fixed_report.version&&eq(s.collectorReportInfo.nativeText,go.fixed_report.metadata_native)&&eq(s.collectorReportInfo.full9Strings,go.fixed_report.full9));
 ck("existing_original_collector_job_and_three_starts_only",s.job===go.original_job&&s.collectorReportBodyStarted===3&&eq(s.collectorReportBody.originalOperations,ids)&&s.collectorReportBody.metadataOperation===go.info_operation);
 ck("quiescent_original_body_lane",s.pending===null&&s.activeObserver===null&&s.nativeCallInFlight===false&&release.pending===null&&release.active_observer===null&&release.runtime_calls_in_flight===0&&release.native_futures_active===0&&release.errors.length===0);
 const old=load("r37_jwt_report_content_qualification_value");
 ck("prior_content202_exact_same_report",old.report_content_qualified===true&&old.check_count===202&&old.checks.every(x=>x.passed===true)&&eq(old.report,{blob:rp.blob,bytes:rp.bytes,sha256:rp.sha256})&&Object.keys(load("r37_jwt_formatted_nine_reconstructed")).length===9);
 const value={...old,schema:"heptabao.root-qualification.JWT-fixed38-full-original-body-and-reconstruction.v1",status:"PASS_ORIGINAL_REPORT_AND_ACTUAL_FORMATTED_SOURCE",evidence_qualified:true,body_original_chain_qualified:true,checks:[...checks,...old.checks],check_count:checks.length+old.check_count,body_chain_check_count:checks.length,content_check_count:old.check_count,body_packet:p.audit,original_ranges:ranges,original_calls:21,original_observers:3,immutable_pages:15,source_freeze_authorized:true,source_frozen:false,compile_qualified:false,product_qualified:false};
 store("r37_jwt_report_full_qualification_value",value);
 return {status:value.status,check_count:value.check_count,body_checks:checks.length,content_checks:old.check_count,report:value.report,source_freeze_authorized:value.source_freeze_authorized};
}
