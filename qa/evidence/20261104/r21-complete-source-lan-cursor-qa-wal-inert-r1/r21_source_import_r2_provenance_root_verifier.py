function verifyImportProvenance(a, parse, u, bs, h, dec, get) {
 const checks=[], need=(x,s)=>{if(!x)throw Error(s);checks.push(s)};
 function raw(path){const r=a.records.find(r=>r.path===path);need(!!r,"record "+path);const s=get(r.blob);if(s===undefined)throw Error("uncached "+path);return s}
 const sdkRecords=a.records.filter(r=>/^sdk\/.+-original\.json$/.test(r.path));
 let pagesN=0;const opids=new Set(),keys=new Set();
 for(const r of sdkRecords){
  const label=r.path.slice(4,-14),sdkRaw=raw(r.path),sdk=parse(sdkRaw),req=parse(raw("requests/"+label+".json"));
  const adm=parse(raw("operations/"+label+"-admission.txt")),status=parse(raw("operations/"+label+"-status.txt"));
  need(adm.reused===false&&adm.automatic_retry===false&&status.automatic_retry===false,"fresh/no retry "+label);
  need(adm.operation_id===status.operation_id&&!opids.has(adm.operation_id),"operation identity "+label);opids.add(adm.operation_id);
  need(!keys.has(req.idempotency_key),"unique key "+label);keys.add(req.idempotency_key);
  need(adm.tool_name===req.operation.tool&&status.tool_name===req.operation.tool,"tool binding "+label);
  need(status.async_state==="completed"&&status.owned_future_active===false&&status.payload_available===true&&status.result_state==="stored_observed","closed payload "+label);
  need(sdk.resultType==="complete"&&sdk.isError===false&&sdk.content.length===1&&sdk.content[0].type==="text","successful SDK "+label);
  need(sdk.content[0].text===raw("native/"+label+".json"),"exact native "+label);
  const pb=a.records.filter(x=>x.path.startsWith("operations/"+label+"-page-")).sort((x,y)=>x.path.localeCompare(y.path));
  let offset=0,parts=[];const sdkbytes=u(sdkRaw),sdkhash=h(bs(sdkbytes));
  for(const pr of pb){
   const pg=parse(raw(pr.path)),d=dec(pg.data_base64);
   need(pg.immutable_snapshot===true&&pg.payload_kind==="native_result"&&pg.operation_id===adm.operation_id,"immutable page identity "+pr.path);
   need(pg.offset===offset&&pg.next_offset===offset+d.length&&pg.total_bytes===sdkbytes.length&&pg.result_sha256===sdkhash,"page bounds/hash "+pr.path);
   offset+=d.length;need(pg.eof===(offset===sdkbytes.length),"page EOF "+pr.path);parts.push(bs(d));pagesN++;
  }
  need(offset===sdkbytes.length&&parts.join("")===bs(sdkbytes),"whole SDK raw "+label);
 }
 need(sdkRecords.length===22&&pagesN===99,"22 closed operations 99 pages");
 let commandSmall=0,sourceSmall=0;const seen=new Set();
 for(let n=0;n<4;n++){
  const label="logs-"+n,req=parse(raw("requests/"+label+".json")),native=parse(raw("native/"+label+".json"));
  need(req.operation.tool==="read_multiple_files"&&req.operation.arguments.host==="desktop","fixed small read "+label);
  need(native.truncated===false&&native.atomic_snapshot===false&&native.snapshot_scope==="independent_file","bounded independent "+label);
  need(JSON.stringify(native.files.map(x=>x.path))===JSON.stringify(req.operation.arguments.paths),"requested paths exact "+label);
  for(const f of native.files){
   const basename=f.path.split("/").pop();need(!seen.has(basename),"unique small body "+basename);seen.add(basename);
   const isSource=basename==="importer.py",s=raw((isSource?"actual/":"commands/")+basename);
   need(f.eof===true&&f.text===s&&f.size===u(s).length&&f.sha256===h(bs(u(s))),"whole actual small body "+basename);
   need(typeof f.version==="string"&&f.version.split(":")[2]===String(f.size),"version size "+basename);
   if(isSource)sourceSmall++;else commandSmall++;
  }
 }
 const assemblies=[];
 for(const kind of ["tree","index"]){
  const record=a.records.find(x=>x.path==="commands/"+(kind==="tree"?"011-materialized-tree.stdout":"012-materialized-index.stdout"));
  const labels=a.records.filter(r=>new RegExp("^native/"+kind+"-chunk-[0-9]+\\.json$").test(r.path)).map(r=>r.path.slice(7,-5)).sort();
  let off=0,parts=[],version=null,unpinned=0;
  for(const label of labels){
   const n=parse(raw("native/"+label+".json")),q=parse(raw("requests/"+label+".json")).operation,d=dec(n.data_base64);
   need(q.tool==="binary_read"&&q.arguments.host==="desktop"&&q.arguments.path===n.path&&q.arguments.offset===n.offset&&q.arguments.limit===65536,"binary request "+label);
   if(q.arguments.expected_version===undefined){need(kind==="index"&&off===0,"only initial index unpinned");unpinned++}else need(q.arguments.expected_version===n.version,"requested version "+label);
   if(version===null)version=n.version;need(n.version===version,"one stable version "+label);
   need(n.offset===off&&n.next_offset===off+d.length&&d.length<=65536&&n.size===record.bytes,"binary bounds "+label);
   need(h(bs(d))===n.chunk_sha256,"chunk checksum "+label);
   off+=d.length;need(n.eof===(off===record.bytes),"binary EOF "+label);parts.push(bs(d));
  }
  need(labels.length===7&&off===record.bytes&&parts.join("")===bs(u(raw(record.path)))&&h(parts.join(""))===record.sha256,"complete original "+kind);
  assemblies.push({kind,chunks:labels.length,bytes:off,sha256:record.sha256,blob:record.blob,version,initial_unpinned_requests:unpinned});
 }
 need(commandSmall===61&&sourceSmall===1&&seen.size===62,"61 small command bodies plus importer and 2 binary command bodies");
 return {checks,summary:{check_count:checks.length,operations:sdkRecords.length,pages:pagesN,small_command_files:commandSmall,whole_source_reads:sourceSmall,binary_chunks:14,assemblies,all_success:true}};
}
