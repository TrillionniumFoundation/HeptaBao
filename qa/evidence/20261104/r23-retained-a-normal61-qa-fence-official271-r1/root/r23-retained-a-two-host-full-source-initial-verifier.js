function verifyRetainedAFullSourceArchives(inputs,canonical,parse,utf8,latin1,sha256,sha1,unb64){
 const checks=[],ck=(n,v)=>{if(!v)throw Error(n);checks.push(n);},hash=s=>sha256(latin1(utf8(s))),out=[];
 const leaves=canonical.tree.filter(x=>x.type==="blob");
 ck("canonical.untruncated_3914",canonical.truncated===false&&leaves.length===3914&&canonical.sha==="eba5e650bd080b8ad41ea52a2bc68867f541d255");
 const expectedTree=leaves.map(x=>x.mode+" blob "+x.sha+"\t"+x.path+"\0").join("");
 const expectedIndex=leaves.map(x=>x.mode+" "+x.sha+" 0\t"+x.path+"\0").join("");
 for(const input of inputs){
  const {host,raw,audit,count}=input,obj=p=>parse(raw[p]),prefix=host+".",core=obj("actual/stage-result.public.json"),manifest=new Map(audit.records.map(x=>[x.path,x])),seen=new Set();
  ck(prefix+"exact_source",core.host===host&&core.source_commit==="4e808d0ecb1bcded22870a7ec960dfb2491cf6ec"&&core.source_tree===canonical.sha);
  for(const p of Object.keys(raw).filter(x=>x.startsWith("sdk/"))){
   const np="native/"+p.slice(4); if(!(np in raw))continue; const s=obj(p);
   ck(prefix+p+".original_native_exact",s.isError===false&&s.content.length===1&&s.content[0].type==="text"&&s.content[0].text===raw[np]);
  }
  const commandPaths=Array.from(manifest.keys()).filter(p=>p.startsWith("commands/")&&p.endsWith(".public.json")).sort();
  ck(prefix+"exact_command_count",commandPaths.length===count&&core.cleanup.length===count&&new Set(core.cleanup.map(x=>x.label)).size===count);
  for(const p of Object.keys(raw).filter(x=>/^native\/(?:record|small_stream)-batch-\d+\.json$/.test(x))){
   const n=obj(p),request=obj("requests/"+p.slice(7));
   ck(prefix+p+".original_bounded_request",request.host===host&&request.paths.length<=16&&n.atomic_snapshot===false&&n.encoding==="utf-8"&&n.files.length===request.paths.length&&n.files.every((x,i)=>x.path===request.paths[i]));
   for(const file of n.files){
    const name=file.path.split("/").pop(),target="commands/"+name,m=manifest.get(target);
    ck(prefix+target+".independent_whole_read",!!m&&!seen.has(target)&&file.eof===true&&file.path===core.root+"/control/"+name&&file.size===utf8(file.text).length&&file.size===m.bytes&&file.sha256===hash(file.text)&&file.sha256===m.sha256&&raw[target]===file.text&&typeof file.version==="string"&&file.version.split(":")[2]===String(file.size));
    seen.add(target);
   }
  }
  const full=[];
  for(let i=0;i<2;i++){
   const info=obj("native/large-"+i+"-info.json"),rp="requests/large-"+i+"-info.json",request=obj(rp),name=info.path.split("/").pop(),target="commands/"+name,m=manifest.get(target);
   ck(prefix+"large"+i+".metadata",request.host===host&&request.path===info.path&&info.path===core.root+"/control/"+name&&info.size===m.bytes&&info.sha256===m.sha256&&info.mode===384&&info.metadata.link_count===1&&info.metadata.uid===(host==="mac"?501:1000)&&info.metadata.gid===(host==="mac"?20:1000));
   const ps=Object.keys(raw).filter(p=>p.startsWith("native/large-"+i+"-offset-")).sort((a,b)=>Number(a.match(/offset-(\d+)/)[1])-Number(b.match(/offset-(\d+)/)[1]));
   ck(prefix+"large"+i+".seven_original_pages",ps.length===7);
   let offset=0,all=[];
   for(const p of ps){
    const n=obj(p),r=obj("requests/"+p.slice(7)),b=unb64(n.data_base64);
    ck(prefix+p+".fixed_version_contiguous_bounded",r.host===host&&r.path===info.path&&r.expected_version===info.version&&r.offset===offset&&r.limit===65536&&n.path===info.path&&n.version===info.version&&n.size===info.size&&n.offset===offset&&n.next_offset===offset+b.length&&b.length===Math.min(65536,info.size-offset)&&n.chunk_sha256===sha256(latin1(b))&&n.eof===(offset+b.length===info.size));
    all=all.concat(b);offset+=b.length;
   }
   ck(prefix+"large"+i+".whole_bytes_and_git_identity",offset===info.size&&sha256(latin1(all))===info.sha256&&sha1(utf8("blob "+all.length+"\0").concat(all))===m.blob);
   const expected=i===0?expectedTree:expectedIndex;
   ck(prefix+"large"+i+".all_3914_paths_mode_blob_exact",latin1(all)===latin1(utf8(expected)));
   full.push(expected);seen.add(target);
  }
  ck(prefix+"every_command_original_covered",seen.size===count*3);
  for(let i=0;i<commandPaths.length;i++){
   const p=commandPaths[i],record=obj(p),base=p.slice(0,-12),label=base.slice(9),cleanup=core.cleanup.find(x=>x.label===label);
   ck(prefix+label+".original_success_reaped_budget",p.slice(9,12)===String(i).padStart(3,"0")&&record.exit_code===0&&record.timed_out===false&&record.direct_child_reaped===true&&record.remaining.length===0&&record.elapsed_seconds>=0&&record.elapsed_seconds<record.limit_seconds&&[30,90,180].includes(record.limit_seconds)&&cleanup?.pid===record.pid&&cleanup.exit_code===0&&cleanup.direct_child_reaped===true&&cleanup.remaining.length===0);
   for(const side of ["stdout","stderr"]){
    const sp=base+"."+side,m=manifest.get(sp);
    ck(prefix+label+"."+side+"_record_sha",!!m&&seen.has(sp)&&record[side+"_sha256"]===m.sha256);
   }
  }
  ck(prefix+"source_stage_only",core.compiler_started===false&&core.server_started===false&&core.production_changed===false&&core.public_network_fetch_used===false);
  out.push({host,tree:audit.tree,files:audit.files,bytes:audit.bytes,original_job:obj("verification/full-command-archive.public.json").original_job,command_records:count,original_streams:count*2,full_NUL_streams:2,version_pinned_pages:14,source_commit:core.source_commit,source_tree:core.source_tree,source_only:true});
 }
 return {schema:"heptabao.root.retained-a-source-full-archives.v1",status:"PASS_FULL_ORIGINAL_SOURCE_ARCHIVES",checks:checks.length,checked:checks,hosts:out,normal61_qualification_not_inferred:true,full_replacement:false};
}