function(prefix){
 const u=eval("("+load("ha_helper_reconstructed_r1_utf8")+")"),h=eval("("+load("ha_helper_reconstructed_r1_sha256")+")"),s1=eval("("+load("ha_helper_reconstructed_r1_sha1")+")"),lj=eval("("+load("ha_helper_reconstructed_r1_lossless_json")+")");
 const raw=load(prefix+"command_raw_files")||{},large=load(prefix+"command_large_content_files")||{},meta=load(prefix+"command_file_metadata")||{},plan=load(prefix+"command_plan"),core=load(prefix+"core_value"),delta=load(prefix+"NUL_reuse_delta"),checks=[];
 const canonical=v=>v===null||typeof v!=="object"?JSON.stringify(v):Array.isArray(v)?"["+v.map(canonical).join(",")+"]":"{"+Object.keys(v).sort().map(k=>JSON.stringify(k)+":"+canonical(v[k])).join(",")+"}",eq=(a,b)=>canonical(a)===canonical(b);
 const ck=(name,pass)=>{checks.push({name,pass:!!pass});if(!pass){store(prefix+"archive_final_checks_failure",checks);throw Error(name);}};
 const filename=path=>{const n=path.slice(plan.fixed_control.length+1);ck("direct fixed control path "+path,path===plan.fixed_control+"/"+n&&!n.includes("/"));return n;};
 ck("original plan 65 = 21 records + 42 streams + 2 source controls",plan.total_files===65&&plan.command_records===21&&plan.saved_streams===42&&plan.source_control_files===2&&plan.small_files.length===63&&plan.large_files.length===2);
 for(let i=1;i<=5;i++){const name="commandlogs"+i;ck(name+" actual native closed/full/verified",load(prefix+name+"_complete_r1")===true&&load(prefix+name+"_closed_status_r1")?.owned_future_active===false&&load(prefix+name+"_verified")===true);}
 const plannedSmall=plan.small_files.map(x=>x.path).sort();
 ck("exact 63 native paths; no unlisted read",eq(Object.keys(meta).sort(),plannedSmall)&&Object.keys(raw).length===63);
 ck("two content-addressed representations only",Object.keys(large).length===2&&load(prefix+"NUL_content_reuse_complete")===true&&delta.root_GO==="f7eda3b5696e478342b58999871788d009fef97a"&&delta.body_RPCs_submitted===0&&delta.replaced_planned_body_slots===14);
 const table=[];
 for(const spec of plan.small_files){
  const n=filename(spec.path),text=raw[n],m=meta[spec.path],b=u(text);
  ck("actual native bytes/SHA/version "+n,m.size===b.length&&m.sha256===h(b)&&m.version.split(":")[2]===String(b.length));
  ck("native source observation closed "+n,load(prefix+m.original_observation+"_complete_r1")===true);
  table.push({path:spec.path,kind:spec.kind,bytes:b.length,sha256:m.sha256,version:m.version,content_blob:s1("blob "+b.length+"\0"+b),content_origin:"ACTUAL_NATIVE_READ_MULTIPLE_FILES_WHOLE",artifact:"actual/original-fixed-files/"+n,original_observation:m.original_observation,operation_id:load(prefix+m.original_observation+"_operation_id_r1"),snapshot_scope:"independent_file",atomic_snapshot:false});
 }
 for(let i=0;i<plan.large_files.length;i++){
  const spec=plan.large_files[i],n=filename(spec.path),b=u(large[n]),d=delta.records.find(x=>x.original_path===spec.path),info=load(prefix+"inventory"+i+"_info_verified_value");
  ck("canonical content matches current independent native whole hash "+n,!!d&&info.path===spec.path&&b.length===spec.bytes&&h(b)===spec.sha256&&info.size===b.length&&info.sha256===h(b)&&info.version===d.version&&s1("blob "+b.length+"\0"+b)===d.content_blob&&eq(info.full9_decimal,d.full9_decimal));
  ck("current NUL info native closed "+n,load(prefix+"inventory"+i+"_info_complete_r1")===true&&load(prefix+"inventory"+i+"_info_closed_status_r1")?.owned_future_active===false);
  table.push({path:spec.path,kind:spec.kind,bytes:b.length,sha256:spec.sha256,version:info.version,full9_decimal:info.full9_decimal,content_blob:d.content_blob,content_origin:d.content_origin,artifact:"content-addressed-reuse/canonical-content/"+n,current_file_info_operation:d.actual_info_operation,current_file_info_blob:d.actual_info_blob,root_reuse_GO:delta.root_GO,current_host_body_RPC_count:0,replaced_unsubmitted_body_slots:d.replaced_planned_unsubmitted_body_slots});
 }
 ck("all 65 representations unique",table.length===65&&new Set(table.map(x=>x.path)).size===65);
 ck("21 actual original commands",core.commands.length===21&&core.cleanup.length===21);
 const all={...raw,...large};
 for(const row of core.commands){
  const record=row.label+".public.json";ck("command record equals actual controller core "+row.label,eq(lj(raw[record]),row));
  ck("original bounded command and ownership "+row.label,row.direct_child_reaped===true&&row.timed_out===false&&Array.isArray(row.remaining)&&row.remaining.length===0&&row.limit_seconds===(row.label==="000-standalone-clone"?90:60)&&row.exit_code===((row.label==="013-no-sparse-config"||row.label==="020-source-after-partial-config")?1:0));
  for(const stream of ["stdout","stderr"]){const n=row.label+"."+stream,b=u(all[n]);ck("saved original stream whole bytes/SHA "+n,b.length===row[stream+"_bytes"]&&h(b)===row[stream+"_sha256"]);}
 }
 const proof=core.canonical_proof,outputs={"002-bundle-heads.stdout":proof.commit+" HEAD\n","005-canonical-kind.stdout":"commit\n","006-canonical-tree.stdout":proof.tree+"\n","007-canonical-parents.stdout":proof.parents.join(" ")+"\n","008-canonical-count.stdout":String(proof.commit_count)+"\n","009-canonical-roots.stdout":proof.root+"\n","010-canonical-full-fsck.stdout":"","010-canonical-full-fsck.stderr":"","013-no-sparse-config.stdout":"","013-no-sparse-config.stderr":"","014-source-after-head.stdout":proof.commit+"\n","015-source-after-tree.stdout":proof.tree+"\n","016-source-after-status.stdout":"","017-source-after-git-dir.stdout":core.source_after.git_directory+"\n","018-source-after-common-dir.stdout":".git\n","019-source-after-shallow.stdout":"false\n","020-source-after-partial-config.stdout":"","020-source-after-partial-config.stderr":""};
 for(const [n,t]of Object.entries(outputs))ck("original Git output semantic "+n,raw[n]===t);
 ck("bundle original standalone full-history output",raw["001-bundle-verify.stdout"]==="The bundle contains this ref:\n"+proof.commit+" HEAD\nThe bundle records a complete history.\nThe bundle uses this hash algorithm: sha1\n");
 ck("saved exact admitted controller",raw["importer.py"]===load(prefix+"source_text"));
 const inv=load(prefix+"inventory_verification");ck("canonical content independently rebuilds current tree/index",inv.passed===true&&inv.tracked_files===3914&&inv.index_files===3914&&inv.tree_equals_index===true&&inv.all_index_stage_zero===true&&inv.merkle_trees===358&&inv.rebuilt_tree===proof.tree&&inv.current_host_body_RPC_count===0&&inv.root_GO===delta.root_GO);
 ck("original unique importer authority and full core already closed",load(prefix+"authority_verified")===true&&load(prefix+"streams_complete")===true&&load(prefix+"core_verified")===true);
 store(prefix+"file_representation_table",{schema:"heptabao.current4e808.source-import.65-content-representations.v1",original_plan_tree:"bc3ac1786389aa597cdd980d2fd5bff5b7ef66e8",native_small_file_reads:63,canonical_reconstructed_large_representations:2,current_host_large_body_RPC_count:0,root_reuse_GO:delta.root_GO,entries:table});
 store(prefix+"archive_final_checks",checks);store(prefix+"command_checks",(load(prefix+"command_checks")||[]).concat(checks));store(prefix+"command_archive_verified",true);
 return {passed:true,checks:checks.length,native_small_files:63,canonical_large:2,total_content_representations:65,current_host_large_body_RPC_count:0,original_records:21,original_streams:42,source_controls:2};
}
