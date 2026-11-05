function verifyH2Data(inputs,utf8,sha1,sha256,parseLossless,applyDiff){
 "use strict";
 const checks=[],ck=(name,ok)=>{checks.push({name,passed:!!ok});if(!ok)throw Error(name);},same=(a,b)=>JSON.stringify(a)===JSON.stringify(b);
 const pin=t=>{const b=utf8(t);return {blob:sha1("blob "+b.length+"\0"+b),bytes:b.length,sha256:sha256(b)};};
 const before=JSON.parse(inputs.before),after=JSON.parse(inputs.after),cli=JSON.parse(inputs.cli),normal=parseLossless(inputs.normal),core=parseLossless(inputs.core),map=inputs.map,changes=inputs.changes;
 ck("exact original H2 template",pin(inputs.before).blob==="8d3002682ea54f648a3a5312f126747978444484");
 ck("template original formatting roundtrip",JSON.stringify(before,null,2)+"\n"===inputs.before);
 ck("exact CLI existing data source",pin(inputs.cli).blob==="728f4c6dd801310de3f05b4b54ff2ea26bb2d331");
 ck("exact normal5 source table",pin(inputs.normal).blob==="795c92856119c5a2f8c73130f5772d82f3dfc295");
 ck("normal source actual five metadata",normal.metadata_complete===true&&normal.files.length===5);
 const paths=["artifacts.server.bytes","artifacts.server.sha256","artifacts.native_receipt.bytes","artifacts.native_receipt.sha256","artifacts.release_receipt.bytes","artifacts.release_receipt.sha256","artifacts.combined_tests.bytes","artifacts.combined_tests.sha256","host.machine_id_sha256","utilities.python.bytes","utilities.python.sha256","utilities.git.bytes","utilities.git.sha256","utilities.openssl.bytes","utilities.openssl.sha256","old_fences"];
 ck("exact sixteen data replacement locations",same(changes.map(x=>x.path),paths));
 const inverse=JSON.parse(inputs.after);
 for(const c of changes){const ks=c.path.split(".");let dst=inverse;for(const k of ks.slice(0,-1))dst=dst[k];ck("changed value "+c.path,same(dst[ks.at(-1)],c.after));dst[ks.at(-1)]=c.before;}
 ck("inverse all other bytes unchanged",JSON.stringify(inverse,null,2)+"\n"===inputs.before);
 const forward=applyDiff(inputs.before,inputs.diff,false),reverse=applyDiff(inputs.after,inputs.diff,true);
 ck("strict three hunks forward",forward.hunks===3&&forward.text===inputs.after);
 ck("strict three hunks reverse",reverse.hunks===3&&reverse.text===inputs.before);
 ck("product canonical remains 4e808",after.candidate_commit===normal.source_commit&&after.candidate_commit==="4e808d0ecb1bcded22870a7ec960dfb2491cf6ec"&&after.candidate_tree===normal.source_tree&&after.candidate_tree==="eba5e650bd080b8ad41ea52a2bc68867f541d255");
 ck("instrument remains df026",after.instrument_build_commit==="df026fe323dd7cf0f0ec57d7d2d9c5a79897053c"&&after.instrument_build_tree==="424463ccd2310ddc1e7b2bbcd7b7af29ae58c825"&&after.instrument_build_commit!==after.candidate_commit);
 ck("readiness remains false",before.ready_for_readonly_prepare===false&&after.ready_for_readonly_prepare===false);
 for(const k of ["schema","candidate_commit","candidate_tree","layout","qa_files","h2_client","budgets","ready_for_readonly_prepare","instrument_build_commit","instrument_build_tree"])ck("unchanged "+k,same(before[k],after[k]));
 ck("exact H2 paths unchanged",after.layout.control.endsWith("/normal-native-h2-gate-control-r2")&&after.layout.work.endsWith("/normal-native-h2-gate-live-r2")&&after.layout.source.endsWith("/normal-same-root-publication-validation-source-r1"));
 const productRoles=["server","native_receipt","release_receipt","combined_tests","test_groups"];
 for(let i=0;i<5;i++){const role=productRoles[i],target=after.artifacts[role],src=normal.files[i];
 ck("product "+role+" content",target.bytes===src.bytes&&target.sha256===src.sha256&&target.path.split("/").at(-1)===src.name);
 ck("product "+role+" planned layout and mode",target.path===after.layout.control+"/artifacts/"+src.name&&target.uid===1000&&target.mode===(i===0?320:384)&&src.mode===(i===0?320:256));
 ck("product "+role+" unchanged layout",target.path===before.artifacts[role].path&&target.mode===before.artifacts[role].mode&&target.uid===before.artifacts[role].uid);
 ck("product "+role+" independent incoming evidence",src.independent_info&&/^[0-9a-f]{40}$/.test(src.independent_info.blob)&&src.matched_receiver_full9===true&&src.version===src.receiver_full9.filter((_,j)=>[0,1,6,7,8].includes(j)).map(String).join(":"));
 }
 ck("machine guard exact inherited",after.host.machine_id_sha256===cli.host.machine_id_sha256);
 ck("six old fences exact ordered",after.old_fences.length===6&&same(after.old_fences,cli.old_fences)&&new Set(after.old_fences.map(f=>f.path)).size===6);
 for(const role of ["python","git","openssl"])ck("utility "+role+" all fields inherited",same(Object.fromEntries(Object.entries(after.utilities[role]).sort()),Object.fromEntries(Object.entries(cli.utilities[role]).sort())));
 ck("five unchanged QA sources",Object.keys(after.qa_files).length===5&&Object.keys(inputs.qaSources).length===5);
 for(const [name,text]of Object.entries(inputs.qaSources)){const q=after.qa_files[name],v=pin(text),leaf=inputs.h2Tree.tree.find(e=>e.path==="candidate/"+name);ck("QA "+name+" full content pin",v.bytes===q.bytes&&v.sha256===q.sha256&&leaf&&leaf.sha===v.blob&&leaf.size===v.bytes&&leaf.mode==="100644");}
 ck("exact reviewed binder unchanged",pin(inputs.qaSources["native_h2_binding_r1.py"]).blob==="9b3a605a2ac2f47729678bdb696d89b0c9b06b9a");
 ck("exact reviewed driver unchanged",pin(inputs.qaSources["native_h2_gate_r1.py"]).blob==="6687ce5d76ae38ec9f079c876f50d86b04f40448");
 ck("original H01 H02 H03 cases retained",inputs.plan.cases.map(x=>x.id).join(",")==="H01,H02,H03");
 ck("original deadlines retained",after.budgets.http_seconds===15&&after.budgets.h2_client_seconds===15&&after.budgets.action_seconds===300&&after.budgets.readiness_seconds===45&&after.budgets.election_seconds===60&&after.budgets.stable_leader_seconds===2.2&&after.budgets.peer_timeout_ms===1500&&after.budgets.forward_timeout_ms===8000&&after.budgets.term_seconds===5&&after.budgets.kill_seconds===5);
 ck("original body and actual transport conjunction unchanged",inputs.plan.h2_message_completion.data_all_ok===true&&inputs.plan.h2_message_completion.trailers_awaited===true&&inputs.plan.h2_message_completion.trailers_empty_required===true&&inputs.plan.h2_message_completion.recv_end_stream_required===true&&inputs.plan.h2_message_completion.body_length_exact===true&&inputs.plan.cases[1].connection.includes("selected ALPN h2"));
 ck("receiver exact accepted original core",pin(inputs.core).blob==="4f45e1efca410e22d9607352f9ffff451fcbc305");
 ck("receiver original completion distinguished from target",core.status==="transferred"&&core.all_owned_stopped===true&&core.remote_cleanup_unknown===false&&core.remote_endpoint_completion_verified===true&&core.receiver.files.length===12&&core.receiver.qa_build_provenance_verified===true);
 ck("twelve roles original ordered",core.files.length===12&&map.rows.length===12&&same(map.rows.map(r=>r.role),core.files.map(r=>r.role)));
 let infoCount=0;
 for(let i=0;i<12;i++){const row=map.rows[i],src=core.files[i],dst=core.receiver.files[i],q=after.h2_client[row.role],full=dst.identity.map(String);
 ck("instrument "+i+" unchanged content and name",src.bytes===q.bytes&&src.sha256===q.sha256&&src.name===q.path.split("/").at(-1)&&dst.name===src.name&&dst.bytes===q.bytes&&dst.sha256===q.sha256);
 ck("instrument "+i+" actual receiver readback",dst.create_only===true&&dst.fsynced===true&&dst.same_fd_readback.bytes===q.bytes&&dst.same_fd_readback.sha256===q.sha256&&same(row.desktop_incoming_receiver.full9_decimal,full));
 ck("instrument "+i+" distinct source and target modes",src.source_mode===(i===0?320:384)&&dst.mode===(i===0?320:256)&&q.mode===(i===0?320:384)&&q.uid===1000&&q.path===after.layout.control+"/h2qa/"+src.name);
 ck("instrument "+i+" not H2 destination observed",row.h2_target_observed===false&&row.h2_target_actual_identity===null&&row.desktop_incoming_receiver.path!==q.path);
 if(i<7){
 const tx=inputs.infoTexts[i],n=parseLossless(tx),v=n.version.split(":"),expected=[v[0],v[1],String(n.metadata.uid),String(n.metadata.gid),String(32768|n.mode),String(n.metadata.link_count),v[2],v[3],v[4]],prov=row.independent_info_provenance,pn=pin(tx);
 ck("instrument "+i+" independent exact native content",same(n,row.independent_desktop_incoming_info)&&prov.blob===pn.blob&&prov.bytes===pn.bytes&&prov.sha256===pn.sha256);
 ck("instrument "+i+" native and receiver identity exact",n.path===dst.path&&n.size===dst.bytes&&n.sha256===dst.sha256&&same(expected,full)&&n.mode===dst.mode&&n.metadata.mode===n.mode);
 if(i<6){const sdk=JSON.parse(inputs.infoSDKs[i]);ck("instrument "+i+" original SDK exact native",sdk.isError===false&&sdk.content.length===1&&sdk.content[0].type==="text"&&sdk.content[0].text===tx);}
 else ck("seventh info accepted root exact pin",inputs.root7.originalOperationId==="58e9e98dbe378a84ac415f02c25b0a3883c09f4258f820ae2a6c4a27ef61f018"&&inputs.root7.reconciledAckReused===false&&same(inputs.root7.fileInfo,n));
 infoCount++;
 }else ck("instrument "+i+" independent info remains unobserved",row.independent_desktop_incoming_info===null&&row.independent_info_provenance===null&&row.independent_info_observed===false);
 }
 ck("seven info five pending counted",infoCount===7&&map.independent_incoming_info_count===7&&same(map.remaining_independent_indices,[7,8,9,10,11])&&map.full_independent_transport_metadata_complete===false);
 ck("old lost ACK not rewritten",map.old_timeouts_relabelled===false&&map.old58e9_reused_false_does_not_prove_prior_future_closed===true);
 ck("22 H2 target files unobserved",inputs.unobserved.h2_target_objects.length===22&&inputs.unobserved.h2_target_objects.every(x=>x.actual_identity===null&&x.observed===false));
 ck("actual binding/prepare not invented",inputs.unobserved.binding.actual_published_sha256===null&&inputs.unobserved.binding.ready_for_readonly_prepare===false&&inputs.unobserved.prepare.actual_result_sha256===null&&inputs.unobserved.all_H2_runtime_authorization===false);
 const stage=inputs.cliStage,binder=inputs.qaSources["native_h2_binding_r1.py"];
 ck("existing CLI stage identity",pin(stage).blob==="45ceb135688a2002e845f31e010ca5c010551517");
 for(const gap of inputs.gap.incompatible_unchanged_body_constraints){
 const walk=a=>{if(Array.isArray(a))a.forEach(walk);else if(a&&typeof a==="object"&&a.exact){const text=gap.required===a?binder:stage;ck("gap anchor "+gap.id+" "+a.line,text.split("\n").slice(a.line-1).join("\n").startsWith(a.exact)||text.split("\n")[a.line-1].includes(a.exact));}};
 walk(gap.existing);walk(gap.required);
 }
 ck("stage gap 5 executable constraints retained",inputs.gap.incompatible_unchanged_body_constraints.length===5&&inputs.gap.no_new_controller_written===true);
 ck("existing dispatch not runnable",inputs.dispatch.ready===false&&inputs.dispatch.requests_authorized===false&&inputs.dispatch.templates.prepare.timeout_seconds===330&&inputs.dispatch.templates.live.timeout_seconds===2400&&inputs.dispatch.templates.prepare.args.includes("UNRESOLVED_ACTUAL_FIXTURE_BINDING_SHA256")&&inputs.dispatch.templates.live.args.includes("UNRESOLVED_ACTUAL_PREPARE_RESULT_SHA256"));
 return {schema:"heptabao.current4e808.h2.data-binding-source-checks.v1",status:"PASS_CONTENT_BINDING_ONLY_WITH_EXPLICIT_STAGE_AND_OBSERVATION_GAPS",checks_count:checks.length,checks,before:pin(inputs.before),after:pin(inputs.after),diff:pin(inputs.diff),literal_locations:16,diff_hunks:3,original_H2_QA_definitions_unchanged:true,new_code_or_controller_written:false,current_product_pins:5,instrument_content_pins:12,incoming_instrument_independent_infos:7,incoming_instrument_missing_infos:[7,8,9,10,11],planned_H2_targets:22,observed_H2_targets:0,utilities_inherited:3,old_fences_inherited:6,ready_for_readonly_prepare:false,Runtime_calls:0,source_module_execution:0,new_builds:0,prepare_dispatch:0,live_dispatch:0};
}
