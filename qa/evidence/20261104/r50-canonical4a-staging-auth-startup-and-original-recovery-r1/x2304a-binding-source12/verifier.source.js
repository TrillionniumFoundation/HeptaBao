function verifyX2304aBindingOnly(files){
 const checks=[];function need(v,label){checks.push({label,pass:!!v});if(!v)throw Error(label);}
 const before=JSON.parse(files["BINDING.before576.public.json"]),after=JSON.parse(files["BINDING.candidate4a.public.json"]),m=JSON.parse(files["CANDIDATE.original.json"]),plan=JSON.parse(files["PLAN.public.json"]);
 need(applyStrict(files["BINDING.before576.public.json"],files["binding.forward.diff"],false)===files["BINDING.candidate4a.public.json"],"strict forward data binding");
 need(applyStrict(files["BINDING.candidate4a.public.json"],files["binding.forward.diff"],true)===files["BINDING.before576.public.json"],"strict inverse data binding");
 need((files["binding.forward.diff"].match(/^@@ /gm)||[]).length===3,"three data-only hunks");
 need(gitBlobMeta(files["stage.template.py"]).blob==="d40b9565ddc74b93caf150fad29c612f7160c8c8","entire original controller unchanged including finally");
 need(gitBlobMeta(files["binder.original.js"]).blob==="5ee4b7696af740666382c8af80d31aba37343b4e","entire original binder unchanged");
 need(files["stage.template.py"].includes("BINDING = None  # EXACT_PUBLIC_SOURCE_BINDING\nassert isinstance(BINDING,dict), 'source binding is not frozen'"),"original unbound fail-closed marker retained");
 const candidate={commit:m.commit,tree:m.tree,parent:m.parent,leaves:m.leafCount,tracked_bytes:m.trackedBytes,full_index_sha256:m.fullLeafIndexSha256,history:m.expectedHistoryCount};
 need(JSON.stringify(after.candidate)===JSON.stringify(candidate),"candidate exact frozen manifest");
 need(after.candidate.leaves===3932&&after.candidate.tracked_bytes===62553956&&after.candidate.history===3770&&after.candidate.full_index_sha256==="7e7acf5b5f4c0b2f9c410e6ead923258cb8b8750389d516b8998f6a45f5e8d7d","four final source geometry values");
 need(after.fresh_root==="/home/qian/hb-4a49405b-src-20261106-r1","fresh candidate root");
 for(const k of ["schema","readonly_base","base_commit","base_tree","base_history","first_prerequisite","intermediate_commit","root_commit"])need(after[k]===before[k],"unchanged "+k);
 need(JSON.stringify(after.bundles[0])===JSON.stringify(before.bundles[0]),"first495->02b bundle byte-values unchanged");
 need(after.bundles.length===2&&after.bundles[1].prerequisite===after.intermediate_commit&&after.bundles[1].head===after.candidate.commit,"second02b->4a distinct from Macfrom576");
 need(after.candidate.parent!==after.bundles[1].prerequisite&&after.candidate.parent==="5767739cd25e458ac052dc8d384019bab8688ae0","candidate sole parent576 retained independently of bundle02b prerequisite");
 need(after.bundles[1].field==="canonical_4a_base64"&&after.bundles[1].name==="canonical-hb-4a49405b-from02b.bundle"&&after.bundles[1].target_mode===before.bundles[1].target_mode,"second bundle names and original0400 mode");
 need(["bytes","sha256","header","header_sha256"].every(k=>after.bundles[1][k]===null),"second actual binary values null");
 need(["blob","bytes","sha256"].every(k=>after.carrier[k]===null),"actual carrier values null");
 need(["bytes","sha256","full9","metadata_version","header","header_sha256","base64_blob","actual_producer_report","actual_file_info","actual_body","root_transport_qualification"].every(k=>plan.second_bundle[k]===null),"all actual producer and transport evidence null");
 need(["runtime_source","carrier","request","typed_binding","journal","product_slot","NativeGO"].every(k=>plan[k]===null),"no execution envelope generated");
 need(plan.original_budgets.stageSeconds===300&&plan.original_budgets.cloneSeconds===90&&plan.original_budgets.gitCommandSeconds===60&&plan.original_budgets.outerSeconds===360,"original300/90/60/360 retained");
 need(plan.input_caps.stdin_bytes===262144&&plan.input_caps.bundle_bytes_total===262144,"both original carrier and bundle total caps retained");
 need(plan.NativeCalls===0&&plan.PythonExecuted===false&&plan.CargoStarted===false,"source-only flags");
 return {pass:true,count:checks.length,checks};
}
