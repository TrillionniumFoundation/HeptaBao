function verifyRetainedARogStage(input,applyUnified,utf8,byteString,sha256){
 const checks=[]; const need=(condition,label)=>{if(!condition)throw Error(label);checks.push(label);};
 const get=b=>input.raw[b]; const hash=s=>sha256(byteString(utf8(s)));
 const specs=[["stager","74c0b34005911a169c34ef65a73dfcd885e36574","5eb1fd375fb7d7bb4f1b2dadb715fa6eecedf494","a6c40dc281b7f01263bac8a6b2c2d214dfb2a5f4",4],["runner","9b318f4acf589e0410263723695f421d0bb224ea","5e50290e953939bfab3b095244a50a7eb77d092d","1167691bfe5638796d36adee511974b5e3da0b6d",1],["launcher","66728acfe52cede473b0dcae21213a2cb87e48ee","7b42cf15a40c4c16b5f473714baf7abea88bef1f","050145181fde602e2c45d234a46cb9e255f98a11",2]];
 for(const [name,before,after,diff,hunks] of specs){const a=applyUnified(get(before),get(diff));need(a.text===get(after),name+".strict_diff");need(a.hunks===hunks,name+".hunk_count");}
 const request=JSON.parse(get("b520b336d6e4015d1162346bb48a41855064fa4b")),carrierRaw=get("f9166bc801c5b10e12b77274f485d27d61cd499a"),carrier=JSON.parse(carrierRaw);
 need(Object.keys(request).sort().join(",")==="args,cwd,executable,host,idempotency_key,stdin,timeout_seconds","exact_request_fields");
 need(request.host==="rog"&&request.executable==="/usr/bin/python3"&&request.cwd==="/home/qian-qi"&&request.timeout_seconds===360,"fixed_host_executable_cwd_outer");
 need(request.idempotency_key==="heptabao-same-root-publication-4e808-rog-source-20261105-r2-3971051a","exact_idempotency_key");
 need(JSON.stringify(request.args)===JSON.stringify(["-I","-S","-B","-c",get("5eb1fd375fb7d7bb4f1b2dadb715fa6eecedf494"),"--self-sha256","3971051a80a776723a4f2b5db701c91876c4c6ff00ba536d781dd46002c812f4","--carrier-sha256","85fd6e473ce1e231f1bcfbd2bcf2bef760e6a4e551040c55ee3274606acebb77"]),"exact_embedded_source_and_args");
 need(request.stdin===carrierRaw,"exact_carrier_body");
 need(hash(carrierRaw)==="85fd6e473ce1e231f1bcfbd2bcf2bef760e6a4e551040c55ee3274606acebb77"&&utf8(carrierRaw).length===79951,"carrier_whole_pin");
 need(Object.keys(carrier).sort().join(",")==="controls,schema"&&carrier.schema==="heptabao.same-root-publication-inert-controls.v1","carrier_schema");
 const controls={"normal_same_root_publication_build.py":[35452,"93dd6190c7f081305defdbc1c49600974bfa581d943736c77798d51a1c8f54be","5e50290e953939bfab3b095244a50a7eb77d092d"],"launch_normal_same_root_publication.py":[35592,"8c0ba96f4953ba934d2dd067ef8bc7de2534f93181d99816fe38b056f564ab96","7b42cf15a40c4c16b5f473714baf7abea88bef1f"],"normal-test-groups.public.json":[6249,"0566f7f98ea16a4c1df43ebaf992172646ad91623c18f68fcc59f7c08b53d1f1",null],"prior-observer-build-authority.public.json":[726,"820a3243ba5be87f4d8fdf3d47d68361a2f2d6a95043d38c0086afab1cf559b6",null]};
 need(Object.keys(carrier.controls).sort().join(",")===Object.keys(controls).sort().join(","),"four_exact_controls");
 for(const [name,[bytes,sha,blob]] of Object.entries(controls)){const body=carrier.controls[name];need(typeof body==="string"&&utf8(body).length===bytes&&hash(body)===sha,"control."+name+".whole_pin");if(blob)need(body===get(blob),"control."+name+".source_exact");}
 const groups=JSON.parse(carrier.controls["normal-test-groups.public.json"]);need(JSON.stringify(groups.map(g=>[g.label,g.tests.length]))===JSON.stringify([["ssh25",25],["mount1",1],["redirect5",5],["actor2",2],["ordinary5",5],["no_forward6",6]])&&groups.every(g=>g.runtime_seconds===600),"original44_groups_and_runtime_caps");
 const ft=input.canonical_tree,leaves=ft.tree.filter(x=>x.type==="blob");need(ft.sha==="eba5e650bd080b8ad41ea52a2bc68867f541d255"&&ft.truncated===false,"independent_canonical_full_tree");
 need(leaves.length===3914&&leaves.reduce((n,x)=>n+x.size,0)===62227757,"independent_full_source_count_bytes");
 need(leaves.every((x,i)=>i===0||leaves[i-1].path<x.path),"canonical_leaf_order");
 const ix=leaves.map(x=>x.path+"\0"+x.mode+"\0"+x.sha+"\0"+x.size+"\n").join("");
 need(hash(ix)==="4bdd85122123e7c8ddfe7e82220688ba23fecd263bb245cfdfc176d08226e092","independent_canonical_worktree_index");
 const future=JSON.parse(get("1c3ec64adee965f426c04f5bca62801125f400ca"));need(future.ready===false&&future.actual_stage_sha256===null&&future.candidate_request.args.includes("__ACTUAL_STAGE_SHA256__"),"future_normal_build_unbound");
 return {schema:"heptabao.retained-a.rog-source.root-review.v1",status:"PASS_SOURCE_ONLY",source_packet:input.audit.tree,whole_files:input.audit.files,whole_bytes:input.audit.bytes,whole_merkle_trees:input.audit.merkle.trees_verified,checks,check_count:checks.length,source_commit:"4e808d0ecb1bcded22870a7ec960dfb2491cf6ec",source_tree:ft.sha,canonical_worktree_index_sha256:hash(ix),original_function_code_unchanged_by_reviewed_exact_diffs:true,source_stage_only:true,normal_build_go:false,production_qualification:false,full_replacement:false};
}
