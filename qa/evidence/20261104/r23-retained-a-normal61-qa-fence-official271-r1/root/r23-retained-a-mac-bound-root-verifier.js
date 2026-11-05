function verifyMacActualBundleBinding(input,apply,utf8,latin1,sha256,unb64){
 const raw=input.raw,checks=[];const ck=(n,v)=>{if(!v)throw Error(n);checks.push(n);},hash=s=>sha256(latin1(utf8(s))),obj=p=>JSON.parse(raw[p]);
 const before=raw["before/mac-stager.unbound.py"],after=raw["candidate/mac-stager.py"],diff=raw["diffs/mac-stager.actual-bundle.diff"],a=apply(before,diff);
 ck("strict_one_hunk_exact_source",a.hunks===1&&a.text===after);
 ck("only_two_none_literals_bound",before.replace("CANONICAL_BUNDLE_BYTES = None\n","CANONICAL_BUNDLE_BYTES = 29953\n").replace("CANONICAL_BUNDLE_SHA256 = None\n","CANONICAL_BUNDLE_SHA256 = 'e5a6b9829a787bbfaea0dd120550aad7e011cc641942ff6947db85a649383b68'\n")===after);
 const req=obj("dispatch/source-stage.request.json"),carrier=obj("dispatch/stdin.public.json"),old=JSON.parse(input.unboundCarrier),template=JSON.parse(input.unboundRequest).candidate_request,bundle=obj("native/bundle-read.json"),info=obj("native/bundle-info.json"),bytes=unb64(bundle.data_base64);
 ck("carrier_only_actual_base64_changed",Object.keys(carrier).sort().join(",")===Object.keys(old).sort().join(",")&&carrier.schema===old.schema&&JSON.stringify(carrier.controls)===JSON.stringify(old.controls)&&old.canonical_bundle_base64===null&&carrier.canonical_bundle_base64===bundle.data_base64);
 ck("actual_bundle_whole_bytes_sha",bytes.length===29953&&sha256(latin1(bytes))==="e5a6b9829a787bbfaea0dd120550aad7e011cc641942ff6947db85a649383b68"&&bundle.chunk_sha256===info.sha256&&info.sha256===sha256(latin1(bytes)));
 ck("actual_bundle_same_version_original_field",bundle.version===info.version&&bundle.offset===0&&bundle.eof===true&&bundle.next_offset===bytes.length&&info.size===bytes.length&&raw["bundle/canonical-same-root-publication-from495.bundle.base64"]===bundle.data_base64+"\n");
 ck("same_root_reviewed_rog_actual_bundle",input.rogRoot.status==="PASS_SOURCE_AND_BUNDLE_ONLY"&&input.rogRoot.bundle.bytes===bytes.length&&input.rogRoot.bundle.sha256===info.sha256&&input.rogRoot.bundle.version===info.version);
 ck("request_same_fixed_fields_and_host",req.host==="mac"&&["host","executable","cwd","timeout_seconds"].every(k=>req[k]===template[k])&&req.timeout_seconds===360&&Object.keys(req).sort().join(",")===Object.keys(template).sort().join(","));
 ck("request_exact_source_and_self_sha",req.args[4]===after&&req.args[6]===hash(after)&&hash(after)==="aeb8e5b510c6b82cfff2df62c9126c84d8732cdf8c4ba69a108f234db084818f");
 ck("request_exact_carrier_and_sha",req.stdin===raw["dispatch/stdin.public.json"]&&req.args[8]===hash(req.stdin)&&utf8(req.stdin).length===108593&&utf8(req.stdin).length<=262144);
 ck("request_exact_bundle_args",req.args[10]===String(bytes.length)&&req.args[12]===info.sha256&&req.args.length===13);
 ck("request_other_args_unchanged",req.args.every((x,i)=>[4,6,8,10,12].includes(i)||x===template.args[i]));
 ck("request_exact_source_bound_key",req.idempotency_key===template.idempotency_key.slice(0,template.idempotency_key.lastIndexOf("-")+1)+hash(after).slice(0,8));
 const v=obj("verification/selected-stdout.public.json"),e=obj("verification/selected-executor.public.json");
 ck("actual_selected_checks_exec_whole_stdout",e.exit_code===0&&e.output===raw["verification/selected-stdout.public.json"]);
 ck("actual25checks_source_only",v.all_passed===true&&v.checks.length===25&&v.checks.every(x=>x.passed===true)&&v.definitions_unchanged===21&&v.source_module_executed===false&&v.selected_argparse_only===true&&v.remote_calls===0&&v.rust_or_cargo===0);
 return{schema:"heptabao.root.mac-4e808-actual-bundle-binding.v1",status:"PASS_EXACT_SOURCE_STAGE_READY",packet:input.audit.tree,files:input.audit.files,bytes:input.audit.bytes,merkle_trees:input.audit.merkle.trees_verified,check_count:checks.length,checks,source_sha256:hash(after),carrier_sha256:hash(req.stdin),bundle:{bytes:bytes.length,sha256:info.sha256,version:info.version},normal_build_go:false,full_replacement:false};
}
